use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use wavvon_farm::db;
use wavvon_farm::hub_manager::HubManager;
use wavvon_farm::server;
use wavvon_farm::settings;
use wavvon_farm::state::FarmState;

/// Persisted farm identity — same shape as hub_identity.json.
#[derive(Serialize, Deserialize)]
struct SavedFarmIdentity {
    secret_key: String,
}

fn load_or_create_keypair(path: &Path) -> Result<(SigningKey, bool)> {
    if path.exists() {
        let json = std::fs::read_to_string(path).context("Failed to read farm_identity.json")?;
        let saved: SavedFarmIdentity =
            serde_json::from_str(&json).context("Failed to parse farm_identity.json")?;
        let bytes = hex::decode(&saved.secret_key).context("Invalid hex in farm_identity.json")?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Secret key must be 32 bytes"))?;
        Ok((SigningKey::from_bytes(&array), false))
    } else {
        let keypair = SigningKey::generate(&mut OsRng);
        let saved = SavedFarmIdentity {
            secret_key: hex::encode(keypair.to_bytes()),
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).context("Failed to create identity directory")?;
        }
        std::fs::write(path, serde_json::to_string_pretty(&saved)?)
            .context("Failed to write farm_identity.json")?;
        Ok((keypair, true))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration first — before logging setup so we can use log_format.
    let cfg = match settings::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    // Computed early — before any partial move of `cfg`'s fields below makes
    // a whole-struct method call on `cfg` impossible.
    let voice_base_port = cfg.resolved_voice_base_port();

    let json_logs = cfg.log_format.to_lowercase() == "json";

    // Optional OpenTelemetry OTLP trace export.
    // Set WAVVON_OTLP_ENDPOINT to any OTLP-compatible collector
    // (Grafana Tempo, Jaeger, Honeycomb, Datadog, etc.).
    // No-op when the variable is unset or empty.
    let otlp_provider = cfg
        .otlp_endpoint
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|endpoint| {
            use opentelemetry_otlp::WithExportConfig;
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .build()
                .ok()?;
            let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", env!("CARGO_PKG_NAME")),
                ]))
                .build();
            opentelemetry::global::set_tracer_provider(provider.clone());
            Some(provider)
        });

    use tracing_subscriber::prelude::*;
    let otel_layer = otlp_provider.as_ref().map(|provider| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(provider.tracer(env!("CARGO_PKG_NAME")))
    });

    // Respect RUST_LOG; default to info (same fix as hub — an unfiltered
    // subscriber logs TRACE from every dependency).
    let env_filter = || {
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
    };
    if json_logs {
        tracing_subscriber::registry()
            .with(otel_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_filter(env_filter()),
            )
            .init();
    } else {
        tracing_subscriber::registry()
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer().with_filter(env_filter()))
            .init();
    }

    tracing::info!("Configuration loaded");

    if otlp_provider.is_some() {
        tracing::info!("OpenTelemetry OTLP trace export enabled");
    }

    // `wavvon-farm migrate` — run migrations and exit.
    let subcommand = std::env::args().nth(1);
    if subcommand.as_deref() == Some("migrate") {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect(&cfg.database_url)
            .await?;
        db::migrations::run(&db).await?;
        tracing::info!("Migrations applied to PostgreSQL database");
        return Ok(());
    }

    let http_port = cfg.http_port;

    // Farm URL — required for embedding in tokens. Must be the externally reachable URL.
    let farm_url = cfg
        .farm_url
        .unwrap_or_else(|| format!("http://127.0.0.1:{http_port}"));

    let (keypair, is_new) = load_or_create_keypair(Path::new("farm_identity.json"))?;
    let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    if is_new {
        tracing::info!("Generated new farm identity: {pubkey_hex}");
    } else {
        tracing::info!("Loaded farm identity: {pubkey_hex}");
    }

    let db = PgPoolOptions::new()
        .max_connections(cfg.db_max_connections)
        .connect(&cfg.database_url)
        .await?;

    db::migrations::run(&db).await?;

    // Ensure the farms singleton row exists.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO farms (id, public_key, created_at)
         VALUES (1, $1, $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(&pubkey_hex)
    .bind(now)
    .execute(&db)
    .await?;

    // Seed the admin on first start, exactly as the hub seeds its owner.
    //
    // `COALESCE` rather than a plain UPDATE: this only ever fills a NULL, so
    // an operator cannot take over a farm that already has an admin by
    // restarting it with the variable set.
    if let Some(admin) = cfg.farm_admin_pubkey.as_deref() {
        let admin = admin.trim();
        let looks_like_a_key = admin.len() == 64 && admin.chars().all(|c| c.is_ascii_hexdigit());
        if !looks_like_a_key {
            anyhow::bail!(
                "WAVVON_FARM_ADMIN_PUBKEY must be 64 hex characters (an Ed25519 public key), got {} character(s)",
                admin.len()
            );
        }
        let updated =
            sqlx::query("UPDATE farms SET admin_pubkey = $1 WHERE id = 1 AND admin_pubkey IS NULL")
                .bind(admin)
                .execute(&db)
                .await?
                .rows_affected();
        if updated > 0 {
            tracing::info!(admin = %admin, "Seeded farm admin from WAVVON_FARM_ADMIN_PUBKEY");
        }
    }

    // A farm with no admin cannot create a hub and cannot appoint one, so say
    // so loudly rather than letting every request answer `admin_only`.
    let admin_exists: Option<String> =
        sqlx::query_scalar::<_, Option<String>>("SELECT admin_pubkey FROM farms WHERE id = 1")
            .fetch_optional(&db)
            .await?
            .flatten();
    if admin_exists.is_none() {
        tracing::warn!(
            "This farm has no admin. `creation_policy` defaults to 'admin_only', so every \
             hub creation will be refused and there is no route to appoint an admin. Set \
             WAVVON_FARM_ADMIN_PUBKEY to your own user pubkey and restart."
        );
    }

    // Resolve the hub binary path: use settings value if provided, else fall back
    // to a sibling of the current executable.
    let hub_bin = if let Some(path) = cfg.hub_bin {
        path
    } else {
        if let Ok(exe) = std::env::current_exe() {
            let dir = exe.parent().unwrap_or(Path::new("."));
            let candidate = dir.join(if cfg!(windows) {
                "wavvon-hub.exe"
            } else {
                "wavvon-hub"
            });
            if candidate.exists() {
                candidate.to_string_lossy().into_owned()
            } else {
                "wavvon-hub".to_string()
            }
        } else {
            "wavvon-hub".to_string()
        }
    };

    tracing::info!("Hub binary path: {hub_bin}");
    let hub_manager = Arc::new(HubManager::new(
        hub_bin,
        farm_url.clone(),
        cfg.hub_base_port,
        voice_base_port,
        // Each hub's database is created on the same server the farm uses.
        cfg.database_url.clone(),
        // Each hub runs in its own directory under here, so they cannot share
        // an identity file.
        cfg.hubs_dir.clone(),
    ));
    hub_manager.spawn_all_from_db(&db).await?;

    let state = Arc::new(FarmState::new(
        db,
        keypair,
        farm_url,
        hub_manager,
        cfg.hubs_dir,
    ));

    wavvon_farm::monitor::spawn(state.clone());

    let app = server::create_router_with_cors(state, &cfg.cors_origins);
    let addr: std::net::SocketAddr = format!("0.0.0.0:{http_port}").parse()?;
    tracing::info!(
        "Farm server listening on http://0.0.0.0:{http_port} (set WAVVON_FARM_URL for the external URL)"
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    if let Some(provider) = otlp_provider {
        let _ = provider.shutdown();
    }

    Ok(())
}
