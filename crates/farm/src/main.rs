use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
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

    if json_logs {
        tracing_subscriber::registry()
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(otel_layer)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }

    tracing::info!("Configuration loaded");

    if otlp_provider.is_some() {
        tracing::info!("OpenTelemetry OTLP trace export enabled");
    }

    // `wavvon-farm migrate` — run migrations and exit.
    let subcommand = std::env::args().nth(1);
    if subcommand.as_deref() == Some("migrate") {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite:farm.db?mode=rwc")
            .await?;
        db::migrations::run(&db).await?;
        println!("Migrations applied to farm.db");
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

    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:farm.db?mode=rwc")
        .await?;

    db::migrations::run(&db).await?;

    // Ensure the farms singleton row exists.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query(
        "INSERT OR IGNORE INTO farms (id, public_key, created_at)
         VALUES (1, ?, ?)",
    )
    .bind(&pubkey_hex)
    .bind(now)
    .execute(&db)
    .await?;

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
    ));
    hub_manager.spawn_all_from_db(&db).await?;

    let state = Arc::new(FarmState::new(
        db,
        keypair,
        farm_url,
        hub_manager,
        cfg.hubs_dir,
    ));

    let app = server::create_router(state);
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
