use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use store::PostgresStore;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::bots::token_expiry;
use wavvon_hub::cert_worker;
use wavvon_hub::db;
use wavvon_hub::dm_worker;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::{AppState, ConsumedVoiceToken};
use wavvon_identity::Identity;

/// Print the `--help` text to stdout.
fn print_help() {
    println!("wavvon-hub {}\n", env!("CARGO_PKG_VERSION"));
    println!("USAGE:");
    println!("  wavvon-hub [SUBCOMMAND | OPTION]\n");
    println!("SUBCOMMANDS:");
    println!("  migrate          Apply DB migrations and exit");
    println!("  backup [FILE]    Write a backup archive (default: hub-backup-<ts>.tar.gz)");
    println!("  restore FILE     Restore from a backup archive");
    println!("  rotate-key       Generate a new hub keypair and sign a rotation payload");
    println!("  update [--check] Self-update binary from GitHub releases (Linux x86_64 only)");
    println!("  admin <cmd>      Admin CLI (stats|users|channels|tokens|backup|restore)\n");
    println!("OPTIONS:");
    println!("  -h, --help       Print this help message");
    println!("  -V, --version    Print version");
    println!("  --doctor         Pre-flight checks: bind ports, verify TLS files, check disk\n");
    println!("ENVIRONMENT VARIABLES:");

    let name_w = wavvon_hub::settings::ENV_VAR_HELP
        .iter()
        .map(|(n, _, _)| n.len())
        .max()
        .unwrap_or(20);
    let default_w = wavvon_hub::settings::ENV_VAR_HELP
        .iter()
        .map(|(_, d, _)| d.len())
        .max()
        .unwrap_or(10);

    println!(
        "  {:<name_w$}  {:<default_w$}  Purpose",
        "Variable", "Default"
    );
    println!(
        "  {:<name_w$}  {:<default_w$}  {}",
        "-".repeat(name_w),
        "-".repeat(default_w),
        "-".repeat(40)
    );
    for (name, default, purpose) in wavvon_hub::settings::ENV_VAR_HELP {
        println!("  {name:<name_w$}  {default:<default_w$}  {purpose}");
    }
    println!();
    println!("Configuration is also accepted from hub.toml in the working directory.");
    println!("Environment variables override hub.toml values.");
}

/// Run --doctor pre-flight checks. Returns true if all checks pass.
async fn run_doctor() -> bool {
    use std::net::TcpListener;
    use tokio::net::UdpSocket;

    let settings = match wavvon_hub::settings::load() {
        Ok(s) => s,
        Err(e) => {
            println!("FAIL  settings: {e}");
            return false;
        }
    };
    println!("PASS  settings: loaded");

    let mut all_pass = true;

    // Check TCP port
    match TcpListener::bind(format!("0.0.0.0:{}", settings.http_port)) {
        Ok(_) => println!("PASS  HTTP port {}: bindable", settings.http_port),
        Err(e) => {
            println!("FAIL  HTTP port {}: {e}", settings.http_port);
            all_pass = false;
        }
    }

    // Check UDP port
    match UdpSocket::bind(format!("0.0.0.0:{}", settings.voice_udp_port)).await {
        Ok(_) => println!("PASS  Voice UDP port {}: bindable", settings.voice_udp_port),
        Err(e) => {
            println!("FAIL  Voice UDP port {}: {e}", settings.voice_udp_port);
            all_pass = false;
        }
    }

    // Check TLS files if configured
    match (settings.tls_cert.as_deref(), settings.tls_key.as_deref()) {
        (Some(cert), Some(key)) => {
            for (label, path) in [("TLS cert", cert), ("TLS key", key)] {
                match std::fs::read(path) {
                    Ok(bytes) => {
                        // Minimal PEM sanity: file must contain "-----BEGIN"
                        if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
                            println!("PASS  {label} ({path}): readable PEM");
                        } else {
                            println!(
                                "FAIL  {label} ({path}): file exists but does not look like PEM"
                            );
                            all_pass = false;
                        }
                    }
                    Err(e) => {
                        println!("FAIL  {label} ({path}): {e}");
                        all_pass = false;
                    }
                }
            }
        }
        (None, None) => {
            println!("INFO  TLS: not configured (plaintext HTTP)");
        }
        _ => {
            println!(
                "FAIL  TLS: WAVVON_TLS_CERT and WAVVON_TLS_KEY must both be set or both unset"
            );
            all_pass = false;
        }
    }

    // Check working directory writable
    let probe = ".wavvon-doctor-probe";
    match std::fs::write(probe, b"ok") {
        Ok(_) => {
            let _ = std::fs::remove_file(probe);
            println!(
                "PASS  working directory ({}): writable",
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "?".into())
            );
        }
        Err(e) => {
            println!(
                "FAIL  working directory ({}): {e}",
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "?".into())
            );
            all_pass = false;
        }
    }

    // Check web client directory when configured
    match settings.web_client_dir.as_deref() {
        None => {
            println!("INFO  web client: disabled (WAVVON_WEB_CLIENT_DIR not set)");
        }
        Some(dir) => {
            let dir_path = std::path::Path::new(dir);
            if !dir_path.exists() {
                println!("FAIL  web client dir '{dir}': directory does not exist");
                all_pass = false;
            } else {
                let index = dir_path.join("index.html");
                match std::fs::read(&index) {
                    Ok(bytes) if !bytes.is_empty() => {
                        println!("PASS  web client dir '{dir}': directory exists, index.html readable ({} bytes)", bytes.len());
                    }
                    Ok(_) => {
                        println!("FAIL  web client dir '{dir}': index.html exists but is empty");
                        all_pass = false;
                    }
                    Err(e) => {
                        println!("FAIL  web client dir '{dir}': cannot read index.html: {e}");
                        all_pass = false;
                    }
                }
            }
        }
    }

    if all_pass {
        println!("\nAll checks passed.");
    } else {
        println!("\nOne or more checks failed.");
    }
    all_pass
}

#[tokio::main]
async fn main() -> Result<()> {
    // Fast-path CLI flags that don't need settings or logging.
    let args: Vec<String> = std::env::args().collect();
    let first_arg = args.get(1).map(|s| s.as_str());

    if matches!(first_arg, Some("-h") | Some("--help")) {
        print_help();
        return Ok(());
    }

    if matches!(first_arg, Some("-V") | Some("--version")) {
        println!("wavvon-hub {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if first_arg == Some("--doctor") {
        let ok = run_doctor().await;
        std::process::exit(if ok { 0 } else { 1 });
    }

    let settings = match wavvon_hub::settings::load() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    let json_logs = settings.log_format.to_lowercase() == "json";

    // Optional OpenTelemetry OTLP trace export.
    // Set WAVVON_OTLP_ENDPOINT or otlp_endpoint in hub.toml to any
    // OTLP-compatible collector (Grafana Tempo, Jaeger, Honeycomb, Datadog, etc.).
    // No-op when unset or empty.
    let otlp_provider = settings
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

    // Subcommand dispatch (migrate, backup, restore, rotate-key, update, admin).
    // These exit before the server starts; `--help` / `--version` / `--doctor`
    // are handled above before settings are loaded.
    let subcommand = std::env::args().nth(1);
    if subcommand.as_deref() == Some("migrate") {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/wavvon".to_string());
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await?;
        db::migrations::run(&db).await?;
        println!("Migrations applied");
        return Ok(());
    }

    if subcommand.as_deref() == Some("backup") {
        let out_path = std::env::args().nth(2).unwrap_or_else(|| {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("hub-backup-{ts}.tar.gz")
        });
        backup(&out_path)?;
        println!("Backup written to {out_path}");
        return Ok(());
    }

    if subcommand.as_deref() == Some("restore") {
        let src = std::env::args()
            .nth(2)
            .ok_or_else(|| anyhow::anyhow!("Usage: wavvon-hub restore <backup.tar.gz>"))?;
        restore(&src)?;
        println!("Restore complete. Restart the hub to apply.");
        return Ok(());
    }

    if subcommand.as_deref() == Some("rotate-key") {
        let new_key_path = std::env::args()
            .nth(2)
            .unwrap_or_else(|| "hub_identity_new.json".to_string());
        rotate_hub_key(Path::new("hub_identity.json"), Path::new(&new_key_path))?;
        println!("Key rotation complete. hub_identity.json now contains the new key.");
        println!("hub_rotation.json contains the signed rotation payload.");
        println!("Restart the hub for the change to take effect.");
        return Ok(());
    }

    if subcommand.as_deref() == Some("update") {
        let check_only = std::env::args().any(|a| a == "--check");
        run_self_update(check_only).await?;
        return Ok(());
    }

    if subcommand.as_deref() == Some("admin") {
        let admin_cmd = std::env::args().nth(2).unwrap_or_default();
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/wavvon".to_string());
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .context("Cannot open DB for admin command")?;

        match admin_cmd.as_str() {
            "stats" => {
                let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
                    .fetch_one(&db)
                    .await
                    .unwrap_or(0);
                let channels: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE is_category=false")
                        .fetch_one(&db)
                        .await
                        .unwrap_or(0);
                let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
                    .fetch_one(&db)
                    .await
                    .unwrap_or(0);
                let bans: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bans")
                    .fetch_one(&db)
                    .await
                    .unwrap_or(0);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "users": users,
                        "channels": channels,
                        "messages": messages,
                        "bans": bans
                    }))
                    .unwrap()
                );
            }
            "users" => {
                let action = std::env::args().nth(3).unwrap_or_default();
                match action.as_str() {
                    "list" => {
                        let rows: Vec<(String, Option<String>, i64)> = sqlx::query_as(
                            "SELECT public_key, display_name, first_seen_at FROM users ORDER BY first_seen_at DESC LIMIT 50",
                        )
                        .fetch_all(&db)
                        .await
                        .unwrap_or_default();
                        let json: Vec<_> = rows
                            .iter()
                            .map(|(pk, dn, ts)| {
                                serde_json::json!({
                                    "pubkey": pk,
                                    "display_name": dn,
                                    "first_seen_at": ts
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&json).unwrap());
                    }
                    "ban" => {
                        let pubkey = std::env::args()
                            .nth(4)
                            .context("Usage: admin users ban <pubkey>")?;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        sqlx::query(
                            "INSERT INTO bans(target_public_key, banned_by, reason, created_at) VALUES($1,'cli','CLI ban',$2) ON CONFLICT (target_public_key) DO NOTHING",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db)
                        .await?;
                        println!("Banned {pubkey}");
                    }
                    "unban" => {
                        let pubkey = std::env::args()
                            .nth(4)
                            .context("Usage: admin users unban <pubkey>")?;
                        sqlx::query("DELETE FROM bans WHERE target_public_key = $1")
                            .bind(&pubkey)
                            .execute(&db)
                            .await?;
                        println!("Unbanned {pubkey}");
                    }
                    "set-owner" => {
                        let pubkey = std::env::args()
                            .nth(4)
                            .context("Usage: admin users set-owner <pubkey>")?;
                        let pubkey = pubkey.to_lowercase();
                        if pubkey.len() != 64 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
                            anyhow::bail!("Invalid pubkey: expected 64 hex characters");
                        }
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        // Revoke any existing owner first
                        let prev: Option<String> = sqlx::query_scalar(
                            "SELECT user_public_key FROM user_roles WHERE role_id = 'builtin-owner' LIMIT 1",
                        )
                        .fetch_optional(&db)
                        .await
                        .unwrap_or(None);
                        sqlx::query("DELETE FROM user_roles WHERE role_id = 'builtin-owner'")
                            .execute(&db)
                            .await?;
                        if let Some(p) = prev {
                            println!("Revoked owner from {}…", &p[..16.min(p.len())]);
                        }
                        // Ensure a minimal user record exists
                        sqlx::query(
                            "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT (public_key) DO NOTHING",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db)
                        .await?;
                        sqlx::query(
                            "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ($1, 'builtin-owner', $2)
                             ON CONFLICT (user_public_key, role_id) DO UPDATE SET assigned_at = excluded.assigned_at",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db)
                        .await?;
                        println!("Owner set to {pubkey}");
                    }
                    _ => println!(
                        "Usage: wavvon-hub admin users [list|ban|unban|set-owner] [pubkey]"
                    ),
                }
            }
            "channels" => {
                let action = std::env::args().nth(3).unwrap_or_default();
                match action.as_str() {
                    "list" => {
                        let rows: Vec<(String, String)> = sqlx::query_as(
                            "SELECT id, name FROM channels WHERE is_category=false ORDER BY display_order",
                        )
                        .fetch_all(&db)
                        .await
                        .unwrap_or_default();
                        println!(
                            "{}",
                            serde_json::to_string_pretty(
                                &rows
                                    .iter()
                                    .map(|(id, name)| serde_json::json!({"id": id, "name": name}))
                                    .collect::<Vec<_>>()
                            )
                            .unwrap()
                        );
                    }
                    _ => println!("Usage: wavvon-hub admin channels [list]"),
                }
            }
            "tokens" => {
                let rows: Vec<(String, String, i64)> = sqlx::query_as(
                    "SELECT token, public_key, created_at FROM sessions ORDER BY created_at DESC LIMIT 20",
                )
                .fetch_all(&db)
                .await
                .unwrap_or_default();
                let json: Vec<_> = rows
                    .iter()
                    .map(|(t, pk, ts)| {
                        serde_json::json!({
                            "token_prefix": &t[..8.min(t.len())],
                            "public_key": pk,
                            "created_at": ts
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
            "backup" => {
                let out = std::env::args().nth(3).unwrap_or_else(|| {
                    format!(
                        "hub-backup-{}.tar.gz",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                    )
                });
                backup(&out)?;
                println!("Backup written to {out}");
            }
            "restore" => {
                let src = std::env::args()
                    .nth(3)
                    .context("Usage: admin restore <backup.tar.gz>")?;
                restore(&src)?;
                println!("Restore complete. Restart the hub.");
            }
            _ => {
                println!("Usage: wavvon-hub admin [stats|users|channels|tokens|backup|restore]");
            }
        }
        return Ok(());
    }

    let http_port = settings.http_port;
    let voice_udp_port = settings.voice_udp_port;

    // ---- Startup summary banner ----
    let tls_enabled = settings.tls_cert.is_some() && settings.tls_key.is_some();
    let scheme = if tls_enabled { "https" } else { "http" };
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".into());

    tracing::info!(
        "wavvon-hub {} starting  port={} ({scheme})  voice_udp={}  tls={}  cors={}",
        env!("CARGO_PKG_VERSION"),
        http_port,
        voice_udp_port,
        if tls_enabled { "enabled" } else { "disabled" },
        settings.cors_origins,
    );
    tracing::info!("data: identity={cwd}/hub_identity.json  database=PostgreSQL");

    if !tls_enabled {
        tracing::warn!(
            "TLS is disabled — browser clients served over HTTPS cannot connect to an http:// hub \
             (mixed-content blocked). Set WAVVON_TLS_CERT and WAVVON_TLS_KEY or terminate TLS at a reverse proxy."
        );
    }
    tracing::info!(
        "Reminder: the voice UDP port {} must be open in any cloud firewall / security group — \
         voice fails silently when the port is blocked.",
        voice_udp_port
    );
    match settings.web_client_dir.as_deref() {
        Some(dir) => tracing::info!("web client: serving from {dir}"),
        None => tracing::info!("web client: disabled (set WAVVON_WEB_CLIENT_DIR to enable)"),
    }

    let (hub_identity, is_new) = Identity::load_or_create(Path::new("hub_identity.json"))?;
    if is_new {
        tracing::info!("Generated new hub identity: {}", hub_identity);
    } else {
        tracing::info!("Loaded hub identity: {}", hub_identity);
    }

    let db_url = settings
        .database_url
        .as_deref()
        .unwrap_or("postgres://postgres:postgres@localhost:5432/wavvon");

    let write_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await
        .expect("Failed to connect to database");

    let read_pool = if let Some(read_url) = settings.database_read_url.as_deref() {
        Some(
            PgPoolOptions::new()
                .max_connections(5)
                .connect(read_url)
                .await
                .expect("Failed to connect to read-replica database"),
        )
    } else {
        None
    };

    let db = write_pool;
    let db_read = read_pool;

    db::migrations::run(&db).await?;

    // If owner_pubkey is configured, seed that key as the hub owner before
    // serving any traffic. Idempotent: skipped if the key is already owner.
    // The farm sets this when spawning a hub created by a specific user.
    if let Some(owner_pk) = settings.owner_pubkey.as_deref() {
        let owner_pk = owner_pk.trim().to_lowercase();
        if owner_pk.len() == 64 && owner_pk.chars().all(|c| c.is_ascii_hexdigit()) {
            let current: Option<String> = sqlx::query_scalar(
                "SELECT user_public_key FROM user_roles WHERE role_id = 'builtin-owner' LIMIT 1",
            )
            .fetch_optional(&db)
            .await
            .unwrap_or(None);

            if current.as_deref() != Some(&owner_pk) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                sqlx::query(
                    "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT (public_key) DO NOTHING",
                )
                .bind(&owner_pk)
                .bind(now)
                .execute(&db)
                .await
                .ok();
                sqlx::query("DELETE FROM user_roles WHERE role_id = 'builtin-owner'")
                    .execute(&db)
                    .await
                    .ok();
                sqlx::query(
                    "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ($1, 'builtin-owner', $2)
                     ON CONFLICT (user_public_key, role_id) DO UPDATE SET assigned_at = excluded.assigned_at",
                )
                .bind(&owner_pk)
                .bind(now)
                .execute(&db)
                .await
                .ok();
                tracing::info!(
                    "Hub owner seeded from owner_pubkey: {}…",
                    &owner_pk[..16.min(owner_pk.len())]
                );
            }
        } else {
            tracing::warn!("owner_pubkey is set but not a valid 64-char hex key; ignoring");
        }
    }

    if settings.owner_pubkey.is_none() {
        tracing::warn!(
            "No WAVVON_OWNER_PUBKEY configured. \
             The hub has no owner; set WAVVON_OWNER_PUBKEY and restart, \
             or assign the builtin-owner role manually via the API."
        );
    }

    // First-run bootstrap: applies a template from template_url or redeems
    // bootstrap_token when the channels table is empty.
    // Non-fatal — a bad template or unreachable URL never blocks startup.
    {
        let bootstrap_client = reqwest::Client::new();
        wavvon_hub::bootstrap::maybe_bootstrap(
            &db,
            &bootstrap_client,
            &wavvon_hub::bootstrap::BootstrapConfig {
                template_url: settings.template_url.clone(),
                bootstrap_token: settings.bootstrap_token.clone(),
                discovery_url: settings.discovery_url.clone(),
            },
        )
        .await
        .unwrap_or_else(|e| tracing::warn!("Bootstrap failed (non-fatal): {e}"));
    }

    let search_path = std::path::Path::new("hub.search");
    let search: Arc<dyn wavvon_hub::search::MessageSearch> =
        if settings.search_backend.as_deref() == Some("none") {
            Arc::new(wavvon_hub::search::null_search::NullSearch)
        } else {
            Arc::new(
                wavvon_hub::search::tantivy_search::TantivySearch::open(search_path)
                    .expect("Failed to open Tantivy search index"),
            )
        };

    let (chat_tx, _) = broadcast::channel::<(
        wavvon_hub::routes::chat_models::ChatEvent,
        std::sync::Arc<str>,
    )>(4096);
    let (voice_event_tx, _) = broadcast::channel(1024);
    let (dm_tx, _) = broadcast::channel(1024);
    let (screen_share_tx, _) = broadcast::channel(1024);

    // Farm integration: fetch the farm pubkey from farm_url if set.
    let farm_url = settings.farm_url.clone();
    let http_client = reqwest::Client::new();
    let cached_farm_pubkey: Arc<tokio::sync::RwLock<Option<String>>> =
        Arc::new(tokio::sync::RwLock::new(None));
    let last_farm_pubkey_fetch: Arc<tokio::sync::RwLock<i64>> =
        Arc::new(tokio::sync::RwLock::new(0));

    if let Some(ref url) = farm_url {
        match http_client
            .get(format!("{url}/farm/info"))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        if let Some(pk) = body.get("public_key").and_then(|v| v.as_str()) {
                            *cached_farm_pubkey.write().await = Some(pk.to_string());
                            tracing::info!(
                                "Cached farm pubkey from {url}: {}",
                                &pk[..16.min(pk.len())]
                            );
                        } else {
                            tracing::warn!("Farm /farm/info response missing public_key field");
                        }
                    }
                    Err(e) => tracing::warn!("Failed to parse farm /farm/info response: {e}"),
                }
            }
            Ok(resp) => tracing::warn!(
                "Farm /farm/info returned non-success status: {}",
                resp.status()
            ),
            Err(e) => tracing::warn!(
                "Could not reach farm at {url} on startup: {e} — hub will work with hub-issued tokens only"
            ),
        }
    }

    let store: Arc<dyn store::HubStore> = Arc::new(PostgresStore::new(db.clone()));

    let state = Arc::new(AppState {
        hub_name: "my-hub".to_string(),
        hub_identity,
        db,
        db_read,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        http_client,
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_udp_port,
        voice_event_tx,
        dm_tx,
        online_users: RwLock::new(HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx,
        bot_sessions: RwLock::new(HashMap::new()),
        farm_url,
        cached_farm_pubkey,
        last_farm_pubkey_fetch,
        voice_zones: RwLock::new(HashMap::new()),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: RwLock::new(HashMap::new()),
        whisper_target_defs: RwLock::new(HashMap::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        voice_pending_binds: RwLock::new(HashMap::new()),
        voice_consumed_tokens: RwLock::new(HashMap::new()),
        voice_ws_senders: RwLock::new(HashMap::new()),
        voice_udp_socket: Arc::new(RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search,
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: settings.owner_pubkey.clone(),
        bots_allow_camera: settings.bots_allow_camera,
    });

    // Bind voice UDP socket and start forwarding task
    let voice_socket = Arc::new(UdpSocket::bind(format!("0.0.0.0:{voice_udp_port}")).await?);
    *state.voice_udp_socket.write().await = Some(voice_socket.clone());
    tracing::info!("Voice UDP listening on port {voice_udp_port}");

    let voice_state = state.clone();
    tokio::spawn(async move {
        // Register packet magic: b"VXRG" (4 bytes) followed by the 64 hex-char token.
        // Total minimum length: 4 + 64 = 68 bytes.
        // Cannot be confused with an audio packet: audio is raw Opus and never
        // starts with the ASCII sequence 'V','X','R','G'.
        const VXRG_MAGIC: &[u8] = b"VXRG";
        const VXRG_TOKEN_LEN: usize = 64; // 32 bytes hex-encoded
        const VXRG_MIN_LEN: usize = 4 + VXRG_TOKEN_LEN; // 68

        // Ack packet sent back to a successfully registered source.
        const VXRA: &[u8] = b"VXRA";

        let mut buf = [0u8; 2048];
        loop {
            match voice_socket.recv_from(&mut buf).await {
                Ok((len, from_addr)) => {
                    let packet_data = &buf[..len];

                    // ── VXRG register packet ──────────────────────────────────
                    if len >= VXRG_MIN_LEN && &packet_data[..4] == VXRG_MAGIC {
                        let token_bytes = &packet_data[4..4 + VXRG_TOKEN_LEN];
                        let token = match std::str::from_utf8(token_bytes) {
                            Ok(t) => t,
                            Err(_) => continue, // not valid UTF-8 → drop
                        };

                        // Check consumed-token map first for idempotent re-ack.
                        // If this source address is already bound (token was consumed
                        // earlier), just ack again — the client may retry.
                        {
                            let already_bound = {
                                let consumed = voice_state.voice_consumed_tokens.read().await;
                                consumed.contains_key(&from_addr)
                            };
                            if already_bound {
                                let _ = voice_socket.send_to(VXRA, from_addr).await;
                                continue;
                            }
                        }

                        // Look up the pending bind.
                        let now = std::time::Instant::now();
                        let bind_opt = {
                            let mut binds = voice_state.voice_pending_binds.write().await;
                            // Purge expired entries opportunistically.
                            binds.retain(|_, v| v.expires_at > now);
                            binds.remove(token)
                        };

                        let bind = match bind_opt {
                            Some(b) if b.expires_at > now => b,
                            _ => {
                                // Unknown, expired, or already consumed from a
                                // different address: drop silently (no reply).
                                continue;
                            }
                        };

                        // Bind the real source address.
                        {
                            let mut addr_map = voice_state.voice_addr_map.write().await;
                            addr_map
                                .insert(from_addr, (bind.channel_id.clone(), bind.pubkey.clone()));
                        }
                        // Update voice_channels to store the real address instead of the sentinel.
                        {
                            let mut channels = voice_state.voice_channels.write().await;
                            if let Some(ch_map) = channels.get_mut(&bind.channel_id) {
                                ch_map.insert(bind.pubkey.clone(), from_addr);
                            }
                        }
                        // Record the consumed token so retries from the same address get re-acked.
                        {
                            let mut consumed = voice_state.voice_consumed_tokens.write().await;
                            consumed.insert(
                                from_addr,
                                ConsumedVoiceToken {
                                    bound_addr: from_addr,
                                    channel_id: bind.channel_id.clone(),
                                    pubkey: bind.pubkey.clone(),
                                },
                            );
                        }

                        tracing::debug!(
                            "Voice VXRG: bound {} → channel {} pubkey {}",
                            from_addr,
                            &bind.channel_id[..8.min(bind.channel_id.len())],
                            &bind.pubkey[..16.min(bind.pubkey.len())],
                        );

                        // Send ack.
                        let _ = voice_socket.send_to(VXRA, from_addr).await;
                        continue;
                    }

                    // ── Audio relay ───────────────────────────────────────────
                    // O(1) lookup: which channel+peer owns this SocketAddr?
                    let lookup = {
                        let map = voice_state.voice_addr_map.read().await;
                        map.get(&from_addr).cloned()
                    };
                    if let Some((channel_id, sender_pk)) = lookup {
                        // Gate: drop the packet if this pubkey no longer has a
                        // live WS-backed voice session.  This is the enforcement
                        // point that ties UDP relay lifetime to WS session
                        // lifetime — leave_voice() removes the entry, so a
                        // packet arriving after WS disconnect is rejected here
                        // before any fan-out work is done.
                        {
                            let active = voice_state.voice_relay_active.read().await;
                            if !active.contains(&sender_pk) {
                                continue;
                            }
                        }
                        // Look up the sender's sender_id for this channel.
                        let sender_id: u16 = {
                            let sids = voice_state.voice_sender_ids.read().await;
                            sids.get(&channel_id)
                                .and_then(|m| m.get(&sender_pk))
                                .copied()
                                .unwrap_or(0)
                        };
                        let sender_id_bytes = sender_id.to_be_bytes();

                        // Determine packet_type:
                        //   0x01 = whisper (fan-out to resolved whisper target set only)
                        //   0x00 = normal channel voice
                        let packet_type: u8 = {
                            let wt = voice_state.whisper_targets.read().await;
                            if wt.contains_key(&sender_pk) {
                                0x01u8
                            } else {
                                0x00u8
                            }
                        };

                        // Build outbound: [sender_id: 2][packet_type: 1][original packet]
                        let mut outbound = Vec::with_capacity(3 + packet_data.len());
                        outbound.extend_from_slice(&sender_id_bytes);
                        outbound.push(packet_type);
                        outbound.extend_from_slice(packet_data);

                        // Fan-out to UDP and WS participants.
                        //
                        // Hard invariant for UDP: only emit to addresses that have completed
                        // an authenticated UDP bind (i.e. present in voice_addr_map).
                        // The sentinel 0.0.0.0:0 is never in voice_addr_map, so
                        // unregistered UDP participants are automatically excluded.
                        // WS clients are identified by presence in voice_ws_senders.
                        let sentinel: SocketAddr = "0.0.0.0:0".parse().unwrap();
                        {
                            let addr_map = voice_state.voice_addr_map.read().await;
                            let channels = voice_state.voice_channels.read().await;
                            let ws_senders = voice_state.voice_ws_senders.read().await;

                            if packet_type == 0x01 {
                                // Whisper: deliver to resolved target set only.
                                // WS clients are not yet supported as whisper targets.
                                let wt = voice_state.whisper_targets.read().await;
                                if let Some(whisper_addrs) = wt.get(&sender_pk) {
                                    for addr in whisper_addrs {
                                        if addr_map.contains_key(addr) {
                                            let _ = voice_socket.send_to(&outbound, *addr).await;
                                        }
                                    }
                                }
                            } else {
                                // Normal: all channel participants except the sender.
                                if let Some(participants) = channels.get(&channel_id) {
                                    for (pk, addr) in participants {
                                        if pk == &sender_pk {
                                            continue;
                                        }
                                        if let Some(ws_tx) = ws_senders.get(pk.as_str()) {
                                            let _ = ws_tx.send(outbound.clone());
                                        } else if *addr != sentinel
                                            && addr_map.contains_key(addr)
                                            && *addr != from_addr
                                        {
                                            let _ = voice_socket.send_to(&outbound, *addr).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Voice UDP recv error: {e}");
                }
            }
        }
    });

    // Retry undelivered federated DMs in the background.
    dm_worker::spawn(state.clone());

    // Warn bots about expiring tokens.
    token_expiry::spawn(state.clone());

    // Issue certifications to eligible members daily.
    cert_worker::spawn(state.clone());

    // Sweep messages and forum posts past their channel retention deadline.
    wavvon_hub::retention_worker::spawn(state.clone());

    // Sync federated ban lists from subscribed sources every 6 hours.
    wavvon_hub::banlist_worker::spawn(state.clone());

    // Poll known cert issuers for revocations every 6 hours.
    wavvon_hub::cert_revocation_worker::spawn(state.clone());

    // Poll known subkey issuers for revocations every 6 hours.
    wavvon_hub::subkey_revocation_worker::spawn(state.clone());

    // Farm heartbeat: POST /farm/heartbeat every 60 seconds when WAVVON_FARM_URL is set.
    if let Some(ref farm_url_for_hb) = state.farm_url {
        let hb_state = state.clone();
        let hb_url = farm_url_for_hb.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let online = hb_state.online_users.read().await.len() as u64;
                let db_size = 0u64; // PostgreSQL: size reported separately by the DB server
                let uptime = hb_state.started_at.elapsed().as_secs();
                let payload = serde_json::json!({
                    "hub_pubkey": hb_state.hub_identity.public_key_hex(),
                    "online_users": online,
                    "storage_bytes": db_size,
                    "uptime_seconds": uptime,
                });
                let _ = hb_state
                    .http_client
                    .post(format!("{hb_url}/farm/heartbeat"))
                    .json(&payload)
                    .send()
                    .await;
            }
        });
    }

    // Log whether the rate limiter will trust X-Forwarded-For.
    if settings.trusted_proxy {
        tracing::info!(
            "Rate limiter: trusted-proxy mode ENABLED — real client IP derived from \
             X-Forwarded-For (last entry). Assumes a single reverse proxy in front."
        );
    } else {
        tracing::info!(
            "Rate limiter: direct mode (socket peer address). \
             Set WAVVON_TRUSTED_PROXY=true when a reverse proxy terminates TLS in front."
        );
    }

    // Load and validate the web client directory when configured.
    // Fail fast here so a misconfigured path doesn't silently result in a
    // running hub that 404s everything at /.
    let web_client_cfg = match settings.web_client_dir.as_deref() {
        Some(dir) => match wavvon_hub::web_client::WebClientConfig::load(dir) {
            Ok(cfg) => {
                tracing::info!(
                    "web client: loaded {} bytes for index.html from {dir}",
                    cfg.index_html.len()
                );
                Some(std::sync::Arc::new(cfg))
            }
            Err(e) => {
                tracing::error!("web client configuration error: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    let app = server::create_router_full(
        state,
        &settings.cors_origins,
        settings.trusted_proxy,
        web_client_cfg,
    );
    let addr: std::net::SocketAddr = format!("0.0.0.0:{http_port}").parse()?;

    if let (Some(cert), Some(key)) = (settings.tls_cert.as_deref(), settings.tls_key.as_deref()) {
        let cert_path = PathBuf::from(cert);
        let key_path = PathBuf::from(key);
        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                .await
                .with_context(|| format!("Failed to load TLS cert/key from {cert:?} / {key:?}"))?;
        tracing::info!("Hub server listening on https://0.0.0.0:{http_port} (TLS enabled)");
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        tracing::info!(
            "Hub server listening on http://0.0.0.0:{http_port} (plaintext — set WAVVON_TLS_CERT and WAVVON_TLS_KEY to enable TLS)"
        );
        let listener = tokio::net::TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await?;
    }

    if let Some(provider) = otlp_provider {
        let _ = provider.shutdown();
    }

    Ok(())
}

fn self_update_asset_name() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("wavvon-hub-linux-x86_64")
    } else {
        None
    }
}

async fn run_self_update(check_only: bool) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("wavvon-hub/", env!("CARGO_PKG_VERSION")))
        .build()?;

    let release: serde_json::Value = client
        .get("https://api.github.com/repos/Wavvon/Wavvon-server/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("Failed to reach GitHub API")?
        .error_for_status()
        .context("GitHub API returned an error")?
        .json()
        .await
        .context("Failed to parse GitHub API response")?;

    let tag = release["tag_name"].as_str().unwrap_or("");
    let latest = tag.trim_start_matches('v');
    let current = env!("CARGO_PKG_VERSION");

    if latest.is_empty() {
        anyhow::bail!(
            "GitHub API returned no tag_name — is the repo public and are releases published?"
        );
    }

    if latest == current {
        println!("Already up to date (v{current}).");
        return Ok(());
    }

    println!("Update available: v{current} → v{latest}");

    if check_only {
        println!("Run 'wavvon-hub update' (without --check) to install.");
        return Ok(());
    }

    let asset_name =
        self_update_asset_name().context("Self-update is only supported on Linux x86_64")?;

    let assets = release["assets"]
        .as_array()
        .context("GitHub API response has no assets array")?;

    let asset = assets
        .iter()
        .find(|a| a["name"].as_str() == Some(asset_name))
        .with_context(|| format!("No asset '{asset_name}' in release {tag}"))?;

    let download_url = asset["browser_download_url"]
        .as_str()
        .context("Asset has no browser_download_url")?;

    println!("Downloading {download_url} ...");

    let response = client
        .get(download_url)
        .send()
        .await
        .context("Download request failed")?
        .error_for_status()
        .context("Download returned an error status")?;

    let bytes = response
        .bytes()
        .await
        .context("Failed to read download body")?;
    println!("Downloaded {} bytes.", bytes.len());

    let current_exe =
        std::env::current_exe().context("Cannot determine current executable path")?;

    let tmp = current_exe.with_file_name(".wavvon-hub-update.tmp");
    std::fs::write(&tmp, &bytes).with_context(|| format!("Cannot write temp file {tmp:?}"))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("Cannot set permissions on {tmp:?}"))?;
    }

    std::fs::rename(&tmp, &current_exe)
        .with_context(|| format!("Cannot replace {current_exe:?} with the new binary"))?;

    println!("Update applied (v{latest}). Restart the server to activate the new version.");

    Ok(())
}

fn backup(out_path: &str) -> anyhow::Result<()> {
    let file = std::fs::File::create(out_path)?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    tar.append_path("hub.db")?;
    if std::path::Path::new("hub_identity.json").exists() {
        tar.append_path("hub_identity.json")?;
    }
    // Write a metadata JSON entry into the archive.
    let meta = serde_json::json!({
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "wavvon_version": env!("CARGO_PKG_VERSION"),
    });
    let meta_bytes = serde_json::to_vec_pretty(&meta)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(meta_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "backup_meta.json", meta_bytes.as_slice())?;
    tar.finish()?;
    Ok(())
}

fn restore(src_path: &str) -> anyhow::Result<()> {
    let file = std::fs::File::open(src_path)?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    let staging = tempfile::tempdir()?;
    archive.unpack(staging.path())?;
    for name in &["hub.db", "hub_identity.json"] {
        let src = staging.path().join(name);
        if src.exists() {
            std::fs::copy(&src, name)?;
        }
    }
    Ok(())
}

/// Generate a new hub keypair, sign a rotation payload with the old key,
/// write it to `hub_rotation.json`, and replace `hub_identity.json` with
/// the new key. The operator must restart the hub afterwards.
fn rotate_hub_key(current_path: &Path, _new_path: &Path) -> anyhow::Result<()> {
    let old_identity =
        Identity::load(current_path).context("Failed to load current hub identity")?;

    let new_identity = Identity::generate();

    let old_pubkey_hex = old_identity.public_key_hex();
    let new_pubkey_hex = new_identity.public_key_hex();

    let effective_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Canonical signing bytes: "<old>:<new>:<effective_at>"
    let payload_str = format!("{old_pubkey_hex}:{new_pubkey_hex}:{effective_at}");
    let sig = old_identity.sign(payload_str.as_bytes());

    let rotation = serde_json::json!({
        "old_pubkey": old_pubkey_hex,
        "new_pubkey": new_pubkey_hex,
        "effective_at": effective_at,
        "signature": hex::encode(sig.to_bytes()),
    });

    std::fs::write(
        "hub_rotation.json",
        serde_json::to_string_pretty(&rotation)?,
    )?;

    // Replace the live identity file with the new key.
    new_identity.save(current_path)?;

    Ok(())
}
