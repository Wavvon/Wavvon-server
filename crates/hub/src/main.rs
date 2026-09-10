use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use store::PostgresStore;
use tokio::sync::{broadcast, RwLock};
use url::Url;
use wavvon_hub::bots::token_expiry;
use wavvon_hub::cert_worker;
use wavvon_hub::db;
use wavvon_hub::dm_worker;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;
use webauthn_rs::WebauthnBuilder;

/// Print the `--help` text to stdout.
fn print_help() {
    println!("wavvon-hub {}\n", env!("CARGO_PKG_VERSION"));
    println!("USAGE:");
    println!("  wavvon-hub [SUBCOMMAND | OPTION]\n");
    println!("SUBCOMMANDS:");
    println!("  setup            Interactive install wizard: generates docker-compose.yml + .env");
    println!("  migrate          Apply DB migrations and exit");
    println!(
        "  backup [FILE]    Back up database + identity + uploads \
         (default: hub-backup-<ts>.tar.gz)"
    );
    println!("  restore FILE [--force]");
    println!("                   Restore a backup archive. Refuses a non-empty");
    println!("                   destination unless --force.");
    println!("  db move --to URL | --from URL [--force]");
    println!("                   Copy this hub's database to (or from) another");
    println!("                   PostgreSQL. Copies only: it does not switch");
    println!("                   modes, and leaves the source untouched.");
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

    // LAN mode: confirm the advertise address is private, and — for the
    // self-signed tier — generate/load the cert and print the fingerprint
    // and join URL an operator would put on an invite/QR (lan-mode.md §4).
    if settings.lan_mode {
        println!("\nLAN mode:");
        match wavvon_hub::lan::resolve_lan_address(settings.lan_advertise_addr.as_deref()) {
            Ok(ip) => {
                println!("PASS  LAN advertise address: {ip} (private/loopback/link-local)");
                let has_ca_cert = settings.tls_cert.is_some() && settings.tls_key.is_some();
                if has_ca_cert {
                    println!(
                        "INFO  trust: CA cert already configured (WAVVON_TLS_CERT/_KEY) — \
                         LAN self-signed/plaintext bootstrap and mDNS advertisement are skipped"
                    );
                } else if settings.lan_tls_mode == "none" {
                    println!(
                        "INFO  trust: plaintext (WAVVON_LAN_TLS_MODE=none) — gated to the \
                         private address above by the LAN-mode guard"
                    );
                    println!("INFO  Join URL: http://{ip}:{}", settings.http_port);
                } else {
                    match wavvon_hub::lan::load_or_create_self_signed(
                        std::path::Path::new("lan_cert.pem"),
                        std::path::Path::new("lan_cert.key"),
                        ip,
                    ) {
                        Ok(cert) => {
                            println!(
                                "PASS  self-signed cert: fingerprint {}",
                                cert.fingerprint_hex
                            );
                            println!(
                                "INFO  Join URL: https://{ip}:{} (client pins fingerprint {} out of band)",
                                settings.http_port, cert.fingerprint_hex
                            );
                        }
                        Err(e) => {
                            println!("FAIL  self-signed cert: {e}");
                            all_pass = false;
                        }
                    }
                }
                println!(
                    "INFO  mDNS advertisement: {}",
                    if settings.lan_mdns {
                        "enabled"
                    } else {
                        "disabled (WAVVON_LAN_MDNS=false)"
                    }
                );
            }
            Err(e) => {
                println!("FAIL  LAN advertise address: {e}");
                all_pass = false;
            }
        }
    }

    // Owner / first-boot invite status. Best-effort only: this needs a live
    // database connection that the rest of doctor doesn't otherwise require,
    // so an unreachable DB (or a hub that has never run migrate/start yet)
    // is reported as INFO, not FAIL — it doesn't block a normal doctor run.
    // Reuses the same idempotent mint used at real startup, so running
    // `--doctor` before the hub's first real launch is enough to get the
    // link — it's safe to call repeatedly and a no-op once a user exists.
    println!();
    // Which database this hub would use, in the words an operator needs: the
    // embedded one is invisible otherwise — no port they chose, no directory
    // they named — and "where is my data" is the first question a backup
    // raises.
    let embedded_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let db_url = match settings.database_url.clone() {
        Some(url) => {
            println!(
                "INFO  database: external, from {}",
                wavvon_hub_env::DATABASE_URL
            );
            url
        }
        None => {
            let data_dir = embedded_root.join("pgdata");
            // Say it here rather than letting the operator find out at first
            // boot: with no WAVVON_DATABASE_URL this build has no database it
            // can reach, and doctor exists precisely to answer that before
            // anything runs.
            if !wavvon_hub::embedded_pg::BUNDLED_AVAILABLE {
                println!(
                    "FAIL  database: none — {} is unset and {}",
                    wavvon_hub_env::DATABASE_URL,
                    wavvon_hub::embedded_pg::unavailable_reason()
                );
                all_pass = false;
            }
            match wavvon_hub::embedded_pg::bundled_major() {
                Some(major) => println!(
                    "INFO  database: built-in PostgreSQL {major}, data in {}",
                    data_dir.display()
                ),
                None => println!(
                    "INFO  database: built-in PostgreSQL, data in {}",
                    data_dir.display()
                ),
            }
            match wavvon_hub::embedded_pg::compatibility(
                wavvon_hub::embedded_pg::data_dir_major(&data_dir),
                wavvon_hub::embedded_pg::bundled_major(),
            ) {
                wavvon_hub::embedded_pg::Compatibility::Start => {}
                wavvon_hub::embedded_pg::Compatibility::NeedsUpgrade { from, to } => println!(
                    "WARN  the data directory was written by PostgreSQL {from} and this hub \
                     carries {to} — back up with the previous binary and restore with this one"
                ),
                wavvon_hub::embedded_pg::Compatibility::Downgraded { from, to } => println!(
                    "FAIL  the data directory was written by PostgreSQL {from} and this hub \
                     carries {to} — an older server cannot read it; run the newer hub"
                ),
            }
            // doctor does not start a server: it reports. Whatever is already
            // running answers the connection below; a hub that has never
            // booted has nothing to connect to yet, which is reported as INFO
            // like every other pre-first-boot state here.
            wavvon_hub::embedded_pg::running_url(&embedded_root)
                .unwrap_or_else(|| wavvon_hub::settings::DEFAULT_DATABASE_URL.to_string())
        }
    };
    match PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
    {
        Ok(pool) => {
            match wavvon_hub::routes::invites::maybe_mint_first_boot_owner_invite(&pool).await {
                Ok(Some(code)) => {
                    // Read the identity rather than create one: on a
                    // farm-hosted hub the public URL contains its pubkey, and
                    // doctor printing a localhost link for a hub that is
                    // actually reachable at https://farm/hub/<key> would be
                    // worse than useless. Absent (hub never started) → falls
                    // back to whatever is configured.
                    let pubkey = Identity::load(Path::new("hub_identity.json"))
                        .ok()
                        .map(|i| i.public_key_hex());
                    let raw_host = wavvon_hub::settings::effective_public_url(
                        settings.public_url.as_deref(),
                        settings.farm_url.as_deref(),
                        pubkey.as_deref(),
                    )
                    .unwrap_or_else(|| format!("localhost:{}", settings.http_port));
                    let host = raw_host
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .trim_end_matches('/');
                    let scheme = if host.starts_with("localhost") || host.starts_with("127.") {
                        "http"
                    } else {
                        "https"
                    };
                    println!(
                        "INFO  hub owner: none yet — first-boot invite {scheme}://{host}/join/{code}"
                    );
                }
                Ok(None) => {
                    println!("PASS  hub owner: already assigned");
                }
                Err((_, e)) => {
                    println!("INFO  hub owner check skipped: {e}");
                }
            }
        }
        Err(e) => {
            println!("INFO  database ({db_url}) unreachable, skipping owner check: {e}");
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

    // `setup` is a pure file-generation wizard: it needs none of the DB/TLS/
    // port config `settings::load()` would otherwise require, and is in fact
    // meant to be usable *before* any of that exists yet. Dispatched here,
    // fast-path, same as --help/--version/--doctor above.
    if first_arg == Some("setup") {
        let setup_args: Vec<String> = std::env::args().skip(2).collect();
        match wavvon_hub::setup::run(&setup_args) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
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

    // Respect RUST_LOG; default to info. Without a filter the subscriber
    // logs TRACE from every dependency (tokio_tungstenite polls, sqlx
    // statements), which floods files/journald on any real deployment.
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

    // Subcommand dispatch (migrate, backup, restore, rotate-key, update, admin).
    // These exit before the server starts; `--help` / `--version` / `--doctor`
    // are handled above before settings are loaded.
    let subcommand = std::env::args().nth(1);
    if subcommand.as_deref() == Some("migrate") {
        let (db_url, started) = cli_database_url().await;
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await?;
        db::version::ensure_supported(&db)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        db::migrations::run(&db).await?;
        println!("Migrations applied");
        db.close().await;
        if let Some(pg) = started {
            pg.stop().await?;
        }
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
        let (db_url, started) = cli_database_url().await;
        backup(&out_path, &db_url).await?;
        println!("Backup written to {out_path}");
        if let Some(pg) = started {
            pg.stop().await?;
        }
        return Ok(());
    }

    if subcommand.as_deref() == Some("restore") {
        let src = std::env::args()
            .nth(2)
            .filter(|a| !a.starts_with("--"))
            .ok_or_else(|| {
                anyhow::anyhow!("Usage: wavvon-hub restore <backup.tar.gz> [--force]")
            })?;
        let force = std::env::args().any(|a| a == "--force");
        let (db_url, started) = cli_database_url().await;
        restore(&src, &db_url, force).await?;
        if let Some(pg) = started {
            pg.stop().await?;
        }
        println!("Restore complete. Restart the hub to apply.");
        return Ok(());
    }

    if subcommand.as_deref() == Some("db") && std::env::args().nth(2).as_deref() == Some("move") {
        let args: Vec<String> = std::env::args().collect();
        let value_after = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .filter(|v| !v.starts_with("--"))
                .cloned()
        };
        let to = value_after("--to");
        let from = value_after("--from");
        let force = args.iter().any(|a| a == "--force");

        // One direction per invocation. "Both" has no meaning and "neither"
        // would silently do nothing, so both are refused rather than guessed.
        let (source_label, target_label, other) = match (&to, &from) {
            (Some(url), None) => ("this hub", "the other database", url.clone()),
            (None, Some(url)) => ("the other database", "this hub", url.clone()),
            _ => anyhow::bail!(
                "Usage: wavvon-hub db move --to <url> | --from <url> [--force]\n\
                 Exactly one direction, and the URL is the *other* database — this hub's own \
                 comes from {} (or the built-in PostgreSQL when that is unset).",
                wavvon_hub_env::DATABASE_URL
            ),
        };

        let (mine, started) = cli_database_url().await;
        let (source_url, target_url) = if to.is_some() {
            (mine, other)
        } else {
            (other, mine)
        };

        db_move(&source_url, &target_url, source_label, target_label, force).await?;
        if let Some(pg) = started {
            pg.stop().await?;
        }
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
        let (db_url, _started) = cli_database_url().await;
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
                backup(&out, &db_url).await?;
                println!("Backup written to {out}");
            }
            "restore" => {
                let src = std::env::args()
                    .nth(3)
                    .filter(|a| !a.starts_with("--"))
                    .context("Usage: admin restore <backup.tar.gz> [--force]")?;
                let force = std::env::args().any(|a| a == "--force");
                restore(&src, &db_url, force).await?;
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

    let (hub_identity, is_new) = Identity::load_or_create(Path::new("hub_identity.json"))?;

    // Where we are reachable from outside. Resolved here, after the identity
    // exists, because a farm-hosted hub derives it from its farm's URL plus
    // its own pubkey — the farm cannot pass it at spawn, since the key in it
    // is generated on this very line. Everything downstream that needs a
    // public address reads this, not `settings.public_url`.
    let public_url = wavvon_hub::settings::effective_public_url(
        settings.public_url.as_deref(),
        settings.farm_url.as_deref(),
        Some(&hub_identity.public_key_hex()),
    );
    if public_url.is_none() {
        tracing::warn!(
            "No public URL: {} is unset and this hub is not farm-managed. Voice, \
             invite links and passkeys all need one and will be unavailable.",
            wavvon_hub_env::PUBLIC_URL,
        );
    }

    // ---- LAN mode resolution ----
    // Must run before the TLS banner below: LAN mode can supply its own
    // self-signed cert/key when no CA cert is already configured, and it
    // always applies the hard private-address guard first (lan-mode.md §4)
    // — this is what makes it structurally impossible for a self-signed or
    // plaintext LAN hub to end up reachable from the public internet.
    let has_ca_cert = settings.tls_cert.is_some() && settings.tls_key.is_some();
    let mut effective_tls_cert = settings.tls_cert.clone();
    let mut effective_tls_key = settings.tls_key.clone();
    // "self" | "none", mirrors AppState::lan_tls_mode. None when LAN mode is
    // off, or when a CA cert is already configured (see has_ca_cert below).
    let mut lan_tls_tier: Option<String> = None;
    let mut lan_fingerprint: Option<String> = None;
    let mut lan_advertise_ip: Option<std::net::IpAddr> = None;

    if settings.lan_mode {
        match wavvon_hub::lan::resolve_lan_address(settings.lan_advertise_addr.as_deref()) {
            Ok(ip) => lan_advertise_ip = Some(ip),
            Err(e) => {
                eprintln!("LAN mode configuration error: {e}");
                std::process::exit(1);
            }
        }
        let ip = lan_advertise_ip.expect("set immediately above");

        if has_ca_cert {
            tracing::info!(
                "LAN mode: WAVVON_TLS_CERT/WAVVON_TLS_KEY are already configured; the \
                 private-address guard stays active but self-signed/plaintext trust bootstrap \
                 and mDNS advertisement are skipped (a CA-issued cert is the 'everyone' tier \
                 from lan-mode.md and doesn't need LAN mode's help)."
            );
        } else if settings.lan_tls_mode == "none" {
            lan_tls_tier = Some("none".to_string());
            lan_fingerprint = Some(hub_identity.public_key_hex());
        } else {
            match wavvon_hub::lan::load_or_create_self_signed(
                Path::new("lan_cert.pem"),
                Path::new("lan_cert.key"),
                ip,
            ) {
                Ok(cert) => {
                    effective_tls_cert = Some("lan_cert.pem".to_string());
                    effective_tls_key = Some("lan_cert.key".to_string());
                    lan_tls_tier = Some("self".to_string());
                    lan_fingerprint = Some(cert.fingerprint_hex);
                }
                Err(e) => {
                    eprintln!("LAN mode: failed to generate self-signed cert: {e}");
                    std::process::exit(1);
                }
            }
        }
    }

    // ---- Startup summary banner ----
    let tls_enabled = effective_tls_cert.is_some() && effective_tls_key.is_some();
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

    // The generic mixed-content warning doesn't apply to LAN plaintext mode
    // (that tier is documented and gated, not an oversight) — the LAN MODE
    // banner below covers it instead.
    if !tls_enabled && lan_tls_tier.as_deref() != Some("none") {
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

    if is_new {
        tracing::info!("Generated new hub identity: {}", hub_identity);
    } else {
        tracing::info!("Loaded hub identity: {}", hub_identity);
    }

    if let (Some(ip), Some(tier)) = (lan_advertise_ip, lan_tls_tier.as_deref()) {
        let trust_desc = if tier == "self" {
            format!(
                "fingerprint {}",
                lan_fingerprint.as_deref().unwrap_or("(unknown)")
            )
        } else {
            "plaintext".to_string()
        };
        tracing::warn!(
            "LAN MODE — serving {scheme} on {ip}:{http_port}; NOT reachable from the internet; \
             trust bootstrapped via {trust_desc}"
        );
    }

    // Mode is chosen by the absence of configuration (decisions.md, "The hub
    // bundles PostgreSQL, and never touches one it did not create"): no URL
    // means the hub starts and supervises its own server, a URL means it is a
    // plain client that runs migrations and manages nothing.
    //
    // Held for the life of the process: dropping the handle does not stop the
    // server, but keeping it is what lets shutdown stop it deliberately.
    let embedded = match settings.database_url.as_deref() {
        Some(_) => None,
        None => {
            let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            match wavvon_hub::embedded_pg::start(&root).await {
                Ok(pg) => {
                    tracing::info!(
                        "database: embedded PostgreSQL, data in {}",
                        pg.data_dir().display()
                    );
                    Some(pg)
                }
                Err(e) => {
                    // Never a fallback to the old localhost guess: connecting
                    // to whatever answers on 5432 is how a hub came to operate
                    // on a database nobody meant.
                    eprintln!("FATAL could not start the built-in PostgreSQL: {e:#}");
                    std::process::exit(1);
                }
            }
        }
    };
    let db_url = match (&embedded, settings.database_url.as_deref()) {
        (Some(pg), _) => pg.url().to_string(),
        (None, Some(url)) => {
            tracing::info!("database: external, as configured");
            url.to_string()
        }
        // Unreachable: no URL took the embedded branch above, which either
        // produced a handle or exited.
        (None, None) => unreachable!("no database URL and no embedded server"),
    };

    let write_pool = PgPoolOptions::new()
        .max_connections(settings.db_max_connections)
        .connect(&db_url)
        .await
        .expect("Failed to connect to database");

    let read_pool = if let Some(read_url) = settings.database_read_url.as_deref() {
        Some(
            PgPoolOptions::new()
                .max_connections(settings.db_max_connections)
                .connect(read_url)
                .await
                .expect("Failed to connect to read-replica database"),
        )
    } else {
        None
    };

    let db = write_pool;
    let db_read = read_pool;

    // Before migrations: a server below the floor otherwise fails partway
    // through applying the schema, and the operator sees a CREATE TABLE
    // syntax error instead of "your PostgreSQL is too old".
    if let Err(e) = db::version::ensure_supported(&db).await {
        eprintln!("FATAL {e}");
        std::process::exit(1);
    }

    db::migrations::run(&db).await?;

    // First-run bootstrap: applies a template (from a wizard-issued bootstrap
    // token, a template URL, a local template file, or a built-in preset)
    // when the hub has no channels and no users yet. Runs before owner_pubkey
    // seeding below so a template's channels/roles exist by the time the
    // owner is assigned. Non-fatal for network/file issues — a bad template,
    // unreachable URL, or missing file never blocks startup, the hub just
    // starts blank. An unrecognized WAVVON_TEMPLATE preset name is a
    // configuration mistake and does fail startup (see bootstrap::presets).
    {
        let bootstrap_client = reqwest::Client::new();
        wavvon_hub::bootstrap::maybe_bootstrap(
            &db,
            &bootstrap_client,
            &wavvon_hub::bootstrap::BootstrapConfig {
                template_url: settings.template_url.clone(),
                template_file: settings.template_file.clone(),
                preset: settings.template.clone(),
            },
        )
        .await?;
    }

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

        // Fresh hubs default to invite_only=true (task #31), which would
        // otherwise leave no invite-free path for anyone to become owner.
        // Mint (or reuse) the one-time owner-granting invite and print the
        // plain /join link so the operator has a concrete way in. No-op once
        // the hub already has a real user — see maybe_mint_first_boot_owner_invite.
        match wavvon_hub::routes::invites::maybe_mint_first_boot_owner_invite(&db).await {
            Ok(Some(code)) => {
                // The /join link must be copy-pasteable: an explicit scheme in
                // public_url wins; a bare public host is assumed TLS-fronted;
                // the localhost fallback matches this process's own TLS state.
                let join_scheme = match public_url.as_deref() {
                    Some(u) if u.starts_with("http://") => "http",
                    Some(_) => "https",
                    None => scheme,
                };
                // `public_url` may carry a path (a farm-hosted hub lives under
                // /hub/<pubkey>), so this is the whole base, not just a host —
                // stripping the scheme and appending /join gives the right
                // link either way.
                let raw_host = public_url
                    .clone()
                    .unwrap_or_else(|| format!("localhost:{}", settings.http_port));
                let host = raw_host
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/');
                tracing::warn!("First-boot owner invite: {join_scheme}://{host}/join/{code}");
            }
            Ok(None) => {}
            Err((_, e)) => {
                tracing::warn!("Could not mint first-boot owner invite: {e}");
            }
        }
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

    // Publicly-reachable host for the voice WebTransport endpoint
    // (voice-transport-v2.md). Voice is dialled directly, never through the
    // farm's HTTP proxy — a datagram carries no path to route on — so only
    // the *host* is taken here, and the port is this hub's own allocated one.
    let voice_udp_host: Option<String> = public_url
        .as_deref()
        .and_then(|u| Url::parse(u).ok())
        .and_then(|parsed| parsed.host_str().map(|h| h.to_string()))
        .or_else(|| lan_advertise_ip.map(|ip| ip.to_string()));
    let voice_wt_url: Option<String> =
        voice_udp_host.map(|host| format!("https://{host}:{voice_udp_port}/voice"));

    // ---- WebAuthn / passkey setup ----
    let rp_id: String = settings
        .webauthn_rp_id
        .clone()
        .or_else(|| {
            public_url.as_deref().and_then(|u| {
                Url::parse(u)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(|h| h.to_string()))
            })
        })
        .unwrap_or_else(|| "localhost".to_string());

    // Origin only — scheme, host and port, never the path. WebAuthn compares
    // the browser's origin, and a hub behind a farm (or any path-prefixing
    // proxy) has a public URL with a path on the end; passing that whole URL
    // would build a relying party nothing ever matches.
    let rp_origin: Url = public_url
        .as_deref()
        .and_then(|u| Url::parse(u).ok())
        .and_then(|parsed| Url::parse(&parsed.origin().ascii_serialization()).ok())
        .unwrap_or_else(|| {
            Url::parse(&format!("http://localhost:{}", settings.http_port)).unwrap()
        });

    let hub_display_name = "Wavvon Hub";

    // A relying party the browser will refuse must not take the hub down with
    // it. This used to `.expect()`, and the first farm-hosted hub to boot found
    // out why that was wrong: a farm reached at an IP derives an rp_id of
    // `127.0.0.1`, WebAuthn requires an effective *domain*, and the whole
    // process died at startup. Losing passkeys on a hub that could never have
    // offered them is the correct outcome; refusing to start is not — and on a
    // farm it takes out a community per misconfigured address.
    let webauthn = Arc::new(
        WebauthnBuilder::new(&rp_id, &rp_origin)
            .and_then(|b| b.rp_name(hub_display_name).build())
            .unwrap_or_else(|e| {
                tracing::warn!(
                    rp_id,
                    rp_origin = %rp_origin,
                    error = %e,
                    "WebAuthn is unavailable on this hub: passkey registration and \
                     sign-in will fail. A relying-party id must be a domain — an IP \
                     address or a bare host cannot be one. Set WAVVON_WEBAUTHN_RP_ID, \
                     or reach this hub by hostname."
                );
                let fallback = Url::parse("http://localhost").expect("static URL");
                WebauthnBuilder::new("localhost", &fallback)
                    .and_then(|b| b.rp_name(hub_display_name).build())
                    .expect("the localhost relying party is always valid")
            }),
    );

    let device_token_ttl_secs = (settings.device_token_ttl_days as i64) * 86400;

    if rp_id != "localhost" && settings.tls_cert.is_none() {
        tracing::warn!(
            "WebAuthn requires HTTPS for non-localhost rp_id '{rp_id}'; \
             passkey registration/assertion will fail on plain HTTP"
        );
    }

    let state = Arc::new(AppState {
        hub_name: "my-hub".to_string(),
        hub_identity,
        db,
        db_read,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        cert_portfolio_cache: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        http_client,
        voice_channels: RwLock::new(HashMap::new()),
        voice_last_active: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_udp_port,
        voice_wt_url,
        // Seeded with what we can work out ourselves; a farm-managed hub has
        // this replaced by the farm's answer on the first heartbeat, which is
        // also how a later rename reaches it.
        canonical_url: Arc::new(RwLock::new(public_url.clone())),
        voice_cert_hash: RwLock::new(None),
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
        whisper_target_defs: RwLock::new(HashMap::new()),
        whisper_optouts: RwLock::new(std::collections::HashSet::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        voice_outbound_loss: RwLock::new(HashMap::new()),
        staging_voice_grants: RwLock::new(HashMap::new()),
        voice_pending_binds: RwLock::new(HashMap::new()),
        ws_key_senders: RwLock::new(HashMap::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search,
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: settings.owner_pubkey.clone(),
        bots_allow_camera: settings.bots_allow_camera,
        bots_allow_video: settings.bots_allow_video,
        bot_video_stream_budget: settings.bot_video_stream_budget as usize,
        webauthn,
        webauthn_reg_challenges: RwLock::new(HashMap::new()),
        webauthn_auth_challenges: RwLock::new(HashMap::new()),
        device_token_ttl_secs,
        webhook_circuit: Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
        lan_mode: settings.lan_mode,
        lan_tls_mode: lan_tls_tier.clone(),
        lan_fingerprint: lan_fingerprint.clone(),
    });

    // LAN mode: advertise via mDNS/DNS-SD (`_wavvon._tcp.local`), when
    // enabled and when a no-CA trust tier is actually in play (see the
    // has_ca_cert skip above). Kept alive for the process lifetime by
    // holding the returned daemon in this binding — dropping it would
    // unregister the service. Failure here is non-fatal: mDNS is a
    // discovery convenience, not part of the safety invariant, and boxes
    // without multicast (containers, some CI) must not fail to start.
    let _lan_mdns_daemon = if settings.lan_mode && settings.lan_mdns {
        match (lan_advertise_ip, lan_tls_tier.as_deref()) {
            (Some(ip), Some(tier)) => {
                let hub_name_for_mdns = wavvon_hub::routes::hub::current_hub_name(&state).await;
                let fp_or_pubkey = lan_fingerprint
                    .clone()
                    .unwrap_or_else(|| state.hub_identity.public_key_hex());
                let params = wavvon_hub::lan::MdnsAnnounceParams {
                    hub_name: &hub_name_for_mdns,
                    advertise_ip: ip,
                    port: http_port,
                    tls_mode: tier,
                    fingerprint_or_pubkey: &fp_or_pubkey,
                };
                match wavvon_hub::lan::start_mdns_advertiser(&params) {
                    Ok(daemon) => {
                        tracing::info!(
                            "LAN mode: advertising via mDNS as _wavvon._tcp.local (name={hub_name_for_mdns})"
                        );
                        Some(daemon)
                    }
                    Err(e) => {
                        tracing::warn!("LAN mode: mDNS advertisement failed (non-fatal): {e}");
                        None
                    }
                }
            }
            _ => None,
        }
    } else {
        None
    };

    // Start the WebTransport voice relay (voice-transport-v2.md). Uses the
    // *raw* WAVVON_TLS_CERT/WAVVON_TLS_KEY, not `effective_tls_cert`/`_key`
    // — a LAN-mode self-signed cert has no rotation story and isn't bounded
    // to the 14-day validity `serverCertificateHashes` requires, so voice
    // always manages its own identity independently of LAN mode.
    let bound_voice_port = wavvon_hub::voice_wt::start(
        state.clone(),
        voice_udp_port,
        settings.tls_cert.as_deref(),
        settings.tls_key.as_deref(),
    )
    .await
    .context("Failed to start voice WebTransport relay")?;
    tracing::info!("Voice WebTransport listening on port {bound_voice_port}");

    // Retry undelivered federated DMs in the background.
    dm_worker::spawn(state.clone());

    // Warn bots about expiring tokens.
    token_expiry::spawn(state.clone());

    // Issue certifications to eligible members daily.
    cert_worker::spawn(state.clone());

    // Sweep messages and forum posts past their channel retention deadline.
    wavvon_hub::retention_worker::spawn(state.clone());

    // Auto-move idle voice participants into the configured AFK channel.
    wavvon_hub::afk_worker::spawn(state.clone());

    // Sync federated ban lists from subscribed sources every 6 hours.
    wavvon_hub::banlist_worker::spawn(state.clone());

    // Poll known cert issuers for revocations every 6 hours.
    wavvon_hub::cert_revocation_worker::spawn(state.clone());

    // Poll known subkey issuers for revocations every 6 hours.
    wavvon_hub::subkey_revocation_worker::spawn(state.clone());

    // Post event reminder cards a configured number of minutes before start.
    wavvon_hub::reminder_worker::spawn(state.clone());

    // Sweep join-to-create temp voice channels past their empty-grace period.
    wavvon_hub::temp_channel_worker::spawn(state.clone());

    // Farm heartbeat: POST /farm/heartbeat every 60 seconds when WAVVON_FARM_URL is set.
    if let Some(ref farm_url_for_hb) = state.farm_url {
        let hb_state = state.clone();
        let hb_url = farm_url_for_hb.clone();
        // The farm allocated our row before this process existed, so it does
        // not know our pubkey — it is generated on first boot. Reporting the
        // id it gave us is how it binds the two. Without it the farm has a hub
        // it can manage but cannot route to, because the proxy keys on
        // `hubs.hub_pubkey`.
        let hb_farm_hub_id = settings.farm_hub_id.clone();
        if hb_farm_hub_id.is_none() {
            tracing::warn!(
                "{} is set but {} is not — the farm cannot bind this hub to its row, \
                 so it will never be able to route traffic to us",
                wavvon_hub_env::FARM_URL,
                wavvon_hub_env::FARM_HUB_ID,
            );
        }
        tokio::spawn(async move {
            // The first tick fires immediately, on purpose. This used to be
            // skipped, which meant a freshly spawned hub said nothing for a
            // full minute — and the first heartbeat is what claims its serial,
            // so for that minute the farm had a hub it could not route to and
            // its monitor had no evidence it was alive. Announce on boot, then
            // every 60s.
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let online = hb_state.online_users.read().await.len() as u64;
                let db_size = 0u64; // PostgreSQL: size reported separately by the DB server
                let uptime = hb_state.started_at.elapsed().as_secs();
                let payload = serde_json::json!({
                    "hub_id": hb_farm_hub_id,
                    "hub_pubkey": hb_state.hub_identity.public_key_hex(),
                    "online_users": online,
                    "storage_bytes": db_size,
                    "uptime_seconds": uptime,
                });
                // The reply carries the address the farm currently publishes
                // for us. Adopting it here is what makes a rename propagate to
                // every connected client within one interval, without a
                // restart — clients re-read /info on connect and on
                // hub_updated, and take the new URL from there.
                if let Ok(resp) = hb_state
                    .http_client
                    .post(format!("{hb_url}/farm/heartbeat"))
                    .json(&payload)
                    .send()
                    .await
                {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Ok(siblings) =
                            serde_json::from_value::<Vec<wavvon_hub::farm_siblings::Sibling>>(
                                body.get("siblings")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null),
                            )
                        {
                            wavvon_hub::farm_siblings::reconcile(&hb_state.db, &siblings).await;
                        }
                        if let Some(url) = body.get("canonical_url").and_then(|v| v.as_str()) {
                            let mut current = hb_state.canonical_url.write().await;
                            if current.as_deref() != Some(url) {
                                tracing::info!(canonical_url = url, "Farm reports our address");
                                *current = Some(url.to_string());
                            }
                        }
                    }
                }
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

    let serve = async {
        if let (Some(cert), Some(key)) =
            (effective_tls_cert.as_deref(), effective_tls_key.as_deref())
        {
            let cert_path = PathBuf::from(cert);
            let key_path = PathBuf::from(key);
            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .with_context(|| {
                        format!("Failed to load TLS cert/key from {cert:?} / {key:?}")
                    })?;
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
        Ok::<(), anyhow::Error>(())
    };

    // Whichever comes first — the listener giving up, or the operator asking
    // us to stop. The signal arm is what makes `stop_embedded` reachable at
    // all; see its doc comment for why an orphaned postmaster matters.
    let result = tokio::select! {
        r = serve => r,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Shutdown requested");
            Ok(())
        }
    };

    stop_embedded(embedded).await;

    if let Some(provider) = otlp_provider {
        let _ = provider.shutdown();
    }

    result
}

/// Stop the PostgreSQL this process started, if it started one.
///
/// The handle above says it is held so "shutdown can stop it deliberately",
/// and until now nothing did: the serve future never returned, so an
/// operator's Ctrl-C left the postmaster running with the data directory
/// open. Adopting an orphan on the next start is handled (embedded_pg
/// `already_running`) — the hazard is the *upgrade* path, where the hub's own
/// refusal tells the operator to move `pgdata` aside. On Windows that fails
/// while a postmaster holds it; on Linux it succeeds and the live postmaster
/// keeps writing to the moved directory, which is the half-migration the
/// version check exists to prevent.
async fn stop_embedded(embedded: Option<wavvon_hub::embedded_pg::EmbeddedPostgres>) {
    let Some(pg) = embedded else { return };
    match pg.stop().await {
        Ok(()) => tracing::info!("Stopped the embedded PostgreSQL"),
        // Worth a line and not a failure: the process is going away either
        // way, and the next start adopts a server that is still up.
        Err(e) => tracing::warn!("Could not stop the embedded PostgreSQL: {e:#}"),
    }
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

/// The database URL for CLI subcommands that run before `Settings` is loaded
/// (`migrate`, `admin`).
///
/// These used to resolve it independently and disagreed: `migrate` read
/// `WAVVON_DATABASE_URL` while `admin` read only the unprefixed
/// `DATABASE_URL`, so `admin users set-owner` — the ownership bootstrap —
/// silently hit the built-in default on any hub configured the documented
/// way. `WAVVON_DATABASE_URL` is the documented variable (the one `Settings`
/// resolves for the server path); the unprefixed name stays as a fallback.
///
/// Falling back to the built-in default is *announced*. These subcommands
/// mutate ownership and schema, and "it said OK" against a database the
/// operator did not mean is the failure this whole function exists to stop.
async fn cli_database_url() -> (String, Option<wavvon_hub::embedded_pg::EmbeddedPostgres>) {
    if let Ok(url) =
        std::env::var(wavvon_hub_env::DATABASE_URL).or_else(|_| std::env::var("DATABASE_URL"))
    {
        return (url, None);
    }

    // No URL means the hub's own PostgreSQL (decisions.md), and a CLI command
    // has to reach the same one the server would — `backup` against a
    // different database is a backup of nothing, reported as success.
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(url) = wavvon_hub::embedded_pg::running_url(&root) {
        // Adopting, not starting — so nothing has pointed the dump tools at
        // the bundled install yet, and `pg_dump` is not on PATH on the setup
        // that owns this branch.
        wavvon_hub::embedded_pg::point_tools_at_bundled(&root);
        return (url, None);
    }
    // Not running: start it for the length of this command. It is the hub's
    // own server in the hub's own directory, so this is not "managing a
    // database we did not create" — it is opening the one we did.
    match wavvon_hub::embedded_pg::start(&root).await {
        Ok(pg) => {
            let url = pg.url().to_string();
            (url, Some(pg))
        }
        Err(e) => {
            eprintln!("FATAL could not open the hub's built-in PostgreSQL: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Everything a hub is, in one file: the database, the identity key, and the
/// uploaded files.
///
/// It used to be the identity file and a metadata stub, with a comment saying
/// to run `pg_dump` separately — so "take a backup first" in the upgrade docs
/// pointed at a tool that did not take one. Uploads were missing too, which
/// meant a restored hub came back with every attachment a broken link.
///
/// The Tantivy search index is deliberately absent: it is derived from the
/// messages table and rebuilt by `POST /admin/search/reindex`, so carrying it
/// would inflate every archive with data the hub can regenerate.
async fn backup(out_path: &str, db_url: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(db_url)
        .await
        .context("Cannot open the database to back it up")?;

    let server_version_num = db::dump::server_version_num(&pool).await?;
    // Whatever schema this hub actually lives in: `public` normally, or one of
    // its own when a farm separates hubs by schema rather than by database.
    // Recorded in the archive so a restore knows what it is holding.
    let schema = db::dump::current_schema(&pool).await?;
    let row_counts = db::dump::row_counts(&pool).await?;

    // Dumped to a temp file first: the tar is written last, so a pg_dump that
    // fails leaves no archive at all rather than a plausible-looking one that
    // is missing the database.
    let staging = tempfile::tempdir()?;
    let dump_path = staging.path().join("database.dump");
    println!("Dumping the database…");
    db::dump::dump(db_url, &dump_path, &schema)?;

    let file = std::fs::File::create(out_path)?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);

    tar.append_path_with_name(&dump_path, "database.dump")?;

    if std::path::Path::new("hub_identity.json").exists() {
        tar.append_path("hub_identity.json")?;
    }

    let uploads = wavvon_hub::routes::uploads::uploads_dir();
    let uploads_included = std::path::Path::new(&uploads).is_dir();
    if uploads_included {
        tar.append_dir_all("uploads", &uploads)?;
    }

    let meta = serde_json::json!({
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "wavvon_version": env!("CARGO_PKG_VERSION"),
        // Read back at restore time to refuse a restore into an older major
        // before anything is written.
        "pg_server_version_num": server_version_num,
        // Compared after the restore, so a partial one is reported as partial.
        "row_counts": row_counts,
        "schema": schema,
        "uploads_included": uploads_included,
    });
    let meta_bytes = serde_json::to_vec_pretty(&meta)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(meta_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "backup_meta.json", meta_bytes.as_slice())?;
    tar.finish()?;

    let tables = row_counts.len();
    let rows: i64 = row_counts.values().sum();
    println!(
        "Backed up {rows} rows across {tables} tables from PostgreSQL {}.{}.",
        server_version_num / 10_000,
        server_version_num % 10_000
    );
    if !uploads_included {
        println!("No uploads directory at {uploads} — nothing to include.");
    }
    Ok(())
}

/// Restore a backup archive over the configured database.
///
/// Refuses rather than half-writes, in this order: the destination must be
/// empty, and its major must be at least the source's. `--force` waives only
/// the emptiness check — the version rule is not the operator's to overrule,
/// because past it `pg_restore` simply cannot parse the archive.
/// Printing wrapper over [`db::dump::move_database`] — the mechanism lives in
/// the library so it can be tested against two real databases.
async fn db_move(
    source_url: &str,
    target_url: &str,
    source_label: &str,
    target_label: &str,
    force: bool,
) -> anyhow::Result<()> {
    println!("Moving from {source_label} to {target_label}…");
    let report = db::dump::move_database(source_url, target_url, force).await?;
    println!(
        "Moved {} rows across {} tables. {source_label} is untouched.",
        report.rows, report.tables
    );
    println!(
        "Nothing has switched over: set (or unset) {} and restart the hub when you are ready.",
        wavvon_hub_env::DATABASE_URL
    );
    Ok(())
}

async fn restore(src_path: &str, db_url: &str, force: bool) -> anyhow::Result<()> {
    let file = std::fs::File::open(src_path)
        .with_context(|| format!("Cannot open backup archive {src_path}"))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    let staging = tempfile::tempdir()?;
    archive
        .unpack(staging.path())
        .context("Cannot unpack the backup archive")?;

    let meta: serde_json::Value = std::fs::read(staging.path().join("backup_meta.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let dump_path = staging.path().join("database.dump");
    if dump_path.exists() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(db_url)
            .await
            .context("Cannot open the destination database")?;

        // Direction first: it is the check that cannot be waived, so failing
        // it should cost nothing.
        if let Some(source) = meta["pg_server_version_num"].as_i64() {
            let target = db::dump::server_version_num(&pool).await?;
            db::dump::check_direction(source as i32, target)?;
        }

        if !db::dump::is_empty(&pool).await? && !force {
            anyhow::bail!(
                "the destination database already has tables. Restoring over them \
                 would merge two hubs into one. Restore into an empty database, or \
                 pass --force if you meant to write into this one."
            );
        }

        println!("Restoring the database…");
        db::dump::restore(db_url, &dump_path)?;

        // The archive's counts are the contract: every table it carried must
        // come back with the same number of rows.
        if let Ok(expected) = serde_json::from_value::<std::collections::BTreeMap<String, i64>>(
            meta["row_counts"].clone(),
        ) {
            let actual = db::dump::row_counts(&pool).await?;
            db::dump::compare_row_counts(&expected, &actual)?;
            let rows: i64 = expected.values().sum();
            println!("Verified {rows} rows across {} tables.", expected.len());
        }
    } else {
        println!(
            "WARN  This archive has no database dump — it was written by a hub from \
             when `backup` only captured the identity file. The database is NOT being \
             restored."
        );
    }

    let src = staging.path().join("hub_identity.json");
    if src.exists() {
        std::fs::copy(&src, "hub_identity.json")?;
        println!("Restored hub_identity.json.");
    }

    let uploads_src = staging.path().join("uploads");
    if uploads_src.is_dir() {
        let dest = wavvon_hub::routes::uploads::uploads_dir();
        copy_dir_all(&uploads_src, std::path::Path::new(&dest))?;
        println!("Restored uploads into {dest}.");
    }

    Ok(())
}

/// Recursive copy, merging into whatever is already there. Files present in
/// the archive win; files only in the destination are left alone — a restore
/// should not delete an attachment the archive simply predates.
fn copy_dir_all(src: &std::path::Path, dest: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
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
