use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::cert_worker;
use voxply_hub::db;
use voxply_hub::bots::token_expiry;
use voxply_hub::dm_worker;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

const DEFAULT_HTTP_PORT: u16 = 3000;
const DEFAULT_VOICE_UDP_PORT: u16 = 3001;

/// Read a u16 port from `var`, falling back to `default` if unset, and
/// erroring out if it's set but unparseable. We'd rather fail loudly on a
/// typo than silently bind to the default.
fn port_from_env(var: &str, default: u16) -> Result<u16> {
    match std::env::var(var) {
        Ok(s) => s
            .parse::<u16>()
            .with_context(|| format!("{var}={s:?} is not a valid port (1..=65535)")),
        Err(_) => Ok(default),
    }
}

/// TLS configuration read from the environment.
/// Both VOXPLY_TLS_CERT and VOXPLY_TLS_KEY must be set to enable HTTPS.
struct TlsConfig {
    cert: PathBuf,
    key: PathBuf,
}

fn tls_config_from_env() -> Option<TlsConfig> {
    let cert = std::env::var("VOXPLY_TLS_CERT").ok()?;
    let key = std::env::var("VOXPLY_TLS_KEY").ok()?;
    Some(TlsConfig {
        cert: PathBuf::from(cert),
        key: PathBuf::from(key),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let json_logs = std::env::var("VOXPLY_LOG_FORMAT")
        .map(|v| v.to_lowercase() == "json")
        .unwrap_or(false);

    // Optional OpenTelemetry OTLP trace export.
    // Set VOXPLY_OTLP_ENDPOINT to any OTLP-compatible collector
    // (Grafana Tempo, Jaeger, Honeycomb, Datadog, etc.).
    // No-op when the variable is unset or empty.
    let otlp_provider = std::env::var("VOXPLY_OTLP_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|endpoint| {
            use opentelemetry_otlp::WithExportConfig;
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_http()
                .with_endpoint(&endpoint)
                .build()
                .ok()?;
            let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new(
                        "service.name",
                        env!("CARGO_PKG_NAME"),
                    ),
                ]))
                .build();
            opentelemetry::global::set_tracer_provider(provider.clone());
            Some(provider)
        });

    use tracing_subscriber::prelude::*;
    let otel_layer = otlp_provider.as_ref().map(|provider| {
        use opentelemetry::trace::TracerProvider as _;
        tracing_opentelemetry::layer().with_tracer(
            provider.tracer(env!("CARGO_PKG_NAME"))
        )
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

    if otlp_provider.is_some() {
        tracing::info!("OpenTelemetry OTLP trace export enabled");
    }

    // Subcommand dispatch. `voxply-hub migrate` runs migrations and exits
    // without starting the HTTP server or UDP listener. Useful for CI,
    // one-off schema upgrades, or running against a prod DB over SSH.
    let subcommand = std::env::args().nth(1);
    if subcommand.as_deref() == Some("migrate") {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite:hub.db?mode=rwc")
            .await?;
        db::migrations::run(&db).await?;
        println!("Migrations applied to hub.db");
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
            .ok_or_else(|| anyhow::anyhow!("Usage: voxply-hub restore <backup.tar.gz>"))?;
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

    if subcommand.as_deref() == Some("admin") {
        let admin_cmd = std::env::args().nth(2).unwrap_or_default();
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite:hub.db?mode=ro".to_string());
        let db = SqlitePoolOptions::new()
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
                let channels: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM channels WHERE is_category=0",
                )
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
                        let db_rw = SqlitePoolOptions::new()
                            .max_connections(1)
                            .connect("sqlite:hub.db?mode=rwc")
                            .await
                            .context("Cannot open DB for write")?;
                        sqlx::query(
                            "INSERT OR IGNORE INTO bans(target_public_key, banned_by, reason, created_at) VALUES(?,'cli','CLI ban',?)",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db_rw)
                        .await?;
                        println!("Banned {pubkey}");
                    }
                    "unban" => {
                        let pubkey = std::env::args()
                            .nth(4)
                            .context("Usage: admin users unban <pubkey>")?;
                        let db_rw = SqlitePoolOptions::new()
                            .max_connections(1)
                            .connect("sqlite:hub.db?mode=rwc")
                            .await
                            .context("Cannot open DB for write")?;
                        sqlx::query("DELETE FROM bans WHERE target_public_key = ?")
                            .bind(&pubkey)
                            .execute(&db_rw)
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
                        let db_rw = SqlitePoolOptions::new()
                            .max_connections(1)
                            .connect("sqlite:hub.db?mode=rwc")
                            .await
                            .context("Cannot open DB for write")?;
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        // Revoke any existing owner first
                        let prev: Option<String> = sqlx::query_scalar(
                            "SELECT user_public_key FROM user_roles WHERE role_id = 'builtin-owner' LIMIT 1",
                        )
                        .fetch_optional(&db_rw)
                        .await
                        .unwrap_or(None);
                        sqlx::query("DELETE FROM user_roles WHERE role_id = 'builtin-owner'")
                            .execute(&db_rw)
                            .await?;
                        if let Some(p) = prev {
                            println!("Revoked owner from {}…", &p[..16.min(p.len())]);
                        }
                        // Ensure a minimal user record exists
                        sqlx::query(
                            "INSERT OR IGNORE INTO users (public_key, first_seen_at) VALUES (?, ?)",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db_rw)
                        .await?;
                        sqlx::query(
                            "INSERT OR REPLACE INTO user_roles (user_public_key, role_id, assigned_at) VALUES (?, 'builtin-owner', ?)",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db_rw)
                        .await?;
                        println!("Owner set to {pubkey}");
                    }
                    _ => println!(
                        "Usage: voxply-hub admin users [list|ban|unban|set-owner] [pubkey]"
                    ),
                }
            }
            "channels" => {
                let action = std::env::args().nth(3).unwrap_or_default();
                match action.as_str() {
                    "list" => {
                        let rows: Vec<(String, String)> = sqlx::query_as(
                            "SELECT id, name FROM channels WHERE is_category=0 ORDER BY display_order",
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
                    _ => println!("Usage: voxply-hub admin channels [list]"),
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
            "rotate-admin-token" => {
                let new_token = hex::encode(rand::random::<[u8; 32]>());
                let db_rw = SqlitePoolOptions::new()
                    .max_connections(1)
                    .connect("sqlite:hub.db?mode=rwc")
                    .await
                    .context("Cannot open DB for write")?;
                sqlx::query(
                    "INSERT OR REPLACE INTO hub_settings(key, value) VALUES('web_admin_token', ?)",
                )
                .bind(&new_token)
                .execute(&db_rw)
                .await?;
                println!("New admin token: {new_token}");
            }
            _ => {
                println!(
                    "Usage: voxply-hub admin [stats|users|channels|tokens|backup|restore|rotate-admin-token]"
                );
            }
        }
        return Ok(());
    }

    let http_port = port_from_env("VOXPLY_HTTP_PORT", DEFAULT_HTTP_PORT)?;
    let voice_udp_port = port_from_env("VOXPLY_VOICE_UDP_PORT", DEFAULT_VOICE_UDP_PORT)?;

    let (hub_identity, is_new) = Identity::load_or_create(Path::new("hub_identity.json"))?;
    if is_new {
        tracing::info!("Generated new hub identity: {}", hub_identity);
    } else {
        tracing::info!("Loaded hub identity: {}", hub_identity);
    }

    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:hub.db?mode=rwc")
        .await?;

    db::migrations::run(&db).await?;

    // First-run bootstrap: applies a template from VOXPLY_TEMPLATE_URL or
    // redeems VOXPLY_BOOTSTRAP_TOKEN when the channels table is empty.
    // Non-fatal — a bad template or unreachable URL never blocks startup.
    {
        let bootstrap_client = reqwest::Client::new();
        voxply_hub::bootstrap::maybe_bootstrap(&db, &bootstrap_client)
            .await
            .unwrap_or_else(|e| tracing::warn!("Bootstrap failed (non-fatal): {e}"));
    }

    let (chat_tx, _) = broadcast::channel::<(voxply_hub::routes::chat_models::ChatEvent, std::sync::Arc<str>)>(256);
    let (voice_event_tx, _) = broadcast::channel(256);
    let (dm_tx, _) = broadcast::channel(256);
    let (screen_share_tx, _) = broadcast::channel(256);

    // Farm integration: fetch the farm pubkey from VOXPLY_FARM_URL if set.
    let farm_url = std::env::var("VOXPLY_FARM_URL").ok();
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

    let state = Arc::new(AppState {
        hub_name: "my-hub".to_string(),
        hub_identity,
        db,
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
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx,
        bot_sessions: RwLock::new(HashMap::new()),
        farm_url,
        cached_farm_pubkey,
        last_farm_pubkey_fetch,
        voice_zones: RwLock::new(HashMap::new()),
        active_game_sessions: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: RwLock::new(HashMap::new()),
        whisper_target_defs: RwLock::new(HashMap::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
    });

    // Bind voice UDP socket and start forwarding task
    let voice_socket = UdpSocket::bind(format!("0.0.0.0:{voice_udp_port}")).await?;
    tracing::info!("Voice UDP listening on port {voice_udp_port}");

    let voice_state = state.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            match voice_socket.recv_from(&mut buf).await {
                Ok((len, from_addr)) => {
                    let packet_data = buf[..len].to_vec();
                    // O(1) lookup: which channel+peer owns this SocketAddr?
                    let lookup = {
                        let map = voice_state.voice_addr_map.read().await;
                        map.get(&from_addr).cloned()
                    };
                    if let Some((channel_id, sender_pk)) = lookup {
                        // Look up the sender's sender_id for this channel.
                        let sender_id: u16 = {
                            let sids = voice_state.voice_sender_ids.read().await;
                            sids.get(&channel_id)
                                .and_then(|m| m.get(&sender_pk))
                                .copied()
                                .unwrap_or(0)
                        };
                        let sender_id_bytes = sender_id.to_be_bytes();

                        // Determine destinations and packet_type:
                        //   0x01 = whisper (fan-out to resolved whisper target set only)
                        //   0x00 = normal channel voice
                        let (dests, packet_type): (Vec<SocketAddr>, u8) = {
                            let wt = voice_state.whisper_targets.read().await;
                            if let Some(whisper_addrs) = wt.get(&sender_pk) {
                                (whisper_addrs.iter().copied().collect(), 0x01u8)
                            } else {
                                drop(wt);
                                let channels = voice_state.voice_channels.read().await;
                                let normal = channels
                                    .get(&channel_id)
                                    .map(|participants| {
                                        participants
                                            .values()
                                            .filter(|a| **a != from_addr)
                                            .copied()
                                            .collect()
                                    })
                                    .unwrap_or_default();
                                (normal, 0x00u8)
                            }
                        };

                        // Build outbound: [sender_id: 2][packet_type: 1][original packet]
                        let mut outbound = Vec::with_capacity(3 + packet_data.len());
                        outbound.extend_from_slice(&sender_id_bytes);
                        outbound.push(packet_type);
                        outbound.extend_from_slice(&packet_data);
                        for addr in dests {
                            let _ = voice_socket.send_to(&outbound, addr).await;
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
    voxply_hub::retention_worker::spawn(state.clone());

    // Sync federated ban lists from subscribed sources every 6 hours.
    voxply_hub::banlist_worker::spawn(state.clone());

    // Farm heartbeat: POST /farm/heartbeat every 60 seconds when VOXPLY_FARM_URL is set.
    if let Some(ref farm_url_for_hb) = state.farm_url {
        let hb_state = state.clone();
        let hb_url = farm_url_for_hb.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.tick().await; // skip the immediate first tick
            loop {
                interval.tick().await;
                let online = hb_state.online_users.read().await.len() as u64;
                let db_size = std::fs::metadata("hub.db").map(|m| m.len()).unwrap_or(0);
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

    // Sweep stale game sessions every 30 minutes. Any session with
    // `last_event_at < now - 7200` (2-hour TTL) is ended with reason "timeout".
    {
        let reaper_state = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(30 * 60)).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                let ttl_cutoff = now - 7200;

                // Collect stale sessions under the lock.
                let stale: Vec<(String, String)> = {
                    let sessions = reaper_state.active_game_sessions.lock().unwrap();
                    sessions
                        .values()
                        .filter(|s| s.last_event_at < ttl_cutoff)
                        .map(|s| (s.id.clone(), s.channel_id.clone()))
                        .collect()
                };

                for (session_id, channel_id) in stale {
                    reaper_state.active_game_sessions.lock().unwrap().remove(&session_id);

                    // Mark in DB.
                    let now_str = now.to_string();
                    let _ = sqlx::query(
                        "UPDATE game_sessions SET ended_at = ?, status = 'ended' WHERE id = ?",
                    )
                    .bind(&now_str)
                    .bind(&session_id)
                    .execute(&reaper_state.db)
                    .await;

                    // Broadcast timeout to channel members.
                    let ev = voxply_hub::routes::chat_models::ChatEvent::Game {
                        channel_id: channel_id.clone(),
                    };
                    let msg = voxply_hub::routes::chat_models::WsServerMessage::GameSessionEnded {
                        session_id: session_id.clone(),
                        reason: Some("timeout".to_string()),
                        result: None,
                    };
                    let json: std::sync::Arc<str> = std::sync::Arc::from(
                        serde_json::to_string(&msg).unwrap().as_str(),
                    );
                    let _ = reaper_state.chat_tx.send((ev, json));

                    tracing::info!("Game session {} timed out and was reaped", &session_id[..8.min(session_id.len())]);
                }
            }
        });
    }

    let app = server::create_router(state);
    let addr: std::net::SocketAddr = format!("0.0.0.0:{http_port}").parse()?;

    if let Some(tls) = tls_config_from_env() {
        let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&tls.cert, &tls.key)
            .await
            .with_context(|| format!("Failed to load TLS cert/key from {:?} / {:?}", tls.cert, tls.key))?;
        tracing::info!("Hub server listening on https://0.0.0.0:{http_port} (TLS enabled)");
        axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        tracing::info!(
            "Hub server listening on http://0.0.0.0:{http_port} (plaintext — set VOXPLY_TLS_CERT and VOXPLY_TLS_KEY to enable TLS)"
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
        "voxply_version": env!("CARGO_PKG_VERSION"),
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
    let old_identity = Identity::load(current_path)
        .context("Failed to load current hub identity")?;

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
