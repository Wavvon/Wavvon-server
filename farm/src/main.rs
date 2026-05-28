use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePoolOptions;
use voxply_farm::db;
use voxply_farm::server;
use voxply_farm::state::FarmState;

const DEFAULT_HTTP_PORT: u16 = 4000;

fn port_from_env(var: &str, default: u16) -> Result<u16> {
    match std::env::var(var) {
        Ok(s) => s
            .parse::<u16>()
            .with_context(|| format!("{var}={s:?} is not a valid port (1..=65535)")),
        Err(_) => Ok(default),
    }
}

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
    tracing_subscriber::fmt::init();

    // `voxply-farm migrate` — run migrations and exit.
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

    let http_port = port_from_env("VOXPLY_FARM_HTTP_PORT", DEFAULT_HTTP_PORT)?;

    // Farm URL — required for embedding in tokens. Must be the externally reachable URL.
    let farm_url = std::env::var("VOXPLY_FARM_URL")
        .unwrap_or_else(|_| format!("http://127.0.0.1:{http_port}"));

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

    let state = Arc::new(FarmState::new(db, keypair, farm_url));

    let app = server::create_router(state);
    let addr: std::net::SocketAddr = format!("0.0.0.0:{http_port}").parse()?;
    tracing::info!(
        "Farm server listening on http://0.0.0.0:{http_port} (set VOXPLY_FARM_URL for the external URL)"
    );
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
