use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::sqlite::SqlitePoolOptions;
use wavvon_seed::db;
use wavvon_seed::revalidation;
use wavvon_seed::server;
use wavvon_seed::state::SeedState;

const DEFAULT_HTTP_PORT: u16 = 5000;

fn port_from_env(var: &str, default: u16) -> Result<u16> {
    match std::env::var(var) {
        Ok(s) => s
            .parse::<u16>()
            .with_context(|| format!("{var}={s:?} is not a valid port (1..=65535)")),
        Err(_) => Ok(default),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // `wavvon-seed migrate` — run migrations and exit.
    let subcommand = std::env::args().nth(1);
    if subcommand.as_deref() == Some("migrate") {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite:seed.db?mode=rwc")
            .await?;
        db::migrations::run(&db).await?;
        println!("Migrations applied to seed.db");
        return Ok(());
    }

    let http_port = port_from_env("WAVVON_SEED_HTTP_PORT", DEFAULT_HTTP_PORT)?;

    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:seed.db?mode=rwc")
        .await
        .context("Failed to open seed.db")?;

    db::migrations::run(&db).await?;

    let state = Arc::new(SeedState::new(db));

    // Start the 6-hour revalidation background sweep.
    revalidation::spawn(Arc::clone(&state));

    let app = server::create_router(state);
    let addr: std::net::SocketAddr = format!("0.0.0.0:{http_port}").parse()?;
    tracing::info!("Seed discovery service listening on http://0.0.0.0:{http_port}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
