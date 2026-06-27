use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use wavvon_seed::db;
use wavvon_seed::revalidation;
use wavvon_seed::server;
use wavvon_seed::state::SeedState;

const DEFAULT_HTTP_PORT: u16 = 5000;
const DEFAULT_DATABASE_URL: &str = "postgres://postgres:postgres@localhost:5432/wavvon_seed";

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

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| DEFAULT_DATABASE_URL.to_string());

    // `wavvon-seed migrate` — run migrations and exit.
    let subcommand = std::env::args().nth(1);
    if subcommand.as_deref() == Some("migrate") {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect(&database_url)
            .await?;
        db::migrations::run(&db).await?;
        println!("Migrations applied");
        return Ok(());
    }

    let http_port = port_from_env("WAVVON_SEED_HTTP_PORT", DEFAULT_HTTP_PORT)?;

    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to PostgreSQL")?;

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
