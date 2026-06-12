/// Integration tests for the background revalidation sweep.
///
/// Spins up a real local HTTP server playing the farm role so `tick` probes
/// `GET /farm/public-info` exactly as it does in production. A request
/// counter on the stub pins the "one fetch per farm per sweep" contract.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use voxply_seed::db;
use voxply_seed::revalidation;
use voxply_seed::state::SeedState;

async fn setup_state() -> Arc<SeedState> {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    Arc::new(SeedState::new(db))
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Insert a farm row directly into the DB, bypassing the HTTP callback.
async fn insert_farm(state: &SeedState, farm_url: &str, last_verified_at: i64) {
    sqlx::query(
        "INSERT INTO registered_farms
            (farm_url, farm_pubkey, name, hub_count, max_hubs_total, capacity_pct,
             country, region, languages, tags, geo_unverified,
             last_verified_at, registered_at)
         VALUES (?, ?, ?, 0, NULL, NULL, NULL, NULL, '[\"en\"]', '[]', 0, ?, ?)",
    )
    .bind(farm_url)
    .bind("aa".repeat(32))
    .bind("Test Farm")
    .bind(last_verified_at)
    .bind(unix_now())
    .execute(&state.db)
    .await
    .unwrap();
}

/// Start a local farm stub serving `GET /farm/public-info` with a fixed body.
/// Returns the base URL plus a counter of how many requests the endpoint saw.
async fn spawn_farm_stub(body: Value) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_handler = hits.clone();
    let app = Router::new().route(
        "/farm/public-info",
        get(move || {
            let hits = hits_handler.clone();
            let body = body.clone();
            async move {
                hits.fetch_add(1, Ordering::SeqCst);
                Json(body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), hits)
}

#[tokio::test]
async fn tick_fetches_each_farm_once_and_updates_counts() {
    let state = setup_state().await;
    let (farm_url, hits) = spawn_farm_stub(json!({
        "allow_discovery_listing": true,
        "hub_count": 7,
        "max_hubs_total": 50,
    }))
    .await;

    let stale_verified_at = unix_now() - 90_000;
    insert_farm(&state, &farm_url, stale_verified_at).await;

    let (checked, removed) = revalidation::tick(&state).await.unwrap();
    assert_eq!((checked, removed), (1, 0));

    // The sweep must hit the farm exactly once.
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let (hub_count, max_hubs_total, capacity_pct, last_verified_at): (
        i64,
        Option<i64>,
        Option<i64>,
        i64,
    ) = sqlx::query_as(
        "SELECT hub_count, max_hubs_total, capacity_pct, last_verified_at
         FROM registered_farms WHERE farm_url = ?",
    )
    .bind(&farm_url)
    .fetch_one(&state.db)
    .await
    .unwrap();

    assert_eq!(hub_count, 7);
    assert_eq!(max_hubs_total, Some(50));
    assert_eq!(capacity_pct, Some(14));
    assert!(
        last_verified_at > stale_verified_at,
        "freshness must update"
    );
}

#[tokio::test]
async fn tick_removes_opted_out_and_unreachable_farms() {
    let state = setup_state().await;

    // Reachable but opted out of discovery listing.
    let (opted_out_url, _hits) = spawn_farm_stub(json!({ "allow_discovery_listing": false })).await;
    insert_farm(&state, &opted_out_url, unix_now()).await;

    // Unreachable: bind a port, then drop the listener before the sweep.
    let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_url = format!("http://{}", dead_listener.local_addr().unwrap());
    drop(dead_listener);
    insert_farm(&state, &dead_url, unix_now()).await;

    let (checked, removed) = revalidation::tick(&state).await.unwrap();
    assert_eq!((checked, removed), (2, 2));

    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM registered_farms")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
