//! The heartbeat handshake that makes a farm-spawned hub routable.
//!
//! The farm allocates a `hubs` row before the process exists, so it cannot
//! know the hub's Ed25519 key — that is generated on the hub's first boot. The
//! hub reports back the id it was given at spawn (`WAVVON_FARM_HUB_ID`) and
//! the farm binds its pubkey to that row, once.
//!
//! Nothing did this, and `hubs.hub_pubkey` stayed NULL forever: the proxy
//! resolves `/hub/<serial>` against that column, so every farm-routed request
//! 404'd; the heartbeat's own recognition check rejected every hub; and the
//! monitor read those missing heartbeats as "offline", restarted each hub on a
//! backoff, then disabled its own auto-restart. All silent.
//!
//! `serial_routing_flow.rs` never caught it because it seeds `hub_pubkey` by
//! hand — it proves the proxy works *given* a serial, which is a different
//! claim from "a real hub ever gets one".

#[path = "common.rs"]
mod common;

use std::sync::Arc;

use axum_test::TestServer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::json;
use wavvon_farm::{db, hub_manager::HubManager, server, state::FarmState, unix_now};

async fn setup() -> (TestServer, Arc<FarmState>, common::TestDbGuard) {
    let (db_pool, guard) = common::create_test_db().await;
    db::migrations::run(&db_pool).await.unwrap();

    let keypair = SigningKey::generate(&mut OsRng);
    let farm_pubkey = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    sqlx::query("INSERT INTO farms (id, public_key, created_at) VALUES (1, $1, $2)")
        .bind(&farm_pubkey)
        .bind(unix_now())
        .execute(&db_pool)
        .await
        .unwrap();

    let hub_manager = Arc::new(HubManager::new(
        "wavvon-hub".to_string(),
        "https://farm.test".to_string(),
        9400,
        10400,
        // Creating a hub provisions it a database on this server.
        common::base_db_url(),
        // Per-hub working directory root: hubs must not share an identity file.
        std::env::temp_dir()
            .join("wavvon-test-hubs")
            .to_string_lossy()
            .to_string(),
    ));
    let state = Arc::new(FarmState::new(
        db_pool,
        keypair,
        "https://farm.test".to_string(),
        hub_manager,
    ));
    let app = server::create_router(state.clone());
    (TestServer::new(app), state, guard)
}

/// A hub row as the farm creates it: allocated, but with no pubkey yet.
async fn insert_unclaimed_hub(state: &FarmState, id: &str) {
    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, visibility, created_at)
         VALUES ($1, 'owner', 'Test Hub', 'private', $2)",
    )
    .bind(id)
    .bind(unix_now())
    .execute(&state.db)
    .await
    .unwrap();
}

async fn stored_pubkey(state: &FarmState, id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT hub_pubkey FROM hubs WHERE id = $1")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .unwrap()
}

fn heartbeat(hub_id: &str, hub_pubkey: &str) -> serde_json::Value {
    json!({
        "hub_id": hub_id,
        "hub_pubkey": hub_pubkey,
        "online_users": 0,
        "storage_bytes": 0,
        "uptime_seconds": 1,
    })
}

#[tokio::test]
async fn first_heartbeat_binds_the_row_to_the_hubs_pubkey() {
    let (server, state, _guard) = setup().await;
    insert_unclaimed_hub(&state, "hub-a").await;
    assert_eq!(
        stored_pubkey(&state, "hub-a").await,
        None,
        "starts unclaimed"
    );

    let serial = "aa".repeat(32);
    let res = server
        .post("/farm/heartbeat")
        .json(&heartbeat("hub-a", &serial))
        .await;
    assert_eq!(res.status_code(), 200);

    assert_eq!(
        stored_pubkey(&state, "hub-a").await.as_deref(),
        Some(serial.as_str()),
        "the row must carry the serial the proxy routes on"
    );
}

/// The steady state: one heartbeat a minute, forever. Re-claiming must be a
/// no-op, not an error and not a rewrite.
#[tokio::test]
async fn repeated_heartbeats_are_idempotent() {
    let (server, state, _guard) = setup().await;
    insert_unclaimed_hub(&state, "hub-b").await;
    let serial = "bb".repeat(32);

    for _ in 0..3 {
        let res = server
            .post("/farm/heartbeat")
            .json(&heartbeat("hub-b", &serial))
            .await;
        assert_eq!(res.status_code(), 200);
    }

    assert_eq!(
        stored_pubkey(&state, "hub-b").await.as_deref(),
        Some(serial.as_str())
    );
}

/// The property that makes the claim safe to accept unauthenticated: a hub can
/// take an *unclaimed* row and nothing else. If this ever regressed, any
/// process able to reach the farm could point an existing community's serial
/// at itself.
#[tokio::test]
async fn a_second_hub_cannot_steal_a_claimed_row() {
    let (server, state, _guard) = setup().await;
    insert_unclaimed_hub(&state, "hub-c").await;

    let honest = "cc".repeat(32);
    let impostor = "dd".repeat(32);

    server
        .post("/farm/heartbeat")
        .json(&heartbeat("hub-c", &honest))
        .await;
    // The impostor knows the row id and claims it with its own key.
    server
        .post("/farm/heartbeat")
        .json(&heartbeat("hub-c", &impostor))
        .await;

    assert_eq!(
        stored_pubkey(&state, "hub-c").await.as_deref(),
        Some(honest.as_str()),
        "a bound row must never be rebound by another key"
    );
}

/// A deleted hub's row is not a free slot to be re-taken.
#[tokio::test]
async fn a_deleted_row_cannot_be_claimed() {
    let (server, state, _guard) = setup().await;
    insert_unclaimed_hub(&state, "hub-d").await;
    sqlx::query("UPDATE hubs SET deleted_at = $1 WHERE id = 'hub-d'")
        .bind(unix_now())
        .execute(&state.db)
        .await
        .unwrap();

    let res = server
        .post("/farm/heartbeat")
        .json(&heartbeat("hub-d", &"ee".repeat(32)))
        .await;

    assert_eq!(
        res.status_code(),
        403,
        "a deleted hub is not a recognised hub"
    );
    assert_eq!(stored_pubkey(&state, "hub-d").await, None);
}

/// Back-compat with the additive-wire rule: a hub built before this change
/// sends no `hub_id`. It must not 500 — it simply stays unclaimed, which is
/// the pre-existing behaviour.
#[tokio::test]
async fn a_heartbeat_without_hub_id_is_not_an_error() {
    let (server, state, _guard) = setup().await;
    insert_unclaimed_hub(&state, "hub-e").await;

    let res = server
        .post("/farm/heartbeat")
        .json(&json!({ "hub_pubkey": "ff".repeat(32), "online_users": 0 }))
        .await;

    // 403 because the hub is still unrecognised — not a crash, and not a claim.
    assert_eq!(res.status_code(), 403);
    assert_eq!(stored_pubkey(&state, "hub-e").await, None);
}
