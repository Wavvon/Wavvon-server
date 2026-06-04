use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

async fn setup() -> TestServer {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let (chat_tx, _) = broadcast::channel(256);
    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx: broadcast::channel(16).0,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
    });
    TestServer::new(server::create_router(state))
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let ch: ChallengeResponse = resp.json();
    let sig = identity.sign(&hex::decode(&ch.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await;
    let v: VerifyResponse = resp.json();
    v.token
}

async fn create_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy-path: create an event, list it, get by id, RSVP, list RSVPs.
#[tokio::test]
async fn event_happy_path() {
    let server = setup().await;
    let id = Identity::generate();
    let token = authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    // POST /events
    let starts_at = 9_999_999_999i64;
    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Dev Hangout",
            "description": "Monthly sync",
            "starts_at": starts_at,
            "location": "Voice #lounge",
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event: Value = resp.json();
    let event_id = event["id"].as_str().unwrap().to_string();
    assert_eq!(event["title"], "Dev Hangout");
    assert_eq!(event["starts_at"], starts_at);

    // GET /events?upcoming=true should include the event (starts_at is far future).
    let resp = server
        .get("/events?upcoming=true&limit=10")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let list: Value = resp.json();
    let arr = list.as_array().unwrap();
    assert!(arr.iter().any(|e| e["id"] == event_id));

    // GET /events/:id
    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["id"], event_id);
    assert_eq!(detail["rsvp_counts"]["going"], 0);

    // POST /events/:id/rsvp
    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "status": "going" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // GET /events/:id should now show rsvp_counts.going = 1
    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["rsvp_counts"]["going"], 1);

    // GET /events/:id/rsvps
    let resp = server
        .get(&format!("/events/{event_id}/rsvps"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let rsvps: Value = resp.json();
    assert_eq!(rsvps.as_array().unwrap().len(), 1);
    assert_eq!(rsvps[0]["status"], "going");

    // DELETE /events/:id
    let resp = server
        .delete(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Confirm deleted.
    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

/// Non-creator without admin cannot delete another user's event.
#[tokio::test]
async fn event_delete_rejected_for_non_creator() {
    let server = setup().await;
    let owner = Identity::generate();
    let other = Identity::generate();
    let token_owner = authenticate(&server, &owner).await;
    let token_other = authenticate(&server, &other).await;
    let channel_id = create_channel(&server, &token_owner).await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {token_owner}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Owner-only event",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event_id = resp.json::<Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .delete(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token_other}"))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

/// Invalid RSVP status is rejected.
#[tokio::test]
async fn event_rsvp_rejects_invalid_status() {
    let server = setup().await;
    let id = Identity::generate();
    let token = authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "channel_id": channel_id, "title": "T", "starts_at": 9_999_999_999i64 }))
        .await;
    let event_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "status": "yes_please" }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}
