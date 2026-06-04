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
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status_success();
    resp.json::<Value>()["id"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy-path: create poll, get it, vote, check totals broadcast path.
#[tokio::test]
async fn poll_happy_path() {
    let server = setup().await;
    let id = Identity::generate();
    let token = authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    // POST /channels/:id/polls
    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "question": "Best raid night?",
            "options": [
                { "id": "fri", "text": "Friday" },
                { "id": "sat", "text": "Saturday" },
                { "id": "sun", "text": "Sunday" },
            ],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let poll: Value = resp.json();
    let poll_id = poll["id"].as_str().unwrap().to_string();
    assert_eq!(poll["question"], "Best raid night?");
    assert_eq!(poll["max_choices"], 1);

    // GET /polls/:id — no votes yet, totals should be empty / zero
    let resp = server
        .get(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["id"], poll_id);
    assert!(detail["your_vote"].is_null());

    // POST /polls/:id/vote
    let resp = server
        .post(&format!("/polls/{poll_id}/vote"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "option_ids": ["fri"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // GET /polls/:id — your_vote should now be ["fri"], totals["fri"] = 1
    let resp = server
        .get(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["your_vote"].as_array().unwrap()[0], "fri");
    assert_eq!(detail["totals"]["fri"], 1);

    // Re-vote changes the selection (upsert).
    let resp = server
        .post(&format!("/polls/{poll_id}/vote"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "option_ids": ["sat"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: Value = resp.json();
    assert_eq!(detail["your_vote"].as_array().unwrap()[0], "sat");
    // "fri" still exists in totals from old row but vote changed, totals["sat"] = 1
    assert_eq!(detail["totals"]["sat"], 1);

    // DELETE /polls/:id
    let resp = server
        .delete(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

/// Selecting too many choices is rejected.
#[tokio::test]
async fn poll_rejects_too_many_choices() {
    let server = setup().await;
    let id = Identity::generate();
    let token = authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "question": "Pick one",
            "options": [
                { "id": "a", "text": "A" },
                { "id": "b", "text": "B" },
            ],
            "max_choices": 1,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let poll_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let resp = server
        .post(&format!("/polls/{poll_id}/vote"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "option_ids": ["a", "b"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

/// Non-creator without admin cannot delete a poll.
#[tokio::test]
async fn poll_delete_rejected_for_non_creator() {
    let server = setup().await;
    let owner = Identity::generate();
    let other = Identity::generate();
    let token_owner = authenticate(&server, &owner).await;
    let token_other = authenticate(&server, &other).await;
    let channel_id = create_channel(&server, &token_owner).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token_owner}"))
        .json(&json!({
            "question": "Delete me?",
            "options": [
                { "id": "y", "text": "Yes" },
                { "id": "n", "text": "No" },
            ],
        }))
        .await;
    let poll_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let resp = server
        .delete(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token_other}"))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
