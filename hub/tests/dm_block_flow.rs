use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
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
    let (voice_event_tx, _) = broadcast::channel(16);

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
        voice_event_tx,
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
    let app = server::create_router(state);
    TestServer::new(app)
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let sig = identity.sign(&challenge_bytes);
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await;
    let verify: VerifyResponse = resp.json();
    verify.token
}

// ---------------------------------------------------------------------------
// PUT / GET dm-blocks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn put_and_get_dm_blocks() {
    let server = setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;

    let resp = server
        .put("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .json(&json!({ "pubkeys": [bob.public_key_hex()] }))
        .await;
    resp.assert_status_ok();

    let resp = server
        .get("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    let pubkeys = body["pubkeys"].as_array().unwrap();
    assert_eq!(pubkeys.len(), 1);
    assert_eq!(pubkeys[0], bob.public_key_hex());
}

#[tokio::test]
async fn put_dm_blocks_replaces_existing() {
    let server = setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;

    server
        .put("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .json(&json!({ "pubkeys": [bob.public_key_hex()] }))
        .await;

    // Replace with carol only.
    server
        .put("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .json(&json!({ "pubkeys": [carol.public_key_hex()] }))
        .await;

    let resp = server
        .get("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .await;
    let body = resp.json::<serde_json::Value>();
    let pubkeys = body["pubkeys"].as_array().unwrap();
    assert_eq!(pubkeys.len(), 1);
    assert_eq!(pubkeys[0], carol.public_key_hex());
}

// ---------------------------------------------------------------------------
// DM block enforcement: sender can't detect the block
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blocked_dm_returns_success_shaped_response() {
    let server = setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob_token = authenticate(&server, &bob).await;

    // Alice blocks Bob.
    server
        .put("/identity/dm-blocks")
        .authorization_bearer(&alice_token)
        .json(&json!({ "pubkeys": [bob.public_key_hex()] }))
        .await
        .assert_status_ok();

    // Bob starts a DM conversation with Alice.
    let resp = server
        .post("/conversations")
        .authorization_bearer(&bob_token)
        .json(&json!({ "members": [alice.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv = resp.json::<serde_json::Value>();
    let conv_id = conv["id"].as_str().unwrap();

    // Bob sends a message to Alice. Should return 201 (success-shaped)
    // even though Alice has blocked Bob.
    let resp = server
        .post(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": "hello alice" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // The message must NOT appear in Alice's inbox.
    let resp = server
        .get(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&alice_token)
        .await;
    resp.assert_status_ok();
    let messages = resp.json::<serde_json::Value>();
    let arr = messages.as_array().unwrap();
    assert_eq!(
        arr.len(),
        0,
        "blocked message must not be stored in Alice's inbox"
    );
}

#[tokio::test]
async fn unblocked_dm_is_delivered_normally() {
    let server = setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate(&server, &alice).await;
    let bob_token = authenticate(&server, &bob).await;

    // Alice does NOT block Bob.
    let resp = server
        .post("/conversations")
        .authorization_bearer(&bob_token)
        .json(&json!({ "members": [alice.public_key_hex()] }))
        .await;
    let conv = resp.json::<serde_json::Value>();
    let conv_id = conv["id"].as_str().unwrap();

    server
        .post(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": "hi" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server
        .get(&format!("/conversations/{conv_id}/messages"))
        .authorization_bearer(&alice_token)
        .await;
    let messages = resp.json::<serde_json::Value>();
    assert_eq!(
        messages.as_array().unwrap().len(),
        1,
        "unblocked message should be stored"
    );
}
