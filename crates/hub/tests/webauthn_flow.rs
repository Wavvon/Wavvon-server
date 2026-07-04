//! Integration tests for WebAuthn device token and credential management.
//!
//! Tests for the full passkey registration/assertion flow (register_begin,
//! register_finish, assert_begin, assert_finish) are intentionally omitted:
//! those endpoints require a real authenticator (or the webauthn-rs internal
//! test helpers which are not stable public API).  The device token and
//! credential management paths are fully exercised here without an authenticator.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum_test::TestServer;
use serde_json::json;
use store::PostgresStore;
use tokio::sync::{broadcast, RwLock};
use url::Url;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;
use webauthn_rs::WebauthnBuilder;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::new_with_prefix(s).finalize())
}

fn gen_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

async fn make_state() -> (Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let webauthn = Arc::new(
        WebauthnBuilder::new("localhost", &Url::parse("http://localhost:3000").unwrap())
            .unwrap()
            .rp_name("test-hub")
            .build()
            .unwrap(),
    );
    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        db_read: None,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx: broadcast::channel(16).0,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(HashMap::new()),
        farm_url: None,
        cached_farm_pubkey: Arc::new(RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(RwLock::new(0)),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: RwLock::new(HashMap::new()),
        whisper_target_defs: RwLock::new(HashMap::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        voice_pending_binds: RwLock::new(HashMap::new()),
        voice_consumed_tokens: RwLock::new(HashMap::new()),
        voice_ws_senders: RwLock::new(HashMap::new()),
        ws_key_senders: RwLock::new(HashMap::new()),
        voice_udp_socket: Arc::new(RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(HashMap::new()),
        search: Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        webauthn,
        webauthn_reg_challenges: RwLock::new(HashMap::new()),
        webauthn_auth_challenges: RwLock::new(HashMap::new()),
        device_token_ttl_secs: 30 * 86400,
        webhook_circuit: std::sync::Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
    });
    (state, guard)
}

async fn setup_server() -> common::TestHarness {
    let (state, guard) = make_state().await;
    common::TestHarness::new(TestServer::new(server::create_router(state)), guard)
}

/// Insert a user + session row so subsequent authenticated requests succeed.
async fn seed_user_and_session(server: &TestServer, pubkey: &str) -> String {
    // We go through the real /auth/challenge + /auth/verify flow so
    // the sessions FK constraint is satisfied.
    let identity = Identity::generate();
    let pk = identity.public_key_hex();

    let ch = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pk }))
        .await;
    ch.assert_status_ok();
    let challenge: serde_json::Value = ch.json();
    let challenge_hex = challenge["challenge"].as_str().unwrap();
    let sig = identity.sign(&hex::decode(challenge_hex).unwrap());

    let v = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pk,
            "challenge": challenge_hex,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await;
    v.assert_status_ok();
    let verify: serde_json::Value = v.json();
    verify["token"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Device token tests
// ---------------------------------------------------------------------------

/// Create a device token then redeem it; verify a session token is returned.
#[tokio::test]
async fn device_token_create_and_redeem() {
    let server = setup_server().await;
    let token = common::authenticate(&server, &Identity::generate()).await;

    // Create
    let res = server
        .post("/auth/device-token/create")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({"device_name": "my-laptop"}))
        .await;
    res.assert_status_ok();
    let created: serde_json::Value = res.json();
    let device_token = created["token"].as_str().unwrap().to_string();
    assert!(!device_token.is_empty());

    // Redeem
    let res = server
        .post("/auth/device-token/redeem")
        .json(&json!({"token": device_token}))
        .await;
    res.assert_status_ok();
    let redeemed: serde_json::Value = res.json();
    assert!(
        redeemed["session_token"].as_str().is_some(),
        "expected session_token in redeem response"
    );
}

/// Redeeming a device token rotates it — the old token must be rejected.
#[tokio::test]
async fn device_token_rotates_on_redeem() {
    let server = setup_server().await;
    let token = common::authenticate(&server, &Identity::generate()).await;

    // Create
    let res = server
        .post("/auth/device-token/create")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({}))
        .await;
    res.assert_status_ok();
    let device_token = res.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();

    // First redeem succeeds and rotates.
    let res = server
        .post("/auth/device-token/redeem")
        .json(&json!({"token": device_token}))
        .await;
    res.assert_status_ok();

    // Second redeem with old token must fail with 401.
    let res = server
        .post("/auth/device-token/redeem")
        .json(&json!({"token": device_token}))
        .await;
    res.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

/// A device token with `expires_at` in the past must be rejected.
#[tokio::test]
async fn device_token_expired_rejected() {
    let (state, guard) = make_state().await;
    let db = &state.db;

    let now = unix_now();
    let raw_token = gen_token();
    let token_hash = sha256_hex(&raw_token);
    let user_pubkey = "a".repeat(64);
    let id = uuid::Uuid::new_v4().to_string();

    // Seed user row.
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&user_pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    // Insert expired token.
    sqlx::query(
        "INSERT INTO device_tokens (id, token_hash, user_pubkey, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(&token_hash)
    .bind(&user_pubkey)
    .bind(now - 7200)
    .bind(now - 1) // already expired
    .execute(db)
    .await
    .unwrap();

    let server = common::TestHarness::new(TestServer::new(server::create_router(state)), guard);
    let res = server
        .post("/auth/device-token/redeem")
        .json(&json!({"token": raw_token}))
        .await;
    res.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

/// A revoked device token must be rejected.
#[tokio::test]
async fn device_token_revoked_rejected() {
    let (state, guard) = make_state().await;
    let db = &state.db;

    let now = unix_now();
    let raw_token = gen_token();
    let token_hash = sha256_hex(&raw_token);
    let user_pubkey = "b".repeat(64);
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&user_pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO device_tokens (id, token_hash, user_pubkey, created_at, expires_at, revoked)
         VALUES ($1, $2, $3, $4, $5, TRUE)",
    )
    .bind(&id)
    .bind(&token_hash)
    .bind(&user_pubkey)
    .bind(now)
    .bind(now + 86400 * 30)
    .execute(db)
    .await
    .unwrap();

    let server = common::TestHarness::new(TestServer::new(server::create_router(state)), guard);
    let res = server
        .post("/auth/device-token/redeem")
        .json(&json!({"token": raw_token}))
        .await;
    res.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Credential management tests
// ---------------------------------------------------------------------------

/// A user with no passkeys gets an empty array from GET /me/credentials.
#[tokio::test]
async fn list_credentials_empty() {
    let server = setup_server().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let res = server
        .get("/me/credentials")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    res.assert_status_ok();
    let body: serde_json::Value = res.json();
    assert_eq!(body, json!([]));
}

/// Inserting a webauthn_credentials row then calling PATCH /me/credentials/:id renames it.
#[tokio::test]
async fn rename_credential() {
    let (state, guard) = make_state().await;
    let db = &state.db;
    let now = unix_now();

    let identity = Identity::generate();
    let pubkey = identity.public_key_hex();
    let cred_id = "deadbeef01".to_string();

    // Seed the user.
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    // Insert a credential row.
    sqlx::query(
        "INSERT INTO webauthn_credentials (credential_id, user_pubkey, passkey_json, created_at)
         VALUES ($1, $2, '{}', $3)",
    )
    .bind(&cred_id)
    .bind(&pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    let server = common::TestHarness::new(TestServer::new(server::create_router(state)), guard);
    let token = common::authenticate(&server, &identity).await;

    // Rename.
    let res = server
        .patch(&format!("/me/credentials/{cred_id}"))
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({"friendly_name": "YubiKey Blue"}))
        .await;
    res.assert_status_ok();

    // Verify via list.
    let res = server
        .get("/me/credentials")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    res.assert_status_ok();
    let body: serde_json::Value = res.json();
    let creds = body.as_array().unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0]["friendly_name"], json!("YubiKey Blue"));
}

/// Deleting a credential removes it from the database.
#[tokio::test]
async fn delete_credential() {
    let (state, guard) = make_state().await;
    let db = &state.db;
    let now = unix_now();

    let identity = Identity::generate();
    let pubkey = identity.public_key_hex();
    let cred_id = "cafebabe02".to_string();

    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO webauthn_credentials (credential_id, user_pubkey, passkey_json, created_at)
         VALUES ($1, $2, '{}', $3)",
    )
    .bind(&cred_id)
    .bind(&pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    let server = common::TestHarness::new(TestServer::new(server::create_router(state)), guard);
    let token = common::authenticate(&server, &identity).await;

    // Delete.
    let res = server
        .delete(&format!("/me/credentials/{cred_id}"))
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    res.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Confirm it's gone.
    let res = server
        .get("/me/credentials")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    res.assert_status_ok();
    let body: serde_json::Value = res.json();
    assert_eq!(body, json!([]));
}

// ---------------------------------------------------------------------------
// Device management tests
// ---------------------------------------------------------------------------

/// GET /me/devices excludes expired tokens.
#[tokio::test]
async fn list_devices_excludes_expired() {
    let (state, guard) = make_state().await;
    let db = &state.db;
    let now = unix_now();

    let identity = Identity::generate();
    let pubkey = identity.public_key_hex();

    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(&pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    let token_a = sha256_hex(&gen_token());
    let token_b = sha256_hex(&gen_token());
    let id_a = uuid::Uuid::new_v4().to_string();
    let id_b = uuid::Uuid::new_v4().to_string();

    // Active token.
    sqlx::query(
        "INSERT INTO device_tokens (id, token_hash, user_pubkey, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id_a)
    .bind(&token_a)
    .bind(&pubkey)
    .bind(now)
    .bind(now + 86400 * 30)
    .execute(db)
    .await
    .unwrap();

    // Expired token.
    sqlx::query(
        "INSERT INTO device_tokens (id, token_hash, user_pubkey, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id_b)
    .bind(&token_b)
    .bind(&pubkey)
    .bind(now - 7200)
    .bind(now - 1)
    .execute(db)
    .await
    .unwrap();

    let server = common::TestHarness::new(TestServer::new(server::create_router(state)), guard);
    let token = common::authenticate(&server, &identity).await;

    let res = server
        .get("/me/devices")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    res.assert_status_ok();
    let body: serde_json::Value = res.json();
    let devices = body.as_array().unwrap();
    assert_eq!(devices.len(), 1, "only the active device should appear");
    assert_eq!(devices[0]["id"], json!(id_a));
}
