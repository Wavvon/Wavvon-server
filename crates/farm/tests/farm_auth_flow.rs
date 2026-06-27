/// Integration tests for the farm auth routes and revoke-check endpoint.
///
/// Each test spins up an in-memory SQLite farm and hits the API through
/// axum-test's TestServer — no network, no disk IO, fast and hermetic.
use std::sync::Arc;

use axum::http::HeaderValue;
use axum_test::TestServer;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use wavvon_farm::db;
use wavvon_farm::hub_manager::HubManager;
use wavvon_farm::server;
use wavvon_farm::state::FarmState;
use wavvon_farm::token::verify_token;
use wavvon_identity::Identity;

// ---------------------------------------------------------------------------
// Test setup helper
// ---------------------------------------------------------------------------

async fn setup() -> (TestServer, Arc<FarmState>) {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();

    let keypair = SigningKey::generate(&mut OsRng);
    let farm_url = "https://farm.test".to_string();

    // Insert the singleton farms row (main.rs does this on real startup).
    let pubkey_hex = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query("INSERT INTO farms (id, public_key, created_at) VALUES (1, ?, ?)")
        .bind(&pubkey_hex)
        .bind(now)
        .execute(&db)
        .await
        .unwrap();

    let hub_manager = Arc::new(HubManager::new(
        "wavvon-hub".to_string(),
        farm_url.clone(),
        9100,
    ));
    let state = Arc::new(FarmState::new(
        db,
        keypair,
        farm_url,
        hub_manager,
        "/tmp/hubs-test".to_string(),
    ));
    let app = server::create_router(state.clone());
    (TestServer::new(app), state)
}

// ---------------------------------------------------------------------------
// GET /farm/info
// ---------------------------------------------------------------------------

#[tokio::test]
async fn farm_info_returns_correct_shape() {
    let (server, state) = setup().await;
    let resp = server.get("/farm/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["kind"], "wavvon-farm");
    assert_eq!(body["public_key"], state.public_key_hex());
    assert!(body["auth"]["challenge_url"].is_string());
    assert!(body["auth"]["verify_url"].is_string());
    assert!(body["auth"]["renew_url"].is_string());
}

// ---------------------------------------------------------------------------
// POST /auth/challenge
// ---------------------------------------------------------------------------

#[tokio::test]
async fn challenge_returns_hex_nonce() {
    let (server, _) = setup().await;
    let identity = Identity::generate();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": identity.public_key_hex() }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let challenge = body["challenge"].as_str().unwrap();
    assert_eq!(
        challenge.len(),
        64,
        "challenge should be 32 bytes hex (64 chars)"
    );
    assert!(hex::decode(challenge).is_ok());
}

#[tokio::test]
async fn challenge_replaces_existing_pending() {
    let (server, _) = setup().await;
    let pubkey = Identity::generate().public_key_hex();

    let r1 = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pubkey }))
        .await;
    r1.assert_status_ok();
    let c1 = r1.json::<Value>()["challenge"]
        .as_str()
        .unwrap()
        .to_string();

    let r2 = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pubkey }))
        .await;
    r2.assert_status_ok();
    let c2 = r2.json::<Value>()["challenge"]
        .as_str()
        .unwrap()
        .to_string();

    // Two challenges for the same key — the second one must be different (random).
    // (Extremely unlikely to collide on 32 random bytes.)
    assert_ne!(c1, c2);
}

// ---------------------------------------------------------------------------
// POST /auth/verify
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_happy_path_returns_farm_token() {
    let (server, state) = setup().await;
    let identity = Identity::generate();
    let pubkey = identity.public_key_hex();

    // 1. Get challenge.
    let cr = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pubkey }))
        .await;
    cr.assert_status_ok();
    let challenge_hex = cr.json::<Value>()["challenge"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Sign the challenge.
    let challenge_bytes = hex::decode(&challenge_hex).unwrap();
    let sig = identity.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());

    // 3. Verify.
    let vr = server
        .post("/auth/verify")
        .json(&json!({ "public_key": pubkey, "signature": sig_hex }))
        .await;
    vr.assert_status_ok();
    let token_str = vr.json::<Value>()["token"].as_str().unwrap().to_string();

    // Token must be a valid farm token verifiable with the farm's pubkey.
    let farm_pubkey = state.public_key_hex();
    let payload = verify_token(&farm_pubkey, &token_str).unwrap();
    assert_eq!(payload.sub, pubkey);
    assert_eq!(payload.scope, "member");
    assert_eq!(payload.v, 1);
}

#[tokio::test]
async fn verify_rejects_bad_signature() {
    let (server, _) = setup().await;
    let identity = Identity::generate();
    let pubkey = identity.public_key_hex();

    let cr = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pubkey }))
        .await;
    cr.assert_status_ok();
    let challenge_hex = cr.json::<Value>()["challenge"]
        .as_str()
        .unwrap()
        .to_string();

    // Sign with a different identity (wrong key).
    let wrong_identity = Identity::generate();
    let challenge_bytes = hex::decode(&challenge_hex).unwrap();
    let bad_sig = wrong_identity.sign(&challenge_bytes);

    let vr = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pubkey,
            "signature": hex::encode(bad_sig.to_bytes()),
        }))
        .await;
    vr.assert_status_unauthorized();
}

#[tokio::test]
async fn verify_rejects_no_pending_challenge() {
    let (server, _) = setup().await;
    let identity = Identity::generate();
    let pubkey = identity.public_key_hex();

    // Skip the challenge step entirely.
    let vr = server
        .post("/auth/verify")
        .json(&json!({ "public_key": pubkey, "signature": "aabbcc" }))
        .await;
    vr.assert_status_unauthorized();
}

// ---------------------------------------------------------------------------
// POST /auth/renew
// ---------------------------------------------------------------------------

#[tokio::test]
async fn renew_returns_new_token_with_different_jti() {
    let (server, state) = setup().await;
    let identity = Identity::generate();
    let pubkey = identity.public_key_hex();

    // Authenticate first.
    let cr = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pubkey }))
        .await;
    let challenge_hex = cr.json::<Value>()["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let challenge_bytes = hex::decode(&challenge_hex).unwrap();
    let sig_hex = hex::encode(identity.sign(&challenge_bytes).to_bytes());
    let vr = server
        .post("/auth/verify")
        .json(&json!({ "public_key": pubkey, "signature": sig_hex }))
        .await;
    let old_token = vr.json::<Value>()["token"].as_str().unwrap().to_string();

    // Renew.
    let rr = server
        .post("/auth/renew")
        .add_header(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {old_token}")).unwrap(),
        )
        .await;
    rr.assert_status_ok();
    let new_token = rr.json::<Value>()["token"].as_str().unwrap().to_string();

    let farm_pubkey = state.public_key_hex();
    let old_payload = verify_token(&farm_pubkey, &old_token).unwrap();
    let new_payload = verify_token(&farm_pubkey, &new_token).unwrap();

    assert_ne!(
        old_payload.jti, new_payload.jti,
        "renew must produce a fresh jti"
    );
    assert_eq!(old_payload.sub, new_payload.sub, "sub must be preserved");
}

#[tokio::test]
async fn renew_rejects_missing_auth_header() {
    let (server, _) = setup().await;
    let resp = server.post("/auth/renew").await;
    resp.assert_status_unauthorized();
}

// ---------------------------------------------------------------------------
// POST /farm/auth/revoke-check
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_check_returns_false_for_active_session() {
    let (server, state) = setup().await;
    let identity = Identity::generate();
    let pubkey = identity.public_key_hex();

    // Auth to get a token.
    let cr = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pubkey }))
        .await;
    let challenge_hex = cr.json::<Value>()["challenge"]
        .as_str()
        .unwrap()
        .to_string();
    let challenge_bytes = hex::decode(&challenge_hex).unwrap();
    let sig_hex = hex::encode(identity.sign(&challenge_bytes).to_bytes());
    let vr = server
        .post("/auth/verify")
        .json(&json!({ "public_key": pubkey, "signature": sig_hex }))
        .await;
    let token_str = vr.json::<Value>()["token"].as_str().unwrap().to_string();

    let payload = verify_token(&state.public_key_hex(), &token_str).unwrap();

    let resp = server
        .post("/farm/auth/revoke-check")
        .json(&json!({ "jti": payload.jti }))
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>()["revoked"], false);
}

#[tokio::test]
async fn revoke_check_returns_true_for_unknown_jti() {
    let (server, _) = setup().await;
    let resp = server
        .post("/farm/auth/revoke-check")
        .json(&json!({ "jti": "nonexistent_jti_value" }))
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>()["revoked"], true);
}

// ---------------------------------------------------------------------------
// POST /farm/heartbeat — auth checks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn heartbeat_rejects_unknown_hub_pubkey() {
    let (server, _) = setup().await;
    // A hub_pubkey not in the hubs table should be rejected.
    let resp = server
        .post("/farm/heartbeat")
        .json(&json!({
            "hub_pubkey": "aabbccdd".repeat(8), // 64-char hex, not in hubs table
            "online_users": 0,
            "storage_bytes": 0,
            "uptime_seconds": 0
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn heartbeat_accepts_known_hub_pubkey() {
    let (server, state) = setup().await;
    // Insert a hub with a known hub_pubkey.
    let hub_pubkey = "ccddeeffe".repeat(7) + "c"; // 64 chars
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO hubs (id, owner_pubkey, name, visibility, db_path, created_at, hub_pubkey)
         VALUES ('hbhub', 'aa', 'Heartbeat Hub', 'private', '/tmp/x.db', ?, ?)",
    )
    .bind(now)
    .bind(&hub_pubkey)
    .execute(&state.db)
    .await
    .unwrap();

    let resp = server
        .post("/farm/heartbeat")
        .json(&json!({
            "hub_pubkey": hub_pubkey,
            "online_users": 5,
            "storage_bytes": 1024,
            "uptime_seconds": 3600
        }))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn heartbeat_rejects_missing_hub_pubkey() {
    let (server, _) = setup().await;
    // Omit hub_pubkey entirely — should get 400.
    let resp = server
        .post("/farm/heartbeat")
        .json(&json!({ "online_users": 1 }))
        .await;
    resp.assert_status_bad_request();
}
