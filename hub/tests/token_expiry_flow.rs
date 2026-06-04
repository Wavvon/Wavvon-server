//! Integration tests for bot session token expiry, renewal, and the
//! background sweep (`token_expiry::tick`).

use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::sync::{broadcast, mpsc, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, RenewResponse, VerifyResponse};
use voxply_hub::bots::token_expiry;
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async fn make_state() -> Arc<AppState> {
    let db = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx: broadcast::channel(256).0,
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
        bot_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
    })
}

async fn setup() -> (Arc<AppState>, TestServer) {
    let state = make_state().await;
    let server = TestServer::new(server::create_router(state.clone()));
    (state, server)
}

/// Perform the challenge-response flow and return the session token.
async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pk = identity.public_key_hex();
    let ch: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pk }))
        .await
        .json();
    let sig = identity.sign(&hex::decode(&ch.challenge).unwrap());
    let v: VerifyResponse = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pk,
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await
        .json();
    v.token
}

/// Insert a minimal bot `users` row directly into the DB (bypassing the
/// invite flow) so we can test expiry without standing up a full bot.
async fn insert_bot_user(db: &sqlx::SqlitePool, pubkey: &str) {
    let now = voxply_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at, approval_status, is_bot)
         VALUES (?, ?, ?, 'approved', 1)",
    )
    .bind(pubkey)
    .bind(now)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT OR IGNORE INTO user_roles (user_public_key, role_id, assigned_at)
         VALUES (?, 'builtin-everyone', ?)",
    )
    .bind(pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();
}

/// Insert a session row directly with the given `expires_at`.
async fn insert_session(
    db: &sqlx::SqlitePool,
    token: &str,
    pubkey: &str,
    expires_at: Option<i64>,
) {
    let now = voxply_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO sessions (token, public_key, created_at, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(token)
    .bind(pubkey)
    .bind(now)
    .bind(expires_at)
    .execute(db)
    .await
    .unwrap();
}

// ---------------------------------------------------------------------------
// Step 3 — Auth middleware enforces expires_at
// ---------------------------------------------------------------------------

/// A human session (expires_at IS NULL) always passes the expiry gate.
#[tokio::test]
async fn human_session_without_expiry_is_accepted() {
    let (_, server) = setup().await;
    let user = Identity::generate();
    let token = authenticate(&server, &user).await;
    server
        .get("/me")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
}

/// A bot session with expires_at in the future is accepted.
#[tokio::test]
async fn bot_session_not_yet_expired_is_accepted() {
    let (state, server) = setup().await;
    let bot = Identity::generate();
    let pk = bot.public_key_hex();
    insert_bot_user(&state.db, &pk).await;

    let future = voxply_hub::auth::handlers::unix_timestamp() + 86400;
    let token = "fresh_bot_token_not_yet_expired";
    insert_session(&state.db, token, &pk, Some(future)).await;

    server
        .get("/me")
        .authorization_bearer(token)
        .await
        .assert_status_ok();
}

/// A bot session with expires_at in the past is rejected with 401.
#[tokio::test]
async fn expired_bot_session_is_rejected() {
    let (state, server) = setup().await;
    let bot = Identity::generate();
    let pk = bot.public_key_hex();
    insert_bot_user(&state.db, &pk).await;

    let past = voxply_hub::auth::handlers::unix_timestamp() - 1;
    let token = "stale_bot_token_that_is_past";
    insert_session(&state.db, token, &pk, Some(past)).await;

    server
        .get("/me")
        .authorization_bearer(token)
        .await
        .assert_status_unauthorized();
}

// ---------------------------------------------------------------------------
// Step 1 — token_expiry::tick warning sweep
// ---------------------------------------------------------------------------

/// Sessions expiring within the 72-hour window get the warning pushed.
#[tokio::test]
async fn tick_sends_warning_for_near_expiry_session() {
    let state = make_state().await;
    let bot = Identity::generate();
    let pk = bot.public_key_hex();
    insert_bot_user(&state.db, &pk).await;

    // expires in 24 hours — within the 72-hour window
    let expires_at = voxply_hub::auth::handlers::unix_timestamp() + 24 * 3600;
    let token = "near_expiry_session_token_0001";
    insert_session(&state.db, token, &pk, Some(expires_at)).await;

    // Register a fake WS sender so the tick can push to it.
    let (tx, mut rx) = mpsc::channel::<String>(8);
    state.bot_sessions.write().await.insert(pk.clone(), tx);

    token_expiry::tick(&state).await.unwrap();

    // Should have received the warning.
    let msg = rx.try_recv().expect("expected token_expiring_soon message");
    let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
    assert_eq!(v["type"], "token_expiring_soon");
    assert_eq!(v["expires_at"], expires_at);

    // expiry_warned_at should be set in the DB.
    let warned_at: Option<i64> =
        sqlx::query_scalar("SELECT expiry_warned_at FROM sessions WHERE token = ?")
            .bind(token)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(warned_at.is_some(), "expiry_warned_at should be set");
}

/// Sessions beyond the 72-hour window should NOT receive a warning.
#[tokio::test]
async fn tick_does_not_warn_session_with_distant_expiry() {
    let state = make_state().await;
    let bot = Identity::generate();
    let pk = bot.public_key_hex();
    insert_bot_user(&state.db, &pk).await;

    // Expires in 10 days — outside the 72-hour window
    let expires_at = voxply_hub::auth::handlers::unix_timestamp() + 10 * 86400;
    let token = "far_expiry_session_token_0002";
    insert_session(&state.db, token, &pk, Some(expires_at)).await;

    let (tx, mut rx) = mpsc::channel::<String>(8);
    state.bot_sessions.write().await.insert(pk.clone(), tx);

    token_expiry::tick(&state).await.unwrap();

    assert!(
        rx.try_recv().is_err(),
        "no warning should be sent for sessions with distant expiry"
    );
}

/// Already-warned sessions (within 24 h) should not be re-warned.
#[tokio::test]
async fn tick_does_not_rewarn_recently_warned_session() {
    let state = make_state().await;
    let bot = Identity::generate();
    let pk = bot.public_key_hex();
    insert_bot_user(&state.db, &pk).await;

    let now = voxply_hub::auth::handlers::unix_timestamp();
    let expires_at = now + 24 * 3600; // within the 72-h window
    let token = "warned_session_token_0003";
    insert_session(&state.db, token, &pk, Some(expires_at)).await;

    // Set expiry_warned_at to 1 hour ago (within the 24-h cooldown).
    sqlx::query("UPDATE sessions SET expiry_warned_at = ? WHERE token = ?")
        .bind(now - 3600)
        .bind(token)
        .execute(&state.db)
        .await
        .unwrap();

    let (tx, mut rx) = mpsc::channel::<String>(8);
    state.bot_sessions.write().await.insert(pk.clone(), tx);

    token_expiry::tick(&state).await.unwrap();

    assert!(
        rx.try_recv().is_err(),
        "session warned within 24 h should not be re-warned"
    );
}

// ---------------------------------------------------------------------------
// Step 1 — token_expiry::tick expiry sweep
// ---------------------------------------------------------------------------

/// Expired sessions get the bot_removed message and are deleted.
#[tokio::test]
async fn tick_closes_and_deletes_expired_session() {
    let state = make_state().await;
    let bot = Identity::generate();
    let pk = bot.public_key_hex();
    insert_bot_user(&state.db, &pk).await;

    let past = voxply_hub::auth::handlers::unix_timestamp() - 1;
    let token = "expired_session_token_0004";
    insert_session(&state.db, token, &pk, Some(past)).await;

    let (tx, mut rx) = mpsc::channel::<String>(8);
    state.bot_sessions.write().await.insert(pk.clone(), tx);

    token_expiry::tick(&state).await.unwrap();

    // Should receive bot_removed.
    let msg = rx.try_recv().expect("expected bot_removed message");
    let v: serde_json::Value = serde_json::from_str(&msg).unwrap();
    assert_eq!(v["type"], "bot_removed");
    assert_eq!(v["reason"], "token_expired");

    // Session row should be gone.
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE token = ?")
            .bind(token)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(count, 0, "expired session row should be deleted");

    // bot_sessions entry should be removed.
    let still_in_map = state.bot_sessions.read().await.contains_key(&pk);
    assert!(!still_in_map, "bot_sessions entry should be cleaned up");
}

/// Non-expired sessions are left alone by the expiry sweep.
#[tokio::test]
async fn tick_does_not_touch_live_sessions() {
    let state = make_state().await;
    let bot = Identity::generate();
    let pk = bot.public_key_hex();
    insert_bot_user(&state.db, &pk).await;

    let future = voxply_hub::auth::handlers::unix_timestamp() + 86400;
    let token = "live_session_token_0005";
    insert_session(&state.db, token, &pk, Some(future)).await;

    token_expiry::tick(&state).await.unwrap();

    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE token = ?")
            .bind(token)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(count, 1, "live session should not be deleted");
}

// ---------------------------------------------------------------------------
// Step 2 — POST /auth/renew
// ---------------------------------------------------------------------------

/// Successful renewal returns a token and an expires_at 30 days out.
#[tokio::test]
async fn renew_returns_new_token_with_expires_at() {
    let (_, server) = setup().await;
    let user = Identity::generate();
    let pk = user.public_key_hex();

    // Human auth to get an existing valid session.
    let existing_token = authenticate(&server, &user).await;

    // Get a fresh challenge for the renew request.
    let ch: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pk }))
        .await
        .json();

    let sig = user.sign(&hex::decode(&ch.challenge).unwrap());
    let resp = server
        .post("/auth/renew")
        .authorization_bearer(&existing_token)
        .json(&json!({
            "public_key": pk,
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await;

    resp.assert_status_ok();
    let body: RenewResponse = resp.json();
    assert!(!body.token.is_empty(), "renewed token should not be empty");

    // expires_at should be roughly now + 30 days.
    let now = voxply_hub::auth::handlers::unix_timestamp();
    let expected = now + 30 * 24 * 3600;
    let delta = (body.expires_at - expected).abs();
    assert!(delta < 5, "expires_at should be ~30 days from now, got delta={delta}s");
}

/// Renewal fails when the bearer token is missing.
#[tokio::test]
async fn renew_rejects_unauthenticated_request() {
    let (_, server) = setup().await;
    let user = Identity::generate();
    let pk = user.public_key_hex();

    let ch: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pk }))
        .await
        .json();

    let sig = user.sign(&hex::decode(&ch.challenge).unwrap());
    server
        .post("/auth/renew")
        // No bearer token
        .json(&json!({
            "public_key": pk,
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await
        .assert_status_unauthorized();
}

/// Renewal fails when the challenge pubkey doesn't match the authenticated user.
#[tokio::test]
async fn renew_rejects_pubkey_mismatch() {
    let (_, server) = setup().await;
    let user = Identity::generate();
    let other = Identity::generate();
    let other_pk = other.public_key_hex();

    let user_token = authenticate(&server, &user).await;

    // Get a challenge for the *other* identity.
    let ch: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": other_pk }))
        .await
        .json();

    let sig = other.sign(&hex::decode(&ch.challenge).unwrap());
    server
        .post("/auth/renew")
        .authorization_bearer(&user_token)
        .json(&json!({
            "public_key": other_pk,   // different from token's owner
            "challenge": ch.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}
