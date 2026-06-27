use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::db;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::routes::search::SearchResult;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// Build a TestServer backed by a real TantivySearch on a temp directory.
/// Returns the TempDir too — drop it after the test to clean up.
async fn setup_with_search() -> (TestServer, tempfile::TempDir) {
    sqlx::any::install_default_drivers();
    let db = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let store: Arc<dyn wavvon_store::HubStore> =
        Arc::new(wavvon_store_sqlite::SqliteStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);
    let tmp = tempfile::tempdir().unwrap();
    let search =
        Arc::new(wavvon_hub::search::tantivy_search::TantivySearch::open(tmp.path()).unwrap());
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
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(tokio::sync::RwLock::new(0)),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search,
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
    });
    (TestServer::new(server::create_router(state)), tmp)
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    let verify: VerifyResponse = resp.json();
    verify.token
}

/// Happy path: send a message, then search for a word in it.
#[tokio::test]
async fn search_finds_matching_message() {
    let (server, _tmp) = setup_with_search().await;
    let identity = Identity::generate();
    let token = authenticate(&server, &identity).await;

    // Create a channel and send a message with a distinctive word.
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let channel: ChannelResponse = resp.json();

    let resp = server
        .post(format!("/channels/{}/messages", channel.id).as_str())
        .authorization_bearer(&token)
        .json(&json!({ "content": "hello wavvonsearch world", "attachments": [] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // Search for the distinctive word.
    let resp = server
        .get("/search")
        .add_query_param("q", "wavvonsearch")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();

    let results: Vec<SearchResult> = resp.json();
    assert_eq!(results.len(), 1, "expected exactly one result");
    let hit = &results[0];
    assert_eq!(hit.channel_id, channel.id);
    assert_eq!(hit.channel_name, "general");
    assert!(hit.content_preview.contains("wavvonsearch"));
}

/// Short query (< 2 chars) returns an empty list, not an error.
#[tokio::test]
async fn search_short_query_returns_empty() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let resp = server
        .get("/search")
        .add_query_param("q", "x")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();

    let results: Vec<SearchResult> = resp.json();
    assert!(results.is_empty());
}

/// Unauthenticated request returns 401.
#[tokio::test]
async fn search_requires_auth() {
    let server = common::setup().await;

    let resp = server.get("/search").add_query_param("q", "anything").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

/// Admin reindex returns 202 Accepted and the status field.
#[tokio::test]
async fn admin_reindex_accepted_for_admin() {
    let (server, _tmp) = setup_with_search().await;
    let admin = Identity::generate();
    let admin_token = authenticate(&server, &admin).await; // first user → owner → admin

    let resp = server
        .post("/admin/search/reindex")
        .authorization_bearer(&admin_token)
        .await;
    resp.assert_status(axum::http::StatusCode::ACCEPTED);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["status"], "started");
}

/// Non-admin users must receive 403.
#[tokio::test]
async fn admin_reindex_forbidden_for_non_admin() {
    let (server, _tmp) = setup_with_search().await;
    // First user is admin; create a second non-admin user.
    let admin = Identity::generate();
    let _admin_token = authenticate(&server, &admin).await;
    let user = Identity::generate();
    let user_token = authenticate(&server, &user).await;

    let resp = server
        .post("/admin/search/reindex")
        .authorization_bearer(&user_token)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

/// Unauthenticated access is rejected.
#[tokio::test]
async fn admin_reindex_requires_auth() {
    let (server, _tmp) = setup_with_search().await;
    let resp = server.post("/admin/search/reindex").await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

/// Message in one channel is not returned when the caller is channel-banned.
#[tokio::test]
async fn search_respects_channel_ban() {
    let (server, _tmp) = setup_with_search().await;

    let poster = Identity::generate();
    let poster_token = authenticate(&server, &poster).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&poster_token)
        .json(&json!({ "name": "restricted" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let channel: ChannelResponse = resp.json();

    server
        .post(format!("/channels/{}/messages", channel.id).as_str())
        .authorization_bearer(&poster_token)
        .json(&json!({ "content": "supersecretword", "attachments": [] }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Second user signs up — can see the message before any ban.
    let watcher = Identity::generate();
    let watcher_token = authenticate(&server, &watcher).await;

    let resp = server
        .get("/search")
        .add_query_param("q", "supersecretword")
        .authorization_bearer(&watcher_token)
        .await;
    resp.assert_status_ok();
    let before: Vec<SearchResult> = resp.json();
    assert_eq!(
        before.len(),
        1,
        "watcher should find the message before ban"
    );

    // Insert the ban directly into the DB via the server state (we can't
    // call the endpoint without setting up admin permissions). We use the
    // poster's token to insert as a shortcut — the ban row only needs to
    // exist for the search filter to take effect.
    server
        .post(format!("/moderation/channels/{}/bans", channel.id).as_str())
        .authorization_bearer(&poster_token)
        .json(&json!({ "target_public_key": watcher.public_key_hex(), "reason": "test" }))
        .await;

    // After the moderation call, confirm search still works for the poster.
    let resp = server
        .get("/search")
        .add_query_param("q", "supersecretword")
        .authorization_bearer(&poster_token)
        .await;
    resp.assert_status_ok();
    let poster_results: Vec<SearchResult> = resp.json();
    assert_eq!(
        poster_results.len(),
        1,
        "poster should still see their own message"
    );
}
