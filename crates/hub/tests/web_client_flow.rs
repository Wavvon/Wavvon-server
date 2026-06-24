//! Integration tests for the optional static web-client serving feature.
//!
//! Tests are split into two sections:
//! - With `web_client_dir` set to a temp dir containing index.html + an asset.
//! - With `web_client_dir` unset (API-only, today's behaviour).

use std::collections::HashMap;
use std::sync::Arc;

use axum::http::header;
use axum_test::TestServer;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_hub::web_client::WebClientConfig;
use voxply_identity::Identity;

/// Build a test server with an optional WebClientConfig.
async fn setup_with_web_client(cfg: Option<Arc<WebClientConfig>>) -> TestServer {
    sqlx::any::install_default_drivers();
    let db = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let store: Arc<dyn voxply_store::HubStore> =
        Arc::new(voxply_store_sqlite::SqliteStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

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
        active_game_sessions: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
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
        search: Arc::new(voxply_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
    });

    let app = server::create_router_full(state, "*", false, cfg);
    TestServer::new(app)
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn make_web_client_dir() -> (tempfile::TempDir, Arc<WebClientConfig>) {
    let dir = tempfile::tempdir().expect("tempdir");

    // Write a minimal index.html with a </head> tag so injection is testable.
    let index_html = b"<html><head><title>Voxply</title></head><body>hello</body></html>";
    std::fs::write(dir.path().join("index.html"), index_html).unwrap();

    // Write a static asset.
    std::fs::write(dir.path().join("app.js"), b"console.log('voxply');").unwrap();

    let cfg = WebClientConfig::load(dir.path()).expect("WebClientConfig::load");
    (dir, Arc::new(cfg))
}

// ── with web client ───────────────────────────────────────────────────────────

/// GET / with Accept: text/html → returns index.html containing __VOXPLY_HOME_HUB__.
#[tokio::test]
async fn root_with_html_accept_returns_index() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server
        .get("/")
        .add_header(header::ACCEPT, "text/html,application/xhtml+xml")
        .await;

    resp.assert_status_ok();
    let body = resp.text();
    assert!(
        body.contains("__VOXPLY_HOME_HUB__"),
        "Expected injected config script in index.html; got: {body}"
    );
    assert!(
        body.contains("</head>"),
        "Expected </head> in index.html; got: {body}"
    );
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/html"),
        "Expected text/html content-type; got: {ct}"
    );
}

/// GET /some/spa/route with Accept: text/html → SPA fallback serves index.html.
#[tokio::test]
async fn spa_route_with_html_accept_returns_index() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server
        .get("/some/spa/route")
        .add_header(header::ACCEPT, "text/html,*/*;q=0.8")
        .await;

    resp.assert_status_ok();
    let body = resp.text();
    assert!(
        body.contains("__VOXPLY_HOME_HUB__"),
        "SPA fallback should serve injected index.html; got: {body}"
    );
}

/// GET /nonexistent with Accept: application/json → plain 404 (not index.html).
/// This is the critical API-semantics preservation test.
#[tokio::test]
async fn non_api_path_with_json_accept_returns_404() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server
        .get("/nonexistent-path-xyz")
        .add_header(header::ACCEPT, "application/json")
        .await;

    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    let body = resp.text();
    // Must NOT be the index.html content.
    assert!(
        !body.contains("__VOXPLY_HOME_HUB__"),
        "JSON client must receive a plain 404, not the SPA index; got: {body}"
    );
}

/// GET /health still returns the health JSON even with web client enabled.
/// This verifies that named API routes take priority over the fallback.
#[tokio::test]
async fn health_route_unaffected_by_web_client() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server
        .get("/health")
        .add_header(header::ACCEPT, "text/html,*/*;q=0.8") // browser-like
        .await;

    resp.assert_status_ok();
    // Should be JSON, not HTML.
    let body = resp.text();
    assert!(
        body.contains("ok") || body.contains("status"),
        "Expected health JSON; got: {body}"
    );
    assert!(
        !body.contains("__VOXPLY_HOME_HUB__"),
        "Health route should not be overridden by web client fallback; got: {body}"
    );
}

/// GET /app.js → static asset is served with 200.
#[tokio::test]
async fn static_asset_is_served() {
    let (_dir, cfg) = make_web_client_dir();
    let server = setup_with_web_client(Some(cfg)).await;

    let resp = server.get("/app.js").await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(
        body.contains("voxply"),
        "Expected JS asset content; got: {body}"
    );
}

// ── without web client (API-only, today's behaviour) ─────────────────────────

/// Without web_client_dir, GET / returns 404 (the current behaviour — no root handler registered).
#[tokio::test]
async fn root_without_web_client_returns_404() {
    let server = setup_with_web_client(None).await;

    let resp = server.get("/").await;
    // The hub has no GET / route registered; axum returns 404 for unmatched paths
    // when no fallback is registered.
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

/// Without web_client_dir, GET /health still works normally.
#[tokio::test]
async fn health_without_web_client() {
    let server = setup_with_web_client(None).await;

    let resp = server.get("/health").await;
    resp.assert_status_ok();
}
