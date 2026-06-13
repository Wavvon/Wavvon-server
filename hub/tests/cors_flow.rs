/// CORS integration tests.
///
/// Verifies that:
///   1. The wildcard default returns `access-control-allow-origin: *` on a
///      simple GET and on an OPTIONS preflight.
///   2. A restricted origin list allows a matching origin and omits the header
///      for a non-matching origin.
use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::server::create_router_with_cors;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

#[path = "common.rs"]
mod common;

async fn setup_with_cors(cors_origins: &str) -> TestServer {
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
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        active_game_sessions: std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::new(),
        )),
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
        search: std::sync::Arc::new(voxply_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });

    let app = create_router_with_cors(state, cors_origins);
    TestServer::new(app)
}

/// Default wildcard CORS: GET /health returns `access-control-allow-origin: *`.
#[tokio::test]
async fn wildcard_cors_on_get() {
    let server = setup_with_cors("*").await;
    let resp = server
        .get("/health")
        .add_header("origin", "https://app.example.com")
        .await;
    resp.assert_status_ok();
    let acao = resp.headers().get("access-control-allow-origin");
    assert!(
        acao.is_some(),
        "access-control-allow-origin header should be present"
    );
    assert_eq!(acao.unwrap(), "*", "wildcard CORS should return *");
}

/// Default wildcard CORS: OPTIONS preflight returns the CORS headers.
#[tokio::test]
async fn wildcard_cors_preflight() {
    let server = setup_with_cors("*").await;
    let resp = server
        .method(axum::http::Method::OPTIONS, "/health")
        .add_header("origin", "https://app.example.com")
        .add_header("access-control-request-method", "GET")
        .add_header("access-control-request-headers", "authorization")
        .await;
    // Tower-http CorsLayer responds to OPTIONS preflight with 200 and the
    // appropriate headers even when the route doesn't explicitly handle OPTIONS.
    let acao = resp.headers().get("access-control-allow-origin");
    assert!(
        acao.is_some(),
        "preflight should include access-control-allow-origin"
    );
    assert_eq!(acao.unwrap(), "*");
    assert!(
        resp.headers().get("access-control-allow-methods").is_some(),
        "preflight should include access-control-allow-methods"
    );
}

/// Restricted origins: matching origin is reflected back.
#[tokio::test]
async fn restricted_cors_matching_origin() {
    let server = setup_with_cors("https://allowed.example.com,https://other.example.com").await;
    let resp = server
        .get("/health")
        .add_header("origin", "https://allowed.example.com")
        .await;
    resp.assert_status_ok();
    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .expect("ACAO header should be present for a matching origin");
    assert_eq!(acao, "https://allowed.example.com");
}

/// Restricted origins: non-matching origin gets no ACAO header (or a vary
/// response that does not allow the foreign origin).
#[tokio::test]
async fn restricted_cors_non_matching_origin() {
    let server = setup_with_cors("https://allowed.example.com").await;
    let resp = server
        .get("/health")
        .add_header("origin", "https://evil.example.com")
        .await;
    // The response itself should still be 200 (CORS is a browser-side policy;
    // the server returns the resource but omits the allow header).
    resp.assert_status_ok();
    let acao = resp.headers().get("access-control-allow-origin");
    // Either the header is absent or it does NOT equal the disallowed origin.
    if let Some(v) = acao {
        assert_ne!(
            v, "https://evil.example.com",
            "non-matching origin must not be reflected"
        );
    }
}
