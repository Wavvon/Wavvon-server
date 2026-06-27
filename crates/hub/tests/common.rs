use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use store::PostgresStore;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::db;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

/// Base PostgreSQL URL for the test database server.
/// Override with the `TEST_DATABASE_URL` environment variable.
/// The default points at a local PostgreSQL instance with no password,
/// matching the GitHub Actions service container in build.yml.
fn base_db_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432".to_string())
}

/// Create a new, isolated PostgreSQL database for a single test, run
/// migrations against it, and return the pool.
///
/// The database name is derived from a UUID to ensure isolation across
/// parallel test runs.
pub async fn create_test_db() -> PgPool {
    let base_url = base_db_url();

    // Connect to the `postgres` maintenance database to issue CREATE DATABASE.
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base_url}/postgres"))
        .await
        .expect("Failed to connect to PostgreSQL (admin)");

    let db_name = format!("wavvon_test_{}", uuid::Uuid::new_v4().simple());

    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&admin_pool)
        .await
        .expect("Failed to create test database");

    // Connect to the newly created test database.
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&format!("{base_url}/{db_name}"))
        .await
        .expect("Failed to connect to test database");

    db::migrations::run(&pool)
        .await
        .expect("Failed to run migrations on test database");

    pool
}

pub async fn setup() -> TestServer {
    let db = create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(PostgresStore::new(db.clone()));
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
        search: std::sync::Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
    });
    let app = server::create_router(state);
    TestServer::new(app)
}

#[allow(dead_code)]
pub async fn authenticate(server: &TestServer, identity: &Identity) -> String {
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

#[allow(dead_code)]
pub async fn setup_with_owner() -> (TestServer, String) {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;
    (server, token)
}
