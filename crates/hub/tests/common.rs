use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use store::PostgresStore;
use tokio::sync::{broadcast, RwLock};
use url::Url;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::db;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;
use webauthn_rs::WebauthnBuilder;

/// Base PostgreSQL URL for the test database server.
/// Override with the `TEST_DATABASE_URL` environment variable.
/// The default points at a local PostgreSQL instance with no password,
/// matching the GitHub Actions service container in build.yml.
fn base_db_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432".to_string())
}

// ---------------------------------------------------------------------------
// Ephemeral database teardown
// ---------------------------------------------------------------------------
//
// Every test gets its own `wavvon_test_<uuid>` database via `create_test_db`.
// Historically nothing ever dropped these, and they piled up in the target
// PostgreSQL container indefinitely (thousands of stale databases have been
// observed, at one point exhausting the container's /dev/shm and crashing
// Postgres mid-suite).
//
// `TestDbGuard` (returned alongside the pool by `create_test_db`, and
// bundled into `TestHarness` for HTTP-level tests) drops the database when
// the last handle referencing it goes out of scope. Because `Drop` cannot
// be `async`, and the caller may already be inside a `#[tokio::test]`
// current-thread runtime (which cannot nest another `block_on`), teardown
// runs on a dedicated OS thread with its own throwaway Tokio runtime. This
// also means teardown fires on test panic/failure (unlike an explicit
// "please clean up" call at the end of a test, which is skipped on unwind).
//
// `DROP DATABASE ... WITH (FORCE)` (Postgres 13+) is used so a connection
// leaked from the test's own pool can't block cleanup.
//
// One-shot backlog sweep: if the target Postgres instance has accumulated a
// backlog of stale `wavvon_test_*` databases (e.g. from runs before this
// fix, or from a hard-killed test process), clear it with:
//
//   cargo test -p wavvon-hub --test db_sweep -- --ignored --nocapture
//
// or manually via psql:
//
//   psql -U postgres -c "SELECT 'DROP DATABASE IF EXISTS \"' || datname || '\" WITH (FORCE);' FROM pg_database WHERE datname LIKE 'wavvon_test_%'" -t | psql -U postgres

struct TestDbGuardInner {
    db_name: String,
    base_url: String,
}

impl Drop for TestDbGuardInner {
    fn drop(&mut self) {
        let db_name = self.db_name.clone();
        let base_url = self.base_url.clone();

        // Escape to a fresh OS thread so we can drive a throwaway runtime
        // to completion, regardless of what runtime (if any) is active on
        // the thread that's dropping us.
        let join_result = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            rt.block_on(async move {
                let admin_pool = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&format!("{base_url}/postgres"))
                    .await?;
                sqlx::query(&format!(
                    "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
                ))
                .execute(&admin_pool)
                .await?;
                Ok::<(), sqlx::Error>(())
            })
        })
        .join();

        match join_result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                eprintln!(
                    "warning: failed to drop test database {}: {err}",
                    self.db_name
                );
            }
            Err(_) => {
                eprintln!(
                    "warning: teardown thread panicked while dropping test database {}",
                    self.db_name
                );
            }
        }
    }
}

/// Cheaply cloneable handle whose last drop tears down the ephemeral test
/// database. Hold on to it (even via `let _guard = ...`) for as long as the
/// pool/server backed by that database is in use.
#[derive(Clone)]
#[must_use = "dropping this immediately tears down the test database while it may still be in use"]
pub struct TestDbGuard(#[allow(dead_code)] Arc<TestDbGuardInner>);

/// Create a new, isolated PostgreSQL database for a single test, run
/// migrations against it, and return the pool together with a guard that
/// drops the database once the test (and anything sharing the guard) is
/// done with it.
///
/// The database name is derived from a UUID to ensure isolation across
/// parallel test runs.
pub async fn create_test_db() -> (PgPool, TestDbGuard) {
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

    let guard = TestDbGuard(Arc::new(TestDbGuardInner {
        db_name: db_name.clone(),
        base_url: base_url.clone(),
    }));

    // Connect to the newly created test database.
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&format!("{base_url}/{db_name}"))
        .await
        .expect("Failed to connect to test database");

    db::migrations::run(&pool)
        .await
        .expect("Failed to run migrations on test database");

    (pool, guard)
}

/// One-shot maintenance helper: drops every leftover `wavvon_test_*`
/// database on the target Postgres server. Safe to run at any time — each
/// test run uses a fresh UUID-derived name, so a backlog left behind by
/// earlier crashed/killed/pre-fix runs is always safe to clear.
///
/// Run explicitly with:
///   cargo test -p wavvon-hub --test db_sweep -- --ignored --nocapture
#[allow(dead_code)]
pub async fn sweep_stale_test_databases() -> usize {
    let base_url = base_db_url();
    let admin_pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&format!("{base_url}/postgres"))
        .await
        .expect("Failed to connect to PostgreSQL (admin)");

    let names: Vec<String> =
        sqlx::query_scalar("SELECT datname FROM pg_database WHERE datname LIKE 'wavvon_test_%'")
            .fetch_all(&admin_pool)
            .await
            .expect("Failed to list stale test databases");

    let mut dropped = 0usize;
    for name in names {
        let result = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
            .execute(&admin_pool)
            .await;
        match result {
            Ok(_) => dropped += 1,
            Err(err) => eprintln!("warning: failed to drop stale test database {name}: {err}"),
        }
    }
    dropped
}

/// Wraps `axum_test::TestServer` together with the `TestDbGuard` for the
/// database backing it, so the database is torn down exactly when the
/// server (and everything derived from it) goes out of scope — including
/// on test panic. `Deref`s to `TestServer` so existing call sites that use
/// `server.get(...)`, `server.post(...)`, or pass `&server` around keep
/// working unchanged.
#[allow(dead_code)]
pub struct TestHarness {
    server: TestServer,
    _guard: TestDbGuard,
    /// Only populated by `setup()` / `setup_with_owner()`, which build the
    /// `AppState` themselves. Callers that hand-roll their own `AppState`
    /// and call `TestHarness::new` directly don't get one -- use `state()`
    /// only from tests that went through `setup()`.
    state: Option<Arc<AppState>>,
}

impl TestHarness {
    #[allow(dead_code)]
    pub fn new(server: TestServer, guard: TestDbGuard) -> Self {
        TestHarness {
            server,
            _guard: guard,
            state: None,
        }
    }

    /// Access the `AppState` backing this harness, for tests that need to
    /// drive a background-worker `tick()` directly rather than through HTTP.
    /// Panics if this harness wasn't built via `setup()`.
    #[allow(dead_code)]
    pub fn state(&self) -> &AppState {
        self.state
            .as_deref()
            .expect("TestHarness::state() requires a harness built via setup()")
    }
}

impl Deref for TestHarness {
    type Target = TestServer;

    fn deref(&self) -> &TestServer {
        &self.server
    }
}

fn make_test_webauthn() -> Arc<webauthn_rs::Webauthn> {
    let origin = Url::parse("http://localhost:3000").unwrap();
    Arc::new(
        WebauthnBuilder::new("localhost", &origin)
            .unwrap()
            .rp_name("test-hub")
            .build()
            .unwrap(),
    )
}

pub async fn setup() -> TestHarness {
    let (db, guard) = create_test_db().await;
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
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
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
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        webauthn: make_test_webauthn(),
        webauthn_reg_challenges: RwLock::new(HashMap::new()),
        webauthn_auth_challenges: RwLock::new(HashMap::new()),
        device_token_ttl_secs: 30 * 86400,
        webhook_circuit: std::sync::Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
    });
    let app = server::create_router(state.clone());
    TestHarness {
        server: TestServer::new(app),
        _guard: guard,
        state: Some(state),
    }
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
pub async fn setup_with_owner() -> (TestHarness, String) {
    let server = setup().await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;
    (server, token)
}
