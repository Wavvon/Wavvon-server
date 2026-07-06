//! Integration tests for the subkey revocation relay worker.
//!
//! Each test spins up a minimal mock HTTP server that serves
//! GET /identity/{master}/revocations?since=, deposits subkey_certs rows
//! pointing at it, calls subkey_revocation_worker::tick(), and verifies the
//! outcome.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use store::PostgresStore;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::state::AppState;
use wavvon_hub::subkey_revocation_worker;
use wavvon_identity::{DeviceSubkey, Identity, RevocationEntry};

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn make_state() -> (Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
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
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
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
        webauthn: {
            let origin = url::Url::parse("http://localhost:3000").unwrap();
            std::sync::Arc::new(
                webauthn_rs::WebauthnBuilder::new("localhost", &origin)
                    .unwrap()
                    .rp_name("test-hub")
                    .build()
                    .unwrap(),
            )
        },
        webauthn_reg_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        webauthn_auth_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        device_token_ttl_secs: 30 * 86400,
        webhook_circuit: std::sync::Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
        lan_mode: false,
        lan_tls_mode: None,
        lan_fingerprint: None,
    });
    (state, guard)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn make_revocation(master: &Identity, subkey_pubkey: &str, revoked_at: u64) -> RevocationEntry {
    let master_key = master.master().unwrap();
    let master_pubkey = master_key.public_key_hex();
    let bytes = RevocationEntry::signing_bytes(&master_pubkey, subkey_pubkey, revoked_at);
    let signature = hex::encode(master_key.sign(&bytes).to_bytes());
    RevocationEntry {
        master_pubkey,
        subkey_pubkey: subkey_pubkey.to_string(),
        revoked_at,
        signature,
    }
}

/// Starts a minimal axum server on a random port. The handler for
/// `/identity/{master}/revocations` always returns the given JSON body.
/// Returns the base URL.
async fn start_mock_hub(revocations_json: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = revocations_json;
    let app = Router::new().route(
        "/identity/{master}/revocations",
        get(move || {
            let b = body.clone();
            async move {
                (
                    axum::http::StatusCode::OK,
                    [("content-type", "application/json")],
                    b,
                )
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    format!("http://127.0.0.1:{port}")
}

async fn insert_subkey_cert(
    db: &sqlx::PgPool,
    master_pubkey: &str,
    subkey_pubkey: &str,
    home_hub_url: &str,
) {
    let now = unix_now();
    sqlx::query(
        "INSERT INTO subkey_certs
         (master_pubkey, subkey_pubkey, device_label, issued_at, not_after,
          fallback_hubs_json, home_hub_url, signature, registered_at)
         VALUES ($1, $2, 'test', $3, NULL, '[]', $4, 'sig', $3)",
    )
    .bind(master_pubkey)
    .bind(subkey_pubkey)
    .bind(now)
    .bind(home_hub_url)
    .execute(db)
    .await
    .unwrap();
}

async fn revocation_exists(db: &sqlx::PgPool, master_pubkey: &str, subkey_pubkey: &str) -> bool {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subkey_revocations WHERE master_pubkey = $1 AND subkey_pubkey = $2",
    )
    .bind(master_pubkey)
    .bind(subkey_pubkey)
    .fetch_one(db)
    .await
    .unwrap();
    count > 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A revoked subkey is inserted into subkey_revocations after one tick.
#[tokio::test]
async fn revoked_subkey_inserted_after_tick() {
    let (state, _guard) = make_state().await;

    let identity = Identity::generate();
    let master_key = identity.master().unwrap();
    let master_pubkey = master_key.public_key_hex();
    let subkey_pubkey = DeviceSubkey::generate("dev".to_string()).public_key_hex();
    let revoked_at = unix_now() as u64 - 100;

    let entry = make_revocation(&identity, &subkey_pubkey, revoked_at);
    let revocations_json = serde_json::to_string(&vec![entry]).unwrap();

    let home_hub_url = start_mock_hub(revocations_json).await;

    insert_subkey_cert(&state.db, &master_pubkey, &subkey_pubkey, &home_hub_url).await;

    assert!(
        !revocation_exists(&state.db, &master_pubkey, &subkey_pubkey).await,
        "revocation should not exist before tick"
    );

    subkey_revocation_worker::tick(&state).await;

    assert!(
        revocation_exists(&state.db, &master_pubkey, &subkey_pubkey).await,
        "revocation should exist after tick"
    );
}

/// The sync cursor is recorded and advances to at least revoked_at after a
/// successful sync.
#[tokio::test]
async fn sync_cursor_advances() {
    let (state, _guard) = make_state().await;

    let identity = Identity::generate();
    let master_key = identity.master().unwrap();
    let master_pubkey = master_key.public_key_hex();
    let subkey_pubkey = DeviceSubkey::generate("dev".to_string()).public_key_hex();
    let revoked_at = unix_now() as u64 - 50;

    let entry = make_revocation(&identity, &subkey_pubkey, revoked_at);
    let revocations_json = serde_json::to_string(&vec![entry]).unwrap();

    let home_hub_url = start_mock_hub(revocations_json).await;

    insert_subkey_cert(&state.db, &master_pubkey, &subkey_pubkey, &home_hub_url).await;

    subkey_revocation_worker::tick(&state).await;

    let cursor: Option<i64> = sqlx::query_scalar(
        "SELECT last_synced_at FROM subkey_revocation_sync
         WHERE master_pubkey = $1 AND home_hub_url = $2",
    )
    .bind(&master_pubkey)
    .bind(&home_hub_url)
    .fetch_optional(&state.db)
    .await
    .unwrap();

    assert!(cursor.is_some(), "sync cursor should be recorded");
    assert!(
        cursor.unwrap() >= revoked_at as i64,
        "cursor should be at least the revoked_at value"
    );
}

/// tick() is a no-op when subkey_certs is empty (no home hubs to discover).
#[tokio::test]
async fn no_op_when_no_subkey_certs() {
    let (state, _guard) = make_state().await;
    subkey_revocation_worker::tick(&state).await;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subkey_revocation_sync")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

/// Revocation from hub A is applied; hub B returning an empty list leaves no
/// extra rows in subkey_revocations for identity B.
#[tokio::test]
async fn only_matching_master_revocations_inserted() {
    let (state, _guard) = make_state().await;

    // Identity A — has a revocation.
    let identity_a = Identity::generate();
    let master_a = identity_a.master().unwrap();
    let master_pubkey_a = master_a.public_key_hex();
    let subkey_a = DeviceSubkey::generate("dev".to_string()).public_key_hex();
    let revoked_at_a = unix_now() as u64 - 10;
    let entry_a = make_revocation(&identity_a, &subkey_a, revoked_at_a);
    let hub_a_url = start_mock_hub(serde_json::to_string(&vec![entry_a]).unwrap()).await;
    insert_subkey_cert(&state.db, &master_pubkey_a, &subkey_a, &hub_a_url).await;

    // Identity B — hub returns empty list.
    let identity_b = Identity::generate();
    let master_b = identity_b.master().unwrap();
    let master_pubkey_b = master_b.public_key_hex();
    let subkey_b = DeviceSubkey::generate("dev".to_string()).public_key_hex();
    let hub_b_url = start_mock_hub("[]".to_string()).await;
    insert_subkey_cert(&state.db, &master_pubkey_b, &subkey_b, &hub_b_url).await;

    subkey_revocation_worker::tick(&state).await;

    assert!(
        revocation_exists(&state.db, &master_pubkey_a, &subkey_a).await,
        "revocation for identity A should be inserted"
    );
    assert!(
        !revocation_exists(&state.db, &master_pubkey_b, &subkey_b).await,
        "no revocation for identity B (hub returned empty list)"
    );
}

/// When the home hub is unreachable, tick completes without panic and
/// subkey_revocations stays empty.
#[tokio::test]
async fn unreachable_hub_does_not_panic() {
    let (state, _guard) = make_state().await;

    let identity = Identity::generate();
    let master_key = identity.master().unwrap();
    let master_pubkey = master_key.public_key_hex();
    let subkey_pubkey = DeviceSubkey::generate("dev".to_string()).public_key_hex();

    // Port 1 is reserved; connection will be refused immediately.
    let home_hub_url = "http://127.0.0.1:1";

    insert_subkey_cert(&state.db, &master_pubkey, &subkey_pubkey, home_hub_url).await;

    subkey_revocation_worker::tick(&state).await;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subkey_revocations")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "subkey_revocations must be empty when hub is unreachable"
    );
}
