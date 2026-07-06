//! Integration tests for the cert revocation relay worker.
//!
//! Each test spins up a minimal mock HTTP server that serves
//! GET /certs/revocations, deposits user_certs rows pointing at it,
//! calls cert_revocation_worker::tick(), and verifies the outcome.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::get;
use axum::Router;
use serde_json::json;
use store::PostgresStore;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use url::Url;
use wavvon_hub::cert_revocation_worker;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;
use webauthn_rs::WebauthnBuilder;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
        webauthn,
        webauthn_reg_challenges: RwLock::new(HashMap::new()),
        webauthn_auth_challenges: RwLock::new(HashMap::new()),
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

/// Starts a minimal axum server on a random port that always returns the given
/// JSON body from GET /certs/revocations. Returns the base URL.
async fn start_mock_issuer(revocations: serde_json::Value) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = revocations.to_string();
    let app = Router::new().route(
        "/certs/revocations",
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

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

async fn insert_user_cert(
    db: &sqlx::PgPool,
    id: &str,
    master_pubkey: &str,
    issuer_pubkey: &str,
    issuer_url: &str,
    expires_at: i64,
) {
    sqlx::query(
        "INSERT INTO user_certs
         (id, master_pubkey, issuer_pubkey, issuer_url, payload_json, signature, expires_at)
         VALUES ($1, $2, $3, $4, '{}', 'sig', $5)",
    )
    .bind(id)
    .bind(master_pubkey)
    .bind(issuer_pubkey)
    .bind(issuer_url)
    .bind(expires_at)
    .execute(db)
    .await
    .unwrap();
}

async fn cert_exists(db: &sqlx::PgPool, id: &str) -> bool {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM user_certs WHERE id = $1")
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap();
    count > 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Revoked cert is deleted from user_certs after one tick.
#[tokio::test]
async fn revoked_cert_removed() {
    let (state, _guard) = make_state().await;
    let now = unix_now();

    let issuer_pubkey = "a".repeat(64);
    let master_pubkey = "b".repeat(64);

    let issuer_url = start_mock_issuer(json!([
        { "id": "cert-1", "subject_pubkey": master_pubkey, "revoked_at": now - 100 }
    ]))
    .await;

    insert_user_cert(
        &state.db,
        "cert-1",
        &master_pubkey,
        &issuer_pubkey,
        &issuer_url,
        now + 86400,
    )
    .await;

    assert!(
        cert_exists(&state.db, "cert-1").await,
        "cert should exist before tick"
    );

    cert_revocation_worker::tick(&state).await;

    assert!(
        !cert_exists(&state.db, "cert-1").await,
        "cert should be removed after tick"
    );
}

/// The sync cursor is recorded and advances after a successful sync.
#[tokio::test]
async fn sync_cursor_advances() {
    let (state, _guard) = make_state().await;
    let now = unix_now();

    let issuer_pubkey = "c".repeat(64);
    let master_pubkey = "d".repeat(64);
    let revoked_at = now - 50;

    let issuer_url = start_mock_issuer(json!([
        { "id": "cert-2", "subject_pubkey": master_pubkey, "revoked_at": revoked_at }
    ]))
    .await;

    insert_user_cert(
        &state.db,
        "cert-2",
        &master_pubkey,
        &issuer_pubkey,
        &issuer_url,
        now + 86400,
    )
    .await;

    cert_revocation_worker::tick(&state).await;

    let cursor: Option<i64> = sqlx::query_scalar(
        "SELECT last_synced_at FROM cert_revocation_sync WHERE issuer_pubkey = $1",
    )
    .bind(&issuer_pubkey)
    .fetch_optional(&state.db)
    .await
    .unwrap();

    assert!(cursor.is_some(), "sync cursor should be recorded");
    assert!(
        cursor.unwrap() >= revoked_at,
        "cursor should be at least the revoked_at value"
    );
}

/// tick() is a no-op when user_certs is empty (no issuers to discover).
#[tokio::test]
async fn no_op_when_no_user_certs() {
    let (state, _guard) = make_state().await;
    cert_revocation_worker::tick(&state).await;
    // No panic and no rows added
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cert_revocation_sync")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

/// Only certs from the revoking issuer are removed; certs from other issuers
/// that had no revocations are left intact.
#[tokio::test]
async fn only_matching_issuer_certs_removed() {
    let (state, _guard) = make_state().await;
    let now = unix_now();

    let issuer_a_pubkey = "e".repeat(64);
    let issuer_b_pubkey = "f".repeat(64);
    let master_pubkey = "g".repeat(64);

    let issuer_a_url = start_mock_issuer(json!([
        { "id": "cert-a", "subject_pubkey": master_pubkey, "revoked_at": now - 10 }
    ]))
    .await;
    let issuer_b_url = start_mock_issuer(json!([])).await;

    insert_user_cert(
        &state.db,
        "cert-a",
        &master_pubkey,
        &issuer_a_pubkey,
        &issuer_a_url,
        now + 86400,
    )
    .await;
    insert_user_cert(
        &state.db,
        "cert-b",
        &master_pubkey,
        &issuer_b_pubkey,
        &issuer_b_url,
        now + 86400,
    )
    .await;

    cert_revocation_worker::tick(&state).await;

    assert!(
        !cert_exists(&state.db, "cert-a").await,
        "revoked cert should be gone"
    );
    assert!(
        cert_exists(&state.db, "cert-b").await,
        "non-revoked cert should remain"
    );
}

/// When the remote issuer is unreachable, existing certs are left untouched.
#[tokio::test]
async fn unreachable_issuer_does_not_delete_certs() {
    let (state, _guard) = make_state().await;
    let now = unix_now();

    let issuer_pubkey = "h".repeat(64);
    let master_pubkey = "i".repeat(64);

    // Point at a port that is not listening.
    let issuer_url = "http://127.0.0.1:1"; // port 1 is reserved; connection will fail

    insert_user_cert(
        &state.db,
        "cert-unreachable",
        &master_pubkey,
        &issuer_pubkey,
        issuer_url,
        now + 86400,
    )
    .await;

    cert_revocation_worker::tick(&state).await;

    assert!(
        cert_exists(&state.db, "cert-unreachable").await,
        "cert must not be removed when issuer is unreachable"
    );
}
