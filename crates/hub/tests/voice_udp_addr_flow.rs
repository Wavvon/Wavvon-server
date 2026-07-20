//! Integration coverage for `voice_udp_addr` on `/info` (farm-impl.md,
//! "Serial routing — first slice" § "UDP voice"). A hub advertises the
//! publicly-reachable `host:port` of its voice UDP relay so a client (or a
//! farm-routed client dialing UDP directly) can find it without guessing.

use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::Value;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// Build a test server with `voice_udp_port` / `voice_udp_addr` set directly
/// on `AppState` — no real socket bind involved, this exercises the `/info`
/// surface only (mirrors `lan_mode_flow.rs`'s approach for LAN fields).
async fn setup_with_voice_addr(
    voice_udp_port: u16,
    voice_udp_addr: Option<&str>,
) -> common::TestHarness {
    let (db, guard) = common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
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
        voice_udp_port,
        voice_udp_addr: voice_udp_addr.map(|s| s.to_string()),
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
        staging_voice_grants: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        bots_allow_video: false,
        bot_video_stream_budget: 2,
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

    let app = server::create_router(state);
    common::TestHarness::new(TestServer::new(app), guard)
}

/// A hub with a known public voice UDP address surfaces it verbatim on
/// `/info`, carrying the configured port.
#[tokio::test]
async fn info_exposes_voice_udp_addr_when_known() {
    let harness = setup_with_voice_addr(3001, Some("hub.example.com:3001")).await;

    let resp = harness.get("/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();

    assert_eq!(body["voice_udp_addr"], "hub.example.com:3001");
}

/// A hub with no known public host (no `WAVVON_PUBLIC_URL`, not in LAN mode)
/// omits the field entirely rather than guessing — clients must treat its
/// absence as "voice UDP location unknown", not as an empty string.
#[tokio::test]
async fn info_omits_voice_udp_addr_when_unknown() {
    let harness = setup_with_voice_addr(3001, None).await;

    let resp = harness.get("/info").await;
    resp.assert_status_ok();
    let body: Value = resp.json();

    assert!(
        body.get("voice_udp_addr").is_none(),
        "expected voice_udp_addr to be absent, got {:?}",
        body.get("voice_udp_addr")
    );
}
