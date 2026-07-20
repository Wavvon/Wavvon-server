/// Integration tests for proximity voice zones (V3).
///
/// Three state-level tests verify zone CRUD directly on AppState.
/// One WS integration test drives VoiceJoin through a real TCP hub and
/// checks that the `voice_zone_state` snapshot is pushed to the joining client.
use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::{AppState, AttenuationConfig, VoiceZone};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Harness — mirrors voice_relay_flow.rs so WS upgrades work.
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "proximity-voice-test".to_string(),
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
        voice_udp_addr: None,
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(RwLock::new(0)),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: RwLock::new(HashMap::new()),
        whisper_target_defs: RwLock::new(HashMap::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        staging_voice_grants: RwLock::new(std::collections::HashMap::new()),
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
        bots_allow_video: false,
        bot_video_stream_budget: 2,
        webauthn: {
            let origin = url::Url::parse("http://localhost:3000").unwrap();
            Arc::new(
                webauthn_rs::WebauthnBuilder::new("localhost", &origin)
                    .unwrap()
                    .rp_name("test-hub")
                    .build()
                    .unwrap(),
            )
        },
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

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (url, state, guard)
}

async fn authenticate_http(base: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();

    let resp: ChallengeResponse = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let challenge_bytes = hex::decode(&resp.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let verify: VerifyResponse = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": resp.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    verify.token
}

async fn create_channel(base: &str, token: &str, name: &str) -> ChannelResponse {
    reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(token)
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    TsMessage,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

async fn connect_ws(base: &str, token: &str) -> (WsSink, WsStream) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

async fn send_ws(tx: &mut WsSink, msg: Value) {
    tx.send(TsMessage::Text(msg.to_string())).await.unwrap();
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

fn make_zone(zone_id: &str, channel_id: &str, creator: &str) -> VoiceZone {
    VoiceZone {
        zone_id: zone_id.to_string(),
        channel_id: channel_id.to_string(),
        name: "Arena".to_string(),
        coordinate_system: "2d".to_string(),
        attenuation: AttenuationConfig {
            model: "linear".to_string(),
            max_radius: 50.0,
            ref_dist: 1.0,
            rolloff: 1.0,
        },
        auth_mode: "any_channel_member".to_string(),
        creator_pubkey: creator.to_string(),
        session_id: None,
        positions: HashMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A zone inserted into AppState persists with all fields intact.
#[tokio::test]
async fn zone_inserted_into_state_is_retrievable() {
    let (_url, state, _guard) = start_hub().await;

    let creator = "aaaa".repeat(16); // 64 hex chars
    let zone = make_zone("z1", "ch1", &creator);
    state
        .voice_zones
        .write()
        .await
        .insert(("ch1".to_string(), "z1".to_string()), zone);

    let zones = state.voice_zones.read().await;
    let z = zones
        .get(&("ch1".to_string(), "z1".to_string()))
        .expect("zone must exist");
    assert_eq!(z.name, "Arena");
    assert_eq!(z.coordinate_system, "2d");
    assert_eq!(z.attenuation.model, "linear");
    assert_eq!(z.attenuation.max_radius, 50.0);
    assert_eq!(z.creator_pubkey, creator);
}

/// Removing a zone from state leaves no entry behind.
#[tokio::test]
async fn zone_destroy_removes_entry() {
    let (_url, state, _guard) = start_hub().await;

    let zone = make_zone("z2", "ch1", "creator");
    state
        .voice_zones
        .write()
        .await
        .insert(("ch1".to_string(), "z2".to_string()), zone);

    // Simulate destroy
    state
        .voice_zones
        .write()
        .await
        .remove(&("ch1".to_string(), "z2".to_string()));

    let zones = state.voice_zones.read().await;
    assert!(
        !zones.contains_key(&("ch1".to_string(), "z2".to_string())),
        "zone must be absent after destroy"
    );
}

/// Position data stored in a zone is keyed by pubkey and holds the coordinate vec.
#[tokio::test]
async fn position_stored_and_retrieved_from_zone() {
    let (_url, state, _guard) = start_hub().await;

    let creator = "bbbb".repeat(16);
    let mut zone = make_zone("z3", "ch1", &creator);
    zone.positions
        .insert(creator.clone(), vec![10.0_f64, 20.0_f64]);
    state
        .voice_zones
        .write()
        .await
        .insert(("ch1".to_string(), "z3".to_string()), zone);

    let zones = state.voice_zones.read().await;
    let z = zones.get(&("ch1".to_string(), "z3".to_string())).unwrap();
    let pos = z.positions.get(&creator).expect("position must be set");
    assert_eq!(*pos, vec![10.0_f64, 20.0_f64]);
}

/// When a zone exists in state before a voice join, the hub pushes a
/// `voice_zone_state` snapshot to the joining client over WS.
#[tokio::test]
async fn voice_join_delivers_zone_snapshot() {
    let (base, state, _guard) = start_hub().await;

    // Authenticate and create a channel via HTTP.
    let identity = Identity::generate();
    let token = authenticate_http(&base, &identity).await;
    let ch = create_channel(&base, &token, "zone-test").await;

    // Pre-insert a zone for that channel.
    let zone = make_zone("snap-zone", &ch.id, &identity.public_key_hex());
    state
        .voice_zones
        .write()
        .await
        .insert((ch.id.clone(), "snap-zone".to_string()), zone);

    // Connect WS and send VoiceJoin.
    let (mut ws_tx, mut ws_rx) = connect_ws(&base, &token).await;
    send_ws(
        &mut ws_tx,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;

    // Read messages until voice_zone_state arrives (or timeout).
    let snapshot: Value = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws_rx.next().await {
                Some(Ok(TsMessage::Text(raw))) => {
                    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                    if v.get("type").and_then(|t| t.as_str()) == Some("voice_zone_state") {
                        return v;
                    }
                }
                Some(Ok(_)) => continue,
                _ => panic!("WS stream ended before voice_zone_state"),
            }
        }
    })
    .await
    .expect("voice_zone_state snapshot not received within 5 s");

    let zones_arr = snapshot["zones"].as_array().expect("zones must be array");
    assert_eq!(zones_arr.len(), 1, "exactly one zone in snapshot");
    assert_eq!(zones_arr[0]["zone_id"], "snap-zone");
    assert_eq!(zones_arr[0]["name"], "Arena");
}
