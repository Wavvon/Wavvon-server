/// Integration tests for the AFK channel (afk-channel): the hub-level
/// `afk_channel_id` / `afk_timeout_secs` settings and the `afk_worker` sweep
/// that pushes idle voice participants a `voice_move` into the AFK channel.
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
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Harness — mirrors voice_move_flow.rs so real WS upgrades work over a real
// TCP listener.
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "afk-test".to_string(),
        hub_identity: Identity::generate(),
        db,
        db_read: None,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        cert_portfolio_cache: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_last_active: RwLock::new(HashMap::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_wt_url: None,
        canonical_url: Arc::new(RwLock::new(None)),
        voice_cert_hash: RwLock::new(None),
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        app_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(RwLock::new(0)),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_target_defs: RwLock::new(HashMap::new()),
        whisper_optouts: RwLock::new(std::collections::HashSet::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        voice_outbound_loss: RwLock::new(HashMap::new()),
        staging_voice_grants: RwLock::new(std::collections::HashMap::new()),
        voice_talk_blocked: Default::default(),
        voice_pending_binds: RwLock::new(HashMap::new()),
        ws_key_senders: RwLock::new(HashMap::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(HashMap::new()),
        search: Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        apps_allow_camera: false,
        http_video_stream_budget: 2,
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

async fn patch_hub(base: &str, token: &str, body: Value) -> reqwest::Response {
    reqwest::Client::new()
        .patch(format!("{base}/hub"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn get_settings(base: &str, token: &str) -> Value {
    reqwest::Client::new()
        .get(format!("{base}/hub/settings"))
        .bearer_auth(token)
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

/// Reads WS frames from `rx` until one of type `want` arrives, or panics
/// after a 5s timeout.
async fn wait_for(rx: &mut WsStream, want: &str) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match rx.next().await {
                Some(Ok(TsMessage::Text(raw))) => {
                    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                    if v.get("type").and_then(|t| t.as_str()) == Some(want) {
                        return v;
                    }
                }
                Some(Ok(_)) => continue,
                other => panic!("WS stream ended before `{want}` arrived: {other:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("`{want}` not received within 5s"))
}

/// Asserts no frame of type `unwanted` arrives within a short grace window.
async fn assert_not_received(rx: &mut WsStream, unwanted: &str) {
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        loop {
            match rx.next().await {
                Some(Ok(TsMessage::Text(raw))) => {
                    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                    if v.get("type").and_then(|t| t.as_str()) == Some(unwanted) {
                        return v;
                    }
                }
                Some(Ok(_)) => continue,
                _ => return Value::Null,
            }
        }
    })
    .await;
    if let Ok(v) = result {
        if v != Value::Null {
            panic!("unexpected `{unwanted}` frame received: {v:?}");
        }
    }
}

/// Backdates a participant's activity stamp so the sweep sees them as idle.
async fn backdate_activity(state: &AppState, pubkey: &str, secs_ago: i64) {
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    state
        .voice_last_active
        .write()
        .await
        .insert(pubkey.to_string(), now - secs_ago);
}

// ---------------------------------------------------------------------------
// Settings surface
// ---------------------------------------------------------------------------

/// Happy path: an admin sets AFK channel + timeout via PATCH /hub, reads
/// them back from GET /hub/settings, and clears the channel with "".
#[tokio::test]
async fn admin_sets_reads_and_clears_afk_settings() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let token = authenticate_http(&base, &owner).await;
    let afk = create_channel(&base, &token, "afk-lounge").await;

    let resp = patch_hub(
        &base,
        &token,
        json!({ "afk_channel_id": afk.id, "afk_timeout_secs": 120 }),
    )
    .await;
    assert!(resp.status().is_success(), "patch failed: {resp:?}");

    let settings = get_settings(&base, &token).await;
    assert_eq!(settings["afk_channel_id"], afk.id);
    assert_eq!(settings["afk_timeout_secs"], 120);

    // Empty string clears the channel (disabling the sweep); the timeout
    // value survives independently.
    let resp = patch_hub(&base, &token, json!({ "afk_channel_id": "" })).await;
    assert!(resp.status().is_success());
    let settings = get_settings(&base, &token).await;
    assert!(settings["afk_channel_id"].is_null());
    assert_eq!(settings["afk_timeout_secs"], 120);
}

/// Rejections: a channel id that doesn't exist, and a sub-minimum timeout.
#[tokio::test]
async fn rejects_unknown_channel_and_too_short_timeout() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let token = authenticate_http(&base, &owner).await;

    let resp = patch_hub(
        &base,
        &token,
        json!({ "afk_channel_id": "no-such-channel" }),
    )
    .await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    let resp = patch_hub(&base, &token, json!({ "afk_timeout_secs": 30 })).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ---------------------------------------------------------------------------
// Sweep behavior
// ---------------------------------------------------------------------------

/// An idle participant gets the `voice_move` push into the AFK channel with
/// `auto: true`; an immediate second sweep does not re-push (the sweep
/// re-stamps the target, so a non-complying client is re-pushed only once
/// per timeout window).
#[tokio::test]
async fn sweep_moves_idle_participant_once_with_auto_true() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let lounge = create_channel(&base, &owner_token, "game-voice").await;
    let afk = create_channel(&base, &owner_token, "afk-lounge").await;
    patch_hub(
        &base,
        &owner_token,
        json!({ "afk_channel_id": afk.id, "afk_timeout_secs": 60 }),
    )
    .await;

    let idler = Identity::generate();
    let idler_token = authenticate_http(&base, &idler).await;
    let idler_pubkey = idler.public_key_hex();

    let mut idler_ws = connect_ws(&base, &idler_token).await;
    send_ws(
        &mut idler_ws.0,
        json!({ "type": "voice_join", "channel_id": lounge.id, "udp_port": 0 }),
    )
    .await;
    wait_for(&mut idler_ws.1, "voice_joined").await;

    backdate_activity(&state, &idler_pubkey, 120).await;
    wavvon_hub::afk_worker::run_sweep(&state).await;

    let push = wait_for(&mut idler_ws.1, "voice_move").await;
    assert_eq!(push["target_channel_id"], afk.id);
    assert_eq!(push["target_channel_name"], "afk-lounge");
    assert_eq!(push["source_channel_id"], lounge.id);
    assert_eq!(push["auto"], true);
    assert!(push["event_id"].is_null());

    // The sweep re-stamped the idler: an immediate second pass is silent.
    wavvon_hub::afk_worker::run_sweep(&state).await;
    assert_not_received(&mut idler_ws.1, "voice_move").await;
}

/// The sweep leaves alone: a recently-active participant, and a participant
/// already sitting (however idly) in the AFK channel itself.
#[tokio::test]
async fn sweep_skips_active_users_and_afk_channel_occupants() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let lounge = create_channel(&base, &owner_token, "game-voice").await;
    let afk = create_channel(&base, &owner_token, "afk-lounge").await;
    patch_hub(
        &base,
        &owner_token,
        json!({ "afk_channel_id": afk.id, "afk_timeout_secs": 60 }),
    )
    .await;

    // Active user in the lounge: joined just now, stamp is fresh.
    let active = Identity::generate();
    let active_token = authenticate_http(&base, &active).await;
    let mut active_ws = connect_ws(&base, &active_token).await;
    send_ws(
        &mut active_ws.0,
        json!({ "type": "voice_join", "channel_id": lounge.id, "udp_port": 0 }),
    )
    .await;
    wait_for(&mut active_ws.1, "voice_joined").await;

    // Long-idle user already parked in the AFK channel.
    let parked = Identity::generate();
    let parked_token = authenticate_http(&base, &parked).await;
    let parked_pubkey = parked.public_key_hex();
    let mut parked_ws = connect_ws(&base, &parked_token).await;
    send_ws(
        &mut parked_ws.0,
        json!({ "type": "voice_join", "channel_id": afk.id, "udp_port": 0 }),
    )
    .await;
    wait_for(&mut parked_ws.1, "voice_joined").await;
    backdate_activity(&state, &parked_pubkey, 3600).await;

    wavvon_hub::afk_worker::run_sweep(&state).await;

    assert_not_received(&mut active_ws.1, "voice_move").await;
    assert_not_received(&mut parked_ws.1, "voice_move").await;
}

/// A `voice_speaking` message refreshes the activity stamp, so a participant
/// who talked recently survives a sweep even after an earlier backdate.
#[tokio::test]
async fn speaking_refreshes_the_activity_stamp() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let lounge = create_channel(&base, &owner_token, "game-voice").await;
    let afk = create_channel(&base, &owner_token, "afk-lounge").await;
    patch_hub(
        &base,
        &owner_token,
        json!({ "afk_channel_id": afk.id, "afk_timeout_secs": 60 }),
    )
    .await;

    let talker = Identity::generate();
    let talker_token = authenticate_http(&base, &talker).await;
    let talker_pubkey = talker.public_key_hex();

    let mut talker_ws = connect_ws(&base, &talker_token).await;
    send_ws(
        &mut talker_ws.0,
        json!({ "type": "voice_join", "channel_id": lounge.id, "udp_port": 0 }),
    )
    .await;
    wait_for(&mut talker_ws.1, "voice_joined").await;

    backdate_activity(&state, &talker_pubkey, 120).await;
    send_ws(
        &mut talker_ws.0,
        json!({ "type": "voice_speaking", "channel_id": lounge.id, "speaking": true }),
    )
    .await;
    // The hub never echoes a speaking broadcast back to its sender, so poll
    // the stamp itself to know the hub processed the message before sweeping.
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let fresh = state
                .voice_last_active
                .read()
                .await
                .get(&talker_pubkey)
                .is_some_and(|last| now - last < 60);
            if fresh {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("voice_speaking never refreshed the activity stamp");

    wavvon_hub::afk_worker::run_sweep(&state).await;
    assert_not_received(&mut talker_ws.1, "voice_move").await;
}
