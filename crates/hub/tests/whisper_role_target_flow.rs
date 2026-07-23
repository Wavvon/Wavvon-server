//! Regression test for the role-target whisper routing gap
//! (docs/docs/client-parity.md): a "role" whisper target was resolved only
//! into the UDP SocketAddr set, never into `whisper_target_pubkeys`, so a
//! role-targeted whisper never reached a WS (web) listener holding that
//! role. See `resolve_whisper_target_pubkeys` in
//! crates/hub/src/routes/ws/voice.rs.
use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::routes::role_models::RoleResponse;
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
        hub_name: "whisper-role-test".to_string(),
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

async fn create_role(base: &str, token: &str, name: &str) -> RoleResponse {
    reqwest::Client::new()
        .post(format!("{base}/roles"))
        .bearer_auth(token)
        .json(&json!({ "name": name, "permissions": [], "priority": 10 }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

async fn assign_role(base: &str, token: &str, pubkey: &str, role_id: &str) {
    let resp = reqwest::Client::new()
        .put(format!("{base}/users/{pubkey}/roles/{role_id}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "assign_role failed: {resp:?}");
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
/// after a 15s timeout.
async fn wait_for(rx: &mut WsStream, want: &str) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
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
    .unwrap_or_else(|_| panic!("`{want}` not received within 15s"))
}

/// Happy path: a member holding `role_id` is in voice, another whisperer
/// starts a whisper targeted at that role, and the role holder receives
/// `voice_whisper_started` over their WS connection -- proving the role was
/// resolved into the pubkey-keyed delivery set, not just the UDP addr set.
#[tokio::test]
async fn role_targeted_whisper_reaches_ws_role_holder() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let ch = create_channel(&base, &owner_token, "whisper-role-ch").await;

    let role = create_role(&base, &owner_token, "moderator").await;

    let whisperer = Identity::generate();
    let whisperer_token = authenticate_http(&base, &whisperer).await;

    let listener = Identity::generate();
    let listener_token = authenticate_http(&base, &listener).await;
    let listener_pk = listener.public_key_hex();
    assign_role(&base, &owner_token, &listener_pk, &role.id).await;

    let (mut w_tx, mut w_rx) = connect_ws(&base, &whisperer_token).await;
    let (mut l_tx, mut l_rx) = connect_ws(&base, &listener_token).await;

    // Both subscribe to the channel (WhisperSignal delivery is channel-gated
    // before the to_pubkeys filter narrows it further) and join voice there.
    for (tx, rx) in [(&mut w_tx, &mut w_rx), (&mut l_tx, &mut l_rx)] {
        send_ws(tx, json!({ "type": "subscribe", "channel_id": ch.id })).await;
        send_ws(
            tx,
            json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
        )
        .await;
        wait_for(rx, "voice_joined").await;
    }

    // Whisperer opens a whisper session targeted at the role.
    send_ws(
        &mut w_tx,
        json!({
            "type": "voice_whisper_start",
            "targets": [{ "type": "role", "id": role.id }],
        }),
    )
    .await;

    // The role holder should see the whisper-started notification.
    let notif = wait_for(&mut l_rx, "voice_whisper_started").await;
    assert_eq!(notif["sender_pubkey"], whisperer.public_key_hex());

    // And the resolved pubkey set should contain the role holder directly.
    let sender_pk = whisperer.public_key_hex();
    let resolved = state
        .whisper_target_pubkeys
        .read()
        .await
        .get(&sender_pk)
        .cloned()
        .unwrap_or_default();
    assert!(
        resolved.contains(&listener_pk),
        "role member should be resolved into whisper_target_pubkeys"
    );

    let _ = w_tx.send(TsMessage::Close(None)).await;
    let _ = l_tx.send(TsMessage::Close(None)).await;
}
