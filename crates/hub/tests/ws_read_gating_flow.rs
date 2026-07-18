//! H1 regression: explicit WS `Subscribe` to a channel the caller can't
//! effectively READ_MESSAGES must be rejected, not silently subscribed.
//! See docs/docs/security-audit-2026-07-04.md H1.

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

/// Boot a real TCP listener on a random port and return the base URL.
/// Mirrors `screen_share_flow.rs`'s `start_hub` -- a real socket is needed
/// because `tokio_tungstenite` speaks actual TCP, unlike `axum_test`.
async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "ws-gate-test".to_string(),
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
        online_users: RwLock::new(std::collections::HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(256).0,
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
        staging_voice_grants: tokio::sync::RwLock::new(std::collections::HashMap::new()),
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

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

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

/// Denies `permission` for `@everyone` on `channel_id` via the
/// channel-permission-overwrites admin route (§3.6).
async fn deny_everyone(base: &str, owner_token: &str, channel_id: &str, permission: &str) {
    let resp = reqwest::Client::new()
        .put(format!(
            "{base}/channels/{channel_id}/permissions/builtin-everyone"
        ))
        .bearer_auth(owner_token)
        .json(&json!({ "allow": [], "deny": [permission] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

async fn send_message(base: &str, token: &str, channel_id: &str, content: &str) {
    let resp = reqwest::Client::new()
        .post(format!("{base}/channels/{channel_id}/messages"))
        .bearer_auth(token)
        .json(&json!({ "content": content }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    TsMessage,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// Connect a WS client and return the split stream.
async fn connect_ws(base: &str, token: &str) -> (WsSink, WsStream) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

async fn send_text(tx: &mut WsSink, msg: Value) {
    tx.send(TsMessage::Text(msg.to_string())).await.unwrap();
}

/// Reads WS frames until one that isn't a connect-time housekeeping frame
/// (hello / presence) is found, or the timeout elapses.
async fn next_meaningful_frame(rx: &mut WsStream, timeout: std::time::Duration) -> Option<Value> {
    loop {
        let msg = match tokio::time::timeout(timeout, rx.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => return None,
        };
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            match v["type"].as_str() {
                Some("hello") | Some("member_online") | Some("member_offline") => continue,
                _ => return Some(v),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A member denied `read_messages` on a channel sends an explicit
/// `Subscribe` for it -- the hub must reject the subscribe (no channel
/// data leaks) rather than silently adding it to the connection's
/// subscribed set.
#[tokio::test]
async fn subscribe_to_denied_channel_is_rejected_and_no_events_leak() {
    let (base, _state, _guard) = start_hub().await;

    let owner_id = Identity::generate();
    let member_id = Identity::generate();
    let owner_token = authenticate_http(&base, &owner_id).await;
    let member_token = authenticate_http(&base, &member_id).await;

    let secret = create_channel(&base, &owner_token, "secret").await;
    deny_everyone(&base, &owner_token, &secret.id, "read_messages").await;

    let (mut member_tx, mut member_rx) = connect_ws(&base, &member_token).await;

    // Explicit Subscribe to the hidden channel.
    send_text(
        &mut member_tx,
        json!({ "type": "subscribe", "channel_id": secret.id }),
    )
    .await;

    // The hub must respond with an error frame, not silently subscribe.
    let frame = next_meaningful_frame(&mut member_rx, std::time::Duration::from_secs(3))
        .await
        .expect("expected an error frame for the denied subscribe");
    assert_eq!(frame["type"], "error");

    // Now the owner (admin) posts a message into the hidden channel. If the
    // Subscribe had gone through, the member would receive a `message`
    // event for it. It must not arrive within a generous timeout.
    send_message(&base, &owner_token, &secret.id, "should not leak").await;

    let leaked = next_meaningful_frame(&mut member_rx, std::time::Duration::from_secs(2)).await;
    assert!(
        leaked.is_none(),
        "denied Subscribe must not receive channel events, got: {leaked:?}"
    );
}

/// Sanity check: a legitimate Subscribe to a readable channel still works
/// and delivers events (guards against over-tightening the gate).
#[tokio::test]
async fn subscribe_to_readable_channel_still_delivers_events() {
    let (base, _state, _guard) = start_hub().await;

    let owner_id = Identity::generate();
    let member_id = Identity::generate();
    let owner_token = authenticate_http(&base, &owner_id).await;
    let member_token = authenticate_http(&base, &member_id).await;

    let open = create_channel(&base, &owner_token, "open").await;

    let (mut member_tx, mut member_rx) = connect_ws(&base, &member_token).await;
    send_text(
        &mut member_tx,
        json!({ "type": "subscribe", "channel_id": open.id }),
    )
    .await;

    send_message(&base, &owner_token, &open.id, "hello everyone").await;

    let frame = next_meaningful_frame(&mut member_rx, std::time::Duration::from_secs(3))
        .await
        .expect("expected the chat message to be delivered");
    assert_eq!(frame["type"], "message");
    assert_eq!(frame["channel_id"], open.id);
}
