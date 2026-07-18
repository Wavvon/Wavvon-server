//! Security-hardening coverage for the `bot_app_join`-minted mini-app
//! session token (bot-mini-apps.md "Scoped session token"). Before this
//! fix, `handle_bot_app_join` (routes/ws/handlers/mini_app.rs) inserted a
//! plain `scope = 'member'` session row bound to the joining user's pubkey
//! — indistinguishable from that user's own full login, so a mini-app
//! webview holding it could call every REST route the user's roles
//! allowed, including admin and federation endpoints. This file asserts
//! the token is now genuinely scoped: WS access confined to the bound
//! channel, and REST access denied outright.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// Boot a real TCP listener on a random port and return the base URL.
/// Mirrors `ws_read_gating_flow.rs`'s `start_hub` — a real socket is needed
/// because `tokio_tungstenite` speaks actual TCP, unlike `axum_test`.
async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "mini-app-scope-test".to_string(),
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

async fn create_channel(base: &str, token: &str, name: &str) -> Value {
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

/// POST /admin/bots — registers a bot with a `mini_app_url`.
async fn create_mini_app_bot(base: &str, token: &str) -> Value {
    let resp = reqwest::Client::new()
        .post(format!("{base}/admin/bots"))
        .bearer_auth(token)
        .json(&json!({
            "display_name": "Gartic Bot",
            "mini_app_url": "https://gartic.example.com/wavvon",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "bot creation should succeed");
    resp.json().await.unwrap()
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    TsMessage,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

/// Connect a WS client and return the split stream. Returns `Err` if the
/// upgrade itself is rejected (used by the voice-ws rejection test).
async fn try_connect_ws(url: &str) -> Result<(WsSink, WsStream), ()> {
    match tokio_tungstenite::connect_async(url).await {
        Ok((ws, _)) => Ok(ws.split()),
        Err(_) => Err(()),
    }
}

async fn connect_ws(base: &str, token: &str) -> (WsSink, WsStream) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    try_connect_ws(&ws_url)
        .await
        .expect("ws upgrade to succeed")
}

async fn send_text(tx: &mut WsSink, msg: Value) {
    tx.send(TsMessage::Text(msg.to_string())).await.unwrap();
}

/// Reads WS frames until one that isn't connect-time housekeeping (hello /
/// presence) is found, or the timeout elapses.
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

/// Drives the full `bot_app_join` handshake over `member_token`'s own WS
/// connection and returns the minted `session_token`.
async fn join_mini_app(base: &str, member_token: &str, bot_id: &str, channel_id: &str) -> String {
    let (mut tx, mut rx) = connect_ws(base, member_token).await;
    send_text(
        &mut tx,
        json!({ "type": "bot_app_join", "bot_id": bot_id, "channel_id": channel_id }),
    )
    .await;
    let frame = next_meaningful_frame(&mut rx, std::time::Duration::from_secs(3))
        .await
        .expect("expected a bot_app_open reply");
    assert_eq!(frame["type"], "bot_app_open");
    frame["session_token"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The minted mini-app session token can open `/ws` and receives events for
/// its bound channel — the legitimate thing mini-apps need.
#[tokio::test]
async fn mini_app_token_can_join_ws_and_receive_bound_channel_events() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let member = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member_token = authenticate_http(&base, &member).await;

    let channel = create_channel(&base, &owner_token, "game-room").await;
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let bot = create_mini_app_bot(&base, &owner_token).await;
    let bot_id = bot["public_key"].as_str().unwrap().to_string();

    let session_token = join_mini_app(&base, &member_token, &bot_id, &channel_id).await;
    assert!(!session_token.is_empty());

    // The scoped token opens its own /ws connection successfully...
    let (_mini_tx, mut mini_rx) = connect_ws(&base, &session_token).await;

    // ...and receives a message posted to the bound channel.
    send_message(&base, &owner_token, &channel_id, "round 1 starting").await;
    let frame = next_meaningful_frame(&mut mini_rx, std::time::Duration::from_secs(3))
        .await
        .expect("mini-app session should receive events for its bound channel");
    assert_eq!(frame["type"], "message");
    assert_eq!(frame["channel_id"], channel_id);
}

/// The minted token does NOT see events from a channel other than the one
/// it's bound to, even though the underlying user can read both.
#[tokio::test]
async fn mini_app_token_does_not_leak_events_from_other_channels() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let member = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member_token = authenticate_http(&base, &member).await;

    let bound_channel = create_channel(&base, &owner_token, "game-room").await;
    let bound_channel_id = bound_channel["id"].as_str().unwrap().to_string();
    let other_channel = create_channel(&base, &owner_token, "general").await;
    let other_channel_id = other_channel["id"].as_str().unwrap().to_string();

    let bot = create_mini_app_bot(&base, &owner_token).await;
    let bot_id = bot["public_key"].as_str().unwrap().to_string();

    let session_token = join_mini_app(&base, &member_token, &bot_id, &bound_channel_id).await;

    let (_mini_tx, mut mini_rx) = connect_ws(&base, &session_token).await;

    // A message in the OTHER channel (which the underlying member can read)
    // must not reach the mini-app session.
    send_message(&base, &owner_token, &other_channel_id, "unrelated chatter").await;
    let leaked = next_meaningful_frame(&mut mini_rx, std::time::Duration::from_secs(2)).await;
    assert!(
        leaked.is_none(),
        "mini-app session must not see events outside its bound channel, got: {leaked:?}"
    );
}

/// The minted token is rejected by the voice-over-WS relay entirely — voice
/// was never part of the mini-app scope.
#[tokio::test]
async fn mini_app_token_cannot_join_voice_ws() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let member = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member_token = authenticate_http(&base, &member).await;

    let channel = create_channel(&base, &owner_token, "game-room").await;
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let bot = create_mini_app_bot(&base, &owner_token).await;
    let bot_id = bot["public_key"].as_str().unwrap().to_string();

    let session_token = join_mini_app(&base, &member_token, &bot_id, &channel_id).await;

    let voice_ws_url = format!(
        "{}/voice/ws?token={}&channel_id={}",
        base.replace("http://", "ws://"),
        session_token,
        channel_id
    );
    let result = try_connect_ws(&voice_ws_url).await;
    // The upgrade may nominally succeed at the HTTP layer but the server
    // task returns immediately without ever completing the voice handshake;
    // either an outright upgrade rejection or an immediate close is
    // acceptable — what must NOT happen is a live, usable voice session.
    if let Ok((_tx, mut rx)) = result {
        let frame = next_meaningful_frame(&mut rx, std::time::Duration::from_secs(2)).await;
        assert!(
            frame.is_none(),
            "mini-app-scoped token must not get a usable voice-ws session, got: {frame:?}"
        );
    }
}

/// The minted token cannot call an admin REST route.
#[tokio::test]
async fn mini_app_token_cannot_call_admin_route() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let member = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member_token = authenticate_http(&base, &member).await;

    let channel = create_channel(&base, &owner_token, "game-room").await;
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let bot = create_mini_app_bot(&base, &owner_token).await;
    let bot_id = bot["public_key"].as_str().unwrap().to_string();

    let session_token = join_mini_app(&base, &member_token, &bot_id, &channel_id).await;

    let resp = reqwest::Client::new()
        .get(format!("{base}/admin/bots"))
        .bearer_auth(&session_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

/// The minted token cannot call a normal REST route either — every
/// documented mini-app interaction rides `/ws`, so REST is fully off-limits
/// for this scope, not just the admin subset.
#[tokio::test]
async fn mini_app_token_cannot_post_messages_over_rest() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let member = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member_token = authenticate_http(&base, &member).await;

    let channel = create_channel(&base, &owner_token, "game-room").await;
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let bot = create_mini_app_bot(&base, &owner_token).await;
    let bot_id = bot["public_key"].as_str().unwrap().to_string();

    let session_token = join_mini_app(&base, &member_token, &bot_id, &channel_id).await;

    let resp = reqwest::Client::new()
        .post(format!("{base}/channels/{channel_id}/messages"))
        .bearer_auth(&session_token)
        .json(&json!({ "content": "should be rejected" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}

/// The minted token cannot call `/me` mutations either — the full-session
/// row this token replaces used to allow this; the scoped replacement must
/// not.
#[tokio::test]
async fn mini_app_token_cannot_patch_me() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let member = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member_token = authenticate_http(&base, &member).await;

    let channel = create_channel(&base, &owner_token, "game-room").await;
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let bot = create_mini_app_bot(&base, &owner_token).await;
    let bot_id = bot["public_key"].as_str().unwrap().to_string();

    let session_token = join_mini_app(&base, &member_token, &bot_id, &channel_id).await;

    let resp = reqwest::Client::new()
        .patch(format!("{base}/me"))
        .bearer_auth(&session_token)
        .json(&json!({ "display_name": "hijacked" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
}
