//! Hub-enforced whisper opt-out (whisper.md): a user can refuse to RECEIVE
//! whispers. Opting out never blocks the user from *starting* their own
//! whisper -- it only removes them from the resolved target set of anyone
//! else's whisper (`resolve_whisper_target_pubkeys` in
//! crates/hub/src/routes/ws/voice.rs).
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
// Harness — mirrors whisper_role_target_flow.rs so real WS upgrades work
// over a real TCP listener.
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "whisper-optout-test".to_string(),
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

/// Asserts that `want` does NOT arrive on `rx` within a short grace window.
/// Any other frame type is drained and ignored.
async fn assert_not_received(rx: &mut WsStream, want: &str) {
    let outcome = tokio::time::timeout(std::time::Duration::from_millis(800), async {
        loop {
            match rx.next().await {
                Some(Ok(TsMessage::Text(raw))) => {
                    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                    if v.get("type").and_then(|t| t.as_str()) == Some(want) {
                        return v;
                    }
                }
                Some(Ok(_)) => continue,
                other => panic!("WS stream ended unexpectedly: {other:?}"),
            }
        }
    })
    .await;
    assert!(
        outcome.is_err(),
        "expected no `{want}` within the grace window, but got one: {outcome:?}"
    );
}

async fn join_voice(tx: &mut WsSink, rx: &mut WsStream, channel_id: &str) {
    send_ws(tx, json!({ "type": "subscribe", "channel_id": channel_id })).await;
    send_ws(
        tx,
        json!({ "type": "voice_join", "channel_id": channel_id, "udp_port": 0 }),
    )
    .await;
    wait_for(rx, "voice_joined").await;
}

/// Full lifecycle: B opts out -> unreachable as a user-type AND channel-type
/// whisper target, while a non-opted bystander C in the same channel still
/// receives it -> B opts back in mid-session and re-resolution (state-level;
/// `re_resolve_whisper_sessions` does not currently re-announce
/// `voice_whisper_started` on membership change for ANY trigger -- join,
/// leave, or opt-out -- so this asserts the resolved set, not a fresh WS
/// push) adds B back -> double opt-out/opt-in toggles are idempotent (no
/// panic, no duplicate bookkeeping).
#[tokio::test]
async fn whisper_optout_blocks_receiving_until_reenabled() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let ch = create_channel(&base, &owner_token, "whisper-optout-ch").await;

    let whisperer = Identity::generate();
    let whisperer_token = authenticate_http(&base, &whisperer).await;
    let whisperer_pk = whisperer.public_key_hex();

    let b = Identity::generate();
    let b_token = authenticate_http(&base, &b).await;
    let b_pk = b.public_key_hex();

    let c = Identity::generate();
    let c_token = authenticate_http(&base, &c).await;

    let (mut w_tx, mut w_rx) = connect_ws(&base, &whisperer_token).await;
    let (mut b_tx, mut b_rx) = connect_ws(&base, &b_token).await;
    let (mut c_tx, mut c_rx) = connect_ws(&base, &c_token).await;

    join_voice(&mut w_tx, &mut w_rx, &ch.id).await;
    join_voice(&mut b_tx, &mut b_rx, &ch.id).await;
    join_voice(&mut c_tx, &mut c_rx, &ch.id).await;

    // B opts out of receiving whispers.
    send_ws(
        &mut b_tx,
        json!({ "type": "voice_whisper_optout", "enabled": true }),
    )
    .await;
    // Give the hub a moment to process before racing the assertion below.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        state.whisper_optouts.read().await.contains(&b_pk),
        "B should be recorded as opted out"
    );

    // --- user-type target: whisperer targets B directly. ---
    send_ws(
        &mut w_tx,
        json!({
            "type": "voice_whisper_start",
            "targets": [{ "type": "user", "id": b_pk }],
        }),
    )
    .await;
    assert_not_received(&mut b_rx, "voice_whisper_started").await;
    let resolved = state
        .whisper_target_pubkeys
        .read()
        .await
        .get(&whisperer_pk)
        .cloned()
        .unwrap_or_default();
    assert!(
        !resolved.contains(&b_pk),
        "opted-out user should never be resolved as a whisper target"
    );

    // --- channel-type target: whisperer targets the channel both B and C
    // are in. C (not opted out) should receive it; B should not. ---
    send_ws(
        &mut w_tx,
        json!({
            "type": "voice_whisper_start",
            "targets": [{ "type": "channel", "id": ch.id }],
        }),
    )
    .await;
    let notif = wait_for(&mut c_rx, "voice_whisper_started").await;
    assert_eq!(notif["sender_pubkey"], whisperer_pk);
    assert_not_received(&mut b_rx, "voice_whisper_started").await;

    let resolved = state
        .whisper_target_pubkeys
        .read()
        .await
        .get(&whisperer_pk)
        .cloned()
        .unwrap_or_default();
    assert!(
        !resolved.contains(&b_pk),
        "opted-out B must stay out of the channel-target resolution"
    );
    assert!(
        resolved.contains(&c.public_key_hex()),
        "non-opted-out C must stay in the channel-target resolution"
    );

    // --- B opts back in mid-session: re-resolution should add them back
    // into the resolved target set immediately (no fresh voice_whisper_start
    // needed from the whisperer). ---
    send_ws(
        &mut b_tx,
        json!({ "type": "voice_whisper_optout", "enabled": false }),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(!state.whisper_optouts.read().await.contains(&b_pk));

    let resolved = state
        .whisper_target_pubkeys
        .read()
        .await
        .get(&whisperer_pk)
        .cloned()
        .unwrap_or_default();
    assert!(
        resolved.contains(&b_pk),
        "B should be back in the resolved target set after opting back in"
    );

    // --- Idempotency: repeating the same toggle must not panic and must
    // not leave stray duplicate bookkeeping (it's a HashSet, so this mostly
    // guards against a future switch to a counting structure). ---
    send_ws(
        &mut b_tx,
        json!({ "type": "voice_whisper_optout", "enabled": false }),
    )
    .await;
    send_ws(
        &mut b_tx,
        json!({ "type": "voice_whisper_optout", "enabled": true }),
    )
    .await;
    send_ws(
        &mut b_tx,
        json!({ "type": "voice_whisper_optout", "enabled": true }),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(
        state.whisper_optouts.read().await.len(),
        1,
        "double opt-out must not create duplicate entries"
    );
    assert!(state.whisper_optouts.read().await.contains(&b_pk));

    let _ = w_tx.send(TsMessage::Close(None)).await;
    let _ = b_tx.send(TsMessage::Close(None)).await;
    let _ = c_tx.send(TsMessage::Close(None)).await;
}

/// Live re-resolution diff (whisper.md "New WS envelopes"): once a whisper is
/// already running, a target opting out mid-session gets a targeted
/// `voice_whisper_stopped`, and opting back in gets a fresh
/// `voice_whisper_started` -- without the whisperer re-sending
/// `voice_whisper_start`. An unaffected bystander in the same target channel
/// gets neither push (no re-announce to the whole set on a partial change).
#[tokio::test]
async fn whisper_optout_midsession_pushes_started_stopped_diff() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let ch = create_channel(&base, &owner_token, "whisper-optout-diff-ch").await;

    let whisperer = Identity::generate();
    let whisperer_token = authenticate_http(&base, &whisperer).await;
    let whisperer_pk = whisperer.public_key_hex();

    let b = Identity::generate();
    let b_token = authenticate_http(&base, &b).await;

    let c = Identity::generate();
    let c_token = authenticate_http(&base, &c).await;

    let (mut w_tx, mut w_rx) = connect_ws(&base, &whisperer_token).await;
    let (mut b_tx, mut b_rx) = connect_ws(&base, &b_token).await;
    let (mut c_tx, mut c_rx) = connect_ws(&base, &c_token).await;

    join_voice(&mut w_tx, &mut w_rx, &ch.id).await;
    join_voice(&mut b_tx, &mut b_rx, &ch.id).await;
    join_voice(&mut c_tx, &mut c_rx, &ch.id).await;

    // Whisperer targets the whole channel: B and C both get started.
    send_ws(
        &mut w_tx,
        json!({
            "type": "voice_whisper_start",
            "targets": [{ "type": "channel", "id": ch.id }],
        }),
    )
    .await;
    let notif = wait_for(&mut b_rx, "voice_whisper_started").await;
    assert_eq!(notif["sender_pubkey"], whisperer_pk);
    let notif = wait_for(&mut c_rx, "voice_whisper_started").await;
    assert_eq!(notif["sender_pubkey"], whisperer_pk);

    // B opts out mid-session -> B alone gets voice_whisper_stopped; C gets
    // nothing (their membership in the target set didn't change).
    send_ws(
        &mut b_tx,
        json!({ "type": "voice_whisper_optout", "enabled": true }),
    )
    .await;
    let notif = wait_for(&mut b_rx, "voice_whisper_stopped").await;
    assert_eq!(notif["sender_pubkey"], whisperer_pk);
    assert_not_received(&mut c_rx, "voice_whisper_stopped").await;
    assert_not_received(&mut c_rx, "voice_whisper_started").await;

    // B opts back in -> B alone gets a fresh voice_whisper_started; C still
    // gets nothing new.
    send_ws(
        &mut b_tx,
        json!({ "type": "voice_whisper_optout", "enabled": false }),
    )
    .await;
    let notif = wait_for(&mut b_rx, "voice_whisper_started").await;
    assert_eq!(notif["sender_pubkey"], whisperer_pk);
    assert_not_received(&mut c_rx, "voice_whisper_started").await;
    assert_not_received(&mut c_rx, "voice_whisper_stopped").await;

    let _ = w_tx.send(TsMessage::Close(None)).await;
    let _ = b_tx.send(TsMessage::Close(None)).await;
    let _ = c_tx.send(TsMessage::Close(None)).await;
}
