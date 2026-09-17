//! Regression tests: a WS connection's DM-membership set (`my_conversations`)
//! is loaded once at connect, so it must be kept live from `dm_member_changed`
//! events — otherwise a conversation created *after* a client connected is
//! dead air (every `dm` frame for it dropped) until that client reconnects.
//! Creating a conversation must also announce itself via `dm_member_changed`.
use std::collections::HashMap;
use std::sync::Arc;

use futures_util::StreamExt;
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

/// Boot a real TCP listener on a random port -- a real socket is needed
/// because `tokio_tungstenite` speaks actual TCP, unlike `axum_test`.
/// Mirrors `hub_updated_broadcast_flow.rs`'s `start_hub`.
async fn start_hub() -> (String, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "dm-live-membership-test".to_string(),
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
        bot_sessions: RwLock::new(HashMap::new()),
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

    let app = server::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    (url, guard)
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

type WsRx = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

async fn connect_ws(base: &str, token: &str) -> WsRx {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let (_tx, rx) = ws.split();
    rx
}

async fn next_frame_of_type(
    rx: &mut WsRx,
    want: &str,
    timeout: std::time::Duration,
) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let msg = match tokio::time::timeout(remaining, rx.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => return None,
        };
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == want {
                return Some(v);
            }
        }
    }
}

/// Both members connected BEFORE the conversation exists: creating it must
/// push `dm_member_changed` to the other member, and a message sent right
/// after must reach them as a `dm` frame over the same (never reconnected)
/// connection.
#[tokio::test]
async fn conversation_created_after_connect_delivers_live() {
    let (base, _guard) = start_hub().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate_http(&base, &alice).await;
    let bob_token = authenticate_http(&base, &bob).await;

    let mut bob_rx = connect_ws(&base, &bob_token).await;
    // Drain any initial frame(s) before triggering anything.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), bob_rx.next()).await;

    let client = reqwest::Client::new();

    // Alice creates the conversation while Bob is already connected.
    let conv: Value = client
        .post(format!("{base}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let conv_id = conv["id"].as_str().unwrap().to_string();

    // Bob's live connection learns about the new conversation.
    let member_frame = next_frame_of_type(
        &mut bob_rx,
        "dm_member_changed",
        std::time::Duration::from_secs(15),
    )
    .await
    .expect("expected dm_member_changed after conversation create");
    assert_eq!(member_frame["conversation_id"], conv_id.as_str());

    // A message sent immediately after must reach Bob without a reconnect —
    // this is the regression: the connect-time membership snapshot dropped it.
    let resp = client
        .post(format!("{base}/conversations/{conv_id}/messages"))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": "hello from alice" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "send DM failed: {resp:?}");

    let dm_frame = next_frame_of_type(&mut bob_rx, "dm", std::time::Duration::from_secs(15))
        .await
        .expect("expected the dm frame on the pre-existing connection");
    assert_eq!(dm_frame["conversation_id"], conv_id.as_str());
    assert_eq!(dm_frame["content"], "hello from alice");
}
