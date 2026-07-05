/// Integration tests for V4 voice encryption key distribution.
///
/// The hub acts as a transparent relay for AES sender-key bundles:
/// - `VoiceKeyOffer` from one client is forwarded as `VoiceKeyReceived` to named recipients.
/// - On voice join the hub sends `VoiceKeyRequest` to existing participants so they
///   can forward their keys to the new joiner.
///
/// The hub never inspects ciphertext.  No actual AES-GCM operations are performed here.
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
// Test harness
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "voice-enc-test".to_string(),
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
    tx.send(TsMessage::Text(msg.to_string().into()))
        .await
        .unwrap();
}

/// Wait for a WS message with the given `type` field, discarding others.
/// Panics if the timeout (5 s) is exceeded.
async fn next_msg_of_type(rx: &mut WsStream, msg_type: &str) -> Value {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match rx.next().await {
                Some(Ok(TsMessage::Text(raw))) => {
                    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                    if v.get("type").and_then(|t| t.as_str()) == Some(msg_type) {
                        return v;
                    }
                }
                Some(Ok(_)) => continue,
                _ => panic!("WS stream closed before receiving {msg_type}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{msg_type} not received within 5 s"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A sends a VoiceKeyOffer bundle for B.  Verify B's WS receives
/// `voice_key_received` with the correct `from_pubkey`.
#[tokio::test]
async fn key_offer_routed_to_recipient() {
    let (base, _state, _guard) = start_hub().await;

    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let token_a = authenticate_http(&base, &id_a).await;
    let token_b = authenticate_http(&base, &id_b).await;

    let ch = create_channel(&base, &token_a, "enc-ch1").await;

    // Connect both users.
    let (mut tx_a, _rx_a) = connect_ws(&base, &token_a).await;
    let (mut tx_b, mut rx_b) = connect_ws(&base, &token_b).await;

    // Both join voice.
    send_ws(
        &mut tx_a,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    send_ws(
        &mut tx_b,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;

    // A sends a key bundle for B.
    send_ws(
        &mut tx_a,
        json!({
            "type": "voice_key_offer",
            "channel_id": ch.id,
            "bundles": [{
                "recipient_pubkey": id_b.public_key_hex(),
                "ciphertext_hex": "deadbeef",
                "nonce_hex": "cafebabe"
            }]
        }),
    )
    .await;

    // B should receive voice_key_received.
    let msg = next_msg_of_type(&mut rx_b, "voice_key_received").await;

    assert_eq!(
        msg["from_pubkey"].as_str().unwrap(),
        id_a.public_key_hex(),
        "from_pubkey must match A's public key"
    );
    assert_eq!(
        msg["ciphertext_hex"].as_str().unwrap(),
        "deadbeef",
        "ciphertext must be forwarded verbatim"
    );
    assert_eq!(
        msg["nonce_hex"].as_str().unwrap(),
        "cafebabe",
        "nonce must be forwarded verbatim"
    );
    assert_eq!(msg["channel_id"].as_str().unwrap(), ch.id);
}

/// When B joins after A is already in voice, A should receive a
/// `voice_key_request` carrying B's pubkey and sender_id.
#[tokio::test]
async fn voice_join_sends_key_request_to_existing_participants() {
    let (base, _state, _guard) = start_hub().await;

    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let token_a = authenticate_http(&base, &id_a).await;
    let token_b = authenticate_http(&base, &id_b).await;

    let ch = create_channel(&base, &token_a, "enc-ch2").await;

    // A joins first and starts listening.
    let (mut tx_a, mut rx_a) = connect_ws(&base, &token_a).await;
    send_ws(
        &mut tx_a,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    // Consume voice_joined for A so we don't pick it up as a key_request.
    next_msg_of_type(&mut rx_a, "voice_joined").await;

    // B connects and joins voice.
    let (mut tx_b, _rx_b) = connect_ws(&base, &token_b).await;
    send_ws(
        &mut tx_b,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;

    // A's connection should receive voice_key_request.
    let msg = next_msg_of_type(&mut rx_a, "voice_key_request").await;

    assert_eq!(
        msg["new_pubkey"].as_str().unwrap(),
        id_b.public_key_hex(),
        "new_pubkey must be B's public key"
    );
    assert_eq!(msg["channel_id"].as_str().unwrap(), ch.id);
}

/// Sending a VoiceKeyOffer for an unknown recipient must not return an error
/// and must not crash the handler.
#[tokio::test]
async fn key_offer_unknown_recipient_is_silently_dropped() {
    let (base, _state, _guard) = start_hub().await;

    let id_a = Identity::generate();
    let token_a = authenticate_http(&base, &id_a).await;
    let ch = create_channel(&base, &token_a, "enc-ch3").await;

    let (mut tx_a, mut rx_a) = connect_ws(&base, &token_a).await;
    send_ws(
        &mut tx_a,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    next_msg_of_type(&mut rx_a, "voice_joined").await;

    // Send a bundle for a pubkey that has no WS connection.
    let unknown_pk = "0".repeat(64);
    send_ws(
        &mut tx_a,
        json!({
            "type": "voice_key_offer",
            "channel_id": ch.id,
            "bundles": [{
                "recipient_pubkey": unknown_pk,
                "ciphertext_hex": "aabbcc",
                "nonce_hex": "112233"
            }]
        }),
    )
    .await;

    // The connection must remain alive — we can still receive voice_joined
    // (already consumed) so we just verify no error arrives within 1 s.
    let no_error = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        loop {
            match rx_a.next().await {
                Some(Ok(TsMessage::Text(raw))) => {
                    let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                    if v.get("type").and_then(|t| t.as_str()) == Some("error") {
                        panic!("unexpected error from hub: {v}");
                    }
                }
                _ => break,
            }
        }
    })
    .await;

    // Timeout is expected (no messages) — that is the success case.
    assert!(
        no_error.is_err(),
        "expected timeout (no messages), not a hub error"
    );
}

/// After A voice-joins and B sends a VoiceKeyOffer for A, the `voice_key_received`
/// delivered to A must carry a non-zero `from_sender_id` matching B's assigned ID.
#[tokio::test]
async fn sender_id_present_in_key_received() {
    let (base, state, _guard) = start_hub().await;

    let id_a = Identity::generate();
    let id_b = Identity::generate();

    let token_a = authenticate_http(&base, &id_a).await;
    let token_b = authenticate_http(&base, &id_b).await;

    let ch = create_channel(&base, &token_a, "enc-ch4").await;

    // A joins first.
    let (mut tx_a, mut rx_a) = connect_ws(&base, &token_a).await;
    send_ws(
        &mut tx_a,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    next_msg_of_type(&mut rx_a, "voice_joined").await;

    // B joins second.
    let (mut tx_b, _rx_b) = connect_ws(&base, &token_b).await;
    send_ws(
        &mut tx_b,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;

    // Give the hub time to process B's join before we query sender_id.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Read B's assigned sender_id from state.
    let b_sender_id = state
        .voice_sender_ids
        .read()
        .await
        .get(&ch.id)
        .and_then(|m| m.get(&id_b.public_key_hex()))
        .copied()
        .expect("B must have a sender_id after voice join");

    // B sends a key bundle for A.
    send_ws(
        &mut tx_b,
        json!({
            "type": "voice_key_offer",
            "channel_id": ch.id,
            "bundles": [{
                "recipient_pubkey": id_a.public_key_hex(),
                "ciphertext_hex": "11223344",
                "nonce_hex": "aabbccdd"
            }]
        }),
    )
    .await;

    // A receives voice_key_received.
    let msg = next_msg_of_type(&mut rx_a, "voice_key_received").await;

    let received_sender_id = msg["from_sender_id"]
        .as_u64()
        .expect("from_sender_id must be a number") as u16;

    assert_eq!(
        received_sender_id, b_sender_id,
        "from_sender_id in voice_key_received must match B's assigned sender_id"
    );
}
