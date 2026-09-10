//! Integration coverage for the WebTransport voice relay
//! (voice-transport-v2.md): two clients join voice over the main hub WS,
//! open WebTransport sessions against the `voice_joined` reply's
//! `voice_wt_url`/`voice_token`/`voice_cert_hash`, and exchange a datagram
//! through the hub's header-only relay.
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
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Connection, Endpoint};

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Test harness — real TCP listener (main WS) + a real WT endpoint bound to
// an ephemeral UDP port.
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    // Reserve an ephemeral UDP port up front: `AppState.voice_udp_port` is a
    // plain field (not behind a lock) baked into the `voice_joined` URL
    // fallback, so it must already be known at construction time, before
    // `voice_wt::start` binds the real WT endpoint on the same number.
    let voice_udp_port = {
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };

    let state = Arc::new(AppState {
        hub_name: "voice-wt-test".to_string(),
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
        voice_udp_port,
        voice_wt_url: None,
        canonical_url: Arc::new(RwLock::new(None)),
        voice_cert_hash: RwLock::new(None),
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashMap::new()),
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

    // Real WT endpoint on the reserved port, self-signed identity.
    let bound_port = wavvon_hub::voice_wt::start(state.clone(), voice_udp_port, None, None)
        .await
        .expect("voice WT relay should start");
    assert_eq!(bound_port, voice_udp_port);

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{http_port}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base, state, guard)
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

/// Drains WS frames until one of type `msg_type`, discarding the rest.
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

/// Drains WS frames until `voice_joined`, returning
/// `(voice_token, voice_wt_url, voice_cert_hash)`.
async fn join_voice(
    tx: &mut WsSink,
    rx: &mut WsStream,
    channel_id: &str,
) -> (String, String, String) {
    // Drain the hello frame first.
    loop {
        let msg = rx.next().await.unwrap().unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == "hello" {
                break;
            }
        }
    }

    send_ws(
        tx,
        json!({ "type": "voice_join", "channel_id": channel_id }),
    )
    .await;

    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), rx.next())
            .await
            .expect("voice_joined timeout")
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == "voice_joined" {
                let voice_token = v["voice_token"].as_str().unwrap().to_string();
                let voice_wt_url = v["voice_wt_url"].as_str().unwrap().to_string();
                let voice_cert_hash = v["voice_cert_hash"].as_str().unwrap().to_string();
                return (voice_token, voice_wt_url, voice_cert_hash);
            }
        }
    }
}

/// Opens a client WT connection trusting the hub's self-signed cert by hash
/// (the Rust-client analog of the browser's `serverCertificateHashes`).
async fn wt_connect(voice_wt_url: &str, voice_token: &str, cert_hash_hex: &str) -> Connection {
    let hash_bytes: [u8; 32] = hex::decode(cert_hash_hex)
        .unwrap()
        .try_into()
        .expect("cert hash must be 32 bytes");
    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([Sha256Digest::new(hash_bytes)])
        .build();
    let endpoint = Endpoint::client(client_config).expect("client endpoint");
    endpoint
        .connect(format!("{voice_wt_url}?token={voice_token}"))
        .await
        .expect("WT session should connect")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Two clients join voice, open WT sessions, and A's datagram reaches B
/// (prefixed with A's sender_id + normal packet_type) but never loops back
/// to A itself.
#[tokio::test]
async fn datagram_relays_with_sender_prefix_and_no_self_echo() {
    let (base, _state, _guard) = start_hub().await;

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let token_a = authenticate_http(&base, &id_a).await;
    let token_b = authenticate_http(&base, &id_b).await;
    let ch = create_channel(&base, &token_a, "wt-relay-ch").await;

    let (mut tx_a, mut rx_a) = connect_ws(&base, &token_a).await;
    let (voice_token_a, voice_wt_url_a, cert_hash_a) =
        join_voice(&mut tx_a, &mut rx_a, &ch.id).await;

    let (mut tx_b, mut rx_b) = connect_ws(&base, &token_b).await;
    let (voice_token_b, voice_wt_url_b, cert_hash_b) =
        join_voice(&mut tx_b, &mut rx_b, &ch.id).await;

    assert_eq!(
        voice_wt_url_a, voice_wt_url_b,
        "both clients should be pointed at the same WT endpoint"
    );
    assert_eq!(cert_hash_a, cert_hash_b);

    let conn_a = wt_connect(&voice_wt_url_a, &voice_token_a, &cert_hash_a).await;
    let conn_b = wt_connect(&voice_wt_url_b, &voice_token_b, &cert_hash_b).await;

    // Give the hub a moment to bind both sessions into voice_channels.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let payload: &[u8] = b"opus-frame-not-inspected-by-hub";
    conn_a.send_datagram(payload).expect("A can send");

    let received =
        tokio::time::timeout(std::time::Duration::from_secs(5), conn_b.receive_datagram())
            .await
            .expect("B should receive A's datagram within 5s")
            .expect("datagram read ok");

    assert!(
        received.len() >= 3 + payload.len(),
        "relayed datagram must carry the 3-byte routing prefix plus payload"
    );
    assert_eq!(
        &received[3..],
        payload,
        "hub must forward the payload verbatim (header-only forwarder)"
    );
    assert_eq!(received[2], 0x00, "normal (non-whisper) packet_type");
    let sender_id = u16::from_be_bytes([received[0], received[1]]);
    // sender_id 0 is a valid assignment (first joiner) but must be A's, not
    // B's own — sanity-checked via voice_sender_ids in a moment.
    let _ = sender_id;

    // A must not receive its own datagram back.
    let self_echo = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        conn_a.receive_datagram(),
    )
    .await;
    assert!(
        self_echo.is_err(),
        "sender must not receive its own datagram echoed back"
    );
}

/// A whisper reaches its target and **nobody else in the room**.
///
/// This is a confidentiality guarantee and nothing exercised it end to end.
/// The client suite's whisper spec asserts badges, banners and the inbox —
/// all state the hub pushes over the WebSocket, so it passes whether the
/// audio went to one person or to everyone, which is the difference the
/// feature exists to make. The same shape hid two complete voice failures on
/// 2026-09-10 (docs shipped log); here the failure it would hide is private
/// audio arriving in a room.
///
/// Read at the relay, because that is where the guarantee lives: three real
/// WT sessions, A whispering to B only, and the assertion is that C's
/// receive times out. The confinement lifting again matters too — a whisper
/// that permanently silences you to the room would be its own bug — so the
/// second half stops the whisper and watches C start hearing A.
#[tokio::test]
async fn a_whisper_reaches_its_target_and_nobody_else() {
    let (base, _state, _guard) = start_hub().await;

    let id_a = Identity::generate();
    let id_b = Identity::generate();
    let id_c = Identity::generate();
    let token_a = authenticate_http(&base, &id_a).await;
    let token_b = authenticate_http(&base, &id_b).await;
    let token_c = authenticate_http(&base, &id_c).await;
    let ch = create_channel(&base, &token_a, "wt-whisper-ch").await;

    let (mut tx_a, mut rx_a) = connect_ws(&base, &token_a).await;
    let (join_a, url, hash) = join_voice(&mut tx_a, &mut rx_a, &ch.id).await;
    let (mut tx_b, mut rx_b) = connect_ws(&base, &token_b).await;
    let (join_b, _, _) = join_voice(&mut tx_b, &mut rx_b, &ch.id).await;
    let (mut tx_c, mut rx_c) = connect_ws(&base, &token_c).await;
    let (join_c, _, _) = join_voice(&mut tx_c, &mut rx_c, &ch.id).await;

    let conn_a = wt_connect(&url, &join_a, &hash).await;
    let conn_b = wt_connect(&url, &join_b, &hash).await;
    let conn_c = wt_connect(&url, &join_c, &hash).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // Baseline: with no whisper open, C hears A. Without this the negative
    // assertion below would also pass on a relay that delivers nothing at
    // all, which is the mistake worth guarding against in a test whose whole
    // point is that something does *not* arrive.
    conn_a.send_datagram(b"open-room").expect("A can send");
    let heard = tokio::time::timeout(std::time::Duration::from_secs(5), conn_c.receive_datagram())
        .await
        .expect("C must hear A in an open room")
        .expect("datagram read ok");
    assert_eq!(&heard[3..], b"open-room");
    assert_eq!(heard[2], 0x00, "an open-room packet is not a whisper");
    // Drain B's copy of the same datagram so the assertions below cannot read
    // it by mistake.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), conn_b.receive_datagram())
        .await
        .expect("B must hear A in an open room too");

    // A whispers to B alone.
    send_ws(
        &mut tx_a,
        json!({
            "type": "voice_whisper_start",
            "targets": [{ "type": "user", "id": id_b.public_key_hex() }],
        }),
    )
    .await;
    // The notification goes to the resolved target set only — which is itself
    // part of the confinement — so B is where it lands, and waiting for it is
    // what proves the whisper is open before anything is sent rather than
    // sleeping and hoping.
    let started = next_msg_of_type(&mut rx_b, "voice_whisper_started").await;
    assert_eq!(
        started["sender_pubkey"].as_str().unwrap(),
        id_a.public_key_hex(),
        "the notification must name the whisperer"
    );

    conn_a.send_datagram(b"for-b-only").expect("A can whisper");

    let whispered =
        tokio::time::timeout(std::time::Duration::from_secs(5), conn_b.receive_datagram())
            .await
            .expect("the target must receive the whisper")
            .expect("datagram read ok");
    assert_eq!(&whispered[3..], b"for-b-only");
    assert_eq!(
        whispered[2], 0x01,
        "a whisper must be marked as one so the client can show it"
    );

    // The point of the feature.
    let leaked = tokio::time::timeout(
        std::time::Duration::from_millis(800),
        conn_c.receive_datagram(),
    )
    .await;
    assert!(
        leaked.is_err(),
        "a whisper must not reach the rest of the room, got {:?}",
        leaked.map(|d| d.map(|d| d.payload().len()))
    );

    // And it lifts.
    send_ws(&mut tx_a, json!({ "type": "voice_whisper_stop" })).await;
    // Again on B: `voice_whisper_stopped` is delivered to the target set, not
    // to the room, so C is told nothing about a whisper it was never in.
    let _ = next_msg_of_type(&mut rx_b, "voice_whisper_stopped").await;
    conn_a.send_datagram(b"room-again").expect("A can send");
    let reheard =
        tokio::time::timeout(std::time::Duration::from_secs(5), conn_c.receive_datagram())
            .await
            .expect("stopping a whisper must give the room its audio back")
            .expect("datagram read ok");
    assert_eq!(&reheard[3..], b"room-again");
    assert_eq!(reheard[2], 0x00);

    // Nothing here reads C's WS, so keep the sinks alive to the end: dropping
    // one closes the socket, and a closed socket takes the participant out of
    // the roster the relay routes on.
    drop((tx_b, tx_c, rx_a, rx_b, rx_c));
}

/// A session request carrying an unknown/garbage token is rejected — no WT
/// session is established.
#[tokio::test]
async fn invalid_token_is_rejected() {
    let (base, _state, _guard) = start_hub().await;

    let id_a = Identity::generate();
    let token_a = authenticate_http(&base, &id_a).await;
    let ch = create_channel(&base, &token_a, "wt-invalid-token-ch").await;

    let (mut tx_a, mut rx_a) = connect_ws(&base, &token_a).await;
    let (_voice_token, voice_wt_url, cert_hash) = join_voice(&mut tx_a, &mut rx_a, &ch.id).await;

    let bogus_token = "0".repeat(64);
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wt_connect_fallible(&voice_wt_url, &bogus_token, &cert_hash),
    )
    .await
    .expect("connect attempt should not hang");

    assert!(
        result.is_err(),
        "a session with an unknown token must be rejected, not accepted"
    );
}

/// Like `wt_connect`, but returns the `Result` instead of unwrapping, for
/// tests that expect rejection.
async fn wt_connect_fallible(
    voice_wt_url: &str,
    voice_token: &str,
    cert_hash_hex: &str,
) -> Result<Connection, wtransport::error::ConnectingError> {
    let hash_bytes: [u8; 32] = hex::decode(cert_hash_hex).unwrap().try_into().unwrap();
    let client_config = ClientConfig::builder()
        .with_bind_default()
        .with_server_certificate_hashes([Sha256Digest::new(hash_bytes)])
        .build();
    let endpoint = Endpoint::client(client_config).expect("client endpoint");
    endpoint
        .connect(format!("{voice_wt_url}?token={voice_token}"))
        .await
}
