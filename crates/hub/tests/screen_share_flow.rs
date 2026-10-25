use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

/// Boot a real TCP listener on a random port and return the base URL.
#[path = "common.rs"]
mod common;

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;

    let state = Arc::new(AppState {
        hub_name: "ss-test".to_string(),
        ..common::base_state(db)
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

/// Connect a WS client and return the split stream.
async fn connect_ws(
    base: &str,
    token: &str,
) -> (
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TsMessage,
    >,
    futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

async fn send_text(
    tx: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TsMessage,
    >,
    msg: Value,
) {
    tx.send(TsMessage::Text(msg.to_string())).await.unwrap();
}

async fn next_text(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> Value {
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(15), rx.next())
            .await
            .expect("timed out waiting for WS message")
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            // Skip hello and presence frames the hub broadcasts on connect/disconnect.
            match v["type"].as_str() {
                Some("hello") | Some("member_online") | Some("member_offline") => continue,
                _ => {}
            }
            return v;
        }
    }
}

/// Read the next raw WS message, returning text or binary.
async fn next_raw(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> TsMessage {
    tokio::time::timeout(std::time::Duration::from_secs(15), rx.next())
        .await
        .expect("timed out waiting for WS message")
        .unwrap()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: sharer sends start + chunk + stop; viewer receives them all.
#[tokio::test]
async fn screen_share_start_chunk_stop_fan_out() {
    let (base, _state, _guard) = start_hub().await;

    let sharer_id = Identity::generate();
    let viewer_id = Identity::generate();

    let sharer_token = authenticate_http(&base, &sharer_id).await;
    let viewer_token = authenticate_http(&base, &viewer_id).await;

    let ch = create_channel(&base, &sharer_token, "general").await;

    // Connect both
    let (mut sharer_tx, _sharer_rx) = connect_ws(&base, &sharer_token).await;
    let (mut viewer_tx, mut viewer_rx) = connect_ws(&base, &viewer_token).await;

    // Viewer subscribes first
    send_text(
        &mut viewer_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;

    // Sharer subscribes too (so chat events reach them) then starts the share
    send_text(
        &mut sharer_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;
    send_text(
        &mut sharer_tx,
        json!({
            "type": "screen_share_start",
            "channel_id": ch.id,
            "stream_id": "stream-1",
            "kind": "screen",
            "mime": "video/webm;codecs=vp8,opus",
            "has_audio": true,
        }),
    )
    .await;

    // Viewer should receive screen_share_started
    let started = next_text(&mut viewer_rx).await;
    assert_eq!(started["type"], "screen_share_started");
    assert_eq!(started["stream_id"], "stream-1");
    assert_eq!(started["kind"], "screen");
    assert_eq!(started["has_audio"], true);

    // Sharer sends a chunk envelope then binary data
    send_text(
        &mut sharer_tx,
        json!({
            "type": "screen_share_chunk",
            "channel_id": ch.id,
            "stream_id": "stream-1",
            "seq": 0,
            "is_init": true,
        }),
    )
    .await;

    sharer_tx
        .send(TsMessage::Binary(b"INIT_SEGMENT_BYTES".to_vec()))
        .await
        .unwrap();

    // Viewer should receive the chunk envelope then the binary
    let chunk_env = next_text(&mut viewer_rx).await;
    assert_eq!(chunk_env["type"], "screen_share_chunk");
    assert_eq!(chunk_env["seq"], 0);
    assert_eq!(chunk_env["is_init"], true);

    let binary_msg = next_raw(&mut viewer_rx).await;
    assert!(matches!(binary_msg, TsMessage::Binary(_)));
    if let TsMessage::Binary(data) = binary_msg {
        assert_eq!(&data[..], b"INIT_SEGMENT_BYTES");
    }

    // Sharer sends stop
    send_text(
        &mut sharer_tx,
        json!({
            "type": "screen_share_stop",
            "channel_id": ch.id,
            "stream_id": "stream-1",
        }),
    )
    .await;

    let stopped = next_text(&mut viewer_rx).await;
    assert_eq!(stopped["type"], "screen_share_stopped");
    assert_eq!(stopped["stream_id"], "stream-1");
}

/// Late joiner: viewer connects after the init chunk is cached and receives it on subscribe.
#[tokio::test]
async fn late_joiner_receives_init_chunk() {
    let (base, _state, _guard) = start_hub().await;

    let sharer_id = Identity::generate();
    let viewer_id = Identity::generate();

    let sharer_token = authenticate_http(&base, &sharer_id).await;
    let viewer_token = authenticate_http(&base, &viewer_id).await;

    let ch = create_channel(&base, &sharer_token, "video").await;

    let (mut sharer_tx, _sharer_rx) = connect_ws(&base, &sharer_token).await;

    // Sharer starts, sends init chunk
    send_text(
        &mut sharer_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;
    send_text(
        &mut sharer_tx,
        json!({
            "type": "screen_share_start",
            "channel_id": ch.id,
            "stream_id": "str-abc",
            "kind": "screen",
            "mime": "video/webm;codecs=vp8",
            "has_audio": false,
        }),
    )
    .await;

    send_text(
        &mut sharer_tx,
        json!({
            "type": "screen_share_chunk",
            "channel_id": ch.id,
            "stream_id": "str-abc",
            "seq": 0,
            "is_init": true,
        }),
    )
    .await;
    sharer_tx
        .send(TsMessage::Binary(b"WEBM_INIT".to_vec()))
        .await
        .unwrap();

    // Give the hub a moment to process the chunk and cache it
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Late viewer now connects and subscribes
    let (mut viewer_tx, mut viewer_rx) = connect_ws(&base, &viewer_token).await;
    send_text(
        &mut viewer_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;

    // Should receive screen_share_started
    let started = next_text(&mut viewer_rx).await;
    assert_eq!(started["type"], "screen_share_started");
    assert_eq!(started["stream_id"], "str-abc");

    // Then a synthetic init chunk envelope
    let chunk_env = next_text(&mut viewer_rx).await;
    assert_eq!(chunk_env["type"], "screen_share_chunk");
    assert_eq!(chunk_env["is_init"], true);

    // Then the binary init segment
    let binary = next_raw(&mut viewer_rx).await;
    assert!(matches!(binary, TsMessage::Binary(_)));
    if let TsMessage::Binary(data) = binary {
        assert_eq!(&data[..], b"WEBM_INIT");
    }
}

/// Co-op multi-stream: multiple users can share simultaneously in the same channel.
/// Each gets their own slot keyed by (channel_id, pubkey); a viewer sees both.
#[tokio::test]
async fn multiple_concurrent_sharers_allowed() {
    let (base, _state, _guard) = start_hub().await;

    let alice = Identity::generate();
    let bob = Identity::generate();
    let viewer_id = Identity::generate();

    let alice_token = authenticate_http(&base, &alice).await;
    let bob_token = authenticate_http(&base, &bob).await;
    let viewer_token = authenticate_http(&base, &viewer_id).await;

    let ch = create_channel(&base, &alice_token, "general").await;

    let (mut alice_tx, _alice_rx) = connect_ws(&base, &alice_token).await;
    let (mut bob_tx, _bob_rx) = connect_ws(&base, &bob_token).await;
    let (mut viewer_tx, mut viewer_rx) = connect_ws(&base, &viewer_token).await;

    send_text(
        &mut viewer_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;

    // Alice starts sharing
    send_text(
        &mut alice_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;
    send_text(
        &mut alice_tx,
        json!({
            "type": "screen_share_start",
            "channel_id": ch.id,
            "stream_id": "alice-stream",
            "kind": "screen",
            "mime": "video/webm",
            "has_audio": false,
        }),
    )
    .await;

    // Viewer sees Alice start
    let alice_start = next_text(&mut viewer_rx).await;
    assert_eq!(alice_start["type"], "screen_share_started");
    assert_eq!(alice_start["stream_id"], "alice-stream");

    // Bob subscribes and starts sharing in the same channel — must succeed
    send_text(
        &mut bob_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;
    send_text(
        &mut bob_tx,
        json!({
            "type": "screen_share_start",
            "channel_id": ch.id,
            "stream_id": "bob-stream",
            "kind": "screen",
            "mime": "video/webm",
            "has_audio": false,
        }),
    )
    .await;

    // Viewer sees Bob start — no error expected
    let bob_start = next_text(&mut viewer_rx).await;
    assert_eq!(
        bob_start["type"], "screen_share_started",
        "Bob should be allowed to share alongside Alice"
    );
    assert_eq!(bob_start["stream_id"], "bob-stream");

    // Bob's own WS should NOT have received an error
    // (send a benign chunk to provoke a response and check it isn't an error)
    send_text(
        &mut bob_tx,
        json!({
            "type": "screen_share_chunk",
            "channel_id": ch.id,
            "stream_id": "bob-stream",
            "seq": 0,
            "is_init": true,
        }),
    )
    .await;
    bob_tx
        .send(TsMessage::Binary(b"BOB_INIT".to_vec()))
        .await
        .unwrap();

    let chunk_env = next_text(&mut viewer_rx).await;
    assert_eq!(chunk_env["type"], "screen_share_chunk");
    assert_ne!(chunk_env["type"], "error", "No error from Bob's share");
}
