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
    let signature =
        identity.sign(&wavvon_identity::auth_challenge_signing_bytes(&challenge_bytes).unwrap());

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

/// Wait for a text frame of the given `type`, skipping everything else.
async fn wait_for_type(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    ty: &str,
) -> Value {
    loop {
        let v = next_text(rx).await;
        if v["type"] == ty {
            return v;
        }
    }
}

async fn revoke_from_everyone(state: &AppState, perm: &str) {
    sqlx::query(
        "DELETE FROM role_permissions WHERE role_id = 'builtin-everyone' AND permission = $1",
    )
    .bind(perm)
    .execute(&state.db)
    .await
    .unwrap();
}

/// `voice.screen_share` is its own grant (#277): revoked from @everyone, a
/// member who may still join voice is refused a share, and nobody sees it.
#[tokio::test]
async fn screen_share_needs_its_own_permission() {
    let (base, state, _guard) = start_hub().await;
    // The owner bypasses every check, so the act is a second member's.
    let owner_token = authenticate_http(&base, &Identity::generate()).await;
    let ch = create_channel(&base, &owner_token, "general").await;
    let sharer_token = authenticate_http(&base, &Identity::generate()).await;
    revoke_from_everyone(&state, "voice.screen_share").await;

    let (mut tx, mut rx) = connect_ws(&base, &sharer_token).await;
    send_text(&mut tx, json!({ "type": "subscribe", "channel_id": ch.id })).await;
    send_text(
        &mut tx,
        json!({
            "type": "screen_share_start",
            "channel_id": ch.id,
            "stream_id": "s-denied",
            "kind": "screen",
            "mime": "video/webm",
            "has_audio": false,
        }),
    )
    .await;

    let err = wait_for_type(&mut rx, "error").await;
    assert_eq!(err["context"], "screen_share_start");
    assert!(state.screen_shares.read().await.is_empty());
}

/// `voice.camera` likewise (#277): in the call, but refused a camera.
#[tokio::test]
async fn camera_needs_its_own_permission() {
    let (base, state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;
    let room: ChannelResponse = reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "room", "channel_type": "voice" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = authenticate_http(&base, &Identity::generate()).await;
    revoke_from_everyone(&state, "voice.camera").await;

    let (mut tx, mut rx) = connect_ws(&base, &token).await;
    send_text(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": room.id, "udp_port": 0 }),
    )
    .await;
    wait_for_type(&mut rx, "voice_joined").await;
    send_text(
        &mut tx,
        json!({ "type": "video_enable", "channel_id": room.id }),
    )
    .await;

    let err = wait_for_type(&mut rx, "error").await;
    assert_eq!(err["context"], "video_enable");
    assert!(state
        .video_channels
        .read()
        .await
        .get(&room.id)
        .is_none_or(|set| set.is_empty()));
}

/// Ping and return the first text frame, so a test can tell whether anything
/// was queued for this connection before the pong.
async fn first_after_ping(
    tx: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TsMessage,
    >,
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> Value {
    send_text(tx, json!({ "type": "ping", "nonce": 7 })).await;
    next_text(rx).await
}

async fn send_chunk(
    tx: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TsMessage,
    >,
    channel_id: &str,
    seq: u64,
    bytes: &[u8],
) {
    send_text(
        tx,
        json!({
            "type": "screen_share_chunk",
            "channel_id": channel_id,
            "stream_id": "s-req",
            "seq": seq,
            "is_init": seq == 0,
        }),
    )
    .await;
    tx.send(TsMessage::Binary(bytes.to_vec())).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// #276: a connection that was opened with `?streams=on_request` hears that a stream
/// started, but gets its bytes only between `stream_subscribe` and
/// `stream_unsubscribe` -- in its own channel too.
#[tokio::test]
async fn streams_on_request_flow_only_once_opened() {
    let (base, _state, _guard) = start_hub().await;
    let sharer_token = authenticate_http(&base, &Identity::generate()).await;
    let viewer_token = authenticate_http(&base, &Identity::generate()).await;
    let ch = create_channel(&base, &sharer_token, "general").await;

    let (mut viewer_tx, mut viewer_rx) =
        connect_ws(&base, &format!("{viewer_token}&streams=on_request")).await;
    send_text(
        &mut viewer_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;

    let (mut sharer_tx, _sharer_rx) = connect_ws(&base, &sharer_token).await;
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
            "stream_id": "s-req",
            "kind": "screen",
            "mime": "video/webm",
            "has_audio": false,
        }),
    )
    .await;
    let started = next_text(&mut viewer_rx).await;
    assert_eq!(started["type"], "screen_share_started");

    send_chunk(&mut sharer_tx, &ch.id, 0, b"INIT").await;
    send_chunk(&mut sharer_tx, &ch.id, 1, b"ONE").await;
    assert_eq!(
        first_after_ping(&mut viewer_tx, &mut viewer_rx).await["type"],
        "pong",
        "nothing flows before the stream is opened"
    );

    send_text(
        &mut viewer_tx,
        json!({ "type": "stream_subscribe", "source_channel_id": ch.id, "stream_id": "s-req" }),
    )
    .await;
    assert_eq!(next_text(&mut viewer_rx).await["type"], "stream_subscribed");
    assert_eq!(next_text(&mut viewer_rx).await["is_init"], true);
    assert!(matches!(next_raw(&mut viewer_rx).await, TsMessage::Binary(b) if &b[..] == b"INIT"));

    send_chunk(&mut sharer_tx, &ch.id, 2, b"TWO").await;
    assert_eq!(next_text(&mut viewer_rx).await["seq"], 2);
    assert!(matches!(next_raw(&mut viewer_rx).await, TsMessage::Binary(b) if &b[..] == b"TWO"));

    send_text(
        &mut viewer_tx,
        json!({ "type": "stream_unsubscribe", "source_channel_id": ch.id, "stream_id": "s-req" }),
    )
    .await;
    send_chunk(&mut sharer_tx, &ch.id, 3, b"THREE").await;
    assert_eq!(
        first_after_ping(&mut viewer_tx, &mut viewer_rx).await["type"],
        "pong",
        "nothing flows after the stream is closed"
    );
}

/// #276: a late joiner on request is told about the stream but is not handed
/// its init segment until it opens it.
#[tokio::test]
async fn streams_on_request_late_joiner_gets_no_init() {
    let (base, _state, _guard) = start_hub().await;
    let sharer_token = authenticate_http(&base, &Identity::generate()).await;
    let viewer_token = authenticate_http(&base, &Identity::generate()).await;
    let ch = create_channel(&base, &sharer_token, "general").await;

    let (mut sharer_tx, _sharer_rx) = connect_ws(&base, &sharer_token).await;
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
            "stream_id": "s-req",
            "kind": "screen",
            "mime": "video/webm",
            "has_audio": false,
        }),
    )
    .await;
    send_chunk(&mut sharer_tx, &ch.id, 0, b"INIT").await;

    let (mut viewer_tx, mut viewer_rx) =
        connect_ws(&base, &format!("{viewer_token}&streams=on_request")).await;
    send_text(
        &mut viewer_tx,
        json!({ "type": "subscribe", "channel_id": ch.id }),
    )
    .await;
    assert_eq!(
        next_text(&mut viewer_rx).await["type"],
        "screen_share_started"
    );
    assert_eq!(
        first_after_ping(&mut viewer_tx, &mut viewer_rx).await["type"],
        "pong"
    );
}

/// #282: knowing a channel id and a stream id is not access. A member who can
/// neither read the source channel nor join its voice is refused the stream.
#[tokio::test]
async fn stream_subscribe_needs_access_to_the_source_channel() {
    let (base, state, _guard) = start_hub().await;
    let owner_token = authenticate_http(&base, &Identity::generate()).await;
    let ch = create_channel(&base, &owner_token, "private").await;
    let viewer_token = authenticate_http(&base, &Identity::generate()).await;
    revoke_from_everyone(&state, "messages.read").await;
    revoke_from_everyone(&state, "voice.join").await;

    let (mut owner_tx, _owner_rx) = connect_ws(&base, &owner_token).await;
    send_text(
        &mut owner_tx,
        json!({
            "type": "screen_share_start",
            "channel_id": ch.id,
            "stream_id": "s-private",
            "kind": "screen",
            "mime": "video/webm",
            "has_audio": false,
        }),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(!state.screen_shares.read().await.is_empty());

    let (mut viewer_tx, mut viewer_rx) = connect_ws(&base, &viewer_token).await;
    send_text(
        &mut viewer_tx,
        json!({ "type": "stream_subscribe", "source_channel_id": ch.id, "stream_id": "s-private" }),
    )
    .await;
    let reply = next_text(&mut viewer_rx).await;
    assert_eq!(reply["type"], "error");
    assert_eq!(reply["context"], "stream_subscribe");
}
