//! Regression tests: a WS connection's DM-membership set (`my_conversations`)
//! is loaded once at connect, so it must be kept live from `dm_member_changed`
//! events — otherwise a conversation created *after* a client connected is
//! dead air (every `dm` frame for it dropped) until that client reconnects.
//! Creating a conversation must also announce itself via `dm_member_changed`.
use std::sync::Arc;

use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
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

    let state = Arc::new(AppState {
        hub_name: "dm-live-membership-test".to_string(),
        ..common::base_state(db)
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
