//! Regression test: PATCH /hub (branding/settings update) must broadcast a
//! `hub_updated` WS event hub-wide so connected clients refetch /info without
//! needing a page reload. See ChatEvent::HubUpdated in chat_models.rs.
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
/// Mirrors `squad_rooms_flow.rs`'s `start_hub`.
async fn start_hub() -> (String, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;

    let state = Arc::new(AppState {
        hub_name: "hub-updated-test".to_string(),
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

async fn connect_ws(
    base: &str,
    token: &str,
) -> futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let (_tx, rx) = ws.split();
    rx
}

async fn next_frame_of_type(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
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

/// Happy path: an admin PATCHes /hub with a new name, and a connected client
/// (subscribed to nothing in particular -- HubUpdated is hub-wide) receives a
/// `hub_updated` frame.
#[tokio::test]
async fn patch_hub_broadcasts_hub_updated() {
    let (base, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let mut watcher_rx = connect_ws(&base, &owner_token).await;
    // Drain the initial snapshot frame(s), if any, before triggering the update.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), watcher_rx.next()).await;

    let resp = reqwest::Client::new()
        .patch(format!("{base}/hub"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "Renamed Hub" }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "PATCH /hub failed: {resp:?}");

    let update_frame = next_frame_of_type(
        &mut watcher_rx,
        "hub_updated",
        std::time::Duration::from_secs(15),
    )
    .await;
    assert!(
        update_frame.is_some(),
        "expected a hub_updated broadcast after PATCH /hub"
    );
}
