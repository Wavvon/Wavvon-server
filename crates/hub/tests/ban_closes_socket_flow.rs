use std::sync::Arc;

use futures_util::StreamExt;
use serde_json::json;
use tokio_tungstenite::tungstenite::Message;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// A socket is authenticated once, at the handshake, so deleting a banned or
// kicked member's sessions logged nobody out of a tab already connected: it
// kept receiving every channel they could read, and stayed in voice.
//
// Multi-thread: the closed socket's cleanup runs on the hub's tasks, and on
// a single-threaded test runtime they wait behind the database teardown,
// which then waits for them -- a minute of pool timeout per test.

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let state = Arc::new(common::base_state(db));
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, state, guard)
}

async fn authenticate(base: &str, identity: &Identity) -> String {
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
    let sig = identity.sign(&hex::decode(&resp.challenge).unwrap());
    let verify: VerifyResponse = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": resp.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify.token
}

/// True once the server closes the socket, false if it is still open after
/// a few seconds.
async fn closed_by_server(
    base: &str,
    token: &str,
    act: impl std::future::Future<Output = ()>,
) -> bool {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    let _ = ws.next().await;
    act.await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => return,
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .is_ok()
}

async fn moderate(path: &str) {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate(&base, &owner).await;
    let member = Identity::generate();
    let member_token = authenticate(&base, &member).await;

    let client = reqwest::Client::new();
    let body = json!({ "target_public_key": member.public_key_hex(), "reason": "test" });
    let closed = closed_by_server(&base, &member_token, async {
        let r = client
            .post(format!("{base}{path}"))
            .bearer_auth(&owner_token)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(r.status().is_success(), "{path}: {}", r.status());
    })
    .await;
    assert!(closed, "{path} left the member's socket open");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ban_closes_the_members_open_socket() {
    moderate("/moderation/bans").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_kick_closes_the_members_open_socket() {
    moderate("/moderation/kick").await;
}
