//! Web Push: subscriptions and delivery to a real local push endpoint.
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::json;
use tokio::sync::mpsc;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

struct Browser {
    secret: p256::SecretKey,
    auth: [u8; 16],
}

impl Browser {
    fn new() -> Self {
        Browser {
            secret: p256::SecretKey::random(&mut rand::rngs::OsRng),
            auth: rand::random(),
        }
    }
    fn subscription(&self, endpoint: &str) -> serde_json::Value {
        json!({
            "endpoint": endpoint,
            "keys": {
                "p256dh": URL_SAFE_NO_PAD.encode(self.secret.public_key().to_encoded_point(false).as_bytes()),
                "auth": URL_SAFE_NO_PAD.encode(self.auth),
            },
        })
    }
}

/// A push service on 127.0.0.1 that answers `status` and hands each request
/// back to the test.
async fn push_service(
    status: StatusCode,
) -> (String, mpsc::UnboundedReceiver<(HeaderMap, Vec<u8>)>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let app = axum::Router::new().route(
        "/push/{id}",
        axum::routing::post(move |headers: HeaderMap, body: axum::body::Bytes| {
            let tx = tx.clone();
            async move {
                let _ = tx.send((headers, body.to_vec()));
                status
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://127.0.0.1:{}/push/1",
        listener.local_addr().unwrap().port()
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, rx)
}

async fn channel(server: &wavvon_test_server::TestServer, token: &str) -> ChannelResponse {
    server
        .post("/channels")
        .authorization_bearer(token)
        .json(&json!({ "name": "general" }))
        .await
        .json()
}

#[tokio::test]
async fn vapid_key_is_generated_once_and_is_a_p256_point() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let a: serde_json::Value = server
        .get("/push/vapid-key")
        .authorization_bearer(&token)
        .await
        .json();
    let b: serde_json::Value = server
        .get("/push/vapid-key")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(a, b);
    let raw = URL_SAFE_NO_PAD
        .decode(a["public_key"].as_str().unwrap())
        .unwrap();
    assert!(p256::PublicKey::from_sec1_bytes(&raw).is_ok());
}

#[tokio::test]
async fn a_private_endpoint_or_bad_keys_are_refused() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let browser = Browser::new();
    server
        .put("/push/subscriptions")
        .authorization_bearer(&token)
        .json(&browser.subscription("https://127.0.0.1/push/1"))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let mut bad = browser.subscription("https://push.example/1");
    bad["keys"]["auth"] = json!("AAAA");
    server
        .put("/push/subscriptions")
        .authorization_bearer(&token)
        .json(&bad)
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_mention_pushes_hub_channel_and_kind_only() {
    let server = common::setup_allowing_private_webhooks().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob_token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &alice_token).await;

    let (endpoint, mut rx) = push_service(StatusCode::CREATED).await;
    let browser = Browser::new();
    server
        .put("/push/subscriptions")
        .authorization_bearer(&alice_token)
        .json(&browser.subscription(&endpoint))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .post(&format!("/channels/{}/messages", ch.id))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": format!("secret words for {}", alice.public_key_hex()) }))
        .await
        .assert_status(StatusCode::CREATED);

    let (headers, body) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("a push within 10 s")
        .unwrap();
    assert_eq!(headers["content-encoding"], "aes128gcm");
    assert!(headers["authorization"]
        .to_str()
        .unwrap()
        .starts_with("vapid t="));
    let plain = web_push_native::decrypt(
        body,
        &browser.secret,
        web_push_native::Auth::from_slice(&browser.auth),
    )
    .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(payload["kind"], "mention");
    assert_eq!(payload["channel_id"], ch.id.as_str());
    assert!(!String::from_utf8_lossy(&plain).contains("secret"));
}

#[tokio::test]
async fn a_silent_channel_is_not_pushed_and_a_gone_endpoint_is_dropped() {
    let harness = common::setup_allowing_private_webhooks().await;
    let server: &wavvon_test_server::TestServer = &harness;
    let alice = Identity::generate();
    let alice_token = common::authenticate(server, &alice).await;
    let bob_token = common::authenticate(server, &Identity::generate()).await;
    let ch = channel(server, &alice_token).await;

    let (endpoint, mut rx) = push_service(StatusCode::GONE).await;
    let browser = Browser::new();
    let mut sub = browser.subscription(&endpoint);
    sub["notify"] = json!({ "channels": { ch.id.clone(): "silent" } });
    server
        .put("/push/subscriptions")
        .authorization_bearer(&alice_token)
        .json(&sub)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    let mention = || async {
        server
            .post(&format!("/channels/{}/messages", ch.id))
            .authorization_bearer(&bob_token)
            .json(&json!({ "content": format!("hey {}", alice.public_key_hex()) }))
            .await
            .assert_status(StatusCode::CREATED);
    };
    mention().await;
    assert!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .is_err(),
        "a silent channel must not push"
    );

    sub["notify"] = json!({});
    server
        .put("/push/subscriptions")
        .authorization_bearer(&alice_token)
        .json(&sub)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    mention().await;
    tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("a push within 10 s");

    let db = &harness.state().db;
    for _ in 0..50 {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM push_subscriptions")
            .fetch_one(db)
            .await
            .unwrap();
        if n == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("a 410 must drop the subscription");
}

#[tokio::test]
async fn a_dm_pushes_the_conversation_and_never_its_text() {
    let server = common::setup_allowing_private_webhooks().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob_token = common::authenticate(&server, &Identity::generate()).await;

    let (endpoint, mut rx) = push_service(StatusCode::CREATED).await;
    let browser = Browser::new();
    server
        .put("/push/subscriptions")
        .authorization_bearer(&alice_token)
        .json(&browser.subscription(&endpoint))
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let conv: serde_json::Value = server
        .post("/conversations")
        .authorization_bearer(&bob_token)
        .json(&json!({ "members": [alice.public_key_hex()] }))
        .await
        .json();
    server
        .post(&format!(
            "/conversations/{}/messages",
            conv["id"].as_str().unwrap()
        ))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": "secret words" }))
        .await
        .assert_status(StatusCode::CREATED);

    let (_, body) = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("a push within 10 s")
        .unwrap();
    let plain = web_push_native::decrypt(
        body,
        &browser.secret,
        web_push_native::Auth::from_slice(&browser.auth),
    )
    .unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(payload["kind"], "dm");
    assert_eq!(payload["conversation_id"], conv["id"]);
    assert!(!String::from_utf8_lossy(&plain).contains("secret"));
}
