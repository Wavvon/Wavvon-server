use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn start_real_hub() -> (String, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;

    let state = Arc::new(AppState {
        hub_name: "rate-test".to_string(),
        ..common::base_state(db)
    });

    let app = server::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (url, guard)
}

async fn setup_server() -> common::TestHarness {
    let (db, guard) = crate::common::create_test_db().await;

    let state = Arc::new(AppState {
        hub_name: "rate-test".to_string(),
        ..common::base_state(db)
    });

    let app = server::create_router(state);
    common::TestHarness::new(TestServer::new(app), guard)
}

async fn authenticate_server(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();

    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    let verify: VerifyResponse = resp.json();
    verify.token
}

#[tokio::test]
async fn message_rate_limit_allows_30() {
    let server = setup_server().await;
    let identity = Identity::generate();
    let token = authenticate_server(&server, &identity).await;

    // Create a channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let channel: ChannelResponse = resp.json();

    // Send exactly 30 messages — all should succeed
    for i in 0..30 {
        let resp = server
            .post(&format!("/channels/{}/messages", channel.id))
            .authorization_bearer(&token)
            .json(&json!({ "content": format!("msg {i}"), "attachments": [] }))
            .await;
        assert!(
            resp.status_code().is_success(),
            "message {i} should succeed, got {}",
            resp.status_code()
        );
    }
}

#[tokio::test]
async fn message_rate_limit_blocks_31st() {
    let server = setup_server().await;
    let identity = Identity::generate();
    let token = authenticate_server(&server, &identity).await;

    // Create a channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "spam" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let channel: ChannelResponse = resp.json();

    // Send 30 messages — all succeed
    for i in 0..30 {
        let resp = server
            .post(&format!("/channels/{}/messages", channel.id))
            .authorization_bearer(&token)
            .json(&json!({ "content": format!("msg {i}"), "attachments": [] }))
            .await;
        assert!(
            resp.status_code().is_success(),
            "message {i} should succeed, got {}",
            resp.status_code()
        );
    }

    // 31st message must be rejected with 429
    let resp = server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token)
        .json(&json!({ "content": "over the limit", "attachments": [] }))
        .await;
    assert_eq!(
        resp.status_code(),
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        "31st message should be rate-limited"
    );
}

#[tokio::test]
async fn auth_challenge_rate_limits_burst() {
    let (hub, _guard) = start_real_hub().await;
    let client = reqwest::Client::new();
    let pk = Identity::generate().public_key_hex();

    // AUTH config allows 10 burst; 20 hits back to back should produce at least one 429.
    let mut got_429 = false;
    for _ in 0..20 {
        let resp = client
            .post(format!("{hub}/auth/challenge"))
            .json(&json!({ "public_key": pk }))
            .send()
            .await
            .unwrap();
        if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            got_429 = true;
            break;
        }
    }
    assert!(
        got_429,
        "expected at least one 429 after bursting past the auth limit"
    );
}
