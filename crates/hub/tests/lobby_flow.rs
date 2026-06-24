use serde_json::{json, Value};
use voxply_hub::auth::models::ChallengeResponse;
use voxply_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn lobby_status_returns_member_when_no_min_level() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // min_security_level defaults to 0 ? status should be "member"
    let resp = server
        .get("/lobby/status")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["status"], "member");
    assert_eq!(body["required_level"], 0);
    assert_eq!(body["current_level"], 0);
}

#[tokio::test]
async fn lobby_status_requires_auth() {
    let server = common::setup().await;
    let resp = server.get("/lobby/status").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn lobby_welcome_returns_hub_name() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .get("/lobby/welcome")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["hub_name"], "test-hub");
    assert_eq!(body["required_level"], 0);
}

#[tokio::test]
async fn admin_can_update_lobby_settings() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Update welcome_md
    let resp = server
        .put("/hub/settings/lobby")
        .authorization_bearer(&token)
        .json(&json!({ "lobby_enabled": true, "welcome_md": "# Welcome!" }))
        .await;
    resp.assert_status_ok();

    // Welcome endpoint should reflect it
    let resp = server
        .get("/lobby/welcome")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["welcome_md"], "# Welcome!");
}

#[tokio::test]
async fn non_admin_cannot_update_lobby_settings() {
    let server = common::setup().await;
    // First user is owner
    let owner = Identity::generate();
    let _owner_token = common::authenticate(&server, &owner).await;

    // Second user is just @everyone
    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    let resp = server
        .put("/hub/settings/lobby")
        .authorization_bearer(&user_token)
        .json(&json!({ "lobby_enabled": false }))
        .await;
    resp.assert_status_forbidden();
}

#[tokio::test]
async fn submit_pow_invalid_format_returns_bad_request() {
    let server = common::setup().await;
    let user = Identity::generate();
    let token = common::authenticate(&server, &user).await;

    let resp = server
        .post("/lobby/submit-pow")
        .authorization_bearer(&token)
        .json(&json!({ "pow_proof": "not-valid" }))
        .await;
    resp.assert_status_bad_request();
}

#[tokio::test]
async fn verify_response_includes_scope_field() {
    let server = common::setup().await;
    let user = Identity::generate();
    let pub_key = user.public_key_hex();

    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = user.sign(&hex::decode(&challenge.challenge).unwrap());

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    // With min_security_level = 0 and lobby_enabled = '1', scope should be "member"
    // because pow_level (0) >= min_level (0)
    assert!(body["scope"].is_string(), "scope field must be present");
    assert_eq!(body["scope"], "member");
}
