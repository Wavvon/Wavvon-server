use axum_test::TestServer;
use serde_json::{json, Value};
use wavvon_hub::auth::models::ChallengeResponse;
use wavvon_identity::{compute_security_level, Identity};

#[path = "common.rs"]
mod common;

/// Runs the full challenge/verify handshake for `identity` with no PoW proof
/// (security_level defaults to 0) and returns the raw `/auth/verify` JSON
/// body, so callers can inspect `scope` directly instead of only the token.
async fn auth_verify_raw(server: &TestServer, identity: &Identity) -> Value {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status_ok();
    resp.json()
}

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

// ---------------------------------------------------------------------------
// Regression coverage for the live 2026-07-06 bug: /auth/verify used to
// hard-403 any sub-level join once min_security_level > 0, instead of
// admitting the user into scope="lobby". See lobby-bot-survey.md Feature 1.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sub_level_join_is_admitted_as_lobby_not_403() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "min_security_level": 8 }))
        .await
        .assert_status_ok();

    // A brand-new user presenting no PoW proof (level 0 < 8) must be
    // admitted with scope="lobby", not hard-403'd.
    let newcomer = Identity::generate();
    let body = auth_verify_raw(&server, &newcomer).await;
    assert_eq!(body["scope"], "lobby");
    assert!(body["token"].is_string());
}

#[tokio::test]
async fn lobby_scope_confined_from_member_surface_but_reaches_lobby_status() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "min_security_level": 8 }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();
    let body = auth_verify_raw(&server, &newcomer).await;
    assert_eq!(body["scope"], "lobby");
    let token = body["token"].as_str().unwrap().to_string();

    // Member-only surface (channels): confined, 403.
    server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .assert_status_forbidden();

    // Explicitly lobby-allowed surfaces: reachable.
    server
        .get("/lobby/status")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    server
        .get("/lobby/welcome")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    server
        .get("/me")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn submit_pow_promotes_lobby_session_to_member_in_place() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    // Use a very low bar so the test PoW search is fast.
    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "min_security_level": 1 }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();
    let body = auth_verify_raw(&server, &newcomer).await;
    assert_eq!(body["scope"], "lobby");
    let token = body["token"].as_str().unwrap().to_string();

    // Confined before promotion.
    server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .assert_status_forbidden();

    let pub_key = newcomer.public_key_hex();
    let (nonce, level) = compute_security_level(&pub_key, 0, 1);
    assert!(level >= 1);

    let resp = server
        .post("/lobby/submit-pow")
        .authorization_bearer(&token)
        .json(&json!({ "pow_proof": format!("{nonce}:{level}") }))
        .await;
    resp.assert_status_ok();
    let pow_body: Value = resp.json();
    assert_eq!(pow_body["promoted"], true);

    // Same token, now unconfined: the session was promoted in place without
    // a fresh /auth/verify.
    server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn first_user_join_is_never_lobby_confined_even_below_level() {
    let server = common::setup().await;

    // Simulate a preset-seeded hub: min_security_level is already set
    // before anyone has joined (bootstrap.rs presets::gaming does this via
    // apply_template, not through an authenticated admin call).
    sqlx::query("UPDATE hub_settings SET value = '8' WHERE key = 'min_security_level'")
        .execute(&server.state().db)
        .await
        .unwrap();

    let owner = Identity::generate();
    let body = auth_verify_raw(&server, &owner).await;
    assert_eq!(
        body["scope"], "member",
        "the implicit first user must never be lobby-confined"
    );

    let token = body["token"].as_str().unwrap().to_string();
    server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn existing_owner_rejoin_is_never_lobby_confined_even_below_level() {
    let server = common::setup().await;
    let owner = Identity::generate();
    // First join: no gate yet, becomes owner.
    common::authenticate(&server, &owner).await;

    // Now raise the bar (as the owner, who is already an admin).
    let owner_token = common::authenticate(&server, &owner).await;
    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "min_security_level": 8 }))
        .await
        .assert_status_ok();

    // Owner re-authenticates (e.g. a new device/session) with no PoW proof.
    // They already hold builtin-owner, so they must still land at "member".
    let body = auth_verify_raw(&server, &owner).await;
    assert_eq!(
        body["scope"], "member",
        "the hub owner must never be lobby-confined on their own hub"
    );

    let token = body["token"].as_str().unwrap().to_string();
    server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn min_security_level_still_hard_rejects_when_lobby_disabled() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "min_security_level": 8 }))
        .await
        .assert_status_ok();

    // Disable the lobby soft-landing explicitly.
    server
        .put("/hub/settings/lobby")
        .authorization_bearer(&owner_token)
        .json(&json!({ "lobby_enabled": false }))
        .await
        .assert_status_ok();

    let newcomer = Identity::generate();
    let pub_key = newcomer.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = newcomer.sign(&hex::decode(&challenge.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
