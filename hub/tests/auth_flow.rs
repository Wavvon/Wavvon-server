
use serde_json::json;
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::routes::me::MeResponse;
use voxply_identity::Identity;

#[path = "common.rs"] mod common;

#[tokio::test]
async fn full_auth_flow() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let pub_key = identity.public_key_hex();

    // 1. Request challenge
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    resp.assert_status_ok();
    let challenge: ChallengeResponse = resp.json();

    // 2. Sign the challenge
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);
    let signature_hex = hex::encode(signature.to_bytes());

    // 3. Verify (get token)
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": signature_hex,
        }))
        .await;
    resp.assert_status_ok();
    let verify: VerifyResponse = resp.json();
    assert!(!verify.token.is_empty());

    // 4. Use token to access /me
    let resp = server
        .get("/me")
        .authorization_bearer(&verify.token)
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.public_key, pub_key);
}

#[tokio::test]
async fn me_rejects_no_token() {
    let server = common::setup().await;
    let resp = server.get("/me").await;
    resp.assert_status_unauthorized();
}

#[tokio::test]
async fn pending_members_are_blocked_until_approved() {
    let server = common::setup().await;

    // Owner signs up first — auto-approved since they're the hub creator.
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    // Owner turns on require_approval.
    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "require_approval": true }))
        .await
        .assert_status_ok();

    // New member joins — they get a token but start pending.
    let newbie = Identity::generate();
    let newbie_token = common::authenticate(&server, &newbie).await;

    // Can see their own status
    let resp = server
        .get("/me")
        .authorization_bearer(&newbie_token)
        .await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.approval_status, "pending");

    // Cannot see channels or anything else
    server
        .get("/channels")
        .authorization_bearer(&newbie_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // Owner sees them in the pending queue
    let resp = server
        .get("/hub/pending")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let pending: serde_json::Value = resp.json();
    assert_eq!(pending.as_array().unwrap().len(), 1);

    // Owner approves
    server
        .post(&format!("/hub/pending/{}/approve", newbie.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    // Newbie can now access channels
    server
        .get("/channels")
        .authorization_bearer(&newbie_token)
        .await
        .assert_status_ok();
}
