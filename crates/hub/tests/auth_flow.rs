use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::routes::me::MeResponse;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

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
    let resp = server.get("/me").authorization_bearer(&verify.token).await;
    resp.assert_status_ok();
    let me: MeResponse = resp.json();
    assert_eq!(me.public_key, pub_key);
}

#[tokio::test]
async fn concurrent_challenges_for_same_key_do_not_stomp() {
    // Regression: pending challenges used to be keyed by pubkey, so a second
    // challenge request overwrote the first and the earlier auth flow died
    // with "No pending challenge" — e.g. two simultaneous federated DM
    // deliveries to the same peer hub. Both outstanding challenges must now
    // be independently verifiable.
    let server = common::setup().await;
    let identity = Identity::generate();
    let pub_key = identity.public_key_hex();

    let first: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let second: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    assert_ne!(first.challenge, second.challenge);

    // Verify the FIRST challenge (issued before the second overwrote it in
    // the old scheme) — must still succeed.
    for challenge in [&first, &second] {
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
        let verify: VerifyResponse = resp.json();
        assert!(!verify.token.is_empty());
    }
}

#[tokio::test]
async fn challenge_cannot_be_verified_by_a_different_key() {
    // A challenge is bound to the pubkey it was issued to; another identity
    // must not be able to consume it, even with a valid signature of its own.
    let server = common::setup().await;
    let alice = Identity::generate();
    let mallory = Identity::generate();

    let challenge: ChallengeResponse = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": alice.public_key_hex() }))
        .await
        .json();

    let signature = mallory.sign(&hex::decode(&challenge.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": mallory.public_key_hex(),
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status_unauthorized();
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
    let resp = server.get("/me").authorization_bearer(&newbie_token).await;
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
