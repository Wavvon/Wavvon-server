use axum_test::TestServer;
use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::routes::invite_models::InviteResponse;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[allow(dead_code)]
async fn authenticate_with_invite(
    server: &TestServer,
    identity: &Identity,
    invite_code: Option<&str>,
) -> String {
    let pub_key = identity.public_key_hex();

    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let mut body = json!({
        "public_key": pub_key,
        "challenge": challenge.challenge,
        "signature": hex::encode(signature.to_bytes()),
    });

    if let Some(code) = invite_code {
        body["invite_code"] = json!(code);
    }

    let resp = server.post("/auth/verify").json(&body).await;
    let verify: VerifyResponse = resp.json();
    verify.token
}

#[tokio::test]
async fn create_and_list_invites() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/invites")
        .authorization_bearer(&token)
        .json(&json!({ "max_uses": 5 }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let invite: InviteResponse = resp.json();
    assert_eq!(invite.max_uses, Some(5));
    assert_eq!(invite.uses, 0);

    let resp = server.get("/invites").authorization_bearer(&token).await;
    let invites: Vec<InviteResponse> = resp.json();
    assert_eq!(invites.len(), 1);
}

#[tokio::test]
async fn invite_only_blocks_without_code() {
    let server = common::setup().await;

    // First user (owner) joins freely
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/invites")
        .authorization_bearer(&owner_token)
        .json(&json!({ "max_uses": 1 }))
        .await;
    let invite: InviteResponse = resp.json();

    let user2 = Identity::generate();
    let pub_key = user2.public_key_hex();

    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = user2.sign(&challenge_bytes);

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
            "invite_code": invite.code,
        }))
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn revoke_invite() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/invites")
        .authorization_bearer(&token)
        .json(&json!({}))
        .await;
    let invite: InviteResponse = resp.json();

    server
        .delete(&format!("/invites/{}", invite.code))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server.get("/invites").authorization_bearer(&token).await;
    let invites: Vec<InviteResponse> = resp.json();
    assert_eq!(invites.len(), 0);
}
