//! Membership is `users.is_member`, and `builtin-everyone` is the floor every
//! member gets without a `user_roles` row (issue #58). Leaving, banning and
//! recovery must clear membership with the roles: a key that keeps the floor
//! after being refused is the failure these tests exist to catch.

use serde_json::json;
use wavvon_hub::permissions::{user_permissions, MESSAGES_SEND};
use wavvon_identity::{
    recovery_attestation_signing_bytes, recovery_request_signing_bytes, Identity,
};

#[path = "common.rs"]
mod common;

async fn is_member(server: &common::TestHarness, who: &Identity) -> bool {
    sqlx::query_scalar("SELECT is_member FROM users WHERE public_key = $1")
        .bind(who.public_key_hex())
        .fetch_one(&server.state().db)
        .await
        .unwrap()
}

async fn assert_no_authority(server: &common::TestHarness, who: &Identity) {
    let perms = user_permissions(&server.state().db, &who.public_key_hex())
        .await
        .unwrap();
    assert!(perms.roles.is_empty(), "no roles at all, not even everyone");
    assert!(perms.effective.is_empty(), "no permissions at all");
    assert!(!is_member(server, who).await);
}

#[tokio::test]
async fn a_member_gets_the_everyone_floor_without_a_row() {
    let server = common::setup().await;
    common::authenticate(&server, &Identity::generate()).await;
    let member = Identity::generate();
    common::authenticate(&server, &member).await;

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE user_public_key = $1")
            .bind(member.public_key_hex())
            .fetch_one(&server.state().db)
            .await
            .unwrap();
    assert_eq!(
        rows, 0,
        "user_roles carries only grants on top of the floor"
    );

    let perms = user_permissions(&server.state().db, &member.public_key_hex())
        .await
        .unwrap();
    assert!(perms.has(MESSAGES_SEND));
    assert!(perms.roles.iter().any(|r| r.id == "builtin-everyone"));
}

#[tokio::test]
async fn editing_everyone_changes_every_members_permissions() {
    let server = common::setup().await;
    common::authenticate(&server, &Identity::generate()).await;
    let a = Identity::generate();
    let b = Identity::generate();
    common::authenticate(&server, &a).await;
    common::authenticate(&server, &b).await;

    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'polls.create')",
    )
    .execute(&server.state().db)
    .await
    .unwrap();

    for who in [&a, &b] {
        let perms = user_permissions(&server.state().db, &who.public_key_hex())
            .await
            .unwrap();
        assert!(perms.has("polls.create"));
    }
}

#[tokio::test]
async fn the_api_still_reports_everyone_for_members() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    common::authenticate(&server, &member).await;

    let members: Vec<String> = server
        .get("/roles/builtin-everyone/members")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(members.contains(&member.public_key_hex()));

    let roles: serde_json::Value = server
        .get(&format!("/users/{}/roles", member.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(roles
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "builtin-everyone"));
}

#[tokio::test]
async fn leaving_leaves_no_permissions() {
    let server = common::setup().await;
    common::authenticate(&server, &Identity::generate()).await;
    let member = Identity::generate();
    let token = common::authenticate(&server, &member).await;
    assert!(is_member(&server, &member).await);

    server
        .delete("/me")
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    assert_no_authority(&server, &member).await;
}

#[tokio::test]
async fn banning_leaves_no_permissions() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    common::authenticate(&server, &member).await;

    server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({ "target_public_key": member.public_key_hex(), "reason": "spam" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    assert_no_authority(&server, &member).await;
}

#[tokio::test]
async fn recovery_moves_membership_and_leaves_the_old_key_empty() {
    let server = common::setup().await;
    let hub_pubkey = server.state().hub_identity.public_key_hex();
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let contact = Identity::generate();
    common::authenticate(&server, &contact).await;
    let old = Identity::generate();
    let old_token = common::authenticate(&server, &old).await;
    let new_key = Identity::generate();

    server
        .put("/recovery/contacts")
        .authorization_bearer(&old_token)
        .json(&json!({ "contacts": [contact.public_key_hex()], "threshold": 1 }))
        .await
        .assert_status_ok();

    let proof = hex::encode(
        new_key
            .sign(&recovery_request_signing_bytes(
                &hub_pubkey,
                &old.public_key_hex(),
                &new_key.public_key_hex(),
            ))
            .to_bytes(),
    );
    let resp = server
        .post("/recovery/rotate-key")
        .json(&json!({
            "old_pubkey": old.public_key_hex(),
            "new_pubkey": new_key.public_key_hex(),
            "new_key_signature": proof,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let request_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let bundle = server
        .get(&format!("/recovery/rotation-request/{request_id}"))
        .await
        .json::<serde_json::Value>();
    let nonce = bundle["nonce"].as_str().unwrap().to_string();
    let sig = hex::encode(
        contact
            .sign(&recovery_attestation_signing_bytes(
                &hub_pubkey,
                &old.public_key_hex(),
                &new_key.public_key_hex(),
                &nonce,
            ))
            .to_bytes(),
    );
    server
        .post(&format!("/recovery/rotation-request/{request_id}/attest"))
        .json(&json!({ "attester": contact.public_key_hex(), "signature": sig }))
        .await
        .assert_status_ok();
    server
        .post(&format!("/admin/recovery/{request_id}/approve"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    assert_no_authority(&server, &old).await;
    let perms = user_permissions(&server.state().db, &new_key.public_key_hex())
        .await
        .unwrap();
    assert!(perms.has(MESSAGES_SEND), "the new key is the member now");
    assert!(is_member(&server, &new_key).await);
}

async fn verify(
    server: &common::TestHarness,
    who: &Identity,
    invite: Option<&str>,
) -> axum::http::StatusCode {
    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": who.public_key_hex() }))
        .await
        .json();
    let ch = challenge["challenge"].as_str().unwrap();
    let sig = who.sign(&hex::decode(ch).unwrap());
    server
        .post("/auth/verify")
        .json(&json!({
            "public_key": who.public_key_hex(),
            "challenge": ch,
            "signature": hex::encode(sig.to_bytes()),
            "invite_code": invite,
        }))
        .await
        .status_code()
}

#[tokio::test]
async fn the_invite_gate_applies_to_non_members_only() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('invite_only', 'true') ON CONFLICT (key) DO UPDATE SET value = 'true'")
        .execute(&server.state().db)
        .await
        .unwrap();

    assert!(
        verify(&server, &member, None).await.is_success(),
        "a returning member needs no invite"
    );
    assert_eq!(
        verify(&server, &Identity::generate(), None).await,
        axum::http::StatusCode::FORBIDDEN,
        "a stranger does"
    );

    server
        .delete("/me")
        .authorization_bearer(&member_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    assert_eq!(
        verify(&server, &member, None).await,
        axum::http::StatusCode::FORBIDDEN,
        "a leaver is a stranger again"
    );

    let invite: serde_json::Value = server
        .post("/invites")
        .authorization_bearer(&owner_token)
        .json(&json!({ "max_uses": 1 }))
        .await
        .json();
    let code = invite["code"].as_str().expect("invite code");
    assert!(verify(&server, &member, Some(code)).await.is_success());
    assert!(is_member(&server, &member).await, "a new invite re-admits");
}
