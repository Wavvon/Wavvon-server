use axum_test::TestServer;
use serde_json::json;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::routes::invite_models::InviteResponse;
use wavvon_hub::routes::role_models::RoleResponse;
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

// ── Task #31: invite-first default ───────────────────────────────────────

/// A freshly migrated hub (no test-harness override) seeds `invite_only =
/// true` — even the very first registrant is turned away without a code.
/// This is exactly the deadlock `maybe_mint_first_boot_owner_invite` (task
/// #34, tested below) exists to break.
#[tokio::test]
async fn default_hub_rejects_join_without_invite() {
    let server = common::setup_raw().await;
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
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

/// A plain (non-role-granting) invite still works for a brand-new
/// registration on an invite-only hub.
#[tokio::test]
async fn join_with_plain_invite_works_on_invite_only_hub() {
    let server = common::setup_raw().await;
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO invites (code, created_by, max_uses, uses, expires_at, created_at)
         VALUES ('plaincode', 'system', NULL, 0, NULL, $1)",
    )
    .bind(now)
    .execute(&server.state().db)
    .await
    .unwrap();

    let token = authenticate_with_invite(&server, &Identity::generate(), Some("plaincode")).await;
    assert!(!token.is_empty());
}

// ── Task #34: role-granting invites ──────────────────────────────────────

/// Creates a role via the API and returns its id.
async fn create_role(server: &TestServer, token: &str, name: &str, priority: i64) -> String {
    let resp = server
        .post("/roles")
        .authorization_bearer(token)
        .json(&json!({ "name": name, "permissions": [], "priority": priority }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = resp.json();
    role.id
}

#[tokio::test]
async fn role_granting_invite_assigns_role_on_join() {
    let server = common::setup_raw().await;
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO invites (code, created_by, max_uses, uses, expires_at, created_at)
         VALUES ('ownercode', 'system', 1, 0, NULL, $1)",
    )
    .bind(now)
    .execute(&server.state().db)
    .await
    .unwrap();

    // First user claims ownership via a plain (non-role-granting) invite.
    let owner = Identity::generate();
    let owner_token = authenticate_with_invite(&server, &owner, Some("ownercode")).await;

    // Owner mints a low-priority custom role and a role-granting invite for it.
    let role_id = create_role(&server, &owner_token, "Trusted", 10).await;
    let resp = server
        .post("/invites")
        .authorization_bearer(&owner_token)
        .json(&json!({ "grant_role_id": role_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let invite: InviteResponse = resp.json();
    assert_eq!(invite.grant_role_id.as_deref(), Some(role_id.as_str()));

    // Second user joins with it and should hold both builtin-everyone and
    // the granted role, but not builtin-owner.
    let member = Identity::generate();
    let member_token = authenticate_with_invite(&server, &member, Some(invite.code.as_str())).await;
    assert!(!member_token.is_empty());

    let resp = server
        .get(&format!("/users/{}/roles", member.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await;
    let roles: Vec<RoleResponse> = resp.json();
    let role_ids: Vec<&str> = roles.iter().map(|r| r.id.as_str()).collect();
    assert!(role_ids.contains(&role_id.as_str()));
    assert!(role_ids.contains(&"builtin-everyone"));
    assert!(!role_ids.contains(&"builtin-owner"));
}

#[tokio::test]
async fn creating_invite_above_own_priority_is_rejected() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // The owner's own max priority is builtin-owner's (999999) — even the
    // owner can't mint an invite granting a role at or above that, which is
    // exactly why the first-boot owner invite has to be minted internally
    // rather than through this endpoint.
    let resp = server
        .post("/invites")
        .authorization_bearer(&token)
        .json(&json!({ "grant_role_id": "builtin-owner" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_granting_invite_is_forced_single_use() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let role_id = create_role(&server, &token, "Sub-Admin", 100).await;
    // Grant it the admin permission directly (below the owner's priority).
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ($1, 'admin')")
        .bind(&role_id)
        .execute(&server.state().db)
        .await
        .unwrap();

    let resp = server
        .post("/invites")
        .authorization_bearer(&token)
        .json(&json!({ "grant_role_id": role_id, "max_uses": 50, "expires_in_seconds": 999_999_999i64 }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let invite: InviteResponse = resp.json();
    assert_eq!(
        invite.max_uses,
        Some(1),
        "admin-granting invite must be forced to a single use"
    );
    assert!(
        invite.expires_at.unwrap() < wavvon_hub::auth::handlers::unix_timestamp() + 999_999_999,
        "admin-granting invite must be forced to the short default expiry"
    );
}

#[tokio::test]
async fn first_boot_owner_invite_grants_owner_and_is_one_time() {
    let server = common::setup_raw().await;
    let db = &server.state().db;

    let code = wavvon_hub::routes::invites::maybe_mint_first_boot_owner_invite(db)
        .await
        .unwrap()
        .expect("a fresh, ownerless hub should mint a first-boot invite");

    // Idempotent: calling again before it's consumed returns the same code.
    let code_again = wavvon_hub::routes::invites::maybe_mint_first_boot_owner_invite(db)
        .await
        .unwrap()
        .expect("still no owner yet");
    assert_eq!(code, code_again);

    let owner = Identity::generate();
    let owner_token = authenticate_with_invite(&server, &owner, Some(code.as_str())).await;
    assert!(!owner_token.is_empty());

    let resp = server
        .get(&format!("/users/{}/roles", owner.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await;
    let roles: Vec<RoleResponse> = resp.json();
    assert!(roles.iter().any(|r| r.id == "builtin-owner"));

    // Now that a real user exists, nothing left to mint.
    let minted_after = wavvon_hub::routes::invites::maybe_mint_first_boot_owner_invite(db)
        .await
        .unwrap();
    assert!(minted_after.is_none());

    // And the invite itself is one-time: a second registrant can't reuse it.
    let intruder = Identity::generate();
    let pub_key = intruder.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let signature = intruder.sign(&hex::decode(&challenge.challenge).unwrap());
    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
            "invite_code": code,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}
