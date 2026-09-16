use serde_json::json;
use wavvon_hub::routes::me::MeResponse;
use wavvon_hub::routes::role_models::RoleResponse;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn first_user_gets_owner_and_everyone() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let resp = server.get("/me").authorization_bearer(&token).await;
    let me: MeResponse = resp.json();

    assert_eq!(me.roles.len(), 2);
    let role_names: Vec<&str> = me.roles.iter().map(|r| r.name.as_str()).collect();
    assert!(role_names.contains(&"Owner"));
    assert!(role_names.contains(&"everyone"));
}

#[tokio::test]
async fn second_user_gets_only_everyone() {
    let server = common::setup().await;

    let owner = Identity::generate();
    common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server.get("/me").authorization_bearer(&token2).await;
    let me: MeResponse = resp.json();

    assert_eq!(me.roles.len(), 1);
    assert_eq!(me.roles[0].name, "everyone");
}

#[tokio::test]
async fn owner_can_create_role() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Moderator",
            "permissions": ["channels.manage", "messages.manage"],
            "priority": 50,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = resp.json();
    assert_eq!(role.name, "Moderator");
    assert_eq!(role.priority, 50);
    assert!(role.permissions.contains(&"channels.manage".to_string()));
}

#[tokio::test]
async fn everyone_user_cannot_create_role() {
    let server = common::setup().await;
    let owner = Identity::generate();
    common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .post("/roles")
        .authorization_bearer(&token2)
        .json(&json!({
            "name": "Hacker",
            "permissions": ["moderation.ban.permanent"],
            "priority": 100,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn priority_enforcement() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    // Owner creates a moderator role at priority 50
    let resp = server
        .post("/roles")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "name": "Moderator",
            "permissions": ["roles.manage", "channels.manage"],
            "priority": 50,
        }))
        .await;
    let mod_role: RoleResponse = resp.json();

    // Create user2 and assign moderator role
    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    server
        .put(&format!(
            "/users/{}/roles/{}",
            user2.public_key_hex(),
            mod_role.id
        ))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    // User2 tries to create a role at priority 50 (= their own) — should fail
    let resp = server
        .post("/roles")
        .authorization_bearer(&token2)
        .json(&json!({
            "name": "HighRole",
            "permissions": ["messages.send"],
            "priority": 50,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // User2 creates a role at priority 49 (< their own) — should succeed
    let resp = server
        .post("/roles")
        .authorization_bearer(&token2)
        .json(&json!({
            "name": "LowRole",
            "permissions": ["messages.send"],
            "priority": 49,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn cannot_modify_builtin_roles() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .patch("/roles/builtin-owner")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Hacked" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    let resp = server
        .delete("/roles/builtin-everyone")
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn permission_gating_on_channels() {
    let server = common::setup().await;
    let owner = Identity::generate();
    common::authenticate(&server, &owner).await;

    // User2 (only @everyone) tries to create a channel — should fail
    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token2)
        .json(&json!({ "name": "test" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cannot_remove_last_owner() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .delete(&format!(
            "/users/{}/roles/builtin-owner",
            owner.public_key_hex()
        ))
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_role_rejects_an_unknown_permission_string() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Typo",
            "permissions": ["channels.manage", "manage_rolez"],
            "priority": 50,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("manage_rolez"));

    // Nothing was written: the role itself must not exist either, or a
    // rejected request would still leave a half-built role behind.
    let list = server.get("/roles").authorization_bearer(&token).await;
    let roles: Vec<RoleResponse> = list.json();
    assert!(
        !roles.iter().any(|r| r.name == "Typo"),
        "rejected create must not persist the role"
    );
}

#[tokio::test]
async fn update_role_rejects_an_unknown_permission_before_applying_anything() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let created = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Moderator",
            "permissions": ["messages.manage"],
            "priority": 50,
        }))
        .await;
    created.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = created.json();

    // Rename and re-permission in one call, with one bad string in the set.
    let resp = server
        .patch(&format!("/roles/{}", role.id))
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Renamed",
            "permissions": ["messages.manage", "not_a_permission"],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // The rename lives in its own UPDATE statement ahead of the permission
    // rewrite, so validating late would commit the new name behind a 400.
    let list = server.get("/roles").authorization_bearer(&token).await;
    let roles: Vec<RoleResponse> = list.json();
    let after = roles
        .iter()
        .find(|r| r.id == role.id)
        .expect("role still exists");
    assert_eq!(after.name, "Moderator", "rejected update must not rename");
    assert_eq!(after.permissions, vec!["messages.manage".to_string()]);
}

/// Owner mints a `manage_roles` + `manage_channels` role at priority 50 and
/// gives it to a second identity. That identity is the delegate every test
/// below escalates from: it can manage roles, and it holds nothing else
/// beyond what `everyone` carries (send/read messages, posts, games, events).
async fn manager_delegate(server: &axum_test::TestServer, owner_token: &str) -> (Identity, String) {
    let resp = server
        .post("/roles")
        .authorization_bearer(owner_token)
        .json(&json!({
            "name": "Delegate",
            "permissions": ["roles.manage", "channels.manage"],
            "priority": 50,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = resp.json();

    let delegate = Identity::generate();
    let token = common::authenticate(server, &delegate).await;
    server
        .put(&format!(
            "/users/{}/roles/{}",
            delegate.public_key_hex(),
            role.id
        ))
        .authorization_bearer(owner_token)
        .await
        .assert_status_ok();

    (delegate, token)
}

#[tokio::test]
async fn delegate_cannot_mint_a_role_carrying_a_permission_they_lack() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let (_delegate, token) = manager_delegate(&server, &owner_token).await;

    // Priority 49 is below their own 50, so the priority guard passes. The
    // escalation is the permission, not the rank.
    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Enforcer",
            "permissions": ["moderation.ban.permanent"],
            "priority": 49,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    assert!(resp.text().contains("moderation.ban.permanent"));

    // What they do hold still works — the guard is a ceiling, not a freeze.
    server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Greeter",
            "permissions": ["messages.send", "channels.manage"],
            "priority": 49,
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn delegate_cannot_add_a_permission_they_lack_to_an_existing_role() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let (_delegate, token) = manager_delegate(&server, &owner_token).await;

    let created = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Greeter", "permissions": ["messages.send"], "priority": 49 }))
        .await;
    created.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = created.json();

    let resp = server
        .patch(&format!("/roles/{}", role.id))
        .authorization_bearer(&token)
        .json(&json!({ "permissions": ["messages.send", "moderation.ban.permanent"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delegate_cannot_assign_a_role_carrying_a_permission_they_lack() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let (delegate, token) = manager_delegate(&server, &owner_token).await;

    // The owner mints it, so minting is not the escalation here — assigning
    // is. Priority 20 is below the delegate's 50, so the priority guard on
    // assign_role passes and only the new check stands between them and
    // ban_members.
    let resp = server
        .post("/roles")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "Enforcer", "permissions": ["moderation.ban.permanent"], "priority": 20 }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let enforcer: RoleResponse = resp.json();

    let resp = server
        .put(&format!(
            "/users/{}/roles/{}",
            delegate.public_key_hex(),
            enforcer.id
        ))
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // The owner holds admin, so the same assignment is fine from them —
    // has() short-circuits on admin and the ceiling never bites.
    server
        .put(&format!(
            "/users/{}/roles/{}",
            delegate.public_key_hex(),
            enforcer.id
        ))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();
}
