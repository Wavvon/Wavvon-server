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
            "permissions": ["manage_channels", "manage_messages"],
            "priority": 50,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = resp.json();
    assert_eq!(role.name, "Moderator");
    assert_eq!(role.priority, 50);
    assert!(role.permissions.contains(&"manage_channels".to_string()));
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
            "permissions": ["admin"],
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
            "permissions": ["manage_roles", "manage_channels"],
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
            "permissions": ["send_messages"],
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
            "permissions": ["send_messages"],
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
