use serde_json::json;
use wavvon_hub::routes::role_models::{RoleCategoryResponse, RoleResponse};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn category_crud_happy_path_and_ordering() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Create two categories out of position order.
    let resp = server
        .post("/role-categories")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Games", "color": "#00FF00", "icon": "🎮", "position": 1 }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let games: RoleCategoryResponse = resp.json();
    assert_eq!(games.name, "Games");
    assert_eq!(games.color.as_deref(), Some("#00FF00"));
    assert_eq!(games.icon.as_deref(), Some("🎮"));
    assert_eq!(games.position, 1);

    let resp = server
        .post("/role-categories")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Staff", "position": 0 }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let staff: RoleCategoryResponse = resp.json();
    assert_eq!(staff.color, None);
    assert_eq!(staff.icon, None);

    // GET lists ordered by position ASC: Staff (0) before Games (1).
    let resp = server
        .get("/role-categories")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let list: Vec<RoleCategoryResponse> = resp.json();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, staff.id);
    assert_eq!(list[1].id, games.id);

    // PATCH renames and recolors Staff.
    let resp = server
        .patch(&format!("/role-categories/{}", staff.id))
        .authorization_bearer(&token)
        .json(&json!({ "name": "Leadership", "color": "#123ABC" }))
        .await;
    resp.assert_status_ok();
    let updated: RoleCategoryResponse = resp.json();
    assert_eq!(updated.name, "Leadership");
    assert_eq!(updated.color.as_deref(), Some("#123ABC"));

    // DELETE removes it.
    let resp = server
        .delete(&format!("/role-categories/{}", staff.id))
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get("/role-categories")
        .authorization_bearer(&token)
        .await;
    let list: Vec<RoleCategoryResponse> = resp.json();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, games.id);
}

#[tokio::test]
async fn role_created_with_color_icon_category_reads_back() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/role-categories")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Staff" }))
        .await;
    let category: RoleCategoryResponse = resp.json();

    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Moderator",
            "permissions": ["manage_messages"],
            "priority": 50,
            "color": "#FF00AA",
            "icon": "🛡️",
            "category_id": category.id,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = resp.json();
    assert_eq!(role.color.as_deref(), Some("#FF00AA"));
    assert_eq!(role.icon.as_deref(), Some("🛡️"));
    assert_eq!(role.category_id.as_deref(), Some(category.id.as_str()));

    // Read back through GET /roles.
    let resp = server.get("/roles").authorization_bearer(&token).await;
    let roles: Vec<RoleResponse> = resp.json();
    let fetched = roles.iter().find(|r| r.id == role.id).unwrap();
    assert_eq!(fetched.color.as_deref(), Some("#FF00AA"));
    assert_eq!(fetched.icon.as_deref(), Some("🛡️"));
    assert_eq!(fetched.category_id.as_deref(), Some(category.id.as_str()));
}

#[tokio::test]
async fn user_profile_endpoint_carries_role_category_color_and_icon() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let pub_key = owner.public_key_hex();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/role-categories")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Staff" }))
        .await;
    let category: RoleCategoryResponse = resp.json();

    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Moderator",
            "permissions": ["manage_messages"],
            "priority": 50,
            "color": "#FF00AA",
            "icon": "🛡️",
            "category_id": category.id,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role: RoleResponse = resp.json();

    // Assign the categorized role to the owner.
    let resp = server
        .put(&format!("/users/{pub_key}/roles/{}", role.id))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();

    // The public profile endpoint must carry category_id/color/icon so the
    // member card can group the role under its category. Regression: it used
    // to select `NULL as color` and omit icon/category_id entirely, so every
    // role landed under "Uncategorized" with no tint.
    let resp = server
        .get(&format!("/users/{pub_key}/profile"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let profile: serde_json::Value = resp.json();
    let roles = profile["roles"].as_array().unwrap();
    let mod_role = roles
        .iter()
        .find(|r| r["id"] == role.id)
        .expect("Moderator role present in profile");
    assert_eq!(mod_role["category_id"], category.id);
    assert_eq!(mod_role["color"], "#FF00AA");
    assert_eq!(mod_role["icon"], "🛡️");
}

#[tokio::test]
async fn deleting_category_sets_role_category_id_null() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/role-categories")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Staff" }))
        .await;
    let category: RoleCategoryResponse = resp.json();

    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Moderator",
            "permissions": ["manage_messages"],
            "priority": 50,
            "category_id": category.id,
        }))
        .await;
    let role: RoleResponse = resp.json();
    assert_eq!(role.category_id.as_deref(), Some(category.id.as_str()));

    let resp = server
        .delete(&format!("/role-categories/{}", category.id))
        .authorization_bearer(&token)
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Role falls back to uncategorized -- verified through the API.
    let resp = server.get("/roles").authorization_bearer(&token).await;
    let roles: Vec<RoleResponse> = resp.json();
    let fetched = roles.iter().find(|r| r.id == role.id).unwrap();
    assert_eq!(fetched.category_id, None);
}

#[tokio::test]
async fn non_manage_roles_user_forbidden_on_category_mutations() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .post("/role-categories")
        .authorization_bearer(&token2)
        .json(&json!({ "name": "Hacker Group" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // Owner creates a category so PATCH/DELETE have a target to attempt against.
    let resp = server
        .post("/role-categories")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "Staff" }))
        .await;
    let category: RoleCategoryResponse = resp.json();

    let resp = server
        .patch(&format!("/role-categories/{}", category.id))
        .authorization_bearer(&token2)
        .json(&json!({ "name": "Hacked" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    let resp = server
        .delete(&format!("/role-categories/{}", category.id))
        .authorization_bearer(&token2)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn invalid_color_rejected_with_400() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Bad color on category create.
    let resp = server
        .post("/role-categories")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Staff", "color": "not-a-color" }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // Bad color on role create.
    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Moderator",
            "permissions": [],
            "priority": 10,
            "color": "red",
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_category_id_rejected_with_400() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/roles")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Moderator",
            "permissions": [],
            "priority": 10,
            "category_id": "does-not-exist",
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}
