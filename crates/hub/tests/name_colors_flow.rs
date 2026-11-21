use serde_json::json;
use wavvon_identity::Identity;

use crate::common;

// ---- PATCH /me name_color: happy path + rejection ----

#[tokio::test]
async fn set_name_color_via_patch_me_roundtrips() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "name_color": "#7c5cff" }))
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<serde_json::Value>()["name_color"], "#7c5cff");

    let resp = server.get("/me").authorization_bearer(&token).await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<serde_json::Value>()["name_color"], "#7c5cff");
}

#[tokio::test]
async fn clear_name_color_with_empty_string() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "name_color": "#123456" }))
        .await
        .assert_status_ok();

    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "name_color": "" }))
        .await;
    resp.assert_status_ok();
    assert!(resp.json::<serde_json::Value>()["name_color"].is_null());
}

#[tokio::test]
async fn name_color_rejects_bad_formats() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    for bad in ["red", "#12345", "#gggggg", "7c5cff"] {
        let resp = server
            .patch("/me")
            .authorization_bearer(&token)
            .json(&json!({ "name_color": bad }))
            .await;
        resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    }
}

// ---- PATCH /hub name_color_mode: happy path + rejection ----

#[tokio::test]
async fn name_color_mode_accepts_every_valid_value() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    for mode in [
        "user_over_role",
        "role_over_user",
        "role_only",
        "user_only",
        "none",
    ] {
        server
            .patch("/hub")
            .authorization_bearer(&token)
            .json(&json!({ "name_color_mode": mode }))
            .await
            .assert_status_ok();

        let resp = server
            .get("/hub/settings")
            .authorization_bearer(&token)
            .await;
        resp.assert_status_ok();
        assert_eq!(resp.json::<serde_json::Value>()["name_color_mode"], mode);
    }
}

#[tokio::test]
async fn name_color_mode_rejects_unknown_value() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "name_color_mode": "everyone_gets_rainbow" }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn name_color_mode_defaults_to_role_over_user_when_unset() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    assert_eq!(
        resp.json::<serde_json::Value>()["name_color_mode"],
        "role_over_user"
    );
}

// ---- Resolution cascade ----

/// Sets up a second (non-owner) member with a colored role AND their own
/// `name_color` profile field, and returns (server, owner_token, member_pubkey).
async fn setup_colored_member() -> (common::TestHarness, String, String) {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;
    let member_pubkey = member.public_key_hex();

    // Give the member a role with a color.
    let resp = server
        .post("/roles")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "name": "Colorful",
            "permissions": [],
            "priority": 10,
            "color": "#ff0000",
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    server
        .put(&format!("/users/{member_pubkey}/roles/{role_id}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    // Give the member their own name_color too.
    server
        .patch("/me")
        .authorization_bearer(&member_token)
        .json(&json!({ "name_color": "#00ff00" }))
        .await
        .assert_status_ok();

    (server, owner_token, member_pubkey)
}

fn find_member<'a>(users: &'a serde_json::Value, pubkey: &str) -> &'a serde_json::Value {
    users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["public_key"] == pubkey)
        .unwrap()
}

#[tokio::test]
async fn resolution_cascade_role_over_user_prefers_role_color() {
    let (server, owner_token, member_pubkey) = setup_colored_member().await;

    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name_color_mode": "role_over_user" }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/users")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let users = resp.json::<serde_json::Value>();
    let member = find_member(&users, &member_pubkey);
    assert_eq!(member["name_color"], "#ff0000");
}

#[tokio::test]
async fn resolution_cascade_user_over_role_prefers_user_color() {
    let (server, owner_token, member_pubkey) = setup_colored_member().await;

    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name_color_mode": "user_over_role" }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/users")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let users = resp.json::<serde_json::Value>();
    let member = find_member(&users, &member_pubkey);
    assert_eq!(member["name_color"], "#00ff00");
}

#[tokio::test]
async fn resolution_cascade_none_hides_both() {
    let (server, owner_token, member_pubkey) = setup_colored_member().await;

    server
        .patch("/hub")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name_color_mode": "none" }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/users")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let users = resp.json::<serde_json::Value>();
    let member = find_member(&users, &member_pubkey);
    assert!(member["name_color"].is_null());
}
