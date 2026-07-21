use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---- Birthday: happy path ----

#[tokio::test]
async fn set_birthday_via_patch_me_visible_in_me_and_member_listing() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "birthday": "07-22" }))
        .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["birthday"], "07-22");

    let resp = server.get("/me").authorization_bearer(&token).await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<serde_json::Value>()["birthday"], "07-22");

    let resp = server
        .get("/hub/members")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let members = resp.json::<serde_json::Value>();
    let me = members
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["public_key"] == owner.public_key_hex())
        .unwrap();
    assert_eq!(me["birthday"], "07-22");
}

#[tokio::test]
async fn clear_birthday_with_empty_string() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "birthday": "12-25" }))
        .await
        .assert_status_ok();

    let resp = server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "birthday": "" }))
        .await;
    resp.assert_status_ok();
    assert!(resp.json::<serde_json::Value>()["birthday"].is_null());
}

// ---- Birthday: rejection on bad formats ----

#[tokio::test]
async fn birthday_rejects_bad_formats() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    for bad in ["1990-07-22", "13-01", "07-32", "junk", "02-30", "04-31"] {
        let resp = server
            .patch("/me")
            .authorization_bearer(&token)
            .json(&json!({ "birthday": bad }))
            .await;
        resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn birthday_accepts_feb_29() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "birthday": "02-29" }))
        .await
        .assert_status_ok();
}

// ---- Birthday: gating via birthdays_enabled ----

#[tokio::test]
async fn disabling_birthdays_hides_them_from_member_listing_and_blocks_patch() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Owner sets a birthday while enabled (default true).
    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "birthday": "03-15" }))
        .await
        .assert_status_ok();

    // Admin disables birthdays hub-wide.
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "birthdays_enabled": false }))
        .await
        .assert_status_ok();

    // Member listing must omit the birthday now.
    let resp = server
        .get("/hub/members")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let members = resp.json::<serde_json::Value>();
    let me = members
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["public_key"] == owner.public_key_hex())
        .unwrap();
    assert!(me["birthday"].is_null());

    // Setting a new birthday while disabled is rejected.
    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "birthday": "04-01" }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);

    // The owner's own GET /me still shows the previously stored value.
    let resp = server.get("/me").authorization_bearer(&token).await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<serde_json::Value>()["birthday"], "03-15");
}

#[tokio::test]
async fn disabling_birthdays_hides_them_from_user_profile_for_others_not_self() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;
    let second = Identity::generate();
    let second_token = common::authenticate(&server, &second).await;

    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "birthday": "09-09" }))
        .await
        .assert_status_ok();

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "birthdays_enabled": false }))
        .await
        .assert_status_ok();

    // Another member viewing the owner's profile: hidden.
    let resp = server
        .get(&format!("/users/{}/profile", owner.public_key_hex()))
        .authorization_bearer(&second_token)
        .await;
    resp.assert_status_ok();
    assert!(resp.json::<serde_json::Value>()["birthday"].is_null());

    // Owner viewing their own profile: still visible.
    let resp = server
        .get(&format!("/users/{}/profile", owner.public_key_hex()))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<serde_json::Value>()["birthday"], "09-09");
}

#[tokio::test]
async fn user_roster_includes_birthday_when_enabled_and_omits_when_disabled() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/me")
        .authorization_bearer(&token)
        .json(&json!({ "birthday": "05-05" }))
        .await
        .assert_status_ok();

    // Enabled (default): GET /users shows it.
    let resp = server.get("/users").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let users = resp.json::<serde_json::Value>();
    let me = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["public_key"] == owner.public_key_hex())
        .unwrap();
    assert_eq!(me["birthday"], "05-05");

    // Disabled: GET /users (and the per-channel roster) must null it out.
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "birthdays_enabled": false }))
        .await
        .assert_status_ok();

    let resp = server.get("/users").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let users = resp.json::<serde_json::Value>();
    let me = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["public_key"] == owner.public_key_hex())
        .unwrap();
    assert!(me["birthday"].is_null());

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let channel_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .get(&format!("/channels/{channel_id}/members"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let members = resp.json::<serde_json::Value>();
    let me = members
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["public_key"] == owner.public_key_hex())
        .unwrap();
    assert!(me["birthday"].is_null());
}

// ---- Timezone: settings + public info ----

#[tokio::test]
async fn set_valid_timezone_visible_in_settings_and_public_info() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "timezone": "Europe/Rome" }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<serde_json::Value>()["timezone"], "Europe/Rome");

    let resp = server.get("/info").await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<serde_json::Value>()["timezone"], "Europe/Rome");
}

#[tokio::test]
async fn timezone_rejects_too_long_and_bad_charset() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let too_long = "A".repeat(65);
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "timezone": too_long }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "timezone": "Europe/Rome; DROP TABLE users" }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);
}
