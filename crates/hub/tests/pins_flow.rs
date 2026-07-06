use axum_test::TestServer;
use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn create_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .authorization_bearer(token)
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

async fn send_message(server: &TestServer, token: &str, channel_id: &str, content: &str) -> String {
    let resp = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(token)
        .json(&json!({ "content": content }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    resp.json::<Value>()["id"].as_str().unwrap().to_string()
}

/// Denies `permission` for `@everyone` on `channel_id` via the
/// channel-permission-overwrites admin route (§3.6).
async fn deny_everyone(server: &TestServer, owner_token: &str, channel_id: &str, permission: &str) {
    let resp = server
        .put(&format!(
            "/channels/{channel_id}/permissions/builtin-everyone"
        ))
        .authorization_bearer(owner_token)
        .json(&json!({ "allow": [], "deny": [permission] }))
        .await;
    resp.assert_status_ok();
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn pin_list_unpin_happy_path() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let channel_id = create_channel(&server, &owner_token).await;
    let message_id = send_message(&server, &owner_token, &channel_id, "pin me").await;

    server
        .post(&format!("/channels/{channel_id}/pins/{message_id}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/channels/{channel_id}/pins"))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let pins: Value = resp.json();
    let arr = pins.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["message_id"], message_id);

    server
        .delete(&format!("/channels/{channel_id}/pins/{message_id}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/channels/{channel_id}/pins"))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let pins: Value = resp.json();
    assert!(pins.as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// H4: read-gating + write-side channel scoping
// ---------------------------------------------------------------------------

/// A member denied `read_messages` on a channel gets 403 on
/// `list_pins`; the admin (immune) still sees the pin.
#[tokio::test]
async fn list_pins_rejected_for_member_denied_read_messages() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    let channel_id = create_channel(&server, &owner_token).await;
    let message_id = send_message(&server, &owner_token, &channel_id, "secret pin").await;
    server
        .post(&format!("/channels/{channel_id}/pins/{message_id}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    deny_everyone(&server, &owner_token, &channel_id, "read_messages").await;

    server
        .get(&format!("/channels/{channel_id}/pins"))
        .authorization_bearer(&member_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // The owner (admin) is unaffected.
    let resp = server
        .get(&format!("/channels/{channel_id}/pins"))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let pins: Value = resp.json();
    assert_eq!(pins.as_array().unwrap().len(), 1);
}

/// `pin_message`/`unpin_message` are gated on channel-scoped
/// MANAGE_MESSAGES, not the hub-wide baseline: a member denied
/// `manage_messages` on this specific channel cannot pin here even if a
/// hub-wide grant would otherwise allow it on other channels.
#[tokio::test]
async fn pin_and_unpin_use_channel_scoped_manage_messages() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;
    let member_key = member.public_key_hex();

    let channel_id = create_channel(&server, &owner_token).await;
    let message_id = send_message(&server, &owner_token, &channel_id, "hi").await;

    // Grant the member hub-wide manage_messages via a role (not admin).
    let resp = server
        .post("/roles")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "Moderator", "permissions": ["manage_messages"], "priority": 10 }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let role_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();
    server
        .put(&format!("/users/{member_key}/roles/{role_id}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();

    // Baseline: the member can pin, since nothing overrides manage_messages
    // on this channel yet.
    server
        .post(&format!("/channels/{channel_id}/pins/{message_id}"))
        .authorization_bearer(&member_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // A channel-scoped deny of manage_messages for the Moderator role now
    // blocks pin/unpin on this specific channel -- proving the check is
    // channel_permissions-based, not the hub-wide baseline.
    server
        .put(&format!("/channels/{channel_id}/permissions/{role_id}"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "allow": [], "deny": ["manage_messages"] }))
        .await
        .assert_status_ok();

    server
        .delete(&format!("/channels/{channel_id}/pins/{message_id}"))
        .authorization_bearer(&member_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}
