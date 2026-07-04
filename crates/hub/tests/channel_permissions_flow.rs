use serde_json::json;
use wavvon_hub::routes::channel_permissions::{ChannelPermissionsResponse, RolePermissionsView};
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::routes::role_models::RoleResponse;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn create_channel(
    server: &axum_test::TestServer,
    token: &str,
    name: &str,
    parent_id: Option<&str>,
    is_category: bool,
) -> ChannelResponse {
    let mut body = json!({ "name": name, "is_category": is_category });
    if let Some(pid) = parent_id {
        body["parent_id"] = json!(pid);
    }
    let resp = server
        .post("/channels")
        .authorization_bearer(token)
        .json(&body)
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    resp.json::<ChannelResponse>()
}

async fn create_role(
    server: &axum_test::TestServer,
    token: &str,
    name: &str,
    permissions: &[&str],
    priority: i64,
) -> RoleResponse {
    let resp = server
        .post("/roles")
        .authorization_bearer(token)
        .json(&json!({ "name": name, "permissions": permissions, "priority": priority }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    resp.json::<RoleResponse>()
}

async fn assign_role(server: &axum_test::TestServer, token: &str, pubkey: &str, role_id: &str) {
    server
        .put(&format!("/users/{pubkey}/roles/{role_id}"))
        .authorization_bearer(token)
        .await
        .assert_status_ok();
}

async fn set_overwrite(
    server: &axum_test::TestServer,
    token: &str,
    channel_id: &str,
    role_id: &str,
    allow: &[&str],
    deny: &[&str],
) -> RolePermissionsView {
    let resp = server
        .put(&format!("/channels/{channel_id}/permissions/{role_id}"))
        .authorization_bearer(token)
        .json(&json!({ "allow": allow, "deny": deny }))
        .await;
    resp.assert_status_ok();
    resp.json::<RolePermissionsView>()
}

// ---- Read gating + admin immunity ----

#[tokio::test]
async fn deny_read_messages_hides_channel_and_blocks_history() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let user2_token = common::authenticate(&server, &user2).await;

    let secret = create_channel(&server, &owner_token, "secret", None, false).await;

    set_overwrite(
        &server,
        &owner_token,
        &secret.id,
        "builtin-everyone",
        &[],
        &["read_messages"],
    )
    .await;

    // user2 (only @everyone) no longer sees the channel in the list.
    let resp = server
        .get("/channels")
        .authorization_bearer(&user2_token)
        .await;
    resp.assert_status_ok();
    let channels: Vec<ChannelResponse> = resp.json();
    assert!(!channels.iter().any(|c| c.id == secret.id));

    // Direct history fetch is rejected.
    server
        .get(&format!("/channels/{}/messages", secret.id))
        .authorization_bearer(&user2_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // The owner (admin) is immune and still sees + can read the channel.
    let resp = server
        .get("/channels")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let channels: Vec<ChannelResponse> = resp.json();
    assert!(channels.iter().any(|c| c.id == secret.id));

    server
        .get(&format!("/channels/{}/messages", secret.id))
        .authorization_bearer(&owner_token)
        .await
        .assert_status_ok();
}

// ---- Cascade + child override ----

#[tokio::test]
async fn parent_deny_cascades_to_child_and_child_allow_overrides() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let user2_token = common::authenticate(&server, &user2).await;

    let category = create_channel(&server, &owner_token, "staff-cat", None, true).await;
    let child = create_channel(
        &server,
        &owner_token,
        "staff-chat",
        Some(&category.id),
        false,
    )
    .await;

    set_overwrite(
        &server,
        &owner_token,
        &category.id,
        "builtin-everyone",
        &[],
        &["read_messages"],
    )
    .await;

    // Both the category and its child are hidden from user2.
    let resp = server
        .get("/channels")
        .authorization_bearer(&user2_token)
        .await;
    let channels: Vec<ChannelResponse> = resp.json();
    assert!(!channels.iter().any(|c| c.id == category.id));
    assert!(!channels.iter().any(|c| c.id == child.id));

    // An explicit allow on the child overrides the parent's deny.
    set_overwrite(
        &server,
        &owner_token,
        &child.id,
        "builtin-everyone",
        &["read_messages"],
        &[],
    )
    .await;

    let resp = server
        .get("/channels")
        .authorization_bearer(&user2_token)
        .await;
    let channels: Vec<ChannelResponse> = resp.json();
    assert!(
        channels.iter().any(|c| c.id == child.id),
        "child's explicit allow must override the parent's deny"
    );
    assert!(
        !channels.iter().any(|c| c.id == category.id),
        "the category itself is still denied"
    );
}

// ---- Allow-wins on same-level conflict ----

#[tokio::test]
async fn allow_wins_over_deny_across_two_roles_same_channel() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let user2_token = common::authenticate(&server, &user2).await;
    let user2_key = user2.public_key_hex();

    let chan = create_channel(&server, &owner_token, "chan-conflict", None, false).await;

    let deny_role = create_role(&server, &owner_token, "DenySend", &[], 10).await;
    assign_role(&server, &owner_token, &user2_key, &deny_role.id).await;

    set_overwrite(
        &server,
        &owner_token,
        &chan.id,
        &deny_role.id,
        &[],
        &["send_messages"],
    )
    .await;

    // With only the deny role's overwrite in effect, sending is blocked.
    server
        .post(&format!("/channels/{}/messages", chan.id))
        .authorization_bearer(&user2_token)
        .json(&json!({ "content": "hello" }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // Now user2 also holds a role with an explicit allow on the same
    // channel + permission. Allow wins within the same level.
    let allow_role = create_role(&server, &owner_token, "AllowSend", &[], 10).await;
    assign_role(&server, &owner_token, &user2_key, &allow_role.id).await;
    set_overwrite(
        &server,
        &owner_token,
        &chan.id,
        &allow_role.id,
        &["send_messages"],
        &[],
    )
    .await;

    server
        .post(&format!("/channels/{}/messages", chan.id))
        .authorization_bearer(&user2_token)
        .json(&json!({ "content": "hello again" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
}

// ---- Admin routes ----

#[tokio::test]
async fn admin_routes_put_get_delete_happy_path() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let chan = create_channel(&server, &owner_token, "admin-chan", None, false).await;
    let staff = create_role(&server, &owner_token, "Staff", &[], 10).await;

    let view = set_overwrite(
        &server,
        &owner_token,
        &chan.id,
        &staff.id,
        &["manage_messages"],
        &["read_messages"],
    )
    .await;
    assert_eq!(view.role_id, staff.id);
    assert!(view
        .overwrites
        .allow
        .contains(&"manage_messages".to_string()));
    assert!(view.overwrites.deny.contains(&"read_messages".to_string()));
    assert!(view.effective.contains(&"manage_messages".to_string()));
    assert!(!view.effective.contains(&"read_messages".to_string()));

    let resp = server
        .get(&format!("/channels/{}/permissions", chan.id))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let body: ChannelPermissionsResponse = resp.json();
    assert_eq!(body.channel_id, chan.id);
    let staff_view = body
        .roles
        .iter()
        .find(|r| r.role_id == staff.id)
        .expect("staff role present in GET response");
    assert!(staff_view
        .overwrites
        .allow
        .contains(&"manage_messages".to_string()));
    assert!(staff_view
        .overwrites
        .deny
        .contains(&"read_messages".to_string()));

    // @everyone has no overwrites on this channel -- inherited == effective,
    // and both come straight from its baseline permissions.
    let everyone_view = body
        .roles
        .iter()
        .find(|r| r.role_id == "builtin-everyone")
        .expect("@everyone present in GET response");
    assert!(everyone_view.overwrites.allow.is_empty());
    assert!(everyone_view.overwrites.deny.is_empty());
    assert_eq!(everyone_view.inherited, everyone_view.effective);

    server
        .delete(&format!("/channels/{}/permissions/{}", chan.id, staff.id))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/channels/{}/permissions", chan.id))
        .authorization_bearer(&owner_token)
        .await;
    let body: ChannelPermissionsResponse = resp.json();
    let staff_view = body
        .roles
        .iter()
        .find(|r| r.role_id == staff.id)
        .expect("staff role still present after clearing overwrites");
    assert!(staff_view.overwrites.allow.is_empty());
    assert!(staff_view.overwrites.deny.is_empty());
}

#[tokio::test]
async fn admin_routes_reject_non_admin() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let user2_token = common::authenticate(&server, &user2).await;

    let chan = create_channel(&server, &owner_token, "guarded-chan", None, false).await;

    server
        .put(&format!(
            "/channels/{}/permissions/builtin-everyone",
            chan.id
        ))
        .authorization_bearer(&user2_token)
        .json(&json!({ "allow": [], "deny": ["send_messages"] }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ---- H2: priority / self-grant / admin-escalation guards ----

/// Sets up a channel plus a "Manager" role (priority 10) holding
/// `manage_roles` + `send_messages` hub-wide -- MANAGE_ROLES but not admin --
/// assigned to `user2`. This mirrors the delegated subtree-manager the
/// channel-permission-overwrites feature exists to enable.
async fn setup_manager(
    server: &axum_test::TestServer,
) -> (String, String, String, RoleResponse, String) {
    let owner = Identity::generate();
    let owner_token = common::authenticate(server, &owner).await;

    let user2 = Identity::generate();
    let user2_token = common::authenticate(server, &user2).await;
    let user2_key = user2.public_key_hex();

    let chan = create_channel(server, &owner_token, "h2-chan", None, false).await;

    let manager = create_role(
        server,
        &owner_token,
        "Manager",
        &["manage_roles", "send_messages"],
        10,
    )
    .await;
    assign_role(server, &owner_token, &user2_key, &manager.id).await;

    (owner_token, user2_token, chan.id, manager, user2_key)
}

#[tokio::test]
async fn manager_cannot_grant_admin_via_overwrite() {
    let server = common::setup().await;
    let (_owner_token, user2_token, chan_id, _manager, _user2_key) = setup_manager(&server).await;

    server
        .put(&format!("/channels/{chan_id}/permissions/builtin-everyone"))
        .authorization_bearer(&user2_token)
        .json(&json!({ "allow": ["admin"], "deny": [] }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn manager_cannot_grant_permission_they_do_not_hold() {
    let server = common::setup().await;
    let (_owner_token, user2_token, chan_id, _manager, _user2_key) = setup_manager(&server).await;

    // Manager holds manage_roles + send_messages, not manage_channels.
    server
        .put(&format!("/channels/{chan_id}/permissions/builtin-everyone"))
        .authorization_bearer(&user2_token)
        .json(&json!({ "allow": ["manage_channels"], "deny": [] }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn manager_cannot_edit_overwrites_for_higher_priority_role() {
    let server = common::setup().await;
    let (owner_token, user2_token, chan_id, _manager, _user2_key) = setup_manager(&server).await;

    // A role ranked above the manager (priority 20 > manager's 10).
    let senior = create_role(&server, &owner_token, "Senior", &[], 20).await;

    server
        .put(&format!("/channels/{chan_id}/permissions/{}", senior.id))
        .authorization_bearer(&user2_token)
        .json(&json!({ "allow": ["send_messages"], "deny": [] }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // DELETE is guarded the same way.
    server
        .delete(&format!("/channels/{chan_id}/permissions/{}", senior.id))
        .authorization_bearer(&user2_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn manager_can_grant_permission_they_hold_on_same_or_lower_role() {
    let server = common::setup().await;
    let (_owner_token, user2_token, chan_id, _manager, _user2_key) = setup_manager(&server).await;

    // builtin-everyone (priority 0) is below the manager's 10, and
    // send_messages is a permission the manager effectively holds.
    let view = set_overwrite(
        &server,
        &user2_token,
        &chan_id,
        "builtin-everyone",
        &["send_messages"],
        &[],
    )
    .await;
    assert!(view.overwrites.allow.contains(&"send_messages".to_string()));
}

#[tokio::test]
async fn admin_routes_reject_unknown_permission() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let chan = create_channel(&server, &owner_token, "bad-perm-chan", None, false).await;

    server
        .put(&format!(
            "/channels/{}/permissions/builtin-everyone",
            chan.id
        ))
        .authorization_bearer(&owner_token)
        .json(&json!({ "allow": ["not_a_real_permission"], "deny": [] }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);
}

// ---- SEND_MESSAGES channel deny blocks only that channel ----

#[tokio::test]
async fn send_messages_deny_blocks_one_channel_not_sibling() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let user2_token = common::authenticate(&server, &user2).await;

    let chan_a = create_channel(&server, &owner_token, "chan-a", None, false).await;
    let chan_b = create_channel(&server, &owner_token, "chan-b", None, false).await;

    set_overwrite(
        &server,
        &owner_token,
        &chan_a.id,
        "builtin-everyone",
        &[],
        &["send_messages"],
    )
    .await;

    server
        .post(&format!("/channels/{}/messages", chan_a.id))
        .authorization_bearer(&user2_token)
        .json(&json!({ "content": "blocked" }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    server
        .post(&format!("/channels/{}/messages", chan_b.id))
        .authorization_bearer(&user2_token)
        .json(&json!({ "content": "still works" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
}
