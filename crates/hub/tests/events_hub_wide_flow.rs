/// Integration tests for hub-level events (events.md §5) and the
/// `update_event` create-time-only guard on `hub_wide`.
use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn create_channel(server: &common::TestHarness, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

/// Denies `permission` for `@everyone` on `channel_id` via the
/// channel-permission-overwrites admin route (§3.6).
async fn deny_everyone(
    server: &common::TestHarness,
    owner_token: &str,
    channel_id: &str,
    permission: &str,
) {
    let resp = server
        .put(&format!(
            "/channels/{channel_id}/permissions/builtin-everyone"
        ))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "allow": [], "deny": [permission] }))
        .await;
    resp.assert_status_ok();
}

/// Allows `permission` for `@everyone` on `channel_id` (a channel-scoped
/// grant, deliberately narrower than the hub-wide baseline).
async fn allow_everyone(
    server: &common::TestHarness,
    owner_token: &str,
    channel_id: &str,
    permission: &str,
) {
    let resp = server
        .put(&format!(
            "/channels/{channel_id}/permissions/builtin-everyone"
        ))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "allow": [permission], "deny": [] }))
        .await;
    resp.assert_status_ok();
}

/// Strips `create_events` from the hub-wide `@everyone` baseline directly
/// (the `/roles/:id` route refuses to touch builtin roles at all -- see
/// `require_not_builtin` in routes/roles.rs -- so this is done the same way
/// `event_slots_flow.rs`'s `slot_deletion_demotes_claimant_via_fk` reaches
/// past the HTTP surface to exercise a state the API can't produce itself).
async fn strip_hub_wide_create_events(server: &common::TestHarness) {
    let db = &server.state().db;
    sqlx::query(
        "DELETE FROM role_permissions WHERE role_id = 'builtin-everyone' AND permission = 'create_events'",
    )
    .execute(db)
    .await
    .expect("strip hub-wide create_events");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A member holding `CREATE_EVENTS` only via a channel overwrite (not
/// hub-wide) can still create a plain, channel-scoped event, but is rejected
/// when attempting `hub_wide: true` on the same channel.
#[tokio::test]
async fn hub_wide_create_rejected_without_hub_level_create_events() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;
    let channel_id = create_channel(&server, &owner_token).await;

    strip_hub_wide_create_events(&server).await;
    // Restore channel-scoped CREATE_EVENTS for @everyone on this one channel
    // -- narrower than the hub-wide baseline they just lost.
    allow_everyone(&server, &owner_token, &channel_id, "create_events").await;

    // hub_wide: true is rejected -- channel-scoped CREATE_EVENTS alone isn't
    // enough for a hub-wide announcement.
    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {member_token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Should be hub-wide-rejected",
            "starts_at": 9_999_999_999i64,
            "hub_wide": true,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // A plain (non-hub-wide) event on the same channel still succeeds --
    // the channel-scoped grant alone is enough for that.
    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {member_token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Plain event still fine",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event: Value = resp.json();
    assert_eq!(event["hub_wide"], false);
}

/// A member holding hub-wide `CREATE_EVENTS` (the `@everyone` default) can
/// create a `hub_wide: true` event; the response and a subsequent `GET`
/// both carry the flag.
#[tokio::test]
async fn hub_wide_create_accepted_with_hub_level_create_events() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {member_token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Community Anniversary",
            "starts_at": 9_999_999_999i64,
            "hub_wide": true,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event: Value = resp.json();
    assert_eq!(event["hub_wide"], true);
    let event_id = event["id"].as_str().unwrap().to_string();

    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {member_token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["hub_wide"], true);
}

/// A `hub_wide` event is visible in both `list_events` and `get_event` to a
/// member who cannot read the anchor channel; a non-hub-wide event on the
/// same (now-hidden) channel stays hidden from them, exactly as before.
#[tokio::test]
async fn hub_wide_event_visible_despite_unreadable_anchor() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Hub-wide Town Hall",
            "starts_at": 9_999_999_999i64,
            "hub_wide": true,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let hub_wide_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Plain Channel Event",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let plain_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    deny_everyone(&server, &owner_token, &channel_id, "read_messages").await;

    // list_events: hub-wide event survives the filter, plain one doesn't.
    let resp = server
        .get("/events?upcoming=true&limit=50")
        .add_header("Authorization", format!("Bearer {member_token}"))
        .await;
    resp.assert_status_success();
    let list: Value = resp.json();
    let arr = list.as_array().unwrap();
    assert!(
        arr.iter().any(|e| e["id"] == hub_wide_id),
        "hub-wide event must be visible despite the unreadable anchor"
    );
    assert!(
        !arr.iter().any(|e| e["id"] == plain_id),
        "non-hub-wide event must stay hidden behind the unreadable anchor"
    );

    // get_event: hub-wide 200s, plain 404s.
    let resp = server
        .get(&format!("/events/{hub_wide_id}"))
        .add_header("Authorization", format!("Bearer {member_token}"))
        .await;
    resp.assert_status_success();

    let resp = server
        .get(&format!("/events/{plain_id}"))
        .add_header("Authorization", format!("Bearer {member_token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

/// `update_event` rejects an attempted flip of `hub_wide` with 400, but
/// re-sending the same value is a harmless no-op.
#[tokio::test]
async fn update_event_cannot_flip_hub_wide() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Flip Attempt",
            "starts_at": 9_999_999_999i64,
            "hub_wide": true,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    // Attempting to flip it off is rejected.
    let resp = server
        .put(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "hub_wide": false }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // Re-sending the same value is a harmless no-op.
    let resp = server
        .put(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "hub_wide": true, "title": "Flip Attempt (renamed)" }))
        .await;
    resp.assert_status_success();
    let updated: Value = resp.json();
    assert_eq!(updated["hub_wide"], true);
    assert_eq!(updated["title"], "Flip Attempt (renamed)");
}
