use axum_test::TestServer;
use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn create_channel(server: &TestServer, token: &str) -> String {
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
async fn deny_everyone(server: &TestServer, owner_token: &str, channel_id: &str, permission: &str) {
    let resp = server
        .put(&format!(
            "/channels/{channel_id}/permissions/builtin-everyone"
        ))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "allow": [], "deny": [permission] }))
        .await;
    resp.assert_status_ok();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy-path: create an event, list it, get by id, RSVP, list RSVPs.
#[tokio::test]
async fn event_happy_path() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    // POST /events
    let starts_at = 9_999_999_999i64;
    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Dev Hangout",
            "description": "Monthly sync",
            "starts_at": starts_at,
            "location": "Voice #lounge",
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event: Value = resp.json();
    let event_id = event["id"].as_str().unwrap().to_string();
    assert_eq!(event["title"], "Dev Hangout");
    assert_eq!(event["starts_at"], starts_at);

    // GET /events?upcoming=true should include the event (starts_at is far future).
    let resp = server
        .get("/events?upcoming=true&limit=10")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let list: Value = resp.json();
    let arr = list.as_array().unwrap();
    assert!(arr.iter().any(|e| e["id"] == event_id));

    // GET /events/:id
    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["id"], event_id);
    assert_eq!(detail["rsvp_counts"]["going"], 0);

    // POST /events/:id/rsvp
    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "status": "going" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // GET /events/:id should now show rsvp_counts.going = 1
    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["rsvp_counts"]["going"], 1);

    // GET /events/:id/rsvps
    let resp = server
        .get(&format!("/events/{event_id}/rsvps"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let rsvps: Value = resp.json();
    assert_eq!(rsvps.as_array().unwrap().len(), 1);
    assert_eq!(rsvps[0]["status"], "going");

    // DELETE /events/:id
    let resp = server
        .delete(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Confirm deleted.
    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

/// Card message inserted by create_event uses the creator's pubkey as sender,
/// not the old zero-string phantom sender.
#[tokio::test]
async fn event_card_sender_is_creator() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Sender check event",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event: Value = resp.json();
    let creator_pubkey = event["creator_pubkey"].as_str().unwrap().to_string();

    let resp = server
        .get(&format!("/channels/{channel_id}/messages"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let messages: Value = resp.json();
    let msgs = messages.as_array().unwrap();
    assert!(!msgs.is_empty(), "expected at least one card message");
    let card = &msgs[0];
    assert_eq!(
        card["sender"].as_str().unwrap(),
        creator_pubkey,
        "event card sender must be the creator, not the zero phantom"
    );
    let zero = "00000000000000000000000000000000000000000000000000000000000000000000";
    assert_ne!(card["sender"].as_str().unwrap(), zero);
}

/// Non-creator without admin cannot delete another user's event.
#[tokio::test]
async fn event_delete_rejected_for_non_creator() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let other = Identity::generate();
    let token_owner = common::authenticate(&server, &owner).await;
    let token_other = common::authenticate(&server, &other).await;
    let channel_id = create_channel(&server, &token_owner).await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {token_owner}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Owner-only event",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let resp = server
        .delete(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token_other}"))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ---- H3: channel-read-gating ----

/// A member denied `read_messages` on a channel never sees that channel's
/// events in `list_events` and 404s (not 403 -- the event id alone must not
/// confirm existence) on `get_event`.
#[tokio::test]
async fn denied_member_cannot_list_or_get_hidden_channel_events() {
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
            "title": "Hidden Channel Event",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    deny_everyone(&server, &owner_token, &channel_id, "read_messages").await;

    // list_events: the event must be filtered out for the denied member.
    let resp = server
        .get("/events?upcoming=true&limit=50")
        .add_header("Authorization", format!("Bearer {member_token}"))
        .await;
    resp.assert_status_success();
    let list: Value = resp.json();
    let arr = list.as_array().unwrap();
    assert!(
        !arr.iter().any(|e| e["id"] == event_id),
        "denied member must not see the hidden channel's event in the list"
    );

    // The owner (admin) still sees it.
    let resp = server
        .get("/events?upcoming=true&limit=50")
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let list: Value = resp.json();
    let arr = list.as_array().unwrap();
    assert!(arr.iter().any(|e| e["id"] == event_id));

    // get_event: 404, not 403, since the event id doesn't reveal the
    // channel -- a 403 here would confirm the event's existence.
    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {member_token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);

    // The owner (admin) can still fetch it directly.
    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    resp.assert_status_success();
}

/// `create_event` is gated on the target channel's effective CREATE_EVENTS,
/// not the hub-wide baseline -- a member denied on the channel cannot
/// create an event targeting it even though @everyone holds CREATE_EVENTS
/// hub-wide.
#[tokio::test]
async fn create_event_rejected_on_channel_denied_create_events() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    let channel_id = create_channel(&server, &owner_token).await;
    deny_everyone(&server, &owner_token, &channel_id, "create_events").await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {member_token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Should be rejected",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // The owner (admin) is unaffected.
    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "channel_id": channel_id,
            "title": "Owner can still create",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
}

/// Invalid RSVP status is rejected.
#[tokio::test]
async fn event_rsvp_rejects_invalid_status() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "channel_id": channel_id, "title": "T", "starts_at": 9_999_999_999i64 }))
        .await;
    let event_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "status": "yes_please" }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}
