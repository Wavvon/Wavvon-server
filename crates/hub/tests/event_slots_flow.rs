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

async fn create_event(server: &TestServer, token: &str, channel_id: &str, body: Value) -> Value {
    let mut payload = json!({
        "channel_id": channel_id,
        "title": "Raid Night",
        "starts_at": 9_999_999_999i64,
    });
    for (k, v) in body.as_object().unwrap() {
        payload[k] = v.clone();
    }
    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&payload)
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    resp.json()
}

// ---------------------------------------------------------------------------
// Slot creation on POST /events
// ---------------------------------------------------------------------------

/// Creating an event with `slots` seeds them in array order; `GET /events/:id`
/// reflects them with zero claimants.
#[tokio::test]
async fn create_event_with_slots() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let event = create_event(
        &server,
        &token,
        &channel_id,
        json!({
            "slots": [
                { "name": "Tank", "capacity": 2 },
                { "name": "Healer", "capacity": 4 },
                { "name": "Bench" },
            ]
        }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();

    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    let slots = detail["slots"].as_array().unwrap();
    assert_eq!(slots.len(), 3);
    assert_eq!(slots[0]["name"], "Tank");
    assert_eq!(slots[0]["capacity"], 2);
    assert_eq!(slots[0]["position"], 0);
    assert_eq!(slots[0]["claimed"], 0);
    assert!(slots[0]["claimants"].as_array().unwrap().is_empty());
    assert_eq!(slots[1]["name"], "Healer");
    assert_eq!(slots[1]["position"], 1);
    assert_eq!(slots[2]["name"], "Bench");
    assert!(slots[2]["capacity"].is_null());
    assert_eq!(slots[2]["position"], 2);
}

// ---------------------------------------------------------------------------
// Claiming a slot via RSVP
// ---------------------------------------------------------------------------

/// Claiming a slot shows up as a claimant in `EventWithRsvps.slots`.
#[tokio::test]
async fn rsvp_claims_a_slot() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "Tank", "capacity": 2 }] }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();
    let slot_id = {
        let resp = server
            .get(&format!("/events/{event_id}"))
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .await;
        let detail: Value = resp.json();
        detail["slots"][0]["id"].as_str().unwrap().to_string()
    };

    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let detail: Value = resp.json();
    let slot = &detail["slots"][0];
    assert_eq!(slot["claimed"], 1);
    assert_eq!(
        slot["claimants"].as_array().unwrap()[0],
        owner.public_key_hex()
    );
}

/// Claiming a slot with a full capacity of one succeeds for the first
/// claimant and 409s for a second, distinct claimant.
#[tokio::test]
async fn slot_capacity_enforced() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let other = Identity::generate();
    let other_token = common::authenticate(&server, &other).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "Tank", "capacity": 1 }] }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();
    let slot_id = {
        let resp = server
            .get(&format!("/events/{event_id}"))
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .await;
        let detail: Value = resp.json();
        detail["slots"][0]["id"].as_str().unwrap().to_string()
    };

    // First claimant succeeds.
    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Second, distinct claimant is rejected: the slot is full.
    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {other_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::CONFLICT);
}

/// A user can switch which slot they've claimed; the old slot's claim count
/// drops and the new slot's rises.
#[tokio::test]
async fn rsvp_can_switch_slots() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "Tank", "capacity": 1 }, { "name": "Healer", "capacity": 1 }] }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();
    let (tank_id, healer_id) = {
        let resp = server
            .get(&format!("/events/{event_id}"))
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .await;
        let detail: Value = resp.json();
        (
            detail["slots"][0]["id"].as_str().unwrap().to_string(),
            detail["slots"][1]["id"].as_str().unwrap().to_string(),
        )
    };

    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": tank_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Switch to Healer.
    let resp = server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": healer_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let detail: Value = resp.json();
    let slots = detail["slots"].as_array().unwrap();
    let tank = slots.iter().find(|s| s["id"] == tank_id).unwrap();
    let healer = slots.iter().find(|s| s["id"] == healer_id).unwrap();
    assert_eq!(tank["claimed"], 0);
    assert_eq!(healer["claimed"], 1);
}

/// RSVP'ing "maybe" or "not_going" clears any slot claim, and RSVP'ing
/// "going" with no slot_id also clears it.
#[tokio::test]
async fn rsvp_status_change_clears_slot() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "Tank", "capacity": 1 }] }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();
    let slot_id = {
        let resp = server
            .get(&format!("/events/{event_id}"))
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .await;
        let detail: Value = resp.json();
        detail["slots"][0]["id"].as_str().unwrap().to_string()
    };

    server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_id }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "maybe" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let detail: Value = resp.json();
    assert_eq!(detail["slots"][0]["claimed"], 0);
}

/// Claiming a slot that doesn't belong to the event 404s.
#[tokio::test]
async fn rsvp_rejects_slot_from_another_event() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event_a = create_event(&server, &owner_token, &channel_id, json!({})).await;
    let event_b = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "Tank" }] }),
    )
    .await;
    let event_a_id = event_a["id"].as_str().unwrap();
    let event_b_id = event_b["id"].as_str().unwrap();

    let resp = server
        .get(&format!("/events/{event_b_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let detail: Value = resp.json();
    let slot_from_b = detail["slots"][0]["id"].as_str().unwrap().to_string();

    let resp = server
        .post(&format!("/events/{event_a_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_from_b }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Slot management routes
// ---------------------------------------------------------------------------

/// PATCH rejects shrinking capacity below the current claim count.
#[tokio::test]
async fn patch_slot_rejects_capacity_below_claims() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let other = Identity::generate();
    let other_token = common::authenticate(&server, &other).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "DPS", "capacity": 3 }] }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();
    let slot_id = {
        let resp = server
            .get(&format!("/events/{event_id}"))
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .await;
        let detail: Value = resp.json();
        detail["slots"][0]["id"].as_str().unwrap().to_string()
    };

    // Two claimants.
    server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_id }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
    server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {other_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_id }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Shrinking to 1 (below the 2 current claims) is rejected.
    let resp = server
        .patch(&format!("/events/{event_id}/slots/{slot_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "capacity": 1 }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);

    // Resizing to exactly the claim count (2) succeeds.
    let resp = server
        .patch(&format!("/events/{event_id}/slots/{slot_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "capacity": 2, "name": "DPS (full)" }))
        .await;
    resp.assert_status_success();
    let slot: Value = resp.json();
    assert_eq!(slot["capacity"], 2);
    assert_eq!(slot["name"], "DPS (full)");
    assert_eq!(slot["claimed"], 2);
}

/// PATCH capacity to null clears it (unlimited).
#[tokio::test]
async fn patch_slot_can_clear_capacity() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "Bench", "capacity": 2 }] }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();
    let slot_id = {
        let resp = server
            .get(&format!("/events/{event_id}"))
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .await;
        let detail: Value = resp.json();
        detail["slots"][0]["id"].as_str().unwrap().to_string()
    };

    let resp = server
        .patch(&format!("/events/{event_id}/slots/{slot_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "capacity": null }))
        .await;
    resp.assert_status_success();
    let slot: Value = resp.json();
    assert!(slot["capacity"].is_null());
}

/// DELETE 409s while the slot has claimants, then succeeds once empty.
#[tokio::test]
async fn delete_slot_requires_empty() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "Tank", "capacity": 2 }] }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();
    let slot_id = {
        let resp = server
            .get(&format!("/events/{event_id}"))
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .await;
        let detail: Value = resp.json();
        detail["slots"][0]["id"].as_str().unwrap().to_string()
    };

    server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_id }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Claimed -> 409.
    let resp = server
        .delete(&format!("/events/{event_id}/slots/{slot_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::CONFLICT);

    // Clear the claim (switch to "maybe"), then deletion succeeds.
    server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "maybe" }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .delete(&format!("/events/{event_id}/slots/{slot_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);
}

/// Standalone `POST /events/:id/slots` appends after existing slots
/// (position keeps incrementing), and a non-creator member holding
/// `CREATE_EVENTS` hub-wide (the default `@everyone` grant) can manage
/// slots even without being the event's creator.
#[tokio::test]
async fn create_slot_route_allows_create_events_holder() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(&server, &owner_token, &channel_id, json!({})).await;
    let event_id = event["id"].as_str().unwrap().to_string();

    // Member is not the creator but holds CREATE_EVENTS hub-wide by default.
    let resp = server
        .post(&format!("/events/{event_id}/slots"))
        .add_header("Authorization", format!("Bearer {member_token}"))
        .json(&json!({ "name": "Tank", "capacity": 2 }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let slot: Value = resp.json();
    assert_eq!(slot["name"], "Tank");
    assert_eq!(slot["position"], 0);
    assert_eq!(slot["claimed"], 0);
}

/// A member denied `create_events` on the event's channel, and who isn't the
/// creator, cannot manage slots.
#[tokio::test]
async fn slot_management_rejected_without_channel_create_events() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(&server, &owner_token, &channel_id, json!({})).await;
    let event_id = event["id"].as_str().unwrap().to_string();

    let resp = server
        .put(&format!(
            "/channels/{channel_id}/permissions/builtin-everyone"
        ))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "allow": [], "deny": ["create_events"] }))
        .await;
    resp.assert_status_ok();

    let resp = server
        .post(&format!("/events/{event_id}/slots"))
        .add_header("Authorization", format!("Bearer {member_token}"))
        .json(&json!({ "name": "Tank" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // The creator is unaffected.
    let resp = server
        .post(&format!("/events/{event_id}/slots"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "name": "Tank" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
}

// ---------------------------------------------------------------------------
// Slot deletion FK behavior (defense in depth)
// ---------------------------------------------------------------------------

/// If an `event_slots` row is ever removed directly (bypassing the
/// app-level "must be empty" gate -- e.g. a future admin tool, or manual
/// intervention), `ON DELETE SET NULL` demotes claimants to a plain "going"
/// RSVP rather than deleting their row. Exercised directly at the SQL level
/// since the HTTP route always blocks deleting a claimed slot (409).
#[tokio::test]
async fn slot_deletion_demotes_claimant_via_fk() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "slots": [{ "name": "Tank", "capacity": 2 }] }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();
    let slot_id = {
        let resp = server
            .get(&format!("/events/{event_id}"))
            .add_header("Authorization", format!("Bearer {owner_token}"))
            .await;
        let detail: Value = resp.json();
        detail["slots"][0]["id"].as_str().unwrap().to_string()
    };

    server
        .post(&format!("/events/{event_id}/rsvp"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "status": "going", "slot_id": slot_id }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Bypass the app-level gate entirely: delete the slot row directly.
    let db = &server.state().db;
    sqlx::query("DELETE FROM event_slots WHERE id = $1")
        .bind(&slot_id)
        .execute(db)
        .await
        .expect("direct slot delete should succeed");

    let (status, remaining_slot_id): (String, Option<String>) = sqlx::query_as(
        "SELECT status, slot_id FROM event_rsvps WHERE event_id = $1 AND user_pubkey = $2",
    )
    .bind(&event_id)
    .bind(owner.public_key_hex())
    .fetch_one(db)
    .await
    .expect("rsvp row must survive slot deletion");

    assert_eq!(status, "going");
    assert!(
        remaining_slot_id.is_none(),
        "slot_id must be demoted to NULL, not left dangling"
    );
}

// ---------------------------------------------------------------------------
// Reminders
// ---------------------------------------------------------------------------

/// A single reminder-worker tick posts a card and sets `reminder_sent_at`
/// for an event whose reminder instant has arrived; it leaves alone events
/// with no reminder configured, events not yet due, and events whose
/// reminder was already sent.
#[tokio::test]
async fn reminder_worker_sends_once_for_due_events() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let now = wavvon_hub::auth::handlers::unix_timestamp();

    // Due: starts in 10 minutes, reminder offset 15 minutes (instant already
    // passed) -- and hasn't started yet.
    let due_event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "starts_at": now + 600, "reminder_minutes": 15 }),
    )
    .await;
    let due_id = due_event["id"].as_str().unwrap().to_string();

    // Not due: starts far in the future, reminder offset only 15 minutes
    // (instant hasn't arrived).
    let future_event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "starts_at": now + 100_000, "reminder_minutes": 15 }),
    )
    .await;
    let future_id = future_event["id"].as_str().unwrap().to_string();

    // No reminder configured at all.
    let no_reminder_event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "starts_at": now + 600 }),
    )
    .await;
    let no_reminder_id = no_reminder_event["id"].as_str().unwrap().to_string();

    let state = server.state();
    wavvon_hub::reminder_worker::tick(state)
        .await
        .expect("tick should succeed");

    let due_sent: Option<i64> =
        sqlx::query_scalar("SELECT reminder_sent_at FROM hub_events WHERE id = $1")
            .bind(&due_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(due_sent.is_some(), "due event's reminder should be sent");

    let future_sent: Option<i64> =
        sqlx::query_scalar("SELECT reminder_sent_at FROM hub_events WHERE id = $1")
            .bind(&future_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(
        future_sent.is_none(),
        "not-yet-due event should not be sent"
    );

    let no_reminder_sent: Option<i64> =
        sqlx::query_scalar("SELECT reminder_sent_at FROM hub_events WHERE id = $1")
            .bind(&no_reminder_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(
        no_reminder_sent.is_none(),
        "event with no reminder configured should never be sent"
    );

    // The reminder card landed in the channel.
    let resp = server
        .get(&format!("/channels/{channel_id}/messages"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let messages: Value = resp.json();
    let msgs = messages.as_array().unwrap();
    assert!(
        msgs.iter().any(|m| m["content"]
            .as_str()
            .unwrap_or("")
            .contains("starts in 15 minutes")),
        "expected a reminder card mentioning the offset"
    );

    // A second tick is a no-op for the already-sent event: reminder_sent_at
    // doesn't move and no duplicate card is posted.
    let resp = server
        .get(&format!("/channels/{channel_id}/messages"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let before: Value = resp.json();
    let count_before = before.as_array().unwrap().len();

    wavvon_hub::reminder_worker::tick(state)
        .await
        .expect("second tick should succeed");

    let resp = server
        .get(&format!("/channels/{channel_id}/messages"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    let after: Value = resp.json();
    assert_eq!(
        after.as_array().unwrap().len(),
        count_before,
        "already-sent reminder must not be re-posted"
    );
}

/// Updating `reminder_minutes` on an event whose reminder already fired
/// resets `reminder_sent_at`, so a re-picked offset can fire again.
#[tokio::test]
async fn update_event_resets_reminder_sent_at() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_channel(&server, &owner_token).await;

    let now = wavvon_hub::auth::handlers::unix_timestamp();
    let event = create_event(
        &server,
        &owner_token,
        &channel_id,
        json!({ "starts_at": now + 600, "reminder_minutes": 15 }),
    )
    .await;
    let event_id = event["id"].as_str().unwrap().to_string();

    let state = server.state();
    wavvon_hub::reminder_worker::tick(state).await.unwrap();

    let sent: Option<i64> =
        sqlx::query_scalar("SELECT reminder_sent_at FROM hub_events WHERE id = $1")
            .bind(&event_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(sent.is_some());

    // Re-pick the same offset via PUT: reminder_sent_at resets to NULL.
    let resp = server
        .put(&format!("/events/{event_id}"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "reminder_minutes": 15 }))
        .await;
    resp.assert_status_success();
    let updated: Value = resp.json();
    assert!(updated["reminder_sent_at"].is_null());

    let sent_after: Option<i64> =
        sqlx::query_scalar("SELECT reminder_sent_at FROM hub_events WHERE id = $1")
            .bind(&event_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(sent_after.is_none());
}
