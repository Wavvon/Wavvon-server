use axum_test::TestServer;
use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn create_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "name": "general" }))
        .await;
    resp.assert_status_success();
    resp.json::<Value>()["id"].as_str().unwrap().to_string()
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

/// Happy-path: create poll, get it, vote, check totals broadcast path.
#[tokio::test]
async fn poll_happy_path() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    // POST /channels/:id/polls
    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "question": "Best raid night?",
            "options": [
                { "id": "fri", "text": "Friday" },
                { "id": "sat", "text": "Saturday" },
                { "id": "sun", "text": "Sunday" },
            ],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let poll: Value = resp.json();
    let poll_id = poll["id"].as_str().unwrap().to_string();
    assert_eq!(poll["question"], "Best raid night?");
    assert_eq!(poll["max_choices"], 1);

    // GET /polls/:id — no votes yet, totals should be empty / zero
    let resp = server
        .get(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["id"], poll_id);
    assert!(detail["your_vote"].is_null());

    // POST /polls/:id/vote
    let resp = server
        .post(&format!("/polls/{poll_id}/vote"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "option_ids": ["fri"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // GET /polls/:id — your_vote should now be ["fri"], totals["fri"] = 1
    let resp = server
        .get(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    let detail: Value = resp.json();
    assert_eq!(detail["your_vote"].as_array().unwrap()[0], "fri");
    assert_eq!(detail["totals"]["fri"], 1);

    // Re-vote changes the selection (upsert).
    let resp = server
        .post(&format!("/polls/{poll_id}/vote"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "option_ids": ["sat"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: Value = resp.json();
    assert_eq!(detail["your_vote"].as_array().unwrap()[0], "sat");
    // "fri" still exists in totals from old row but vote changed, totals["sat"] = 1
    assert_eq!(detail["totals"]["sat"], 1);

    // DELETE /polls/:id
    let resp = server
        .delete(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

/// Selecting too many choices is rejected.
#[tokio::test]
async fn poll_rejects_too_many_choices() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "question": "Pick one",
            "options": [
                { "id": "a", "text": "A" },
                { "id": "b", "text": "B" },
            ],
            "max_choices": 1,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let poll_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let resp = server
        .post(&format!("/polls/{poll_id}/vote"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "option_ids": ["a", "b"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

/// Card message inserted by create_poll uses the creator's pubkey as sender,
/// not the old zero-string phantom sender.
#[tokio::test]
async fn poll_card_sender_is_creator() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "question": "Sender check?",
            "options": [
                { "id": "y", "text": "Yes" },
                { "id": "n", "text": "No" },
            ],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let poll: Value = resp.json();
    let creator_pubkey = poll["creator_pubkey"].as_str().unwrap().to_string();

    // Fetch the channel's messages and verify the card is attributed to the
    // creator, not the zero-string phantom sender.
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
        "poll card sender must be the creator, not the zero phantom"
    );
    let zero = "00000000000000000000000000000000000000000000000000000000000000000000";
    assert_ne!(card["sender"].as_str().unwrap(), zero);
}

/// Non-creator without admin cannot delete a poll.
#[tokio::test]
async fn poll_delete_rejected_for_non_creator() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let other = Identity::generate();
    let token_owner = common::authenticate(&server, &owner).await;
    let token_other = common::authenticate(&server, &other).await;
    let channel_id = create_channel(&server, &token_owner).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token_owner}"))
        .json(&json!({
            "question": "Delete me?",
            "options": [
                { "id": "y", "text": "Yes" },
                { "id": "n", "text": "No" },
            ],
        }))
        .await;
    let poll_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let resp = server
        .delete(&format!("/polls/{poll_id}"))
        .add_header("Authorization", format!("Bearer {token_other}"))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

/// GET /channels/:id/polls happy path: created polls come back newest-first,
/// with vote totals and the caller's own vote merged into each option.
#[tokio::test]
async fn list_polls_happy_path() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "question": "First poll",
            "options": [
                { "id": "a", "text": "A" },
                { "id": "b", "text": "B" },
            ],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let first_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    // created_at has second granularity; sleep past the second boundary so
    // the two polls sort deterministically by newest-first.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "question": "Second poll",
            "options": [
                { "id": "y", "text": "Yes" },
                { "id": "n", "text": "No" },
            ],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let second_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    // Vote on the second poll and confirm the listing reflects it.
    let resp = server
        .post(&format!("/polls/{second_id}/vote"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "option_ids": ["y"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_ok();
    let polls: Value = resp.json();
    let arr = polls.as_array().unwrap();
    assert_eq!(arr.len(), 2);

    // Newest first: the second poll created should come before the first.
    assert_eq!(arr[0]["id"], second_id);
    assert_eq!(arr[1]["id"], first_id);

    // Second poll: option "y" carries the vote, matches client Poll shape.
    let second = &arr[0];
    assert_eq!(second["question"], "Second poll");
    assert_eq!(second["total_votes"], 1);
    assert_eq!(second["is_deleted"], false);
    let options = second["options"].as_array().unwrap();
    let yes_opt = options.iter().find(|o| o["id"] == "y").unwrap();
    assert_eq!(yes_opt["vote_count"], 1);
    assert_eq!(yes_opt["voted"], true);
    let no_opt = options.iter().find(|o| o["id"] == "n").unwrap();
    assert_eq!(no_opt["vote_count"], 0);
    assert_eq!(no_opt["voted"], false);

    // First poll: no votes yet.
    let first = &arr[1];
    assert_eq!(first["total_votes"], 0);
}

/// A member denied `read_messages` on a channel gets 403 on the poll
/// listing; the channel owner (admin, immune) still sees it.
#[tokio::test]
async fn list_polls_rejected_for_member_denied_read_messages() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    let channel_id = create_channel(&server, &owner_token).await;
    let resp = server
        .post(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "question": "Secret poll",
            "options": [
                { "id": "a", "text": "A" },
                { "id": "b", "text": "B" },
            ],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    deny_everyone(&server, &owner_token, &channel_id, "read_messages").await;

    server
        .get(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {member_token}"))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    let resp = server
        .get(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>().as_array().unwrap().len(), 1);
}

/// A channel with no polls returns an empty array, not a 404.
#[tokio::test]
async fn list_polls_empty_channel_returns_empty_array() {
    let server = common::setup().await;
    let id = Identity::generate();
    let token = common::authenticate(&server, &id).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .get(&format!("/channels/{channel_id}/polls"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_ok();
    let polls: Value = resp.json();
    assert!(polls.as_array().unwrap().is_empty());
}
