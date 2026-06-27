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
