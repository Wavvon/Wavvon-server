/// Integration tests for event card propagation to sub-channels
/// (events.md §6).
use axum_test::TestServer;
use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn create_channel(
    server: &TestServer,
    token: &str,
    name: &str,
    parent_id: Option<&str>,
    is_category: bool,
) -> Value {
    let mut body = json!({ "name": name, "is_category": is_category });
    if let Some(pid) = parent_id {
        body["parent_id"] = json!(pid);
    }
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    resp.json()
}

async fn set_overwrite(
    server: &TestServer,
    token: &str,
    channel_id: &str,
    role_id: &str,
    allow: &[&str],
    deny: &[&str],
) {
    let resp = server
        .put(&format!("/channels/{channel_id}/permissions/{role_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "allow": allow, "deny": deny }))
        .await;
    resp.assert_status_ok();
}

async fn channel_messages(server: &TestServer, token: &str, channel_id: &str) -> Vec<Value> {
    let resp = server
        .get(&format!("/channels/{channel_id}/messages"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    resp.assert_status_success();
    resp.json::<Value>().as_array().unwrap().clone()
}

/// `propagate_to_children: true` posts the announcement card into the
/// anchor **and** its descendant; a member who can read only the descendant
/// (anchor denied, descendant re-allowed -- a deeper overwrite level
/// overriding a shallower one, §3.2) sees only that copy, demonstrating
/// delivery is decided entirely by the existing per-channel read gate.
#[tokio::test]
async fn propagated_card_lands_in_anchor_and_descendant_with_read_gating_intact() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    // Anchor must be a category to have a child (create_channel's parent
    // constraint); the anchor itself still accepts messages/events like any
    // other channel.
    let anchor = create_channel(&server, &owner_token, "raid-planning", None, true).await;
    let anchor_id = anchor["id"].as_str().unwrap().to_string();
    let squad = create_channel(
        &server,
        &owner_token,
        "squad-alpha",
        Some(&anchor_id),
        false,
    )
    .await;
    let squad_id = squad["id"].as_str().unwrap().to_string();

    // Deny read on the anchor for @everyone, then re-allow it specifically
    // on the descendant -- the member can read the squad channel but not
    // the anchor.
    set_overwrite(
        &server,
        &owner_token,
        &anchor_id,
        "builtin-everyone",
        &[],
        &["read_messages"],
    )
    .await;
    set_overwrite(
        &server,
        &owner_token,
        &squad_id,
        "builtin-everyone",
        &["read_messages"],
        &[],
    )
    .await;

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "channel_id": anchor_id,
            "title": "Raid Night",
            "starts_at": 9_999_999_999i64,
            "propagate_to_children": true,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let event: Value = resp.json();
    assert_eq!(event["propagate_to_children"], true);

    // The owner (can read both) sees a card in each channel.
    let anchor_msgs = channel_messages(&server, &owner_token, &anchor_id).await;
    assert_eq!(anchor_msgs.len(), 1, "anchor should get exactly one card");
    let squad_msgs = channel_messages(&server, &owner_token, &squad_id).await;
    assert_eq!(
        squad_msgs.len(),
        1,
        "descendant should get exactly one card"
    );
    assert_eq!(anchor_msgs[0]["content"], squad_msgs[0]["content"]);

    // The member can't even list the anchor's messages (403, denied read).
    let resp = server
        .get(&format!("/channels/{anchor_id}/messages"))
        .add_header("Authorization", format!("Bearer {member_token}"))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // But the member reads the descendant fine and sees the propagated card.
    let member_squad_msgs = channel_messages(&server, &member_token, &squad_id).await;
    assert_eq!(member_squad_msgs.len(), 1);
    assert_eq!(member_squad_msgs[0]["content"], squad_msgs[0]["content"]);
}

/// Without `propagate_to_children`, the card lands only in the anchor.
#[tokio::test]
async fn non_propagated_event_card_stays_in_anchor_only() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let anchor = create_channel(&server, &owner_token, "announcements", None, true).await;
    let anchor_id = anchor["id"].as_str().unwrap().to_string();
    let child = create_channel(&server, &owner_token, "off-topic", Some(&anchor_id), false).await;
    let child_id = child["id"].as_str().unwrap().to_string();

    let resp = server
        .post("/events")
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({
            "channel_id": anchor_id,
            "title": "Regular Event",
            "starts_at": 9_999_999_999i64,
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    let anchor_msgs = channel_messages(&server, &owner_token, &anchor_id).await;
    assert_eq!(anchor_msgs.len(), 1);
    let child_msgs = channel_messages(&server, &owner_token, &child_id).await;
    assert!(
        child_msgs.is_empty(),
        "child channel must not receive a card without propagation"
    );
}
