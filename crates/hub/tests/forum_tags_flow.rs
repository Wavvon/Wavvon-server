use axum_test::TestServer;
use serde_json::{json, Value};
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::routes::post_models::{ForumTag, PostDetail, PostListResponse};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// Create a forum channel and return its id.
async fn create_forum_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "name": "tracker", "channel_type": "forum" }))
        .await;
    assert_eq!(resp.status_code(), 201, "create channel: {}", resp.text());
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

/// Create a text channel and return its id.
async fn create_text_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "name": "general" }))
        .await;
    assert_eq!(resp.status_code(), 201, "create channel: {}", resp.text());
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

async fn create_tag(
    server: &TestServer,
    token: &str,
    channel_id: &str,
    label: &str,
    color: Option<&str>,
) -> ForumTag {
    let mut body = json!({ "label": label });
    if let Some(c) = color {
        body["color"] = json!(c);
    }
    let resp = server
        .post(&format!("/channels/{channel_id}/tags"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    resp.json()
}

// ── Tag CRUD happy path ──────────────────────────────────────────────────────

#[tokio::test]
async fn tag_create_list_edit_delete() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let bug = create_tag(&server, &token, &channel_id, "bug", Some("#ff0000")).await;
    assert_eq!(bug.label, "bug");
    assert_eq!(bug.color.as_deref(), Some("#ff0000"));
    assert_eq!(bug.channel_id, channel_id);

    let _feature = create_tag(&server, &token, &channel_id, "feature-request", None).await;

    // List — ordered by position (both default 0), so just check membership.
    let resp = server
        .get(&format!("/channels/{channel_id}/tags"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let tags: Vec<ForumTag> = resp.json();
    assert_eq!(tags.len(), 2);
    assert!(tags.iter().any(|t| t.label == "bug"));
    assert!(tags.iter().any(|t| t.label == "feature-request"));

    // Edit: change label and position, leave color untouched.
    let resp = server
        .patch(&format!("/tags/{}", bug.id))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "label": "bug-confirmed", "position": 5 }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let updated: ForumTag = resp.json();
    assert_eq!(updated.label, "bug-confirmed");
    assert_eq!(updated.position, 5);
    assert_eq!(updated.color.as_deref(), Some("#ff0000"));

    // Delete.
    let resp = server
        .delete(&format!("/tags/{}", bug.id))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    let resp = server
        .get(&format!("/channels/{channel_id}/tags"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let tags: Vec<ForumTag> = resp.json();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].label, "feature-request");
}

#[tokio::test]
async fn tag_create_rejects_non_manage_posts_user() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let channel_id = create_forum_channel(&server, &owner_token).await;

    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/tags"))
        .add_header("Authorization", format!("Bearer {token2}"))
        .json(&json!({ "label": "bug" }))
        .await;
    assert_eq!(resp.status_code(), 403, "{}", resp.text());

    let tag = create_tag(&server, &owner_token, &channel_id, "bug", None).await;

    let resp = server
        .patch(&format!("/tags/{}", tag.id))
        .add_header("Authorization", format!("Bearer {token2}"))
        .json(&json!({ "label": "hacked" }))
        .await;
    assert_eq!(resp.status_code(), 403);

    let resp = server
        .delete(&format!("/tags/{}", tag.id))
        .add_header("Authorization", format!("Bearer {token2}"))
        .await;
    assert_eq!(resp.status_code(), 403);
}

#[tokio::test]
async fn tag_routes_return_not_a_forum_on_text_channel() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_text_channel(&server, &token).await;

    let resp = server
        .get(&format!("/channels/{channel_id}/tags"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 409, "{}", resp.text());
    assert!(resp.text().contains("not_a_forum"));

    let resp = server
        .post(&format!("/channels/{channel_id}/tags"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "label": "bug" }))
        .await;
    assert_eq!(resp.status_code(), 409);
}

// ── Post + tag integration ───────────────────────────────────────────────────

#[tokio::test]
async fn post_create_with_tags_appears_in_list_and_detail() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let bug = create_tag(&server, &token, &channel_id, "bug", Some("#ff0000")).await;
    let planned = create_tag(&server, &token, &channel_id, "planned", None).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "title": "Crash on startup",
            "body": "repro steps",
            "tag_ids": [bug.id, planned.id],
        }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    let detail: PostDetail = resp.json();
    assert_eq!(detail.summary.tags.len(), 2);
    let post_id = detail.summary.id.clone();

    // List — tags populated.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let list: PostListResponse = resp.json();
    assert_eq!(list.posts.len(), 1);
    assert_eq!(list.posts[0].tags.len(), 2);
    assert!(list.posts[0].tags.iter().any(|t| t.label == "bug"));

    // Detail — tags populated.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail2: PostDetail = resp.json();
    assert_eq!(detail2.summary.tags.len(), 2);
}

#[tokio::test]
async fn post_edit_replaces_tags_and_omitted_leaves_unchanged() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let bug = create_tag(&server, &token, &channel_id, "bug", None).await;
    let done = create_tag(&server, &token, &channel_id, "done", None).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "t", "body": "b", "tag_ids": [bug.id] }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();
    assert_eq!(detail.summary.tags.len(), 1);

    // Edit body only, omitting tag_ids — tags must be unchanged.
    let resp = server
        .patch(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "body": "new body" }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let updated: PostDetail = resp.json();
    assert_eq!(updated.summary.tags.len(), 1);
    assert_eq!(updated.summary.tags[0].id, bug.id);

    // Edit with tag_ids — replaces the assignment set.
    let resp = server
        .patch(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "tag_ids": [done.id] }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let updated: PostDetail = resp.json();
    assert_eq!(updated.summary.tags.len(), 1);
    assert_eq!(updated.summary.tags[0].id, done.id);

    // Edit with empty tag_ids — clears all tags.
    let resp = server
        .patch(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "tag_ids": [] }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let updated: PostDetail = resp.json();
    assert!(updated.summary.tags.is_empty());
}

#[tokio::test]
async fn post_create_rejects_more_than_five_tags() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let mut ids = Vec::new();
    for i in 0..6 {
        let tag = create_tag(&server, &token, &channel_id, &format!("t{i}"), None).await;
        ids.push(tag.id);
    }

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "t", "body": "b", "tag_ids": ids }))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
}

#[tokio::test]
async fn post_create_rejects_tag_from_another_channel() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_a = create_forum_channel(&server, &token).await;

    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "name": "other-forum", "channel_type": "forum" }))
        .await;
    let channel_b: Value = resp.json();
    let channel_b_id = channel_b["id"].as_str().unwrap().to_string();

    let foreign_tag = create_tag(&server, &token, &channel_b_id, "foreign", None).await;

    let resp = server
        .post(&format!("/channels/{channel_a}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "t", "body": "b", "tag_ids": [foreign_tag.id] }))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
    assert!(resp.text().contains("tag_id_not_in_channel"));
}

#[tokio::test]
async fn forum_require_tag_rejects_post_without_tags() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    // Enable forum_require_tag via channel settings.
    let resp = server
        .patch(&format!("/channels/{channel_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "forum_require_tag": true }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());

    // Post with no tags — rejected.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "t", "body": "b" }))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
    assert!(resp.text().contains("forum_require_tag"));

    // Post with a tag — accepted.
    let tag = create_tag(&server, &token, &channel_id, "bug", None).await;
    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "t", "body": "b", "tag_ids": [tag.id] }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
}

#[tokio::test]
async fn tag_filter_on_list_route() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let bug = create_tag(&server, &token, &channel_id, "bug", None).await;
    let feature = create_tag(&server, &token, &channel_id, "feature", None).await;

    server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Bug post", "body": "b", "tag_ids": [bug.id] }))
        .await;
    server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Feature post", "body": "b", "tag_ids": [feature.id] }))
        .await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts?tag={}", bug.id))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let list: PostListResponse = resp.json();
    assert_eq!(list.posts.len(), 1);
    assert_eq!(list.posts[0].title.as_deref(), Some("Bug post"));
}

#[tokio::test]
async fn deleting_tag_removes_assignment_from_posts() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let bug = create_tag(&server, &token, &channel_id, "bug", None).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "t", "body": "b", "tag_ids": [bug.id] }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();
    assert_eq!(detail.summary.tags.len(), 1);

    let resp = server
        .delete(&format!("/tags/{}", bug.id))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail2: PostDetail = resp.json();
    assert!(detail2.summary.tags.is_empty());
}

// ── forum_require_tag channel-settings round trip ────────────────────────────

#[tokio::test]
async fn forum_require_tag_round_trips_through_channel_settings() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    // Fresh channel defaults to false.
    let resp = server
        .get("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let channels: Vec<ChannelResponse> = resp.json();
    let ch = channels.iter().find(|c| c.id == channel_id).unwrap();
    assert!(!ch.forum_require_tag);

    // Flip it on.
    let resp = server
        .patch(&format!("/channels/{channel_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "forum_require_tag": true }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());

    let resp = server
        .get("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let channels: Vec<ChannelResponse> = resp.json();
    let ch = channels.iter().find(|c| c.id == channel_id).unwrap();
    assert!(ch.forum_require_tag);

    // A no-op PATCH (omitting the field) leaves it unchanged.
    let resp = server
        .patch(&format!("/channels/{channel_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "description": "unrelated update" }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());

    let resp = server
        .get("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let channels: Vec<ChannelResponse> = resp.json();
    let ch = channels.iter().find(|c| c.id == channel_id).unwrap();
    assert!(ch.forum_require_tag, "unrelated PATCH must not clear it");
}

#[tokio::test]
async fn forum_require_tag_rejected_on_text_channel() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_text_channel(&server, &token).await;

    let resp = server
        .patch(&format!("/channels/{channel_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "forum_require_tag": true }))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
}
