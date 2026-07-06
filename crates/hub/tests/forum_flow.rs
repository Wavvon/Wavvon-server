use axum_test::TestServer;
use serde_json::{json, Value};
use wavvon_hub::routes::post_models::{PostDetail, PostListResponse, PostSearchResponse};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// Create a forum channel and return its id.
async fn create_forum_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "name": "announcements", "channel_type": "forum" }))
        .await;
    assert_eq!(resp.status_code(), 201, "create channel: {}", resp.text());
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

/// Create a text channel and return its id.
async fn create_text_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "name": "general" }))
        .await;
    assert_eq!(resp.status_code(), 201, "create channel: {}", resp.text());
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

// ── Happy-path CRUD ──────────────────────────────────────────────────────────

#[tokio::test]
async fn forum_create_list_get_post() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    // Create a post.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Hello forum", "body": "First post body" }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    let detail: PostDetail = resp.json();
    assert_eq!(detail.summary.title.as_deref(), Some("Hello forum"));
    assert!(!detail.summary.is_deleted);
    let post_id = detail.summary.id.clone();

    // List posts — should include the new post.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200);
    let list: PostListResponse = resp.json();
    assert_eq!(list.posts.len(), 1);
    assert_eq!(list.posts[0].id, post_id);

    // Get post detail.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200);
    let detail2: PostDetail = resp.json();
    assert_eq!(detail2.summary.id, post_id);
    assert_eq!(detail2.body.as_deref(), Some("First post body"));
}

#[tokio::test]
async fn forum_edit_post() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Old title", "body": "Old body" }))
        .await;
    assert_eq!(resp.status_code(), 201);
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    let resp = server
        .patch(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "New title", "body": "New body" }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let updated: PostDetail = resp.json();
    assert_eq!(updated.summary.title.as_deref(), Some("New title"));
    assert_eq!(updated.body.as_deref(), Some("New body"));
}

#[tokio::test]
async fn forum_delete_post_soft() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Delete me", "body": "Gone" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    let resp = server
        .delete(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    // The post list excludes soft-deleted posts.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200);
    let list: PostListResponse = resp.json();
    assert!(list.posts.is_empty());
}

#[tokio::test]
async fn forum_reply_create_edit_delete() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "With replies", "body": "Body" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    // Create reply.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/replies"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "body": "First reply" }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    let reply: Value = resp.json();
    let reply_id = reply["id"].as_str().unwrap().to_string();
    assert_eq!(reply["body"].as_str(), Some("First reply"));

    // reply_count should be updated.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: PostDetail = resp.json();
    assert_eq!(detail.summary.reply_count, 1);

    // Edit reply.
    let resp = server
        .patch(&format!(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}"
        ))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "body": "Edited reply" }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let updated: Value = resp.json();
    assert_eq!(updated["body"].as_str(), Some("Edited reply"));

    // Delete reply.
    let resp = server
        .delete(&format!(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}"
        ))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    // reply_count decremented.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: PostDetail = resp.json();
    assert_eq!(detail.summary.reply_count, 0);
}

#[tokio::test]
async fn forum_pin_and_lock() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Pin me", "body": "body" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    // Pin.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/pin"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204, "{}", resp.text());

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: PostDetail = resp.json();
    assert!(detail.summary.is_pinned);

    // Unpin.
    let resp = server
        .delete(&format!("/channels/{channel_id}/posts/{post_id}/pin"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    // Lock.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/lock"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let detail: PostDetail = resp.json();
    assert!(detail.summary.is_locked);

    // Unlock.
    let resp = server
        .delete(&format!("/channels/{channel_id}/posts/{post_id}/lock"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204);
}

#[tokio::test]
async fn forum_search_returns_hits() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Rust is great", "body": "I love Rust programming" }))
        .await;

    server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Unrelated post", "body": "Nothing relevant here" }))
        .await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/search?q=Rust"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());
    let sr: PostSearchResponse = resp.json();
    assert!(!sr.results.is_empty(), "expected search hits for 'Rust'");
}

// ── Rejection tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn forum_routes_return_not_a_forum_on_text_channel() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_text_channel(&server, &token).await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 409, "{}", resp.text());
    assert!(resp.text().contains("not_a_forum"));

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Oops", "body": "Nope" }))
        .await;
    assert_eq!(resp.status_code(), 409);
}

#[tokio::test]
async fn forum_locked_post_rejects_new_reply_from_non_moderator() {
    let server = common::setup().await;

    // Owner creates forum channel and a post.
    let owner_id = Identity::generate();
    let owner_token = common::authenticate(&server, &owner_id).await;
    let channel_id = create_forum_channel(&server, &owner_token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "title": "Locked post", "body": "body" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    // Owner locks it.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/lock"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .await;
    assert_eq!(resp.status_code(), 204);

    // A second user tries to reply — should be forbidden.
    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/replies"))
        .add_header("Authorization", format!("Bearer {token2}"))
        .json(&json!({ "body": "I can't reply" }))
        .await;
    assert_eq!(resp.status_code(), 403, "{}", resp.text());
    assert!(resp.text().contains("post_locked"));
}

#[tokio::test]
async fn forum_non_author_cannot_edit_or_delete_post() {
    let server = common::setup().await;

    let owner_id = Identity::generate();
    let owner_token = common::authenticate(&server, &owner_id).await;
    let channel_id = create_forum_channel(&server, &owner_token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {owner_token}"))
        .json(&json!({ "title": "My post", "body": "body" }))
        .await;
    let detail: PostDetail = resp.json();
    let post_id = detail.summary.id.clone();

    // Second user without manage_posts.
    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .patch(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token2}"))
        .json(&json!({ "body": "hacked" }))
        .await;
    assert_eq!(resp.status_code(), 403);

    let resp = server
        .delete(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token2}"))
        .await;
    assert_eq!(resp.status_code(), 403);
}

#[tokio::test]
async fn forum_search_requires_non_empty_query() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/search?q="))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
    assert!(resp.text().contains("q_required"));
}

// ── Reactions ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn forum_post_reaction_add_and_remove() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    // Create a post (parse as Value to access reactions via indexing).
    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "React to me", "body": "body" }))
        .await;
    assert_eq!(resp.status_code(), 201);
    let v: Value = resp.json();
    let post_id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["reactions"].as_array().map(|a| a.len()), Some(0));

    // Add reaction.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/reactions"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "emoji": "👍" }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());

    // Get post — reactions should include the thumbs-up with count=1, me=true.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 200);
    let v: Value = resp.json();
    let reactions = v["reactions"].as_array().unwrap();
    assert_eq!(reactions.len(), 1);
    assert_eq!(reactions[0]["emoji"].as_str(), Some("👍"));
    assert_eq!(reactions[0]["count"].as_i64(), Some(1));
    assert_eq!(reactions[0]["me"].as_bool(), Some(true));

    // Remove reaction.
    let resp = server
        .delete(&format!(
            "/channels/{channel_id}/posts/{post_id}/reactions/👍"
        ))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204, "{}", resp.text());

    // Reactions should now be empty.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let v: Value = resp.json();
    assert_eq!(v["reactions"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn forum_reply_reaction_add_and_remove() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "Post", "body": "body" }))
        .await;
    let v: Value = resp.json();
    let post_id = v["id"].as_str().unwrap().to_string();

    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/replies"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "body": "A reply" }))
        .await;
    assert_eq!(resp.status_code(), 201);
    let reply: Value = resp.json();
    let reply_id = reply["id"].as_str().unwrap().to_string();
    assert_eq!(reply["reactions"].as_array().map(|a| a.len()), Some(0));

    // Add reaction to reply.
    let resp = server
        .post(&format!(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}/reactions"
        ))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "emoji": "❤️" }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());

    // Fetch post detail — reply should have the reaction.
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let v: Value = resp.json();
    let replies = v["replies"].as_array().unwrap();
    let found = replies.iter().find(|r| r["id"].as_str() == Some(&reply_id));
    assert!(found.is_some(), "reply not found in post detail");
    let reactions = found.unwrap()["reactions"].as_array().unwrap();
    assert_eq!(reactions.len(), 1);
    assert_eq!(reactions[0]["emoji"].as_str(), Some("❤️"));
    assert_eq!(reactions[0]["count"].as_i64(), Some(1));

    // Remove reply reaction.
    let resp = server
        .delete(&format!(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}/reactions/❤️"
        ))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 204, "{}", resp.text());

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let v: Value = resp.json();
    let replies = v["replies"].as_array().unwrap();
    let found = replies
        .iter()
        .find(|r| r["id"].as_str() == Some(&reply_id))
        .unwrap();
    assert_eq!(found["reactions"].as_array().map(|a| a.len()), Some(0));
}

#[tokio::test]
async fn forum_post_reaction_invalid_emoji_rejected() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "T", "body": "b" }))
        .await;
    let v: Value = resp.json();
    let post_id = v["id"].as_str().unwrap().to_string();

    // Empty emoji.
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/reactions"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "emoji": "" }))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());

    // Too-long emoji (9 chars).
    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/reactions"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "emoji": "123456789" }))
        .await;
    assert_eq!(resp.status_code(), 400, "{}", resp.text());
}

// ── Attachments ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn forum_post_with_attachments() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "title": "With files",
            "body": "see attachment",
            "attachments": [
                { "url": "https://example.com/file.pdf", "name": "file.pdf", "mime": "application/pdf", "size": 12345 }
            ]
        }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    let v: Value = resp.json();
    let attachments = v["attachments"].as_array().unwrap();
    assert_eq!(attachments.len(), 1);
    assert_eq!(
        attachments[0]["url"].as_str(),
        Some("https://example.com/file.pdf")
    );
    assert_eq!(attachments[0]["name"].as_str(), Some("file.pdf"));

    // Verify round-trip via GET.
    let post_id = v["id"].as_str().unwrap().to_string();
    let resp = server
        .get(&format!("/channels/{channel_id}/posts/{post_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let v2: Value = resp.json();
    assert_eq!(v2["attachments"].as_array().map(|a| a.len()), Some(1));
}

#[tokio::test]
async fn forum_reply_with_attachments() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/posts"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "title": "T", "body": "b" }))
        .await;
    let v: Value = resp.json();
    let post_id = v["id"].as_str().unwrap().to_string();

    let resp = server
        .post(&format!("/channels/{channel_id}/posts/{post_id}/replies"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "body": "reply with file",
            "attachments": [
                { "url": "https://example.com/img.png", "name": "img.png", "mime": "image/png", "size": 9000 }
            ]
        }))
        .await;
    assert_eq!(resp.status_code(), 201, "{}", resp.text());
    let reply: Value = resp.json();
    let attachments = reply["attachments"].as_array().unwrap();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0]["mime"].as_str(), Some("image/png"));
}

#[tokio::test]
async fn forum_get_post_not_found_returns_404() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_forum_channel(&server, &token).await;

    let resp = server
        .get(&format!("/channels/{channel_id}/posts/no-such-id"))
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(resp.status_code(), 404);
}
