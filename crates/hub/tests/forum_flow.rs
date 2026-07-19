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

// ── Federation read-through (forum.md section 9, phase 1) ───────────────────
//
// These need two real HTTP hubs talking to each other over the federation
// client, so `axum_test::TestServer` (in-process, no network) doesn't work
// here -- mirrors the `start_hub` harness in `alliance_flow.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::alliance_models::AllianceResponse;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;

async fn start_hub(name: &str) -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: name.to_string(),
        hub_identity: Identity::generate(),
        db,
        db_read: None,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_udp_addr: None,
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        staging_voice_grants: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        webauthn: {
            let origin = url::Url::parse("http://localhost:3000").unwrap();
            std::sync::Arc::new(
                webauthn_rs::WebauthnBuilder::new("localhost", &origin)
                    .unwrap()
                    .rp_name("test-hub")
                    .build()
                    .unwrap(),
            )
        },
        webauthn_reg_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        webauthn_auth_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        device_token_ttl_secs: 30 * 86400,
        webhook_circuit: std::sync::Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
        lan_mode: false,
        lan_tls_mode: None,
        lan_fingerprint: None,
    });

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    (url, state, guard)
}

async fn authenticate_user(hub_url: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();

    let challenge: ChallengeResponse = client
        .post(format!("{hub_url}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let verify: VerifyResponse = client
        .post(format!("{hub_url}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    verify.token
}

/// Hub B owns a forum channel shared into an alliance with Hub A. Hub A
/// reads the post list and post detail (with replies) purely through the
/// alliance read-through proxy -- Hub A never stores a copy, it federates
/// the read to Hub B on every call.
#[tokio::test]
async fn alliance_forum_read_through_proxies_to_owning_hub() {
    let (hub_a_url, _hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, _hub_b_state, _hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;
    let user_b = Identity::generate();
    let token_b = authenticate_user(&hub_b_url, &user_b).await;

    // Hub A creates the alliance.
    let alliance: AllianceResponse = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "Forum Alliance" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let invite: wavvon_hub::routes::alliance_models::AllianceInviteResponse = client
        .post(format!("{hub_a_url}/alliances/{}/invite", alliance.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{hub_b_url}/alliances/join"))
        .bearer_auth(&token_b)
        .json(&json!({
            "inviter_hub_url": hub_a_url,
            "alliance_id": alliance.id,
            "invite_token": invite.token,
            "own_hub_url": hub_b_url,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Hub B: create a forum channel with a post and a reply, then share it.
    let channel: ChannelResponse = client
        .post(format!("{hub_b_url}/channels"))
        .bearer_auth(&token_b)
        .json(&json!({ "name": "patch-notes", "channel_type": "forum" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(channel.channel_type, "forum");

    let resp = client
        .post(format!("{hub_b_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token_b)
        .json(&json!({ "channel_id": channel.id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let post: PostDetail = client
        .post(format!("{hub_b_url}/channels/{}/posts", channel.id))
        .bearer_auth(&token_b)
        .json(&json!({ "title": "v1.2 notes", "body": "Fixed the thing" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let _reply: Value = client
        .post(format!(
            "{hub_b_url}/channels/{}/posts/{}/replies",
            channel.id, post.summary.id
        ))
        .bearer_auth(&token_b)
        .json(&json!({ "body": "nice, thanks" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Hub A: list posts via the alliance proxy -- it owns no copy, this is
    // a live federated read every time.
    let resp = client
        .get(format!(
            "{hub_a_url}/alliances/{}/channels/{}/posts",
            alliance.id, channel.id
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    let list: PostListResponse = client
        .get(format!(
            "{hub_a_url}/alliances/{}/channels/{}/posts",
            alliance.id, channel.id
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.posts.len(), 1);
    assert_eq!(list.posts[0].id, post.summary.id);
    assert_eq!(list.posts[0].title.as_deref(), Some("v1.2 notes"));

    // Hub A: get post detail (with the reply) via the proxy.
    let detail: PostDetail = client
        .get(format!(
            "{hub_a_url}/alliances/{}/channels/{}/posts/{}",
            alliance.id, channel.id, post.summary.id
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail.body.as_deref(), Some("Fixed the thing"));
    assert_eq!(detail.replies.len(), 1);
    assert_eq!(detail.replies[0].body.as_deref(), Some("nice, thanks"));
}

/// Reading posts for a channel that isn't shared with the alliance on any
/// member hub is rejected with 404, mirroring the message-proxy rejection.
#[tokio::test]
async fn alliance_forum_read_through_rejects_unshared_channel() {
    let (hub_a_url, _hub_a_state, _hub_a_guard) = start_hub("hub-a").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;

    let alliance: AllianceResponse = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "Solo Alliance" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // A forum channel that was never shared into the alliance.
    let channel: ChannelResponse = client
        .post(format!("{hub_a_url}/channels"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "private-forum", "channel_type": "forum" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .get(format!(
            "{hub_a_url}/alliances/{}/channels/{}/posts",
            alliance.id, channel.id
        ))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

// ── Federation proxied writes (forum.md section 9, phase 2) ─────────────────

/// Common two-hub setup shared by the proxied-write tests below: Hub B owns
/// an alliance-shared forum channel with one post; Hub A is a fellow member
/// with no local copy, everything routes through the write proxy.
struct ForumAllianceSetup {
    hub_a_url: String,
    hub_a_state: Arc<AppState>,
    _hub_a_guard: common::TestDbGuard,
    hub_b_url: String,
    _hub_b_state: Arc<AppState>,
    _hub_b_guard: common::TestDbGuard,
    token_a: String,
    token_b: String,
    alliance_id: String,
    channel_id: String,
    post_id: String,
    client: reqwest::Client,
}

async fn setup_forum_alliance(forum_remote_write: Option<&str>) -> ForumAllianceSetup {
    let (hub_a_url, hub_a_state, hub_a_guard) = start_hub("hub-a").await;
    let (hub_b_url, hub_b_state, hub_b_guard) = start_hub("hub-b").await;
    let client = reqwest::Client::new();

    let user_a = Identity::generate();
    let token_a = authenticate_user(&hub_a_url, &user_a).await;
    let user_b = Identity::generate();
    let token_b = authenticate_user(&hub_b_url, &user_b).await;

    let alliance: AllianceResponse = client
        .post(format!("{hub_a_url}/alliances"))
        .bearer_auth(&token_a)
        .json(&json!({ "name": "Forum Alliance" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let invite: wavvon_hub::routes::alliance_models::AllianceInviteResponse = client
        .post(format!("{hub_a_url}/alliances/{}/invite", alliance.id))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let resp = client
        .post(format!("{hub_b_url}/alliances/join"))
        .bearer_auth(&token_b)
        .json(&json!({
            "inviter_hub_url": hub_a_url,
            "alliance_id": alliance.id,
            "invite_token": invite.token,
            "own_hub_url": hub_b_url,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let channel: ChannelResponse = client
        .post(format!("{hub_b_url}/channels"))
        .bearer_auth(&token_b)
        .json(&json!({ "name": "allied-forum", "channel_type": "forum" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let mut share_body = json!({ "channel_id": channel.id });
    if let Some(policy) = forum_remote_write {
        share_body["forum_remote_write"] = json!(policy);
    }
    let resp = client
        .post(format!("{hub_b_url}/alliances/{}/channels", alliance.id))
        .bearer_auth(&token_b)
        .json(&share_body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());

    let post: PostDetail = client
        .post(format!("{hub_b_url}/channels/{}/posts", channel.id))
        .bearer_auth(&token_b)
        .json(&json!({ "title": "seed post", "body": "seed body" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    ForumAllianceSetup {
        hub_a_url,
        hub_a_state,
        _hub_a_guard: hub_a_guard,
        hub_b_url,
        _hub_b_state: hub_b_state,
        _hub_b_guard: hub_b_guard,
        token_a,
        token_b,
        alliance_id: alliance.id,
        channel_id: channel.id,
        post_id: post.summary.id,
        client,
    }
}

/// Hub A's user replies to Hub B's post through the write proxy. The reply
/// lands on Hub B (the owning hub) with `author_hub` set to Hub A's own
/// public key, and surfaces that way both directly on Hub B and through
/// Hub A's phase-1 read-through.
#[tokio::test]
async fn alliance_forum_proxied_reply_carries_author_hub() {
    let s = setup_forum_alliance(None).await; // default policy: replies_only

    let resp = s
        .client
        .post(format!(
            "{}/alliances/{}/channels/{}/posts/{}/replies",
            s.hub_a_url, s.alliance_id, s.channel_id, s.post_id
        ))
        .bearer_auth(&s.token_a)
        .json(&json!({ "body": "greetings from hub A" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let reply: Value = resp.json().await.unwrap();
    assert_eq!(reply["body"].as_str(), Some("greetings from hub A"));
    let hub_a_pubkey = s.hub_a_state.hub_identity.public_key_hex();
    assert_eq!(reply["author_hub"].as_str(), Some(hub_a_pubkey.as_str()));

    // Directly on the owning hub: the reply is there with author_hub set.
    let detail: PostDetail = s
        .client
        .get(format!(
            "{}/channels/{}/posts/{}",
            s.hub_b_url, s.channel_id, s.post_id
        ))
        .bearer_auth(&s.token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail.replies.len(), 1);
    assert_eq!(
        detail.replies[0].author_hub.as_deref(),
        Some(hub_a_pubkey.as_str())
    );

    // Through Hub A's own phase-1 read-through proxy.
    let detail_via_proxy: PostDetail = s
        .client
        .get(format!(
            "{}/alliances/{}/channels/{}/posts/{}",
            s.hub_a_url, s.alliance_id, s.channel_id, s.post_id
        ))
        .bearer_auth(&s.token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail_via_proxy.replies.len(), 1);
    assert_eq!(
        detail_via_proxy.replies[0].author_hub.as_deref(),
        Some(hub_a_pubkey.as_str())
    );
}

/// `forum_remote_write = "none"` rejects every federated write, including
/// replies.
#[tokio::test]
async fn alliance_forum_proxied_write_rejected_under_none_policy() {
    let s = setup_forum_alliance(Some("none")).await;

    let resp = s
        .client
        .post(format!(
            "{}/alliances/{}/channels/{}/posts/{}/replies",
            s.hub_a_url, s.alliance_id, s.channel_id, s.post_id
        ))
        .bearer_auth(&s.token_a)
        .json(&json!({ "body": "should be rejected" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502, "{}", resp.text().await.unwrap());
    // The requester's proxy surfaces the owning hub's 403 wrapped as a
    // gateway error (`create_forum_reply` bubbles the HTTP status through
    // `anyhow`, same shape as the other federation-client methods) --
    // the underlying rejection reason is still visible in the body text.
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("forum_remote_write_disabled") || body.contains("403"),
        "expected a forum_remote_write rejection, got: {body}"
    );
}

/// `forum_remote_write = "replies_only"` (the default) accepts a federated
/// reply but rejects a federated post.
#[tokio::test]
async fn alliance_forum_replies_only_allows_replies_blocks_posts() {
    let s = setup_forum_alliance(Some("replies_only")).await;

    let resp = s
        .client
        .post(format!(
            "{}/alliances/{}/channels/{}/posts/{}/replies",
            s.hub_a_url, s.alliance_id, s.channel_id, s.post_id
        ))
        .bearer_auth(&s.token_a)
        .json(&json!({ "body": "reply ok" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());

    let resp = s
        .client
        .post(format!(
            "{}/alliances/{}/channels/{}/posts",
            s.hub_a_url, s.alliance_id, s.channel_id
        ))
        .bearer_auth(&s.token_a)
        .json(&json!({ "title": "should fail", "body": "should fail" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 502, "{}", resp.text().await.unwrap());
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("forum_remote_write_posts_disabled") || body.contains("403"),
        "expected posts to be rejected under replies_only, got: {body}"
    );
}

/// `forum_remote_write = "posts_and_replies"` accepts a federated post too.
#[tokio::test]
async fn alliance_forum_posts_and_replies_allows_posts() {
    let s = setup_forum_alliance(Some("posts_and_replies")).await;

    let resp = s
        .client
        .post(format!(
            "{}/alliances/{}/channels/{}/posts",
            s.hub_a_url, s.alliance_id, s.channel_id
        ))
        .bearer_auth(&s.token_a)
        .json(&json!({ "title": "allied post", "body": "allied body" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{}", resp.text().await.unwrap());
    let detail: PostDetail = resp.json().await.unwrap();
    assert_eq!(detail.summary.title.as_deref(), Some("allied post"));
    let hub_a_pubkey = s.hub_a_state.hub_identity.public_key_hex();
    assert_eq!(
        detail.summary.author_hub.as_deref(),
        Some(hub_a_pubkey.as_str())
    );
}

/// The per-origin-hub rate limiter (30 writes/60s, forum.md §9
/// "Threat-model deltas") trips after enough proxied writes from the same
/// origin hub, independent of whether the target post exists -- the limiter
/// is checked before the post lookup so a flood can't dodge it with bogus IDs.
#[tokio::test]
async fn alliance_forum_proxied_write_rate_limited() {
    let s = setup_forum_alliance(Some("posts_and_replies")).await;

    let mut last_status = 0u16;
    for _ in 0..31 {
        let resp = s
            .client
            .post(format!(
                "{}/alliances/{}/channels/{}/posts/no-such-post/replies",
                s.hub_a_url, s.alliance_id, s.channel_id
            ))
            .bearer_auth(&s.token_a)
            .json(&json!({ "body": "flood" }))
            .send()
            .await
            .unwrap();
        last_status = resp.status().as_u16();
    }
    // The 31st call trips the limiter on the owning hub; the requester's
    // proxy surfaces that as a gateway error same as any other rejection.
    assert_eq!(last_status, 502);
}
