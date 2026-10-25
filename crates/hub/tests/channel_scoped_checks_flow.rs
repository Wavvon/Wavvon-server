use axum::http::StatusCode;
use axum_test::multipart::{MultipartForm, Part};
use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// Routes that act on a channel without asking the channel: each used to check
// a hub-wide permission, or nothing at all, where the channel's own overwrite
// should have decided (#118).

async fn channel(server: &common::TestHarness, token: &str, kind: &str) -> String {
    let ch: Value = server
        .post("/channels")
        .authorization_bearer(token)
        .json(&json!({ "name": format!("{kind}-{}", uuid::Uuid::new_v4().simple()), "channel_type": kind }))
        .await
        .json();
    ch["id"].as_str().unwrap().to_string()
}

async fn deny_everyone(server: &common::TestHarness, owner: &str, channel_id: &str, perm: &str) {
    server
        .put(&format!(
            "/channels/{channel_id}/permissions/builtin-everyone"
        ))
        .authorization_bearer(owner)
        .json(&json!({ "allow": [], "deny": [perm] }))
        .await
        .assert_status_ok();
}

async fn hub() -> (common::TestHarness, String, String, Identity) {
    let server = common::setup().await;
    let owner = common::authenticate(&server, &Identity::generate()).await;
    let member_id = Identity::generate();
    let member = common::authenticate(&server, &member_id).await;
    (server, owner, member, member_id)
}

#[tokio::test]
async fn a_read_only_channel_takes_no_poll_and_no_upload() {
    let (server, owner, member, _) = hub().await;
    let ch = channel(&server, &owner, "text").await;
    deny_everyone(&server, &owner, &ch, "messages.send").await;

    server
        .post(&format!("/channels/{ch}/polls"))
        .authorization_bearer(&member)
        .json(&json!({
            "question": "?",
            "options": [{ "id": "a", "text": "A" }, { "id": "b", "text": "B" }],
        }))
        .await
        .assert_status(StatusCode::FORBIDDEN);

    let form = MultipartForm::new().add_part(
        "file",
        Part::bytes(vec![0u8; 16])
            .file_name("x.png")
            .mime_type("image/png"),
    );
    server
        .post(&format!("/channels/{ch}/upload"))
        .authorization_bearer(&member)
        .multipart(form)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_poll_in_a_hidden_channel_cannot_be_read_or_voted() {
    let (server, owner, member, _) = hub().await;
    let ch = channel(&server, &owner, "text").await;
    let poll: Value = server
        .post(&format!("/channels/{ch}/polls"))
        .authorization_bearer(&owner)
        .json(&json!({
            "question": "?",
            "options": [{ "id": "a", "text": "A" }, { "id": "b", "text": "B" }],
        }))
        .await
        .json();
    let poll_id = poll["id"].as_str().unwrap().to_string();
    deny_everyone(&server, &owner, &ch, "messages.read").await;

    server
        .get(&format!("/polls/{poll_id}"))
        .authorization_bearer(&member)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .post(&format!("/polls/{poll_id}/vote"))
        .authorization_bearer(&member)
        .json(&json!({ "option_ids": ["a"] }))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_hidden_forum_cannot_be_searched_and_a_muted_member_cannot_post() {
    let (server, owner, member, member_id) = hub().await;
    let hidden = channel(&server, &owner, "forum").await;
    deny_everyone(&server, &owner, &hidden, "messages.read").await;
    server
        .get(&format!("/channels/{hidden}/posts/search"))
        .add_query_param("q", "anything")
        .authorization_bearer(&member)
        .await
        .assert_status(StatusCode::FORBIDDEN);

    let open = channel(&server, &owner, "forum").await;
    server
        .post("/moderation/mutes")
        .authorization_bearer(&owner)
        .json(&json!({ "target_public_key": member_id.public_key_hex() }))
        .await
        .assert_status(StatusCode::CREATED);
    server
        .post(&format!("/channels/{open}/posts"))
        .authorization_bearer(&member)
        .json(&json!({ "title": "t", "body": "b" }))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}
