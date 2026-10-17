use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// `messages.created_at` is in milliseconds. The retention sweep compared it
// against a cutoff in seconds, so a member's message was never old enough to
// delete and a channel's retention setting silently did nothing (#114).
#[tokio::test]
async fn retention_deletes_a_member_message_older_than_the_window() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let channel: Value = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "ephemeral" }))
        .await
        .json();
    let channel_id = channel["id"].as_str().unwrap().to_string();
    let old: Value = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&token)
        .json(&json!({ "content": "old news" }))
        .await
        .json();
    server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&token)
        .json(&json!({ "content": "fresh" }))
        .await
        .assert_status_success();

    let db = &server.state().db;
    sqlx::query("UPDATE channels SET retention_days = 30 WHERE id = $1")
        .bind(&channel_id)
        .execute(db)
        .await
        .unwrap();
    let forty_days_ms = 40 * 86_400 * 1000i64;
    sqlx::query("UPDATE messages SET created_at = created_at - $1 WHERE id = $2")
        .bind(forty_days_ms)
        .bind(old["id"].as_str().unwrap())
        .execute(db)
        .await
        .unwrap();

    wavvon_hub::retention_worker::run_sweep(server.state()).await;

    let left: Vec<String> =
        sqlx::query_scalar("SELECT content FROM messages WHERE channel_id = $1")
            .bind(&channel_id)
            .fetch_all(db)
            .await
            .unwrap();
    assert_eq!(left, ["fresh"]);
}
