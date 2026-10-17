use serde_json::json;

#[path = "common.rs"]
mod common;

/// The URL token is the whole credential of an incoming webhook: the right one
/// posts, a wrong one is refused, and no header changes either answer.
#[tokio::test]
async fn the_url_token_is_the_credential() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "alerts" }))
        .await
        .json();
    let created: serde_json::Value = server
        .post("/admin/webhooks")
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_id": chan["id"], "display_name": "CI" }))
        .await
        .json();
    let url = created["webhook_url"].as_str().unwrap();
    let path = &url[url.find("/webhooks/").unwrap()..];
    let (base, _token) = path.rsplit_once('/').unwrap();

    server
        .post(path)
        .json(&json!({ "content": "build green" }))
        .await
        .assert_status_ok();

    server
        .post(&format!("{base}/not-the-token"))
        .add_header("X-Wavvon-Signature", "00")
        .json(&json!({ "content": "spoofed" }))
        .await
        .assert_status_unauthorized();
}
