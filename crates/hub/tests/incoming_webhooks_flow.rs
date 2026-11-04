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

/// A webhook's `username` and `avatar_url` are a masquerade stored with the
/// message: they used to reach only the live broadcast, so history showed the
/// webhook's own name. The avatar is kept only as the hub's own copy, so one
/// the hub may not fetch (here a loopback address) is dropped, never stored as
/// a third-party URL.
#[tokio::test]
async fn a_webhook_masquerade_is_kept_in_history() {
    let (server, owner_token) = common::setup_with_owner().await;
    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "bridge" }))
        .await
        .json();
    let created: serde_json::Value = server
        .post("/admin/webhooks")
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_id": chan["id"], "display_name": "Bridge" }))
        .await
        .json();
    let url = created["webhook_url"].as_str().unwrap();
    let path = &url[url.find("/webhooks/").unwrap()..];

    server
        .post(path)
        .json(&json!({
            "content": "hello from elsewhere",
            "username": "Ada",
            "avatar_url": "https://127.0.0.1/ada.png",
        }))
        .await
        .assert_status_ok();

    let msgs: serde_json::Value = server
        .get(&format!(
            "/channels/{}/messages",
            chan["id"].as_str().unwrap()
        ))
        .authorization_bearer(&owner_token)
        .await
        .json();
    let m = &msgs.as_array().unwrap()[0];
    assert_eq!(m["sender_name"], "Bridge");
    assert_eq!(m["masquerade"]["name"], "Ada");
    assert!(m["masquerade"].get("avatar_url").is_none());
}

/// Masquerading needs `messages.masquerade`: a plain member is refused, and a
/// malformed one is refused even for the owner.
#[tokio::test]
async fn masquerade_needs_the_permission_and_a_sane_name() {
    let (server, owner_token) = common::setup_with_owner().await;
    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "general2" }))
        .await
        .json();
    let path = format!("/channels/{}/messages", chan["id"].as_str().unwrap());

    let member = common::authenticate(&server, &wavvon_identity::Identity::generate()).await;
    server
        .post(&path)
        .authorization_bearer(&member)
        .json(&json!({ "content": "hi", "masquerade": { "name": "Someone else" } }))
        .await
        .assert_status_forbidden();

    server
        .post(&path)
        .authorization_bearer(&owner_token)
        .json(&json!({ "content": "hi", "masquerade": { "name": "  " } }))
        .await
        .assert_status_bad_request();

    let sent: serde_json::Value = server
        .post(&path)
        .authorization_bearer(&owner_token)
        .json(&json!({ "content": "relayed", "masquerade": { "name": "Grace" } }))
        .await
        .json();
    assert_eq!(sent["masquerade"]["name"], "Grace");
    assert!(sent["masquerade"].get("avatar_url").is_none());
}
