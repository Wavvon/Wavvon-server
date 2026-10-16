use axum::http::StatusCode;
use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// A channel ban means the channel grants that member nothing. It used to
/// gate only sending and typing, so the history stayed readable and the
/// channel stayed in the member's list.
#[tokio::test]
async fn a_channel_ban_hides_the_history_too() {
    let server = common::setup().await;
    let owner = common::authenticate(&server, &Identity::generate()).await;
    let member_id = Identity::generate();
    let member = common::authenticate(&server, &member_id).await;

    let ch: Value = server
        .post("/channels")
        .authorization_bearer(&owner)
        .json(&json!({ "name": "general" }))
        .await
        .json();
    let ch = ch["id"].as_str().unwrap().to_string();
    server
        .post(&format!("/channels/{ch}/bans"))
        .authorization_bearer(&owner)
        .json(&json!({ "pubkey": member_id.public_key_hex() }))
        .await
        .assert_status(StatusCode::CREATED);

    server
        .get(&format!("/channels/{ch}/messages"))
        .authorization_bearer(&member)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    let listed: Value = server
        .get("/channels")
        .authorization_bearer(&member)
        .await
        .json();
    assert!(
        !listed
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == ch.as_str()),
        "a banned channel must not be listed"
    );
}
