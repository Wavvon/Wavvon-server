use serde_json::{json, Value};
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_identity::Identity;
use wavvon_test_server::TestServer;

use crate::common;

/// Create a text channel, optionally marking it NSFW at creation time.
async fn create_channel(
    server: &TestServer,
    token: &str,
    name: &str,
    nsfw: Option<bool>,
) -> String {
    let mut body = json!({ "name": name });
    if let Some(v) = nsfw {
        body["nsfw"] = json!(v);
    }
    let resp = server
        .post("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .await;
    assert_eq!(resp.status_code(), 201, "create channel: {}", resp.text());
    let created: Value = resp.json();
    created["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn nsfw_create_defaults_false_and_true_round_trips_through_list() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let default_id = create_channel(&server, &token, "general", None).await;
    let nsfw_id = create_channel(&server, &token, "uncensored", Some(true)).await;

    let resp = server
        .get("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let channels: Vec<ChannelResponse> = resp.json();

    let default_ch = channels.iter().find(|c| c.id == default_id).unwrap();
    assert!(
        !default_ch.nsfw,
        "default channel must default to nsfw=false"
    );

    let nsfw_ch = channels.iter().find(|c| c.id == nsfw_id).unwrap();
    assert!(
        nsfw_ch.nsfw,
        "channel created with nsfw=true must list as nsfw"
    );
}

#[tokio::test]
async fn nsfw_patch_toggles_on_and_off_without_disturbing_other_fields() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;
    let channel_id = create_channel(&server, &token, "general", None).await;

    // Flip it on.
    let resp = server
        .patch(&format!("/channels/{channel_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "nsfw": true }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());

    let resp = server
        .get("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let channels: Vec<ChannelResponse> = resp.json();
    let ch = channels.iter().find(|c| c.id == channel_id).unwrap();
    assert!(ch.nsfw);

    // A PATCH of an unrelated field leaves nsfw unchanged.
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
    assert!(ch.nsfw, "unrelated PATCH must not clear nsfw");

    // Flip it back off.
    let resp = server
        .patch(&format!("/channels/{channel_id}"))
        .add_header("Authorization", format!("Bearer {token}"))
        .json(&json!({ "nsfw": false }))
        .await;
    assert_eq!(resp.status_code(), 200, "{}", resp.text());

    let resp = server
        .get("/channels")
        .add_header("Authorization", format!("Bearer {token}"))
        .await;
    let channels: Vec<ChannelResponse> = resp.json();
    let ch = channels.iter().find(|c| c.id == channel_id).unwrap();
    assert!(!ch.nsfw);
}
