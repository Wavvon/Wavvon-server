use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// One hub, two alliances that have nothing to do with each other.
//
// A hub can be in many alliances (alliances.md), and the whole point is that
// they do not merge: an ally in one must not see what the hub shares into
// another. These drive that from the only position that can test it — a hub
// identity, which is what a federating peer authenticates as.
// ---------------------------------------------------------------------------

/// Authenticates `hub` as a **federating peer** (`is_hub: true`), the posture
/// every hub takes when it talks to another. It needs no invite: a peer is not
/// a person joining a community.
async fn authenticate_as_hub(server: &axum_test::TestServer, hub: &Identity) -> String {
    let pub_key = hub.public_key_hex();
    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let verify: serde_json::Value = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(hub.sign(&bytes).to_bytes()),
            "is_hub": true,
        }))
        .await
        .json();
    verify["token"].as_str().unwrap().to_string()
}

/// Creates an alliance owning one shared text channel, and returns its id.
async fn alliance_with_shared_channel(
    server: &axum_test::TestServer,
    owner_token: &str,
    name: &str,
    channel_name: &str,
    message: &str,
) -> String {
    let channel: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(owner_token)
        .json(&json!({ "name": channel_name, "channel_type": "text" }))
        .await
        .json();
    let channel_id = channel["id"].as_str().unwrap().to_string();

    server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(owner_token)
        .json(&json!({ "content": message }))
        .await
        .assert_status_success();

    let alliance: serde_json::Value = server
        .post("/alliances")
        .authorization_bearer(owner_token)
        .json(&json!({ "name": name }))
        .await
        .json();
    let alliance_id = alliance["id"].as_str().unwrap().to_string();

    server
        .post(&format!("/alliances/{alliance_id}/channels"))
        .authorization_bearer(owner_token)
        .json(&json!({ "channel_id": channel_id }))
        .await
        .assert_status_success();

    alliance_id
}

#[tokio::test]
async fn a_stranger_hub_sees_no_alliances() {
    let (server, owner_token) = common::setup_with_owner().await;
    alliance_with_shared_channel(&server, &owner_token, "Sewing", "patterns", "hello").await;

    let stranger = Identity::generate();
    let stranger_token = authenticate_as_hub(&server, &stranger).await;

    let listed = server
        .get("/alliances")
        .authorization_bearer(&stranger_token)
        .await;
    listed.assert_status_ok();
    let body = listed.json::<serde_json::Value>();
    assert_eq!(
        body.as_array().map(|a| a.len()),
        Some(0),
        "a hub in none of this hub's alliances must be told about none of them, got {body}",
    );
}

#[tokio::test]
async fn a_stranger_hub_cannot_read_an_alliance_channel() {
    let (server, owner_token) = common::setup_with_owner().await;
    let alliance_id =
        alliance_with_shared_channel(&server, &owner_token, "Sewing", "patterns", "secret").await;

    let stranger = Identity::generate();
    let stranger_token = authenticate_as_hub(&server, &stranger).await;

    let channels = server
        .get(&format!("/alliances/{alliance_id}/channels"))
        .authorization_bearer(&stranger_token)
        .await;
    assert!(
        channels.status_code().is_client_error(),
        "listing another alliance's shared channels must be refused, got {} {}",
        channels.status_code(),
        channels.text(),
    );
}

#[tokio::test]
async fn a_stranger_hub_cannot_read_alliance_messages() {
    let (server, owner_token) = common::setup_with_owner().await;
    let alliance_id =
        alliance_with_shared_channel(&server, &owner_token, "Sewing", "patterns", "secret").await;

    // The channel id, as a member would see it.
    let mine: serde_json::Value = server
        .get(&format!("/alliances/{alliance_id}/channels"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    let channel_id = mine[0]["channel_id"].as_str().unwrap().to_string();

    let stranger = Identity::generate();
    let stranger_token = authenticate_as_hub(&server, &stranger).await;

    let messages = server
        .get(&format!(
            "/alliances/{alliance_id}/channels/{channel_id}/messages"
        ))
        .authorization_bearer(&stranger_token)
        .await;
    assert!(
        messages.status_code().is_client_error(),
        "reading another alliance's messages must be refused, got {} {}",
        messages.status_code(),
        messages.text(),
    );
}
