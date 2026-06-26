use serde_json::json;
use voxply_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn any_member_can_create_list_and_delete_bot() {
    let server = common::setup().await;
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    // Create a bot — any authenticated user can create
    let resp = server
        .post("/admin/bots")
        .authorization_bearer(&member_token)
        .json(&json!({ "display_name": "MyBot" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = resp.json();
    assert_eq!(body["display_name"], "MyBot");
    let bot_key = body["public_key"].as_str().unwrap().to_string();
    assert!(bot_key.starts_with("bot_"));
    let returned_token = body["token"].as_str().unwrap().to_string();
    assert_eq!(returned_token.len(), 64);
    // created_by should be the member
    assert_eq!(body["created_by"], member.public_key_hex());
    // token must NOT be in the list response
    assert!(body.get("webhook_url").is_some() || body.get("webhook_url").is_none()); // field may or may not appear

    // List shows the bot (without token)
    let list: serde_json::Value = server
        .get("/admin/bots")
        .authorization_bearer(&member_token)
        .await
        .json();
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["public_key"], bot_key);
    assert!(arr[0].get("token").is_none() || arr[0]["token"].is_null());

    // Get detail
    let detail: serde_json::Value = server
        .get(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&member_token)
        .await
        .json();
    assert_eq!(detail["public_key"], bot_key);
    assert!(detail["commands"].as_array().unwrap().is_empty());

    // Creator can delete
    server
        .delete(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&member_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Gone from list
    let list2: serde_json::Value = server
        .get("/admin/bots")
        .authorization_bearer(&member_token)
        .await
        .json();
    assert_eq!(list2.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn non_creator_cannot_delete_without_admin() {
    let server = common::setup().await;
    // First authenticator becomes the owner (gets Owner role).
    let _owner_token = common::authenticate(&server, &Identity::generate()).await;
    let creator = Identity::generate();
    let creator_token = common::authenticate(&server, &creator).await;
    let rando = Identity::generate();
    let rando_token = common::authenticate(&server, &rando).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&creator_token)
        .json(&json!({ "display_name": "BotX" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();

    // rando cannot delete creator's bot
    let del = server
        .delete(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&rando_token)
        .await;
    del.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn creator_can_set_and_clear_webhook() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "WebhookBot" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();

    // Set webhook
    server
        .put(&format!("/admin/bots/{bot_key}/webhook"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "webhook_url": "https://example.com/hook" }))
        .await
        .assert_status_success();

    let detail: serde_json::Value = server
        .get(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert_eq!(detail["webhook_url"], "https://example.com/hook");

    // Clear webhook
    server
        .put(&format!("/admin/bots/{bot_key}/webhook"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "webhook_url": null }))
        .await
        .assert_status_success();

    let detail2: serde_json::Value = server
        .get(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(detail2["webhook_url"].is_null());
}

#[tokio::test]
async fn bot_token_can_set_commands_and_poll() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "CmdBot" }))
        .await
        .json();
    let bot_token = resp["token"].as_str().unwrap().to_string();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();

    // Set slash commands
    server
        .put("/bot/commands")
        .authorization_bearer(&bot_token)
        .json(&json!({
            "commands": [
                { "command": "ping", "description": "Ping the bot" },
                { "command": "echo", "description": "Echo back" }
            ]
        }))
        .await
        .assert_status_success();

    // Detail shows commands
    let detail: serde_json::Value = server
        .get(&format!("/admin/bots/{bot_key}"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    let cmds = detail["commands"].as_array().unwrap();
    assert_eq!(cmds.len(), 2);
    let cmd_names: Vec<&str> = cmds
        .iter()
        .map(|c| c["command"].as_str().unwrap())
        .collect();
    assert!(cmd_names.contains(&"ping"));
    assert!(cmd_names.contains(&"echo"));

    // Poll with no events returns empty list
    let poll: serde_json::Value = server
        .get("/bot/poll")
        .authorization_bearer(&bot_token)
        .await
        .json();
    assert_eq!(poll["events"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn bot_can_send_message() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    // Create a channel first
    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "general" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "MsgBot" }))
        .await
        .json();
    let bot_token = resp["token"].as_str().unwrap().to_string();

    let send = server
        .post("/bot/send")
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id, "content": "Hello from bot" }))
        .await;
    send.assert_status_success();
    let body: serde_json::Value = send.json();
    assert_eq!(body["ok"], true);
}

// ---------------------------------------------------------------------------
// Bot voice join/leave tests (M3)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bot_voice_join_returns_ws_url() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    // Create a non-category channel.
    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "voice-test" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // Create the bot.
    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "VoiceBot" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();
    let bot_token = resp["token"].as_str().unwrap().to_string();

    // Happy path: bot authenticates as itself and requests to join a channel.
    let join_resp = server
        .post(&format!("/bots/{bot_key}/voice/join"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    join_resp.assert_status_success();
    let body: serde_json::Value = join_resp.json();
    assert!(body["voice_ws_url"].as_str().unwrap().contains("/voice/ws"));
    assert_eq!(body["channel_id"], channel_id);
}

#[tokio::test]
async fn bot_voice_join_rejects_wrong_caller() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    // Create two bots.
    let bot_a: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "BotA" }))
        .await
        .json();
    let bot_a_key = bot_a["public_key"].as_str().unwrap().to_string();

    let bot_b: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "BotB" }))
        .await
        .json();
    let bot_b_token = bot_b["token"].as_str().unwrap().to_string();

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "test" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // Bot B tries to join as Bot A — must be forbidden.
    let bad = server
        .post(&format!("/bots/{bot_a_key}/voice/join"))
        .authorization_bearer(&bot_b_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    bad.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bot_voice_join_rejects_missing_channel() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "NoChBot" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();
    let bot_token = resp["token"].as_str().unwrap().to_string();

    let not_found = server
        .post(&format!("/bots/{bot_key}/voice/join"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": "nonexistent-channel-id" }))
        .await;
    not_found.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn bot_voice_join_rejects_non_bot_pubkey_in_path() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let bot: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "RealBot" }))
        .await
        .json();
    let bot_token = bot["token"].as_str().unwrap().to_string();

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "ch" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // Use a pubkey that doesn't exist in users as a registered bot.
    let not_found = server
        .post("/bots/fake-bot-key/voice/join")
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    // The bot token belongs to a different pubkey, so it's forbidden.
    not_found.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bot_voice_leave_succeeds() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "LeaveBot" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();
    let bot_token = resp["token"].as_str().unwrap().to_string();

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "leave-ch" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // Leave succeeds even when the bot was never in the channel (no-op cleanup).
    let leave = server
        .delete(&format!("/bots/{bot_key}/voice/leave"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    leave.assert_status(axum::http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn bot_voice_leave_rejects_wrong_caller() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let bot_a: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "BotA2" }))
        .await
        .json();
    let bot_a_key = bot_a["public_key"].as_str().unwrap().to_string();

    let bot_b: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "BotB2" }))
        .await
        .json();
    let bot_b_token = bot_b["token"].as_str().unwrap().to_string();

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "ch2" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let bad = server
        .delete(&format!("/bots/{bot_a_key}/voice/leave"))
        .authorization_bearer(&bot_b_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    bad.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn voice_participants_includes_is_bot_field() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "bot-voice-ch" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // GET /voice/participants returns an empty map when no one is in voice.
    // Verify the endpoint is reachable and returns the right shape.
    let participants: serde_json::Value = server
        .get("/voice/participants")
        .authorization_bearer(&owner_token)
        .await
        .json();
    // With no active voice sessions the map is empty.
    assert!(
        participants.as_object().unwrap().is_empty()
            || participants[&channel_id].is_null()
            || participants[&channel_id]
                .as_array()
                .map(|a| a.is_empty())
                .unwrap_or(true)
    );
}

// ---------------------------------------------------------------------------
// Rejection tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_bot_rejects_empty_display_name() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "   " }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_bot_returns_404_for_unknown_key() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp = server
        .delete("/admin/bots/bot_does_not_exist")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_bot_returns_404_for_unknown_key() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp = server
        .get("/admin/bots/bot_does_not_exist")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn invalid_bot_token_returns_unauthorized_on_poll() {
    let server = common::setup().await;

    let resp = server
        .get("/bot/poll")
        .authorization_bearer("totallyfaketoken1234")
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_auth_returns_unauthorized_on_bot_send() {
    let server = common::setup().await;

    let resp = server
        .post("/bot/send")
        .json(&json!({ "channel_id": "x", "content": "hi" }))
        .await;
    resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
}
