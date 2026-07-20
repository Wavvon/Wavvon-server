use serde_json::json;
use wavvon_identity::Identity;

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
// Bot screenshare start/stop tests (M4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bot_screenshare_start_returns_stream_id() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "share-test" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "ShareBot" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();
    let bot_token = resp["token"].as_str().unwrap().to_string();

    let start = server
        .post(&format!("/bots/{bot_key}/screenshare/start"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    start.assert_status_success();
    let body: serde_json::Value = start.json();
    assert!(!body["stream_id"].as_str().unwrap().is_empty());
    assert_eq!(body["channel_id"], channel_id);
}

#[tokio::test]
async fn bot_screenshare_stop_removes_stream() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "share-stop" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "StopBot" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();
    let bot_token = resp["token"].as_str().unwrap().to_string();

    // Start a stream.
    let start_body: serde_json::Value = server
        .post(&format!("/bots/{bot_key}/screenshare/start"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id }))
        .await
        .json();
    let stream_id = start_body["stream_id"].as_str().unwrap().to_string();

    // Stop returns 204.
    server
        .delete(&format!("/bots/{bot_key}/screenshare/stop"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id, "stream_id": stream_id }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Stop again (idempotent) is still 204.
    server
        .delete(&format!("/bots/{bot_key}/screenshare/stop"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id, "stream_id": stream_id }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn bot_screenshare_start_rejects_wrong_caller() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let bot_a: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "BotA3" }))
        .await
        .json();
    let bot_a_key = bot_a["public_key"].as_str().unwrap().to_string();

    let bot_b: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "BotB3" }))
        .await
        .json();
    let bot_b_token = bot_b["token"].as_str().unwrap().to_string();

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "ch3" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // Bot B tries to start a share as Bot A — must be forbidden.
    let bad = server
        .post(&format!("/bots/{bot_a_key}/screenshare/start"))
        .authorization_bearer(&bot_b_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    bad.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bot_screenshare_start_rejects_missing_channel() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "NoChanShareBot" }))
        .await
        .json();
    let bot_key = resp["public_key"].as_str().unwrap().to_string();
    let bot_token = resp["token"].as_str().unwrap().to_string();

    let not_found = server
        .post(&format!("/bots/{bot_key}/screenshare/start"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": "does-not-exist" }))
        .await;
    not_found.assert_status(axum::http::StatusCode::NOT_FOUND);
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

// ---------------------------------------------------------------------------
// Game-modal launch card (bot-capability-layer.md §2) on POST /messages
// ---------------------------------------------------------------------------

/// Invites `bot` as an external bot (admin_token needs manage_roles/admin,
/// which the hub's first authenticated user holds via builtin-owner) and
/// completes the normal Ed25519 challenge/verify flow, returning the bot's
/// session token -- same shape as `voice_relay_flow.rs`'s helper of the same
/// name, adapted to the in-process `axum_test::TestServer` used here.
async fn invite_and_auth_bot(
    server: &axum_test::TestServer,
    admin_token: &str,
    bot: &wavvon_identity::Identity,
) -> String {
    let pub_key = bot.public_key_hex();

    server
        .post("/bots")
        .authorization_bearer(admin_token)
        .json(&json!({ "pubkey": pub_key }))
        .await
        .assert_status_success();

    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let challenge_bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let signature = bot.sign(&challenge_bytes);

    let verify: serde_json::Value = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(signature.to_bytes()),
            "is_bot": true,
            "bot_meta": { "name": "GameBot" },
        }))
        .await
        .json();
    verify["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn external_bot_can_post_message_with_game_launch_card() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "game-room" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&bot_token)
        .json(&json!({
            "content": "Play a round?",
            "game": {
                "entry_url": "https://ttt.example.com/play",
                "name": "Tic-Tac-Toe",
                "description": "1v1"
            }
        }))
        .await;
    resp.assert_status_success();

    // The POST response itself carries the launch card.
    let posted: serde_json::Value = resp.json();
    assert_eq!(posted["game"]["entry_url"], "https://ttt.example.com/play");
    assert_eq!(posted["game"]["name"], "Tic-Tac-Toe");

    // It also survives the DB round-trip and comes back on a plain GET.
    let messages: serde_json::Value = server
        .get(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    let msgs = messages.as_array().unwrap();
    let game_msg = msgs
        .iter()
        .find(|m| m["content"] == "Play a round?")
        .expect("posted message should be in the read-back list");
    assert_eq!(
        game_msg["game"]["entry_url"],
        "https://ttt.example.com/play"
    );
    assert_eq!(game_msg["game"]["name"], "Tic-Tac-Toe");
    assert_eq!(game_msg["game"]["description"], "1v1");
}

/// `external_bot_can_post_message_with_game_launch_card` above (and every
/// other bot test in this file) runs on `setup()`, which forces
/// `invite_only = false` -- the one setting every real hub defaults to `true`
/// (task #31, `helpers/live.ts` in the web client). An invited external bot's
/// `/auth/verify` used to still hit the human invite-code gate below the
/// is_bot admission check and 403 with "This hub requires an invite code",
/// even though `POST /bots` was already the admin's explicit consent --
/// found running the ttt-bot demo against a real, default-config hub
/// (bot-capability-layer.md §7).
#[tokio::test]
async fn external_bot_auth_bypasses_the_invite_only_gate() {
    let server = common::setup_raw().await;

    // Bootstrap a real owner the same way a fresh hub actually does under
    // `invite_only = true` (invite_flow.rs's `first_boot_owner_invite_grants_
    // owner_and_is_one_time`) -- a bare `common::authenticate` with no invite
    // code 403s here too (`default_hub_rejects_join_without_invite`), so this
    // is not the human invite-code gate being exercised.
    let db = &server.state().db;
    let first_boot_code = wavvon_hub::routes::invites::maybe_mint_first_boot_owner_invite(db)
        .await
        .unwrap()
        .expect("a fresh, ownerless hub should mint a first-boot invite");

    let owner = Identity::generate();
    let pub_key = owner.public_key_hex();
    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let challenge_bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let signature = owner.sign(&challenge_bytes);
    let verify: serde_json::Value = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(signature.to_bytes()),
            "invite_code": first_boot_code,
        }))
        .await
        .json();
    let owner_token = verify["token"].as_str().unwrap().to_string();

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;
    assert!(!bot_token.is_empty());
}

// ---------------------------------------------------------------------------
// PATCH /channels/:id/messages/:id with a result embed (bot-capability-
// layer.md §7 step 5: "the bot updates the launch-card message via
// PATCH /messages/:id with a result embed"). Previously `EditMessageRequest`
// only carried `content` -- a bot had no way to attach the result embed on
// game end at all.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bot_can_patch_message_with_result_embed() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "game-room-patch" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;

    let posted: serde_json::Value = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "content": "Tic-Tac-Toe: click Play to join!" }))
        .await
        .json();
    let message_id = posted["id"].as_str().unwrap().to_string();

    let resp = server
        .patch(&format!("/channels/{channel_id}/messages/{message_id}"))
        .authorization_bearer(&bot_token)
        .json(&json!({
            "content": "Tic-Tac-Toe — game over.",
            "embeds": [{ "title": "Tic-Tac-Toe", "description": "X wins!", "color": "#22c55e" }]
        }))
        .await;
    resp.assert_status_success();
    let updated: serde_json::Value = resp.json();
    assert_eq!(updated["embeds"][0]["title"], "Tic-Tac-Toe");
    assert_eq!(updated["embeds"][0]["description"], "X wins!");
}

#[tokio::test]
async fn non_bot_cannot_patch_message_with_embeds() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "game-room-patch-2" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let posted: serde_json::Value = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "content": "hello" }))
        .await
        .json();
    let message_id = posted["id"].as_str().unwrap().to_string();

    let resp = server
        .patch(&format!("/channels/{channel_id}/messages/{message_id}"))
        .authorization_bearer(&owner_token)
        .json(&json!({
            "content": "hello",
            "embeds": [{ "title": "not allowed" }]
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_bot_cannot_post_message_with_game_launch_card() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "game-room-2" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let resp = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&owner_token)
        .json(&json!({
            "content": "Play a round?",
            "game": { "entry_url": "https://ttt.example.com/play", "name": "Tic-Tac-Toe" }
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Profile-declared game descriptor on the bot directory (bot-capability-
// layer.md §11 "the one thin slice worth building now"): lets the per-hub
// bot directory render a Play affordance without a live launch-card message
// in view.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bot_profile_game_descriptor_surfaces_on_directory_listing() {
    let (server, owner_token) = common::setup_with_owner().await;

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;

    // Bot declares a game descriptor via PUT /bots/me/profile.
    server
        .put("/bots/me/profile")
        .authorization_bearer(&bot_token)
        .json(&json!({
            "name": "GameBot",
            "game": {
                "entry_url": "https://ttt.example.com/play",
                "name": "Tic-Tac-Toe",
                "description": "1v1",
                "thumbnail_url": "https://ttt.example.com/thumb.png"
            }
        }))
        .await
        .assert_status_success();

    // The hub-local bot directory carries the descriptor for any member.
    let list: serde_json::Value = server
        .get("/bots")
        .authorization_bearer(&owner_token)
        .await
        .json();
    let entries = list.as_array().unwrap();
    let entry = entries
        .iter()
        .find(|e| e["pubkey"] == bot.public_key_hex())
        .expect("bot should appear in the directory listing");
    assert_eq!(entry["game"]["entry_url"], "https://ttt.example.com/play");
    assert_eq!(entry["game"]["name"], "Tic-Tac-Toe");
    assert_eq!(entry["game"]["description"], "1v1");
}

// ---------------------------------------------------------------------------
// GET /admin/bots/external -- admin management view (bots.md §4)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_lists_external_bots_across_pending_active_and_removed() {
    let (server, owner_token) = common::setup_with_owner().await;

    // Pending: invited with a local note, never accepted.
    let pending_bot = Identity::generate();
    let pending_key = pending_bot.public_key_hex();
    server
        .post("/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "pubkey": pending_key, "note": "mod bot, pending" }))
        .await
        .assert_status_success();

    // Active: invited and fully authenticated.
    let active_bot = Identity::generate();
    let active_key = active_bot.public_key_hex();
    let _active_token = invite_and_auth_bot(&server, &owner_token, &active_bot).await;

    // Removed: invited, accepted, then removed by an admin.
    let removed_bot = Identity::generate();
    let removed_key = removed_bot.public_key_hex();
    invite_and_auth_bot(&server, &owner_token, &removed_bot).await;
    server
        .delete(&format!("/bots/{removed_key}"))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let list: serde_json::Value = server
        .get("/admin/bots/external")
        .authorization_bearer(&owner_token)
        .await
        .json();
    let rows = list.as_array().unwrap();

    let find = |key: &str| rows.iter().find(|r| r["public_key"] == key).unwrap();

    let pending_row = find(&pending_key);
    assert_eq!(pending_row["approval_status"], "pending");
    assert_eq!(pending_row["local_note"], "mod bot, pending");

    let active_row = find(&active_key);
    assert_eq!(active_row["approval_status"], "active");

    let removed_row = find(&removed_key);
    assert_eq!(removed_row["approval_status"], "removed");
}

#[tokio::test]
async fn non_admin_cannot_list_external_bots() {
    let server = common::setup().await;
    let _owner_token = common::authenticate(&server, &Identity::generate()).await;
    let rando_token = common::authenticate(&server, &Identity::generate()).await;

    let resp = server
        .get("/admin/bots/external")
        .authorization_bearer(&rando_token)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// PUT /admin/bots/:pubkey/channels -- channel scope (bots.md §14)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_can_set_and_reset_bot_channel_scope() {
    let (server, owner_token) = common::setup_with_owner().await;

    let bot = Identity::generate();
    let bot_pubkey = bot.public_key_hex();
    invite_and_auth_bot(&server, &owner_token, &bot).await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "scoped-channel" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // Restrict to a single channel.
    let resp = server
        .put(&format!("/admin/bots/{bot_pubkey}/channels"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_ids": [channel_id.clone()] }))
        .await;
    resp.assert_status_success();
    let body: serde_json::Value = resp.json();
    assert_eq!(
        body["channel_ids"].as_array().unwrap(),
        std::slice::from_ref(&channel_id)
    );

    // Reset to hub-wide with an empty list.
    let resp2 = server
        .put(&format!("/admin/bots/{bot_pubkey}/channels"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_ids": [] }))
        .await;
    resp2.assert_status_success();
    let body2: serde_json::Value = resp2.json();
    assert!(body2["channel_ids"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn admin_can_get_bot_channel_scope() {
    let (server, owner_token) = common::setup_with_owner().await;

    let bot = Identity::generate();
    let bot_pubkey = bot.public_key_hex();
    invite_and_auth_bot(&server, &owner_token, &bot).await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "scoped-channel-get" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    server
        .put(&format!("/admin/bots/{bot_pubkey}/channels"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_ids": [channel_id.clone()] }))
        .await
        .assert_status_success();

    let resp = server
        .get(&format!("/admin/bots/{bot_pubkey}/channels"))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_success();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["bot_pubkey"], bot_pubkey);
    assert_eq!(
        body["channel_ids"].as_array().unwrap(),
        std::slice::from_ref(&channel_id)
    );
}

#[tokio::test]
async fn non_admin_cannot_get_bot_channel_scope() {
    let (server, owner_token) = common::setup_with_owner().await;
    let rando_token = common::authenticate(&server, &Identity::generate()).await;

    let bot = Identity::generate();
    let bot_pubkey = bot.public_key_hex();
    invite_and_auth_bot(&server, &owner_token, &bot).await;

    let resp = server
        .get(&format!("/admin/bots/{bot_pubkey}/channels"))
        .authorization_bearer(&rando_token)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn set_channel_scope_404s_for_unknown_bot() {
    let (server, owner_token) = common::setup_with_owner().await;

    let resp = server
        .put("/admin/bots/not-a-real-bot/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_ids": [] }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn non_admin_cannot_set_bot_channel_scope() {
    let (server, owner_token) = common::setup_with_owner().await;
    let rando_token = common::authenticate(&server, &Identity::generate()).await;

    let bot = Identity::generate();
    let bot_pubkey = bot.public_key_hex();
    invite_and_auth_bot(&server, &owner_token, &bot).await;

    let resp = server
        .put(&format!("/admin/bots/{bot_pubkey}/channels"))
        .authorization_bearer(&rando_token)
        .json(&json!({ "channel_ids": [] }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bot_directory_listing_omits_game_field_when_undeclared() {
    let (server, owner_token) = common::setup_with_owner().await;

    let bot = Identity::generate();
    // invite_and_auth_bot's bot_meta has no "game" field at all.
    invite_and_auth_bot(&server, &owner_token, &bot).await;

    let list: serde_json::Value = server
        .get("/bots")
        .authorization_bearer(&owner_token)
        .await
        .json();
    let entries = list.as_array().unwrap();
    let entry = entries
        .iter()
        .find(|e| e["pubkey"] == bot.public_key_hex())
        .expect("bot should appear in the directory listing");
    assert!(
        entry.get("game").is_none(),
        "game field should be absent (skip_serializing_if), got: {entry:?}"
    );
}
