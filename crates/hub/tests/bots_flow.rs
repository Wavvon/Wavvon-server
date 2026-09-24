use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Bot voice join/leave tests (M3)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Rejection tests
// ---------------------------------------------------------------------------

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

// ===========================================================================
// Unified bot path (decisions.md, "Every bot is an external bot")
//
// These replace the self-service equivalents that were deleted with
// POST /admin/bots. Same surfaces, same assertions, but the bot arrives with
// its own keypair and a session token instead of a hub-minted bearer token.
// ===========================================================================

#[tokio::test]
async fn self_service_bot_creation_is_gone() {
    let (server, owner_token) = common::setup_with_owner().await;

    let resp = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "ShouldNotExist" }))
        .await;

    // The router no longer has the path at all. Asserting "not success" rather
    // than a specific code keeps this honest about 404-vs-405 routing details.
    assert!(
        !resp.status_code().is_success(),
        "POST /admin/bots must not succeed; got {}",
        resp.status_code()
    );
}

#[tokio::test]
async fn external_bot_can_send_over_the_http_transport() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "bot-transport" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;

    server
        .post("/bot/send")
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id, "content": "posted without a websocket" }))
        .await
        .assert_status_success();

    let messages: serde_json::Value = server
        .get(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&owner_token)
        .await
        .json();
    let posted = messages
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["content"] == "posted without a websocket")
        .expect("the bot's message should be readable by a member");
    assert_eq!(posted["sender"], bot.public_key_hex());
}

#[tokio::test]
async fn member_session_is_rejected_on_the_bot_transport() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "bot-transport-gate" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // The owner is a perfectly valid session — it is simply not a bot. This is
    // the check that replaces "does this bearer token match a row in `bots`".
    let resp = server
        .post("/bot/send")
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_id": channel_id, "content": "I am human" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn external_bot_can_poll_events() {
    let (server, owner_token) = common::setup_with_owner().await;

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;

    let resp = server
        .get("/bot/poll")
        .authorization_bearer(&bot_token)
        .await;
    resp.assert_status_success();

    // A freshly invited bot has an empty queue — the shape matters, not the
    // contents, which is what the deleted self-service test asserted too.
    let body: serde_json::Value = resp.json();
    assert!(
        body["events"]
            .as_array()
            .expect("events must be an array")
            .is_empty(),
        "a new bot should have no queued events"
    );
}

#[tokio::test]
async fn external_bot_voice_leave_succeeds() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "voice-test" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;

    // Idempotent by contract: leaving without having joined is a no-op.
    let resp = server
        .delete(&format!("/bots/{}/voice/leave", bot.public_key_hex()))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn external_bot_screenshare_start_and_stop() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "share-test" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;
    let bot_key = bot.public_key_hex();

    let start = server
        .post(&format!("/bots/{bot_key}/screenshare/start"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    start.assert_status_success();
    let body: serde_json::Value = start.json();
    let stream_id = body["stream_id"].as_str().unwrap().to_string();
    assert!(!stream_id.is_empty());
    assert_eq!(body["channel_id"], channel_id);

    server
        .delete(&format!("/bots/{bot_key}/screenshare/stop"))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": channel_id, "stream_id": stream_id }))
        .await
        .assert_status_success();
}

#[tokio::test]
async fn external_bot_voice_leave_rejects_a_different_bot_in_the_path() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "voice-test" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let caller = Identity::generate();
    let caller_token = invite_and_auth_bot(&server, &owner_token, &caller).await;
    let other = Identity::generate();
    invite_and_auth_bot(&server, &owner_token, &other).await;

    let resp = server
        .delete(&format!("/bots/{}/voice/leave", other.public_key_hex()))
        .authorization_bearer(&caller_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn bot_voice_join_rest_endpoint_is_gone() {
    let (server, owner_token) = common::setup_with_owner().await;

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&server, &owner_token, &bot).await;

    // It only ever echoed back a constant "/ws" after an auth check. Voice is
    // joined over the WebSocket, which is also where the capability gate is.
    let resp = server
        .post(&format!("/bots/{}/voice/join", bot.public_key_hex()))
        .authorization_bearer(&bot_token)
        .json(&json!({ "channel_id": "whatever" }))
        .await;
    assert!(
        !resp.status_code().is_success(),
        "the join helper must not route; got {}",
        resp.status_code()
    );
}

// ---------------------------------------------------------------------------
// Who `POST /bots` may be pointed at (issue #29)
// ---------------------------------------------------------------------------

/// Authenticate normally — no `is_bot` — the way a person's client does.
async fn authenticate_as_a_person(
    server: &axum_test::TestServer,
    identity: &Identity,
) -> axum_test::TestResponse {
    let pub_key = identity.public_key_hex();
    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let challenge_bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let signature = identity.sign(&challenge_bytes);

    server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await
}

/// Inviting a key that already belongs to a member is refused, rather than
/// answered 200 with a token that can never be redeemed: `accept-invite`
/// looks for `is_bot = TRUE`, and a member's row is not one.
#[tokio::test]
async fn inviting_an_existing_member_as_a_bot_is_refused() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let member = Identity::generate();
    common::authenticate(&server, &member).await;

    let resp = server
        .post("/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "pubkey": member.public_key_hex() }))
        .await;
    resp.assert_status(axum::http::StatusCode::CONFLICT);

    // And the member's row is untouched: still a person, no invite token
    // stamped onto it.
    let is_bot: bool = sqlx::query_scalar("SELECT is_bot FROM users WHERE public_key = $1")
        .bind(member.public_key_hex())
        .fetch_one(&server.state().db)
        .await
        .unwrap();
    assert!(
        !is_bot,
        "a member must not become a bot by being invited as one"
    );

    let token: Option<String> =
        sqlx::query_scalar("SELECT bot_invite_token FROM users WHERE public_key = $1")
            .bind(member.public_key_hex())
            .fetch_one(&server.state().db)
            .await
            .unwrap();
    assert!(token.is_none(), "no unusable token written onto a member");
}

/// The open question in issue #29, answered rather than assumed: a stranger's
/// key — a person who simply has not joined yet — invited as a bot gets a
/// `bot_pending` row with `is_bot = TRUE`, and **authenticating normally does
/// not clear it**. They are admitted as an ordinary member and every later
/// read still treats them as a bot, DM exclusion included.
///
/// This test records today's behaviour so the review has the answer in one
/// place; it is not an endorsement of it.
#[tokio::test]
async fn a_stranger_invited_as_a_bot_stays_flagged_after_joining_as_a_person() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let stranger = Identity::generate();
    server
        .post("/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "pubkey": stranger.public_key_hex() }))
        .await
        .assert_status_success();

    // They authenticate as a person, asserting nothing about bots.
    let resp = authenticate_as_a_person(&server, &stranger).await;
    resp.assert_status_ok();

    let (is_bot, approval): (bool, String) =
        sqlx::query_as("SELECT is_bot, approval_status FROM users WHERE public_key = $1")
            .bind(stranger.public_key_hex())
            .fetch_one(&server.state().db)
            .await
            .unwrap();
    assert!(
        is_bot,
        "today the flag survives a normal join — the hub cannot tell a process from a person"
    );
    assert_eq!(
        approval, "bot_pending",
        "and they are left in the bots' waiting room rather than admitted"
    );

    // And `bot_pending` costs them nothing at the door: the session works and
    // reads succeed, so the practical effect of the whole thing is a person
    // wearing a bot's flag — excluded from DMs by the guard that reads it.
    let token = resp.json::<serde_json::Value>()["token"]
        .as_str()
        .unwrap()
        .to_string();
    server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
}
