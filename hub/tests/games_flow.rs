//! Integration tests for Tier 2 game session routes.

use axum_test::TestServer;
use serde_json::{json, Value};
use voxply_identity::Identity;

#[path = "common.rs"] mod common;

// ---------------------------------------------------------------------------
// Setup helpers
// ---------------------------------------------------------------------------

/// Install a minimal game and return its id.
async fn install_game(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/admin/games")
        .authorization_bearer(token)
        .json(&json!({
            "name": "Test Game",
            "entry_url": "https://example.com/game/index.html"
        }))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

/// Create a text channel and return its id.
async fn create_channel(server: &TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .authorization_bearer(token)
        .json(&json!({ "name": "game-room" }))
        .await;
    resp.assert_status_success();
    let body: Value = resp.json();
    body["id"].as_str().unwrap().to_string()
}

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_session_happy_path() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    let body: Value = resp.json();
    assert_eq!(body["game_id"].as_str().unwrap(), game_id);
    assert_eq!(body["channel_id"].as_str().unwrap(), channel_id);
    assert_eq!(body["host_pubkey"].as_str().unwrap(), identity.public_key_hex());
    assert!(body["ended_at"].is_null());
}

#[tokio::test]
async fn get_session_after_create() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    create_resp.assert_status(axum::http::StatusCode::CREATED);
    let created: Value = create_resp.json();
    let session_id = created["id"].as_str().unwrap().to_string();

    let resp = server
        .get(&format!("/game-sessions/{session_id}"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["id"].as_str().unwrap(), session_id);
}

#[tokio::test]
async fn join_session_happy_path() {
    let server = common::setup().await;
    let host = Identity::generate();
    let host_token = common::authenticate(&server, &host).await;
    let player = Identity::generate();
    let player_token = common::authenticate(&server, &player).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    create_resp.assert_status(axum::http::StatusCode::CREATED);
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let join_resp = server
        .post(&format!("/game-sessions/{session_id}/join"))
        .authorization_bearer(&player_token)
        .await;
    join_resp.assert_status_ok();
    let body: Value = join_resp.json();
    // players list comes from in-memory state; should include the joiner.
    let players: Vec<String> = body["players"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(players.contains(&player.public_key_hex()));
}

#[tokio::test]
async fn patch_state_by_host() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let patch_resp = server
        .post(&format!("/game-sessions/{session_id}/state"))
        .authorization_bearer(&token)
        .json(&json!({ "patch": { "round": 1, "phase": "voting" } }))
        .await;
    patch_resp.assert_status(axum::http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn shared_kv_set_and_get() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    // Set a key.
    let set_resp = server
        .post(&format!("/game-sessions/{session_id}/shared-kv/leaderboard"))
        .authorization_bearer(&token)
        .json(&json!({ "value": "[{\"pubkey\":\"abc\",\"score\":100}]" }))
        .await;
    set_resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Get it back.
    let get_resp = server
        .get(&format!("/game-sessions/{session_id}/shared-kv/leaderboard"))
        .authorization_bearer(&token)
        .await;
    get_resp.assert_status_ok();
    let body: Value = get_resp.json();
    assert_eq!(body["key"].as_str().unwrap(), "leaderboard");
    assert!(body["value"].as_str().unwrap().contains("score"));
}

#[tokio::test]
async fn end_session_by_host() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let del_resp = server
        .delete(&format!("/game-sessions/{session_id}"))
        .authorization_bearer(&token)
        .await;
    del_resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // GET now returns 410 GONE.
    let get_resp = server
        .get(&format!("/game-sessions/{session_id}"))
        .authorization_bearer(&token)
        .await;
    get_resp.assert_status(axum::http::StatusCode::GONE);
}

// ---------------------------------------------------------------------------
// Rejection / auth tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_session_rejects_unknown_game() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "game_id": "no-such-game", "channel_id": channel_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn patch_state_rejected_for_non_host() {
    let server = common::setup().await;
    let host = Identity::generate();
    let host_token = common::authenticate(&server, &host).await;
    let other = Identity::generate();
    let other_token = common::authenticate(&server, &other).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    // Other user (non-admin, non-host) tries to patch.
    let patch_resp = server
        .post(&format!("/game-sessions/{session_id}/state"))
        .authorization_bearer(&other_token)
        .json(&json!({ "patch": { "cheating": true } }))
        .await;
    patch_resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn end_session_rejected_for_non_host() {
    let server = common::setup().await;
    let host = Identity::generate();
    let host_token = common::authenticate(&server, &host).await;
    let other = Identity::generate();
    let other_token = common::authenticate(&server, &other).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/channels/{channel_id}/game-sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "game_id": game_id, "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let del_resp = server
        .delete(&format!("/game-sessions/{session_id}"))
        .authorization_bearer(&other_token)
        .await;
    del_resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Spec Tier 2 route tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_session_v2_happy_path() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post(&format!("/games/{game_id}/sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    let body: Value = resp.json();
    assert_eq!(body["game_id"].as_str().unwrap(), game_id);
    assert_eq!(body["channel_id"].as_str().unwrap(), channel_id);
    assert_eq!(body["host_pubkey"].as_str().unwrap(), identity.public_key_hex());
    assert_eq!(body["status"].as_str().unwrap(), "lobby");
    assert!(body["session_id"].is_string());
}

#[tokio::test]
async fn list_sessions_returns_created() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    server
        .post(&format!("/games/{game_id}/sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "channel_id": channel_id }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let list_resp = server
        .get(&format!("/games/sessions?channel_id={channel_id}"))
        .authorization_bearer(&token)
        .await;
    list_resp.assert_status_ok();
    let body: Value = list_resp.json();
    let sessions = body["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0]["game_id"].as_str().unwrap(), game_id);
}

#[tokio::test]
async fn join_and_get_session_v2() {
    let server = common::setup().await;
    let host = Identity::generate();
    let host_token = common::authenticate(&server, &host).await;
    let player = Identity::generate();
    let player_token = common::authenticate(&server, &player).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/games/{game_id}/sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    create_resp.assert_status(axum::http::StatusCode::CREATED);
    let session_id = create_resp.json::<Value>()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Player joins.
    let join_resp = server
        .post(&format!("/games/sessions/{session_id}/join"))
        .authorization_bearer(&player_token)
        .await;
    join_resp.assert_status_ok();
    let body: Value = join_resp.json();
    let pubkeys: Vec<&str> = body["players"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["pubkey"].as_str().unwrap())
        .collect();
    assert!(pubkeys.contains(&player.public_key_hex().as_str()));

    // GET the session.
    let get_resp = server
        .get(&format!("/games/sessions/{session_id}"))
        .authorization_bearer(&player_token)
        .await;
    get_resp.assert_status_ok();
    let get_body: Value = get_resp.json();
    assert_eq!(get_body["session_id"].as_str().unwrap(), session_id);
    assert_eq!(get_body["status"].as_str().unwrap(), "lobby");
}

#[tokio::test]
async fn leave_session_removes_player() {
    let server = common::setup().await;
    let host = Identity::generate();
    let host_token = common::authenticate(&server, &host).await;
    let player = Identity::generate();
    let player_token = common::authenticate(&server, &player).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/games/{game_id}/sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    server
        .post(&format!("/games/sessions/{session_id}/join"))
        .authorization_bearer(&player_token)
        .await
        .assert_status_ok();

    let leave_resp = server
        .post(&format!("/games/sessions/{session_id}/leave"))
        .authorization_bearer(&player_token)
        .await;
    leave_resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Session should still exist (host didn't leave).
    let get_resp = server
        .get(&format!("/games/sessions/{session_id}"))
        .authorization_bearer(&host_token)
        .await;
    get_resp.assert_status_ok();
    let body: Value = get_resp.json();
    let pubkeys: Vec<&str> = body["players"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["pubkey"].as_str().unwrap())
        .collect();
    assert!(!pubkeys.contains(&player.public_key_hex().as_str()));
}

#[tokio::test]
async fn force_end_session_by_host_v2() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let game_id = install_game(&server, &token).await;
    let channel_id = create_channel(&server, &token).await;

    let create_resp = server
        .post(&format!("/games/{game_id}/sessions"))
        .authorization_bearer(&token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let del_resp = server
        .delete(&format!("/games/sessions/{session_id}"))
        .authorization_bearer(&token)
        .await;
    del_resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // GET returns 404 (removed from in-memory map).
    let get_resp = server
        .get(&format!("/games/sessions/{session_id}"))
        .authorization_bearer(&token)
        .await;
    get_resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn force_end_session_rejected_for_non_host_v2() {
    let server = common::setup().await;
    let host = Identity::generate();
    let host_token = common::authenticate(&server, &host).await;
    let other = Identity::generate();
    let other_token = common::authenticate(&server, &other).await;

    let game_id = install_game(&server, &host_token).await;
    let channel_id = create_channel(&server, &host_token).await;

    let create_resp = server
        .post(&format!("/games/{game_id}/sessions"))
        .authorization_bearer(&host_token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    let session_id = create_resp.json::<Value>()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let del_resp = server
        .delete(&format!("/games/sessions/{session_id}"))
        .authorization_bearer(&other_token)
        .await;
    del_resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_session_v2_rejects_unknown_game() {
    let server = common::setup().await;
    let identity = Identity::generate();
    let token = common::authenticate(&server, &identity).await;

    let channel_id = create_channel(&server, &token).await;

    let resp = server
        .post("/games/no-such-game/sessions")
        .authorization_bearer(&token)
        .json(&json!({ "channel_id": channel_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}
