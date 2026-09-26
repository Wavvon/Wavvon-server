//! A program is a member with `apps.register`, and nothing else sets it
//! apart. These tests cover the surface that replaced the bot subsystem:
//! self-service registration, the message shapes that registration unlocks,
//! event subscriptions and their polling transport — and, in the rejection
//! half, that the old admission fork is gone rather than renamed.

use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

/// Grants `apps.register` to everyone on this hub, which is how an admin
/// would do it: a permission on a role, not a property of an identity.
async fn grant_apps_register(server: &common::TestHarness) {
    sqlx::query(
        "INSERT INTO role_permissions (role_id, permission)
         VALUES ('builtin-everyone', 'apps.register')
         ON CONFLICT DO NOTHING",
    )
    .execute(&server.state().db)
    .await
    .unwrap();
}

/// An identity that has authenticated normally and registered an app.
async fn register_app(server: &common::TestHarness, name: &str) -> (Identity, String) {
    let app = Identity::generate();
    let token = common::authenticate(server, &app).await;

    server
        .put("/me/app/profile")
        .authorization_bearer(&token)
        .json(&json!({ "name": name }))
        .await
        .assert_status_success();

    (app, token)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn registering_an_app_needs_the_permission() {
    // The owner holds every permission, so the caller under test has to be
    // the second identity on the hub.
    let (server, _owner_token) = common::setup_with_owner().await;
    let stranger = Identity::generate();
    let token = common::authenticate(&server, &stranger).await;

    let resp = server
        .put("/me/app/profile")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Scoreboard" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_registered_app_reads_back_its_profile_and_commands() {
    let server = common::setup().await;
    grant_apps_register(&server).await;
    let (_app, token) = register_app(&server, "Scoreboard").await;

    server
        .put("/me/app/commands")
        .authorization_bearer(&token)
        .json(&json!({
            "commands": [
                { "name": "score", "description": "show the score" },
                { "name": "reset", "description": "start over" }
            ]
        }))
        .await
        .assert_status_success();

    let me: serde_json::Value = server
        .get("/me/app")
        .authorization_bearer(&token)
        .await
        .json();

    assert_eq!(me["name"], "Scoreboard");
    let names: Vec<&str> = me["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["reset", "score"], "commands come back sorted");
}

#[tokio::test]
async fn an_identity_with_no_registration_has_no_app() {
    let server = common::setup().await;
    grant_apps_register(&server).await;
    let holder = Identity::generate();
    let token = common::authenticate(&server, &holder).await;

    let resp = server.get("/me/app").authorization_bearer(&token).await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// What registration unlocks on a message
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_registered_app_posts_a_game_launch_card() {
    let (server, owner_token) = common::setup_with_owner().await;
    grant_apps_register(&server).await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "game-room" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let (_app, token) = register_app(&server, "GameApp").await;

    let resp = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&token)
        .json(&json!({
            "content": "play me",
            "game": { "entry_url": "https://example.test/ttt", "name": "Tic Tac Toe" }
        }))
        .await;
    resp.assert_status_success();

    let posted: serde_json::Value = resp.json();
    assert_eq!(posted["game"]["name"], "Tic Tac Toe");
}

#[tokio::test]
async fn a_member_without_the_permission_cannot_post_a_launch_card() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "game-room" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&member_token)
        .json(&json!({
            "content": "trust me",
            "game": { "entry_url": "https://example.test/x", "name": "Definitely Fine" }
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Subscriptions and the polling transport
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_message_subscription_must_name_its_channels() {
    let server = common::setup().await;
    grant_apps_register(&server).await;
    let (_app, token) = register_app(&server, "Logger").await;

    let resp = server
        .put("/me/app/subscriptions")
        .authorization_bearer(&token)
        .json(&json!({ "subscriptions": [{ "event": "message.created" }] }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn hub_scoped_subscriptions_are_replaced_atomically() {
    let server = common::setup().await;
    grant_apps_register(&server).await;
    let (app, token) = register_app(&server, "Logger").await;

    let first: serde_json::Value = server
        .put("/me/app/subscriptions")
        .authorization_bearer(&token)
        .json(&json!({
            "subscriptions": [{ "event": "member.joined" }, { "event": "member.left" }]
        }))
        .await
        .json();
    assert_eq!(first["count"], 2);

    let second: serde_json::Value = server
        .put("/me/app/subscriptions")
        .authorization_bearer(&token)
        .json(&json!({ "subscriptions": [{ "event": "member.joined" }] }))
        .await
        .json();
    assert_eq!(second["count"], 1);

    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM app_subscriptions WHERE app_pubkey = $1")
            .bind(app.public_key_hex())
            .fetch_one(&server.state().db)
            .await
            .unwrap();
    assert_eq!(rows, 1, "the replace must not leave the old rows behind");
}

#[tokio::test]
async fn queued_events_are_polled_then_acknowledged() {
    let server = common::setup().await;
    grant_apps_register(&server).await;
    let (app, token) = register_app(&server, "Poller").await;

    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO app_event_queue (id, app_pubkey, event_type, payload, created_at)
         VALUES ('evt-1', $1, 'member.joined', '{}', $2)",
    )
    .bind(app.public_key_hex())
    .bind(now)
    .execute(&server.state().db)
    .await
    .unwrap();

    let polled: serde_json::Value = server
        .get("/me/events")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(polled["events"].as_array().unwrap().len(), 1);

    server
        .delete("/me/events")
        .authorization_bearer(&token)
        .json(&json!({ "ids": ["evt-1"] }))
        .await
        .assert_status_success();

    let after: serde_json::Value = server
        .get("/me/events")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(after["events"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn one_identity_never_reads_another_ones_queue() {
    let server = common::setup().await;
    grant_apps_register(&server).await;
    let (app, _app_token) = register_app(&server, "Poller").await;
    let (_other, other_token) = register_app(&server, "Nosy").await;

    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO app_event_queue (id, app_pubkey, event_type, payload, created_at)
         VALUES ('evt-1', $1, 'member.joined', '{}', $2)",
    )
    .bind(app.public_key_hex())
    .bind(now)
    .execute(&server.state().db)
    .await
    .unwrap();

    let polled: serde_json::Value = server
        .get("/me/events")
        .authorization_bearer(&other_token)
        .await
        .json();
    assert!(polled["events"].as_array().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Voice and screenshare over HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn screenshare_starts_and_stops_over_http() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "stage" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    let started: serde_json::Value = server
        .post("/screenshare/start")
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_id": channel_id }))
        .await
        .json();
    let stream_id = started["stream_id"].as_str().unwrap().to_string();

    server
        .delete("/screenshare/stop")
        .authorization_bearer(&owner_token)
        .json(&json!({ "channel_id": channel_id, "stream_id": stream_id }))
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn leaving_voice_over_http_is_idempotent() {
    let (server, owner_token) = common::setup_with_owner().await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "stage" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    for _ in 0..2 {
        server
            .delete("/voice/leave")
            .authorization_bearer(&owner_token)
            .json(&json!({ "channel_id": channel_id }))
            .await
            .assert_status(axum::http::StatusCode::NO_CONTENT);
    }
}

// ---------------------------------------------------------------------------
// The admission fork is gone, not renamed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_bot_admission_endpoints_are_gone() {
    let (server, owner_token) = common::setup_with_owner().await;

    for (method, path) in [
        ("POST", "/bots"),
        ("GET", "/bots"),
        ("POST", "/bots/accept-invite"),
        ("GET", "/bots/me"),
        ("GET", "/admin/bots/external"),
        ("POST", "/bot/send"),
        ("GET", "/bot/poll"),
    ] {
        let resp = match method {
            "POST" => {
                server
                    .post(path)
                    .authorization_bearer(&owner_token)
                    .json(&json!({}))
                    .await
            }
            _ => server.get(path).authorization_bearer(&owner_token).await,
        };
        assert_eq!(
            resp.status_code(),
            axum::http::StatusCode::NOT_FOUND,
            "{method} {path} should not exist",
        );
    }
}

/// The hole the old fork left open: `POST /bots` wrote an `is_bot` row for a
/// pubkey whose owner had never arrived, and every later read treated that
/// person as a bot. With one admission path there is nothing to pre-seed —
/// a stranger presents an invite code, or does not get in.
#[tokio::test]
async fn a_program_joins_through_the_one_admission_gate() {
    let server = common::setup_raw().await;

    let program = Identity::generate();
    let pub_key = program.public_key_hex();

    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let challenge_bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let signature = program.sign(&challenge_bytes);

    let refused = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(signature.to_bytes()),
            "is_bot": true,
        }))
        .await;
    refused.assert_status(axum::http::StatusCode::FORBIDDEN);

    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO invites (code, created_by, max_uses, uses, expires_at, created_at)
         VALUES ('letmein', 'system', 1, 0, NULL, $1)",
    )
    .bind(now)
    .execute(&server.state().db)
    .await
    .unwrap();

    let challenge: serde_json::Value = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await
        .json();
    let challenge_bytes = hex::decode(challenge["challenge"].as_str().unwrap()).unwrap();
    let signature = program.sign(&challenge_bytes);

    let admitted = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge["challenge"],
            "signature": hex::encode(signature.to_bytes()),
            "invite_code": "letmein",
        }))
        .await;
    admitted.assert_status_success();
}

// ---------------------------------------------------------------------------
// The hub-wide listing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn any_member_lists_the_registered_apps_with_their_commands() {
    let (server, _owner_token) = common::setup_with_owner().await;
    grant_apps_register(&server).await;
    let (_app, app_token) = register_app(&server, "Scoreboard").await;

    server
        .put("/me/app/commands")
        .authorization_bearer(&app_token)
        .json(&json!({
            "commands": [{ "name": "score", "description": "show the score" }]
        }))
        .await
        .assert_status_success();

    // A plain member, holding nothing in particular: the list is what the
    // slash-command autocomplete reads, so it cannot need a permission.
    let member = Identity::generate();
    let member_token = common::authenticate(&server, &member).await;

    let apps: serde_json::Value = server
        .get("/apps")
        .authorization_bearer(&member_token)
        .await
        .json();

    let entries = apps.as_array().unwrap();
    assert_eq!(entries.len(), 1, "one app is registered");
    assert_eq!(entries[0]["name"], "Scoreboard");
    assert_eq!(entries[0]["commands"][0]["name"], "score");
}

#[tokio::test]
async fn an_identity_that_registered_nothing_is_not_in_the_listing() {
    let (server, owner_token) = common::setup_with_owner().await;
    grant_apps_register(&server).await;

    let apps: serde_json::Value = server
        .get("/apps")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(apps.as_array().unwrap().is_empty());
}
