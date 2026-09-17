use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn setup(startup_name: &str) -> common::TestHarness {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: startup_name.to_string(),
        hub_identity: Identity::generate(),
        db,
        db_read: None,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        cert_portfolio_cache: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_last_active: RwLock::new(HashMap::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_wt_url: None,
        canonical_url: Arc::new(RwLock::new(None)),
        voice_cert_hash: RwLock::new(None),
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_optouts: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_outbound_loss: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        staging_voice_grants: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_talk_blocked: Default::default(),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        bots_allow_video: false,
        bot_video_stream_budget: 2,
        webauthn: {
            let origin = url::Url::parse("http://localhost:3000").unwrap();
            std::sync::Arc::new(
                webauthn_rs::WebauthnBuilder::new("localhost", &origin)
                    .unwrap()
                    .rp_name("test-hub")
                    .build()
                    .unwrap(),
            )
        },
        webauthn_reg_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        webauthn_auth_challenges: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        device_token_ttl_secs: 30 * 86400,
        webhook_circuit: std::sync::Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
        lan_mode: false,
        lan_tls_mode: None,
        lan_fingerprint: None,
    });
    let app = server::create_router(state);
    common::TestHarness::new(TestServer::new(app), guard)
}

async fn authenticate(server: &TestServer, identity: &Identity) -> String {
    let pub_key = identity.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    let verify: VerifyResponse = resp.json();
    verify.token
}

/// Regression test for the lazy hub_name read. Before the fix, alliance code
/// embedded the startup-time AppState.hub_name into alliance member rows.
/// After the admin renamed the hub, new alliances would still show the old
/// name. This verifies that creating an alliance after a rename uses the new
/// name from hub_settings.
#[tokio::test]
async fn alliance_member_row_uses_renamed_hub_name() {
    let server = setup("Original Name").await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    // Admin renames the hub via the same /hub PATCH the admin UI uses.
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Renamed Hub" }))
        .await
        .assert_status_ok();

    // Create an alliance after the rename.
    server
        .post("/alliances")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Test Alliance" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Pull alliance list and verify the member row shows the renamed name,
    // not the startup name.
    let resp = server.get("/alliances").authorization_bearer(&token).await;
    let alliances = resp.json::<serde_json::Value>();
    let arr = alliances.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let alliance_id = arr[0]["id"].as_str().unwrap();

    let resp = server
        .get(&format!("/alliances/{alliance_id}"))
        .authorization_bearer(&token)
        .await;
    let detail = resp.json::<serde_json::Value>();
    let members = detail["members"].as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(
        members[0]["hub_name"], "Renamed Hub",
        "alliance member row should reflect the renamed hub, not the startup name"
    );
}

/// Companion: when no rename has happened, the startup name is still used as
/// the fallback. Confirms current_hub_name's fallback path.
#[tokio::test]
async fn alliance_member_row_falls_back_to_startup_name() {
    let server = setup("Original Name").await;
    let owner = Identity::generate();
    let token = authenticate(&server, &owner).await;

    server
        .post("/alliances")
        .authorization_bearer(&token)
        .json(&json!({ "name": "Test Alliance" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server.get("/alliances").authorization_bearer(&token).await;
    let arr = resp.json::<serde_json::Value>();
    let alliance_id = arr.as_array().unwrap()[0]["id"].as_str().unwrap();

    let resp = server
        .get(&format!("/alliances/{alliance_id}"))
        .authorization_bearer(&token)
        .await;
    let detail = resp.json::<serde_json::Value>();
    let members = detail["members"].as_array().unwrap();
    assert_eq!(members[0]["hub_name"], "Original Name");
}

// ---------------------------------------------------------------------------
// Welcome invite banner (operator-configurable, PATCH /hub + GET /info).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn welcome_banner_absent_by_default() {
    let server = common::setup().await;
    let owner = Identity::generate();
    common::authenticate(&server, &owner).await;

    let info: serde_json::Value = server.get("/info").await.json();
    assert!(
        info.get("welcome_label").is_none(),
        "welcome_label should be absent when unset"
    );
    assert!(
        info.get("welcome_invite_url").is_none(),
        "welcome_invite_url should be absent when unset"
    );
}

#[tokio::test]
async fn welcome_banner_set_and_read_back_via_info() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({
            "welcome_label": "Acme Co.",
            "welcome_invite_url": "https://example.com/invite/abc123",
        }))
        .await
        .assert_status_ok();

    let info: serde_json::Value = server.get("/info").await.json();
    assert_eq!(info["welcome_label"], "Acme Co.");
    assert_eq!(
        info["welcome_invite_url"],
        "https://example.com/invite/abc123"
    );
}

#[tokio::test]
async fn welcome_banner_accepts_wavvon_scheme_invite() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "welcome_invite_url": "wavvon://join/abc123" }))
        .await
        .assert_status_ok();

    let info: serde_json::Value = server.get("/info").await.json();
    assert_eq!(info["welcome_invite_url"], "wavvon://join/abc123");
}

#[tokio::test]
async fn welcome_banner_invalid_url_rejected() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Not a URL at all.
    let resp = server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "welcome_invite_url": "not a url" }))
        .await;
    assert!(!resp.status_code().is_success());

    // Valid URL but wrong scheme.
    let resp = server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "welcome_invite_url": "ftp://example.com/invite" }))
        .await;
    assert!(!resp.status_code().is_success());

    // Confirm the rejected value never got persisted.
    let info: serde_json::Value = server.get("/info").await.json();
    assert!(info.get("welcome_invite_url").is_none());
}

#[tokio::test]
async fn welcome_banner_label_too_long_rejected() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let long_label = "x".repeat(101);
    let resp = server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "welcome_label": long_label }))
        .await;
    assert!(!resp.status_code().is_success());

    let info: serde_json::Value = server.get("/info").await.json();
    assert!(info.get("welcome_label").is_none());
}

// ---------------------------------------------------------------------------
// Per-message attachment cap — an operator-settable limit
// ---------------------------------------------------------------------------

/// The cap was a compile-time constant, so an operator asking "where do I
/// change the upload limit?" had no answer. It is a hub setting now, with a
/// floor and a ceiling that exist for a reason (attachments are stored inline,
/// and a reverse proxy in front refuses oversized bodies first).
#[tokio::test]
async fn admin_sets_and_reads_the_attachment_cap() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Defaults to the value the old constant had, so an existing hub does not
    // change behaviour just because the setting appeared.
    let settings: serde_json::Value = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(settings["max_attachment_bytes"], 3 * 1024 * 1024);

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "max_attachment_bytes": 5 * 1024 * 1024 }))
        .await
        .assert_status_ok();

    let settings: serde_json::Value = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(settings["max_attachment_bytes"], 5 * 1024 * 1024);
}

#[tokio::test]
async fn attachment_cap_rejects_values_outside_the_bounds() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Below the floor: ordinary screenshots would stop working and the setting
    // would look broken rather than strict.
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "max_attachment_bytes": 1024 }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);

    // Above the ceiling: hosting.md's nginx vhost caps bodies at 10M, so a
    // larger hub-side limit only produces uploads that die at the proxy.
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "max_attachment_bytes": 64 * 1024 * 1024 }))
        .await
        .assert_status(axum::http::StatusCode::BAD_REQUEST);

    // Rejected means unchanged, not partially applied.
    let settings: serde_json::Value = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(settings["max_attachment_bytes"], 3 * 1024 * 1024);
}

#[tokio::test]
async fn a_message_over_the_configured_cap_is_refused() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let chan: serde_json::Value = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "uploads" }))
        .await
        .json();
    let channel_id = chan["id"].as_str().unwrap().to_string();

    // Tighten the cap, then send just over it. Proves the send path reads the
    // setting rather than the old constant — with the constant still in force
    // this 200 KB payload would sail through.
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "max_attachment_bytes": 128 * 1024 }))
        .await
        .assert_status_ok();

    let payload = "A".repeat(200 * 1024);
    let resp = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&token)
        .json(&json!({
            "content": "too big",
            "attachments": [{ "name": "big.bin", "mime": "application/octet-stream", "data_b64": payload }],
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::PAYLOAD_TOO_LARGE);

    // And a small one still goes through under the same tightened cap.
    server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&token)
        .json(&json!({
            "content": "small enough",
            "attachments": [{ "name": "ok.bin", "mime": "application/octet-stream", "data_b64": "A".repeat(1024) }],
        }))
        .await
        .assert_status_success();
}

// ---------------------------------------------------------------------------
// Farewell label — shown by a client when someone removes this hub from their
// device (decisions.md, "Leave hub does not leave").

#[tokio::test]
async fn farewell_label_absent_by_default() {
    let server = common::setup().await;
    let owner = Identity::generate();
    common::authenticate(&server, &owner).await;

    let info: serde_json::Value = server.get("/info").await.json();
    assert!(
        info.get("farewell_label").is_none(),
        "farewell_label should be absent when unset, not an empty string"
    );
}

#[tokio::test]
async fn farewell_label_round_trips_and_is_cleared_by_an_empty_string() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "farewell_label": "Sorry to see you go. The door stays open." }))
        .await
        .assert_status_ok();

    let info: serde_json::Value = server.get("/info").await.json();
    assert_eq!(
        info["farewell_label"],
        "Sorry to see you go. The door stays open."
    );

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "farewell_label": "" }))
        .await
        .assert_status_ok();

    let info: serde_json::Value = server.get("/info").await.json();
    assert!(
        info.get("farewell_label").is_none(),
        "an empty string clears the setting rather than serving an empty one"
    );
}

#[tokio::test]
async fn farewell_label_is_length_capped() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Multi-byte on purpose: the cap counts characters, and a byte-length
    // check would refuse a legitimate message in most of the languages the
    // client ships.
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "farewell_label": "é".repeat(280) }))
        .await
        .assert_status_ok();

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "farewell_label": "é".repeat(281) }))
        .await
        .assert_status_bad_request();
}
