//! Integration tests for ME1 (federated ban list admin routes) and
//! ME2 (circuit-breaker unit test) moderation enhancements.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::banlist::{
    BanOverrideResponse, BanSourceResponse, BanlistSettingsResponse, FederatedBanEntryResponse,
};
use wavvon_hub::routes::hub::ModerationSettingsResponse;
use wavvon_hub::server;
use wavvon_hub::state::{AppState, WebhookCircuit};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// ME1 — Federated ban list admin routes
// ---------------------------------------------------------------------------

// GET /admin/banlist/sources — empty list on a fresh hub
#[tokio::test]
async fn list_sources_empty_on_fresh_hub() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .get("/admin/banlist/sources")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let sources: Vec<BanSourceResponse> = resp.json();
    assert!(sources.is_empty());
}

// POST /admin/banlist/sources — happy path
#[tokio::test]
async fn add_source_creates_row() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/admin/banlist/sources")
        .authorization_bearer(&token)
        .json(&json!({
            "url": "https://peer.example.com",
            "policy": "soft-flag"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let source: BanSourceResponse = resp.json();
    assert_eq!(source.url, "https://peer.example.com");
    assert_eq!(source.policy, "soft-flag");

    // Should now appear in the list.
    let resp = server
        .get("/admin/banlist/sources")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let sources: Vec<BanSourceResponse> = resp.json();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].url, "https://peer.example.com");
    assert_eq!(sources[0].policy, "soft-flag");
}

// POST /admin/banlist/sources — rejected without ADMIN permission
#[tokio::test]
async fn add_source_rejected_without_admin() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let _owner_token = common::authenticate(&server, &owner).await;

    let user = Identity::generate();
    let user_token = common::authenticate(&server, &user).await;

    let resp = server
        .post("/admin/banlist/sources")
        .authorization_bearer(&user_token)
        .json(&json!({ "url": "https://peer.example.com" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

// POST /admin/banlist/sources — rejects invalid policy
#[tokio::test]
async fn add_source_rejects_invalid_policy() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/admin/banlist/sources")
        .authorization_bearer(&token)
        .json(&json!({
            "url": "https://peer.example.com",
            "policy": "ban-them-all"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

// PATCH /admin/banlist/sources — update policy
#[tokio::test]
async fn update_source_policy() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Add first.
    server
        .post("/admin/banlist/sources")
        .authorization_bearer(&token)
        .json(&json!({ "url": "https://peer.example.com", "policy": "hard-reject" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Update policy.
    let resp = server
        .patch("/admin/banlist/sources")
        .authorization_bearer(&token)
        .json(&json!({ "url": "https://peer.example.com", "policy": "soft-flag" }))
        .await;
    resp.assert_status_ok();

    // Verify.
    let resp = server
        .get("/admin/banlist/sources")
        .authorization_bearer(&token)
        .await;
    let sources: Vec<BanSourceResponse> = resp.json();
    assert_eq!(sources[0].policy, "soft-flag");
}

// PATCH /admin/banlist/sources — 404 when source does not exist
#[tokio::test]
async fn update_source_returns_404_when_missing() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .patch("/admin/banlist/sources")
        .authorization_bearer(&token)
        .json(&json!({ "url": "https://no-such-peer.example.com", "policy": "soft-flag" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// DELETE /admin/banlist/sources — removes source and its federated_bans rows
#[tokio::test]
async fn delete_source_removes_rows() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Add source.
    server
        .post("/admin/banlist/sources")
        .authorization_bearer(&token)
        .json(&json!({ "url": "https://peer.example.com", "policy": "hard-reject" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Remove source.
    let resp = server
        .delete("/admin/banlist/sources")
        .authorization_bearer(&token)
        .json(&json!({ "url": "https://peer.example.com" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Should be gone.
    let resp = server
        .get("/admin/banlist/sources")
        .authorization_bearer(&token)
        .await;
    let sources: Vec<BanSourceResponse> = resp.json();
    assert!(sources.is_empty());
}

// GET /admin/banlist/entries — list federated ban entries
#[tokio::test]
async fn list_entries_returns_synced_bans() {
    let (hub_url, state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    // Insert a federated_bans row directly (simulating what banlist_worker does).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO federated_bans (source_hub_pubkey, target_master_pubkey, reason, added_at, synced_at)
         VALUES ('hub-abc', 'user-pubkey-xyz', 'spam', $1, $2)",
    )
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    let resp = client
        .get(format!("{hub_url}/admin/banlist/entries"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let entries: Vec<FederatedBanEntryResponse> = resp.json().await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].source_hub_pubkey, "hub-abc");
    assert_eq!(entries[0].target_master_pubkey, "user-pubkey-xyz");

    // Filter by source.
    let resp = client
        .get(format!("{hub_url}/admin/banlist/entries?source=hub-abc"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    let filtered: Vec<FederatedBanEntryResponse> = resp.json().await.unwrap();
    assert_eq!(filtered.len(), 1);

    // Non-matching filter.
    let resp = client
        .get(format!(
            "{hub_url}/admin/banlist/entries?source=different-hub"
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    let none_found: Vec<FederatedBanEntryResponse> = resp.json().await.unwrap();
    assert!(none_found.is_empty());
}

// POST /admin/banlist/overrides — add whitelist entry
#[tokio::test]
async fn add_whitelist_override() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let target = Identity::generate().public_key_hex();

    let resp = server
        .post("/admin/banlist/overrides")
        .authorization_bearer(&token)
        .json(&json!({
            "target_pubkey": target,
            "override_type": "whitelist",
            "reason": "trusted community member"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let ov: BanOverrideResponse = resp.json();
    assert_eq!(ov.target_pubkey, target);
    assert_eq!(ov.override_type, "whitelist");
    assert_eq!(ov.reason.as_deref(), Some("trusted community member"));

    // Should appear in list.
    let resp = server
        .get("/admin/banlist/overrides")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let overrides: Vec<BanOverrideResponse> = resp.json();
    assert_eq!(overrides.len(), 1);
}

// POST /admin/banlist/overrides — rejects invalid override_type
#[tokio::test]
async fn add_override_rejects_invalid_type() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/admin/banlist/overrides")
        .authorization_bearer(&token)
        .json(&json!({
            "target_pubkey": "some-pubkey",
            "override_type": "superallow"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

// DELETE /admin/banlist/overrides/:pubkey — removes override
#[tokio::test]
async fn delete_override_removes_it() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let target = Identity::generate().public_key_hex();

    server
        .post("/admin/banlist/overrides")
        .authorization_bearer(&token)
        .json(&json!({ "target_pubkey": target, "override_type": "blacklist" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    server
        .delete(&format!("/admin/banlist/overrides/{target}"))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    let resp = server
        .get("/admin/banlist/overrides")
        .authorization_bearer(&token)
        .await;
    let overrides: Vec<BanOverrideResponse> = resp.json();
    assert!(overrides.is_empty());
}

// GET/PATCH /admin/settings/banlist — publish toggle
#[tokio::test]
async fn banlist_publish_toggle() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Starts false.
    let resp = server
        .get("/admin/settings/banlist")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let settings: BanlistSettingsResponse = resp.json();
    assert!(!settings.publish_banlist);

    // Enable.
    server
        .patch("/admin/settings/banlist")
        .authorization_bearer(&token)
        .json(&json!({ "publish_banlist": true }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/settings/banlist")
        .authorization_bearer(&token)
        .await;
    let settings: BanlistSettingsResponse = resp.json();
    assert!(settings.publish_banlist);
}

// Whitelist override admits user even when they're in federated_bans
#[tokio::test]
async fn whitelist_override_admits_federated_banned_user() {
    let (hub_url, state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    let user = Identity::generate();
    let user_token = http_authenticate(&hub_url, &user).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Add the user to federated_bans AND add a source with hard-reject policy
    // so the normal path would deny them.
    sqlx::query(
        "INSERT INTO federated_ban_sources (url, policy, added_at, issuer_pubkey)
         VALUES ('https://peer.example.com', 'hard-reject', $1, 'hub-source-pk')",
    )
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO federated_bans (source_hub_pubkey, target_master_pubkey, reason, added_at, synced_at)
         VALUES ('hub-source-pk', $1, 'test', $2, $2)",
    )
    .bind(user.public_key_hex())
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    // Whitelist the user.
    let resp = client
        .post(format!("{hub_url}/admin/banlist/overrides"))
        .bearer_auth(&owner_token)
        .json(&json!({
            "target_pubkey": user.public_key_hex(),
            "override_type": "whitelist",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);

    // The channel must be created before we can post.
    let channel_resp: serde_json::Value = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let channel_id = channel_resp["id"].as_str().unwrap();

    // Whitelisted user can still post even though they're in federated_bans.
    let post_resp = client
        .post(format!("{hub_url}/channels/{channel_id}/messages"))
        .bearer_auth(&user_token)
        .json(&json!({ "content": "hello from whitelisted user", "attachments": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        post_resp.status().as_u16(),
        201,
        "whitelisted user must be admitted despite being in federated_bans"
    );
}

// Blacklist override denies user even when NOT in federated_bans
#[tokio::test]
async fn blacklist_override_denies_user_at_auth() {
    let (hub_url, state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    http_authenticate(&hub_url, &owner).await;
    let owner_token = http_authenticate(&hub_url, &owner).await;

    let user = Identity::generate();
    // User authenticates once to get a session (before blacklist is applied).
    let user_token = http_authenticate(&hub_url, &user).await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Apply blacklist override.
    sqlx::query(
        "INSERT INTO federated_ban_overrides (target_pubkey, override_type, reason, created_at)
         VALUES ($1, 'blacklist', 'bad actor', $2)",
    )
    .bind(user.public_key_hex())
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    // Create a channel.
    let channel_resp: serde_json::Value = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "main" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let channel_id = channel_resp["id"].as_str().unwrap();

    // The blacklisted user's existing session must be blocked at the message endpoint.
    let post_resp = client
        .post(format!("{hub_url}/channels/{channel_id}/messages"))
        .bearer_auth(&user_token)
        .json(&json!({ "content": "should be blocked", "attachments": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        post_resp.status().as_u16(),
        403,
        "blacklisted user must be denied"
    );
}

// ---------------------------------------------------------------------------
// ME2 — GET /admin/settings/moderation circuit-breaker state
// ---------------------------------------------------------------------------

#[tokio::test]
async fn get_moderation_settings_no_webhook() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .get("/admin/settings/moderation")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let settings: ModerationSettingsResponse = resp.json();
    assert!(!settings.webhook_secret_set);
    assert!(!settings.circuit_open);
    assert!(settings.circuit_open_until.is_none());
    assert!(settings.webhook_url.is_none());
}

#[tokio::test]
async fn get_moderation_settings_with_webhook_set() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Configure the webhook.
    server
        .patch("/admin/settings/moderation")
        .authorization_bearer(&token)
        .json(&json!({
            "webhook_url": "https://automod.example.com/check",
            "webhook_secret": "s3cr3t"
        }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/settings/moderation")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let settings: ModerationSettingsResponse = resp.json();
    assert_eq!(
        settings.webhook_url.as_deref(),
        Some("https://automod.example.com/check")
    );
    assert!(
        settings.webhook_secret_set,
        "secret must be reported as set"
    );
    assert!(!settings.circuit_open);
}

#[tokio::test]
async fn get_moderation_settings_circuit_open() {
    let (hub_url, state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    // Force the circuit open in memory.
    let open_until = crate::common_helpers::unix_ts() + 600;
    {
        let mut circuit = state.webhook_circuit.lock().await;
        circuit.consecutive_failures = 3;
        circuit.open_until = Some(open_until);
    }

    let resp = client
        .get(format!("{hub_url}/admin/settings/moderation"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let settings: ModerationSettingsResponse = resp.json().await.unwrap();
    assert!(settings.circuit_open, "circuit must be reported as open");
    assert_eq!(settings.circuit_open_until, Some(open_until));
}

// ---------------------------------------------------------------------------
// ME2 — Circuit-breaker unit test (no HTTP server needed)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn circuit_breaker_opens_after_three_5xx_within_60s() {
    // Set the initial streak time to "now" and simulate 3 consecutive failures.
    let circuit = Arc::new(tokio::sync::Mutex::new(WebhookCircuit::default()));
    let now = common_helpers::unix_ts();

    for i in 0..3u32 {
        let mut c = circuit.lock().await;
        let streak_start = c.streak_started_at.get_or_insert(now);
        let age = now - *streak_start;
        c.consecutive_failures += 1;
        if c.consecutive_failures >= 3 && age <= 60 {
            c.open_until = Some(now + 600);
        } else if age > 60 {
            c.consecutive_failures = 1;
            c.streak_started_at = Some(now);
        }
        drop(c);
        let _ = i; // suppress unused warning
    }

    let c = circuit.lock().await;
    assert!(
        c.open_until.is_some(),
        "circuit should open after 3 consecutive failures within 60s"
    );
    let open_until = c.open_until.unwrap();
    assert!(
        open_until >= now + 599,
        "open_until should be at least 10 minutes in the future"
    );
}

#[tokio::test]
async fn circuit_breaker_resets_on_success() {
    let circuit = Arc::new(tokio::sync::Mutex::new(WebhookCircuit {
        consecutive_failures: 3,
        open_until: Some(common_helpers::unix_ts() + 600),
        streak_started_at: Some(common_helpers::unix_ts() - 10),
    }));

    // Simulate a successful response.
    {
        let mut c = circuit.lock().await;
        c.consecutive_failures = 0;
        c.open_until = None;
        c.streak_started_at = None;
    }

    let c = circuit.lock().await;
    assert!(
        c.open_until.is_none(),
        "circuit should be closed after success"
    );
    assert_eq!(c.consecutive_failures, 0);
}

#[tokio::test]
async fn circuit_does_not_open_on_3_failures_spanning_more_than_60s() {
    let circuit = Arc::new(tokio::sync::Mutex::new(WebhookCircuit::default()));

    // First failure at t=0, second at t=30, third at t=90 (outside 60s window).
    let t0 = common_helpers::unix_ts() - 90;

    {
        let mut c = circuit.lock().await;
        c.streak_started_at = Some(t0);
        // Simulate first two failures in the old window.
        c.consecutive_failures = 2;
    }

    // Third failure at now — streak age = 90s > 60s, so we reset the window.
    {
        let mut c = circuit.lock().await;
        let now = common_helpers::unix_ts();
        let age = now - c.streak_started_at.unwrap_or(now);
        c.consecutive_failures += 1;
        if c.consecutive_failures >= 3 && age <= 60 {
            c.open_until = Some(now + 600);
        } else if age > 60 {
            // Reset: new streak starts here.
            c.consecutive_failures = 1;
            c.streak_started_at = Some(now);
        }
    }

    let c = circuit.lock().await;
    assert!(
        c.open_until.is_none(),
        "circuit must NOT open when failures span more than 60s"
    );
    assert_eq!(
        c.consecutive_failures, 1,
        "streak should have been reset to 1"
    );
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

mod common_helpers {
    pub fn unix_ts() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

async fn spawn_real_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
        hub_identity: Identity::generate(),
        db,
        db_read: None,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx: broadcast::channel(256).0,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_udp_addr: None,
        voice_event_tx: broadcast::channel(16).0,
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
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        staging_voice_grants: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
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
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (format!("http://127.0.0.1:{port}"), state, guard)
}

async fn http_authenticate(hub_url: &str, identity: &Identity) -> String {
    use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();
    let challenge: ChallengeResponse = client
        .post(format!("{hub_url}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let signature = identity.sign(&hex::decode(&challenge.challenge).unwrap());
    let verify: VerifyResponse = client
        .post(format!("{hub_url}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify.token
}
