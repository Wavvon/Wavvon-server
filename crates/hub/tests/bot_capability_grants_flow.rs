//! bot-capability-layer.md §6 Phase 1 — the consent spine.
//!
//! Covers: the `PUT /admin/bots/:pubkey/capabilities` admin route (happy
//! path, non-admin rejection, unknown-bot rejection), the
//! `can_use_interactive_ui` gate on `bot_app_join` (gated open + ungranted
//! rejection), and the migration backfill that keeps a pre-existing
//! self-declared voice bot working once the voice gate switches to the
//! requested-∩-granted resolver.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// HTTP-only tests — admin/bots capabilities route (axum_test harness).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_can_grant_capabilities_and_it_lands_in_the_audit_log() {
    let (server, owner_token) = common::setup_with_owner().await;

    let bot: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&owner_token)
        .json(&json!({ "display_name": "CapBot" }))
        .await
        .json();
    let bot_key = bot["public_key"].as_str().unwrap().to_string();

    let resp = server
        .put(&format!("/admin/bots/{bot_key}/capabilities"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "capabilities": ["can_use_interactive_ui", "can_speak_voice"] }))
        .await;
    resp.assert_status_success();
    let body: serde_json::Value = resp.json();
    assert_eq!(body["bot_pubkey"], bot_key);
    let caps = body["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 2);

    // Replacing the set atomically drops anything not in the new list.
    let resp2 = server
        .put(&format!("/admin/bots/{bot_key}/capabilities"))
        .authorization_bearer(&owner_token)
        .json(&json!({ "capabilities": ["can_speak_voice"] }))
        .await;
    resp2.assert_status_success();
    let body2: serde_json::Value = resp2.json();
    assert_eq!(body2["capabilities"].as_array().unwrap().len(), 1);

    // bot.capabilities_changed shows up on the audit stream.
    let log: serde_json::Value = server
        .get("/admin/audit-log")
        .authorization_bearer(&owner_token)
        .await
        .json();
    let entries = log["entries"].as_array().unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e["event_type"] == "bot.capabilities_changed" && e["target_pubkey"] == bot_key),
        "expected a bot.capabilities_changed audit entry for {bot_key}, got: {entries:?}"
    );
}

#[tokio::test]
async fn non_admin_cannot_grant_bot_capabilities() {
    let server = common::setup().await;
    // First authenticator becomes Owner/admin; a second member is plain.
    let _owner_token = common::authenticate(&server, &Identity::generate()).await;
    let admin_token = common::authenticate(&server, &Identity::generate()).await;
    let rando_token = common::authenticate(&server, &Identity::generate()).await;

    let bot: serde_json::Value = server
        .post("/admin/bots")
        .authorization_bearer(&admin_token)
        .json(&json!({ "display_name": "NoAdminBot" }))
        .await
        .json();
    let bot_key = bot["public_key"].as_str().unwrap().to_string();

    let resp = server
        .put(&format!("/admin/bots/{bot_key}/capabilities"))
        .authorization_bearer(&rando_token)
        .json(&json!({ "capabilities": ["can_speak_voice"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn grant_capabilities_404s_for_unknown_bot() {
    let (server, owner_token) = common::setup_with_owner().await;

    let resp = server
        .put("/admin/bots/not-a-real-bot/capabilities")
        .authorization_bearer(&owner_token)
        .json(&json!({ "capabilities": ["can_speak_voice"] }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// can_use_interactive_ui gate on bot_app_join — needs a real TCP listener
// for the WS upgrade (mirrors mini_app_scope_flow.rs's harness).
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "bot-capability-grants-test".to_string(),
        hub_identity: Identity::generate(),
        db,
        db_read: None,
        store,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx,
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
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(RwLock::new(0)),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: RwLock::new(HashMap::new()),
        whisper_target_defs: RwLock::new(HashMap::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        staging_voice_grants: RwLock::new(std::collections::HashMap::new()),
        voice_pending_binds: RwLock::new(HashMap::new()),
        voice_consumed_tokens: RwLock::new(HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(HashMap::new()),
        search: Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
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
    let url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, state, guard)
}

async fn authenticate_http(base: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();

    let resp: ChallengeResponse = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let challenge_bytes = hex::decode(&resp.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

    let verify: VerifyResponse = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": resp.challenge,
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

async fn create_channel(base: &str, token: &str, name: &str) -> Value {
    reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(token)
        .json(&json!({ "name": name }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// POST /admin/bots — registers a self-service bot with a `mini_app_url`,
/// no capability grant.
async fn create_mini_app_bot(base: &str, token: &str) -> String {
    let resp = reqwest::Client::new()
        .post(format!("{base}/admin/bots"))
        .bearer_auth(token)
        .json(&json!({
            "display_name": "GateBot",
            "mini_app_url": "https://gate-bot.example.com/app",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: Value = resp.json().await.unwrap();
    body["public_key"].as_str().unwrap().to_string()
}

async fn grant_capabilities(
    base: &str,
    admin_token: &str,
    bot_pubkey: &str,
    capabilities: &[&str],
) {
    let resp = reqwest::Client::new()
        .put(format!("{base}/admin/bots/{bot_pubkey}/capabilities"))
        .bearer_auth(admin_token)
        .json(&json!({ "capabilities": capabilities }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

type WsSink = futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    TsMessage,
>;
type WsStream = futures_util::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
>;

async fn connect_ws(base: &str, token: &str) -> (WsSink, WsStream) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

async fn send_text(tx: &mut WsSink, msg: Value) {
    tx.send(TsMessage::Text(msg.to_string())).await.unwrap();
}

async fn next_meaningful_frame(rx: &mut WsStream, timeout: std::time::Duration) -> Option<Value> {
    loop {
        let msg = match tokio::time::timeout(timeout, rx.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => return None,
        };
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            match v["type"].as_str() {
                Some("hello") | Some("member_online") | Some("member_offline") => continue,
                _ => return Some(v),
            }
        }
    }
}

/// A bot with `mini_app_url` set but no `can_use_interactive_ui` grant: the
/// joining member's `bot_app_join` gets no `bot_app_open` reply at all.
#[tokio::test]
async fn mini_app_join_is_rejected_without_capability_grant() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let member = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member_token = authenticate_http(&base, &member).await;

    let channel = create_channel(&base, &owner_token, "gate-room").await;
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let bot_id = create_mini_app_bot(&base, &owner_token).await;
    // Deliberately no grant call.

    let (mut tx, mut rx) = connect_ws(&base, &member_token).await;
    send_text(
        &mut tx,
        json!({ "type": "bot_app_join", "bot_id": bot_id, "channel_id": channel_id }),
    )
    .await;

    let frame = next_meaningful_frame(&mut rx, std::time::Duration::from_secs(2)).await;
    assert!(
        frame.is_none(),
        "ungranted bot must not yield a bot_app_open reply, got: {frame:?}"
    );
}

/// The same bot, once granted `can_use_interactive_ui`, opens normally.
#[tokio::test]
async fn mini_app_join_succeeds_after_capability_grant() {
    let (base, _state, _guard) = start_hub().await;

    let owner = Identity::generate();
    let member = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member_token = authenticate_http(&base, &member).await;

    let channel = create_channel(&base, &owner_token, "gate-room-ok").await;
    let channel_id = channel["id"].as_str().unwrap().to_string();

    let bot_id = create_mini_app_bot(&base, &owner_token).await;
    grant_capabilities(&base, &owner_token, &bot_id, &["can_use_interactive_ui"]).await;

    let (mut tx, mut rx) = connect_ws(&base, &member_token).await;
    send_text(
        &mut tx,
        json!({ "type": "bot_app_join", "bot_id": bot_id, "channel_id": channel_id }),
    )
    .await;

    let frame = next_meaningful_frame(&mut rx, std::time::Duration::from_secs(3))
        .await
        .expect("granted bot should yield a bot_app_open reply");
    assert_eq!(frame["type"], "bot_app_open");
    assert!(!frame["session_token"].as_str().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Migration backfill — a bot that already had self-declared capabilities
// before this feature shipped keeps passing the (now grant-backed) gate.
// ---------------------------------------------------------------------------

/// Simulates a bot that existed before the capability-grant migration: a
/// `users` row (is_bot) + a `bot_profiles` row with `capabilities` set,
/// inserted directly (bypassing the app layer, since there's no pre-Phase-1
/// code path left to drive). Re-running migrations (idempotent, same as a
/// hub restart) must backfill a matching `bot_capability_grants` row so
/// `effective_capabilities` -- what the voice gate actually calls -- still
/// resolves the capability as effective.
#[tokio::test]
async fn migration_backfills_grant_for_pre_existing_self_declared_bot() {
    let (db, _guard) = common::create_test_db().await;

    let bot_pubkey = "deadbeef00000000000000000000000000000000000000000000000000beef";
    let now = wavvon_hub::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at, approval_status, is_bot)
         VALUES ($1, $2, $2, 'approved', TRUE)",
    )
    .bind(bot_pubkey)
    .bind(now)
    .execute(&db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO bot_profiles (pubkey, name, capabilities, updated_at)
         VALUES ($1, 'PreExistingVoiceBot', '[\"can_speak_voice\"]', $2)",
    )
    .bind(bot_pubkey)
    .bind(now)
    .execute(&db)
    .await
    .unwrap();

    // Before the (re-run) migration backfills it, there is no grant yet.
    assert!(
        !wavvon_hub::bots::capabilities::has_capability(&db, bot_pubkey, "can_speak_voice").await,
        "no grant should exist until the backfill runs"
    );

    // Re-run migrations (idempotent, mirrors a hub restart after upgrade).
    wavvon_hub::db::migrations::run(&db).await.unwrap();

    assert!(
        wavvon_hub::bots::capabilities::has_capability(&db, bot_pubkey, "can_speak_voice").await,
        "backfill should grant the pre-existing self-declared capability"
    );
}
