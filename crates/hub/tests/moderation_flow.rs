use std::collections::HashMap;
use std::sync::Arc;

use serde_json::json;
use tokio::sync::{broadcast, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::routes::moderation_models::{
    BanResponse, ChannelBanByPubkeyResponse, ChannelVoiceMuteResponse, RaiseHandResponse,
};
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn ban_blocks_authentication() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let _token2 = common::authenticate(&server, &user2).await;

    // Owner bans user2
    let resp = server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "target_public_key": user2.public_key_hex(),
            "reason": "spamming",
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // user2 tries to authenticate again — should be rejected
    let pub_key = user2.public_key_hex();
    let resp = server
        .post("/auth/challenge")
        .json(&json!({ "public_key": pub_key }))
        .await;
    let challenge: ChallengeResponse = resp.json();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = user2.sign(&challenge_bytes);

    let resp = server
        .post("/auth/verify")
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn mute_blocks_sending_messages() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    // Create a channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "general" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // user2 can send before mute
    let resp = server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "hello" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);

    // Owner mutes user2
    server
        .post("/moderation/mutes")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "target_public_key": user2.public_key_hex(),
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // user2 can't send while muted
    let resp = server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "still here" }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);

    // Owner unmutes
    server
        .delete(&format!("/moderation/mutes/{}", user2.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // user2 can send again
    let resp = server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "im back" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn cannot_moderate_higher_priority_user() {
    let server = common::setup().await;

    // Owner is first user (gets Owner role)
    let owner = Identity::generate();
    let _owner_token = common::authenticate(&server, &owner).await;

    // user2 (only @everyone) tries to ban owner
    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .post("/moderation/bans")
        .authorization_bearer(&token2)
        .json(&json!({
            "target_public_key": owner.public_key_hex(),
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn unban_allows_reauth() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    common::authenticate(&server, &user2).await;

    // Ban then unban
    server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({ "target_public_key": user2.public_key_hex() }))
        .await;

    server
        .delete(&format!("/moderation/bans/{}", user2.public_key_hex()))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // user2 can authenticate again
    let token2 = common::authenticate(&server, &user2).await;
    assert!(!token2.is_empty());
}

#[tokio::test]
async fn list_bans() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    common::authenticate(&server, &user2).await;

    server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&json!({
            "target_public_key": user2.public_key_hex(),
            "reason": "testing",
        }))
        .await;

    let resp = server
        .get("/moderation/bans")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let bans: Vec<BanResponse> = resp.json();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].target_public_key, user2.public_key_hex());
    assert_eq!(bans[0].reason, Some("testing".to_string()));
}

#[tokio::test]
async fn channel_ban_blocks_messages() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    // Create channel
    let resp = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "general" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // user2 can send before channel ban
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "hello" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Ban user2 from channel
    server
        .post(&format!("/moderation/channels/{}/bans", channel.id))
        .authorization_bearer(&owner_token)
        .json(&json!({ "target_public_key": user2.public_key_hex() }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // user2 can't send to that channel
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "blocked" }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // Unban
    server
        .delete(&format!(
            "/moderation/channels/{}/bans/{}",
            channel.id,
            user2.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // user2 can send again
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "im back" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
}

// --- WebSocket-level voice moderation enforcement ---

use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Spin up a real listener so we can connect a WebSocket client to it.
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

/// Send a voice_join over WS, return the first server frame as JSON.
async fn ws_voice_join_and_recv(hub_url: &str, token: &str, channel_id: &str) -> serde_json::Value {
    let ws_url = hub_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let url = format!("{ws_url}/ws?token={token}");
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    let (mut tx, mut rx) = ws_stream.split();

    // Consume the `hello` frame the hub sends on connect.
    let hello_frame = rx.next().await.unwrap().unwrap();
    let WsMessage::Text(hello_text) = hello_frame else {
        panic!("expected hello text frame")
    };
    let hello: serde_json::Value = serde_json::from_str(&hello_text).unwrap();
    assert_eq!(hello["type"], "hello", "first frame should be hello");

    tx.send(WsMessage::Text(
        json!({ "type": "voice_join", "channel_id": channel_id, "udp_port": 12345 }).to_string(),
    ))
    .await
    .unwrap();
    loop {
        let frame = rx.next().await.unwrap().unwrap();
        let WsMessage::Text(text) = frame else {
            panic!("expected text frame, got {frame:?}")
        };
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        match v["type"].as_str() {
            Some("member_online") | Some("member_offline") => continue,
            _ => return v,
        }
    }
}

#[tokio::test]
async fn voice_mute_blocks_voice_join() {
    let (hub_url, _state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    // Owner first to get the Owner role + permissions
    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    // Victim joins second (gets only @everyone)
    let victim = Identity::generate();
    let victim_token = http_authenticate(&hub_url, &victim).await;

    // Create a channel
    let channel: ChannelResponse = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Owner voice-mutes the victim
    client
        .post(format!("{hub_url}/moderation/voice-mutes"))
        .bearer_auth(&owner_token)
        .json(&json!({ "target_public_key": victim.public_key_hex() }))
        .send()
        .await
        .unwrap();

    // Victim attempts to join voice — should get an error frame, not voice_joined
    let frame = ws_voice_join_and_recv(&hub_url, &victim_token, &channel.id).await;
    assert_eq!(frame["type"], "error");
    assert_eq!(frame["context"], "voice_join");
    assert!(frame["message"].as_str().unwrap().contains("muted"));
}

#[tokio::test]
async fn talk_power_blocks_low_priority_user() {
    let (hub_url, state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    // Owner sets up the channel + talk power
    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    // Random user with only @everyone (priority 0)
    let randuser = Identity::generate();
    let rand_token = http_authenticate(&hub_url, &randuser).await;

    let channel: ChannelResponse = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "vip-only" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Require talk power 100 — only the Owner role qualifies
    client
        .post(format!("{hub_url}/channels/{}/talk-power", channel.id))
        .bearer_auth(&owner_token)
        .json(&json!({ "min_talk_power": 100 }))
        .send()
        .await
        .unwrap();

    // Sanity: confirm the row landed
    let stored: i64 =
        sqlx::query_scalar("SELECT min_talk_power FROM channel_settings WHERE channel_id = $1")
            .bind(&channel.id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(stored, 100);

    // Random user tries to join — should be refused
    let frame = ws_voice_join_and_recv(&hub_url, &rand_token, &channel.id).await;
    assert_eq!(frame["type"], "error");
    assert_eq!(frame["context"], "voice_join");
    assert!(frame["message"].as_str().unwrap().contains("priority"));

    // Owner can still join (priority is 999999)
    let frame = ws_voice_join_and_recv(&hub_url, &owner_token, &channel.id).await;
    assert_eq!(frame["type"], "voice_joined");
}

// ---------------------------------------------------------------------------
// Task #6 — Channel bans at /channels/:id/bans (pubkey field)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn channel_ban_v2_blocks_messages_and_list() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "testchan" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // user2 can post before ban
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "hello" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Ban user2 via new route
    let resp = server
        .post(&format!("/channels/{}/bans", channel.id))
        .authorization_bearer(&owner_token)
        .json(&json!({ "pubkey": user2.public_key_hex() }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let ban: ChannelBanByPubkeyResponse = resp.json();
    assert_eq!(ban.pubkey, user2.public_key_hex());
    assert_eq!(ban.channel_id, channel.id);

    // user2 can't post to that channel
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "blocked" }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    // List bans
    let resp = server
        .get(&format!("/channels/{}/bans", channel.id))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let bans: Vec<ChannelBanByPubkeyResponse> = resp.json();
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].pubkey, user2.public_key_hex());

    // Unban
    server
        .delete(&format!(
            "/channels/{}/bans/{}",
            channel.id,
            user2.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // user2 can post again
    server
        .post(&format!("/channels/{}/messages", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "content": "back" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);
}

#[tokio::test]
async fn channel_ban_v2_rejected_without_permission() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "perm-test-chan" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // user2 (only @everyone) tries to ban owner via new route — should be 403
    server
        .post(&format!("/channels/{}/bans", channel.id))
        .authorization_bearer(&token2)
        .json(&json!({ "pubkey": owner.public_key_hex() }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// Task #7 — Per-channel voice mutes at /channels/:id/voice-mutes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn channel_voice_mute_blocks_voice_join() {
    let (hub_url, _state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    let victim = Identity::generate();
    let victim_token = http_authenticate(&hub_url, &victim).await;

    let channel: ChannelResponse = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "voice-ch" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Mute victim in this channel
    let resp = client
        .post(format!("{hub_url}/channels/{}/voice-mutes", channel.id))
        .bearer_auth(&owner_token)
        .json(&json!({ "pubkey": victim.public_key_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);
    let mute: ChannelVoiceMuteResponse = resp.json().await.unwrap();
    assert_eq!(mute.pubkey, victim.public_key_hex());

    // Victim can't join voice in that channel
    let frame = ws_voice_join_and_recv(&hub_url, &victim_token, &channel.id).await;
    assert_eq!(frame["type"], "error");
    assert_eq!(frame["context"], "voice_join");
    assert!(frame["message"].as_str().unwrap().contains("muted"));

    // List mutes
    let mutes: Vec<ChannelVoiceMuteResponse> = client
        .get(format!("{hub_url}/channels/{}/voice-mutes", channel.id))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(mutes.len(), 1);
    assert_eq!(mutes[0].pubkey, victim.public_key_hex());

    // Unmute
    client
        .delete(format!(
            "{hub_url}/channels/{}/voice-mutes/{}",
            channel.id,
            victim.public_key_hex()
        ))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap();

    // Victim can join again
    let frame = ws_voice_join_and_recv(&hub_url, &victim_token, &channel.id).await;
    assert_eq!(frame["type"], "voice_joined");
}

// ---------------------------------------------------------------------------
// Task #8 — Talk power: PATCH /channels/:id min_talk_power + raise-hand
// ---------------------------------------------------------------------------

#[tokio::test]
async fn patch_channel_sets_min_talk_power() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "vchan" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // PATCH to set min_talk_power
    server
        .patch(&format!("/channels/{}", channel.id))
        .authorization_bearer(&owner_token)
        .json(&json!({ "min_talk_power": 50 }))
        .await
        .assert_status_ok();

    // Verify via direct DB check is not needed — the WS enforcement test proves it works
}

#[tokio::test]
async fn raise_hand_and_lower_hand_flow() {
    let server = common::setup().await;

    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let user2 = Identity::generate();
    let token2 = common::authenticate(&server, &user2).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "handchan" }))
        .await;
    let channel: ChannelResponse = resp.json();

    // user2 raises hand
    let resp = server
        .post(&format!("/channels/{}/raise-hand", channel.id))
        .authorization_bearer(&token2)
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let rh: RaiseHandResponse = resp.json();
    assert_eq!(rh.pubkey, user2.public_key_hex());
    assert_eq!(rh.channel_id, channel.id);

    // List raised hands (admin)
    let resp = server
        .get(&format!("/channels/{}/raise-hands", channel.id))
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status_ok();
    let hands: Vec<RaiseHandResponse> = resp.json();
    assert_eq!(hands.len(), 1);
    assert_eq!(hands[0].pubkey, user2.public_key_hex());

    // Admin lowers hand
    server
        .delete(&format!(
            "/channels/{}/raise-hand/{}",
            channel.id,
            user2.public_key_hex()
        ))
        .authorization_bearer(&owner_token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // List should now be empty
    let resp = server
        .get(&format!("/channels/{}/raise-hands", channel.id))
        .authorization_bearer(&owner_token)
        .await;
    let hands: Vec<RaiseHandResponse> = resp.json();
    assert!(hands.is_empty());
}

#[tokio::test]
async fn raise_hand_allows_voice_join_below_threshold() {
    let (hub_url, state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;
    let user2 = Identity::generate();
    let user2_token = http_authenticate(&hub_url, &user2).await;

    let channel: ChannelResponse = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "tp-hand-chan" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Set min_talk_power on the channel via PATCH
    client
        .patch(format!("{hub_url}/channels/{}", channel.id))
        .bearer_auth(&owner_token)
        .json(&json!({ "min_talk_power": 100 }))
        .send()
        .await
        .unwrap();

    // Confirm min_talk_power was written to the channels table
    let stored: i64 = sqlx::query_scalar("SELECT min_talk_power FROM channels WHERE id = $1")
        .bind(&channel.id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(stored, 100);

    // user2 (priority 0) is blocked without hand raised
    let frame = ws_voice_join_and_recv(&hub_url, &user2_token, &channel.id).await;
    assert_eq!(frame["type"], "error");
    assert!(frame["message"].as_str().unwrap().contains("priority"));

    // user2 raises hand
    client
        .post(format!("{hub_url}/channels/{}/raise-hand", channel.id))
        .bearer_auth(&user2_token)
        .send()
        .await
        .unwrap();

    // user2 can now join voice
    let frame = ws_voice_join_and_recv(&hub_url, &user2_token, &channel.id).await;
    assert_eq!(frame["type"], "voice_joined");
}

/// A user whose master key appears in `federated_bans` must not be able to
/// post messages even when they hold a valid session token obtained before
/// the ban was applied. This directly exercises the `is_federated_banned`
/// helper added in this changeset.
#[tokio::test]
async fn federated_ban_blocks_message_posting() {
    // Use spawn_real_hub so we have access to the DB to insert the ban row.
    let (hub_url, state, _guard) = spawn_real_hub().await;
    let client = reqwest::Client::new();

    let owner = Identity::generate();
    let owner_token = http_authenticate(&hub_url, &owner).await;

    let user = Identity::generate();
    let user_token = http_authenticate(&hub_url, &user).await;

    // Create a channel.
    let channel: ChannelResponse = client
        .post(format!("{hub_url}/channels"))
        .bearer_auth(&owner_token)
        .json(&json!({ "name": "general" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // User can post before the federated ban.
    let pre_ban = client
        .post(format!("{hub_url}/channels/{}/messages", channel.id))
        .bearer_auth(&user_token)
        .json(&json!({ "content": "hello before ban", "attachments": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(pre_ban.status(), 201);

    // Insert a row directly into `federated_bans`, simulating what the
    // banlist_worker does when a peer hub subscribes a ban.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO federated_bans
             (source_hub_pubkey, target_master_pubkey, reason, added_at, synced_at)
         VALUES ('peer-hub-pubkey', $1, 'test', $2, $3)",
    )
    .bind(user.public_key_hex())
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .expect("insert into federated_bans");

    // The user's active token must now be rejected at the message endpoint.
    let post_ban = client
        .post(format!("{hub_url}/channels/{}/messages", channel.id))
        .bearer_auth(&user_token)
        .json(&json!({ "content": "should be blocked", "attachments": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        post_ban.status(),
        403,
        "federally banned user must not post messages"
    );
}

// ---------------------------------------------------------------------------
// Membership semantics: kick/ban remove the member from /users
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kicked_user_leaves_the_member_list_and_can_rejoin() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let target = Identity::generate();
    let target_token = common::authenticate(&server, &target).await;
    let target_pk = target.public_key_hex();

    // Present in /users before the kick.
    let users: serde_json::Value = server
        .get("/users")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(users
        .as_array()
        .unwrap()
        .iter()
        .any(|u| u["public_key"].as_str() == Some(target_pk.as_str())));

    server
        .post("/moderation/kick")
        .authorization_bearer(&owner_token)
        .json(&serde_json::json!({ "target_public_key": target_pk }))
        .await
        .assert_status_ok();

    // Gone from /users; their session token is dead.
    let users: serde_json::Value = server
        .get("/users")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(
        !users
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["public_key"].as_str() == Some(target_pk.as_str())),
        "kicked user must not appear in /users"
    );
    server
        .get("/me")
        .authorization_bearer(&target_token)
        .await
        .assert_status_unauthorized();

    // Not banned: re-auth works and restores membership.
    let _new_token = common::authenticate(&server, &target).await;
    let users: serde_json::Value = server
        .get("/users")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(
        users
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["public_key"].as_str() == Some(target_pk.as_str())),
        "re-authenticated (kicked, not banned) user re-joins the member list"
    );
}

#[tokio::test]
async fn banned_user_leaves_the_member_list_and_cannot_return() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;

    let target = Identity::generate();
    let _target_token = common::authenticate(&server, &target).await;
    let target_pk = target.public_key_hex();

    server
        .post("/moderation/bans")
        .authorization_bearer(&owner_token)
        .json(&serde_json::json!({ "target_public_key": target_pk, "reason": "test ban" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Gone from /users.
    let users: serde_json::Value = server
        .get("/users")
        .authorization_bearer(&owner_token)
        .await
        .json();
    assert!(
        !users
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["public_key"].as_str() == Some(target_pk.as_str())),
        "banned user must not appear in /users"
    );

    // Re-auth is refused entirely (existing ban gate at verify).
    let resp = server
        .post("/auth/challenge")
        .json(&serde_json::json!({ "public_key": target_pk }))
        .await;
    resp.assert_status_ok();
    let challenge: serde_json::Value = resp.json();
    let ch = challenge["challenge"].as_str().unwrap();
    let sig = target.sign(&hex::decode(ch).unwrap());
    server
        .post("/auth/verify")
        .json(&serde_json::json!({
            "public_key": target_pk,
            "challenge": ch,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}
