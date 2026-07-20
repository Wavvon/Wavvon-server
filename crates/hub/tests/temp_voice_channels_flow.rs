//! Join-to-create temporary voice channels (docs/docs/temp-voice-channels.md).

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::channels::spawn_temp_channel;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_hub::temp_channel_worker;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Test harness — real TCP listener so WS upgrades work (mirrors
// voice_relay_flow.rs / ws_read_gating_flow.rs).
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "temp-voice-test".to_string(),
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

async fn set_display_name(base: &str, token: &str, name: &str) {
    let resp = reqwest::Client::new()
        .patch(format!("{base}/me"))
        .bearer_auth(token)
        .json(&json!({ "display_name": name }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

async fn create_channel(base: &str, token: &str, body: Value) -> ChannelResponse {
    let resp = reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "create channel failed: {}",
        resp.status()
    );
    resp.json().await.unwrap()
}

async fn list_channels(base: &str, token: &str) -> Vec<ChannelResponse> {
    reqwest::Client::new()
        .get(format!("{base}/channels"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
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

async fn send_ws(tx: &mut WsSink, msg: Value) {
    tx.send(TsMessage::Text(msg.to_string())).await.unwrap();
}

/// Denies `permission` for `@everyone` on `channel_id` via the
/// channel-permission-overwrites admin route (mirrors ws_read_gating_flow.rs).
async fn deny_everyone(base: &str, owner_token: &str, channel_id: &str, permission: &str) {
    let resp = reqwest::Client::new()
        .put(format!(
            "{base}/channels/{channel_id}/permissions/builtin-everyone"
        ))
        .bearer_auth(owner_token)
        .json(&json!({ "allow": [], "deny": [permission] }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
}

/// Connects to `/voice/ws?token=..&channel_id=..` -- the separate transport
/// the web client uses for voice audio (routes/voice_ws.rs), distinct from
/// the main hub `/ws` connection's `voice_join` message.
async fn connect_voice_ws(base: &str, token: &str, channel_id: &str) -> (WsSink, WsStream) {
    let ws_url = format!(
        "{}/voice/ws?token={}&channel_id={}",
        base.replace("http://", "ws://"),
        token,
        channel_id
    );
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

/// Reads WS frames until one of the given types is found, or the timeout
/// elapses. Skips connect-time housekeeping frames.
async fn next_frame_of_type(
    rx: &mut WsStream,
    want: &str,
    timeout: std::time::Duration,
) -> Option<Value> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let msg = match tokio::time::timeout(remaining, rx.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => return None,
        };
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == want {
                return Some(v);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A spawner channel can be created via the ordinary channel-create route
/// and is distinct from an ordinary temp channel (not temporary itself).
#[tokio::test]
async fn creating_a_spawner_channel_works() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let spawner = create_channel(
        &base,
        &owner_token,
        json!({ "name": "voice-lobby", "channel_type": "spawner" }),
    )
    .await;

    assert_eq!(spawner.channel_type, "spawner");
    assert!(!spawner.is_temporary);
    assert!(spawner.owner_pubkey.is_none());
}

/// Joining a spawner's voice creates a temp sibling channel under the
/// spawner's parent, and the WS `voice_joined` reply carries the new
/// channel's id -- never the spawner's.
#[tokio::test]
async fn joining_spawner_voice_creates_temp_sibling() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let category = create_channel(
        &base,
        &owner_token,
        json!({ "name": "voice-category", "is_category": true }),
    )
    .await;
    let spawner = create_channel(
        &base,
        &owner_token,
        json!({
            "name": "voice-lobby",
            "parent_id": category.id,
            "channel_type": "spawner",
        }),
    )
    .await;

    let member = Identity::generate();
    let member_token = authenticate_http(&base, &member).await;
    set_display_name(&base, &member_token, "Alice").await;

    let (mut tx, mut rx) = connect_ws(&base, &member_token).await;
    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": spawner.id, "udp_port": 0 }),
    )
    .await;

    let joined = next_frame_of_type(&mut rx, "voice_joined", std::time::Duration::from_secs(3))
        .await
        .expect("expected a voice_joined reply");
    let temp_channel_id = joined["channel_id"].as_str().unwrap().to_string();
    assert_ne!(
        temp_channel_id, spawner.id,
        "voice_joined must carry the spawned room's id, not the spawner's"
    );

    // The spawner itself must never hold voice participants.
    assert!(
        !state.voice_channels.read().await.contains_key(&spawner.id),
        "spawner must not appear in voice_channels"
    );
    assert!(
        state
            .voice_channels
            .read()
            .await
            .contains_key(&temp_channel_id),
        "the spawned room should hold the joiner"
    );

    let channels = list_channels(&base, &owner_token).await;
    let temp = channels
        .iter()
        .find(|c| c.id == temp_channel_id)
        .expect("spawned room should be listed");
    assert_eq!(temp.parent_id.as_deref(), Some(category.id.as_str()));
    assert!(temp.is_temporary);
    assert_eq!(
        temp.owner_pubkey.as_deref(),
        Some(member.public_key_hex().as_str())
    );
    assert_eq!(temp.name, "Alice's room");
    assert_eq!(temp.channel_type, "text");

    let _ = tx.send(TsMessage::Close(None)).await;
}

/// Name collisions on `spawn_temp_channel` are resolved with a bounded,
/// numbered suffix rather than failing the join.
#[tokio::test]
async fn spawn_name_collision_gets_numbered_suffix() {
    let (state, _guard) = db_only_state().await;

    let spawner_id = seed_spawner(&state.db, None, None).await;
    for pk in ["aaaa1111", "bbbb2222", "cccc3333"] {
        seed_user(&state.db, pk).await;
    }

    let first = spawn_temp_channel(&state.db, &spawner_id, "aaaa1111", Some("Alice"))
        .await
        .expect("first spawn should succeed");
    assert_eq!(first.name, "Alice's room");

    let second = spawn_temp_channel(&state.db, &spawner_id, "bbbb2222", Some("Alice"))
        .await
        .expect("second spawn should succeed via numbered suffix");
    assert_eq!(second.name, "Alice's room 2");

    let third = spawn_temp_channel(&state.db, &spawner_id, "cccc3333", Some("Alice"))
        .await
        .expect("third spawn should succeed via numbered suffix");
    assert_eq!(third.name, "Alice's room 3");
}

/// GC deletes a temp channel once its `empty_since` is past the 60s grace
/// period, but leaves a freshly-stamped one alone. Drives `tick()` directly
/// against seeded rows instead of waiting on a real clock.
#[tokio::test]
async fn gc_deletes_only_past_grace_period() {
    let (state, _guard) = db_only_state().await;

    let now = wavvon_hub::auth::handlers::unix_timestamp();
    let spawner_id = seed_spawner(&state.db, None, None).await;
    for pk in ["aaaa1111", "bbbb2222"] {
        seed_user(&state.db, pk).await;
    }

    let expired = spawn_temp_channel(&state.db, &spawner_id, "aaaa1111", Some("Expired"))
        .await
        .unwrap()
        .id;
    let fresh = spawn_temp_channel(&state.db, &spawner_id, "bbbb2222", Some("Fresh"))
        .await
        .unwrap()
        .id;

    sqlx::query("UPDATE channels SET empty_since = $1 WHERE id = $2")
        .bind(now - 61)
        .bind(&expired)
        .execute(&state.db)
        .await
        .unwrap();
    sqlx::query("UPDATE channels SET empty_since = $1 WHERE id = $2")
        .bind(now - 30)
        .bind(&fresh)
        .execute(&state.db)
        .await
        .unwrap();

    temp_channel_worker::tick(&state).await.unwrap();

    let expired_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
            .bind(&expired)
            .fetch_optional(&state.db)
            .await
            .unwrap();
    assert!(
        expired_exists.is_none(),
        "past-grace temp channel should be GC'd"
    );

    let fresh_exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(&fresh)
        .fetch_optional(&state.db)
        .await
        .unwrap();
    assert!(
        fresh_exists.is_some(),
        "temp channel within the grace period must not be GC'd yet"
    );
}

/// The worker's boot-sweep behavior: a temp channel with no `empty_since`
/// and no current voice participants gets stamped on the first tick, while
/// one that's actually occupied does not.
#[tokio::test]
async fn gc_stamps_unoccupied_unstamped_temp_channels() {
    let (state, _guard) = db_only_state().await;

    let spawner_id = seed_spawner(&state.db, None, None).await;
    for pk in ["aaaa1111", "bbbb2222"] {
        seed_user(&state.db, pk).await;
    }

    let orphaned = spawn_temp_channel(&state.db, &spawner_id, "aaaa1111", Some("Orphan"))
        .await
        .unwrap()
        .id;
    let occupied = spawn_temp_channel(&state.db, &spawner_id, "bbbb2222", Some("Occupied"))
        .await
        .unwrap()
        .id;

    // Simulate an occupied room: someone's in the in-memory voice roster.
    state
        .voice_channels
        .write()
        .await
        .entry(occupied.clone())
        .or_default()
        .insert("ffff9999".to_string(), "0.0.0.0:0".parse().unwrap());

    temp_channel_worker::tick(&state).await.unwrap();

    let orphaned_stamp: Option<i64> =
        sqlx::query_scalar("SELECT empty_since FROM channels WHERE id = $1")
            .bind(&orphaned)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(
        orphaned_stamp.is_some(),
        "an unoccupied temp channel with no empty_since should get stamped"
    );

    let occupied_stamp: Option<i64> =
        sqlx::query_scalar("SELECT empty_since FROM channels WHERE id = $1")
            .bind(&occupied)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(
        occupied_stamp.is_none(),
        "an occupied temp channel must not be stamped"
    );
}

/// A temp channel's owner may rename it without MANAGE_CHANNELS; a non-owner
/// without MANAGE_CHANNELS may not.
#[tokio::test]
async fn owner_can_rename_temp_channel_but_others_cannot() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let spawner = create_channel(
        &base,
        &owner_token,
        json!({ "name": "voice-lobby", "channel_type": "spawner" }),
    )
    .await;

    let room_owner = Identity::generate();
    let room_owner_token = authenticate_http(&base, &room_owner).await;

    let (mut tx, mut rx) = connect_ws(&base, &room_owner_token).await;
    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": spawner.id, "udp_port": 0 }),
    )
    .await;
    let joined = next_frame_of_type(&mut rx, "voice_joined", std::time::Duration::from_secs(3))
        .await
        .unwrap();
    let temp_channel_id = joined["channel_id"].as_str().unwrap().to_string();
    let _ = tx.send(TsMessage::Close(None)).await;

    // The room's owner (a plain @everyone member, no MANAGE_CHANNELS) can
    // rename their own temp room.
    let resp = reqwest::Client::new()
        .patch(format!("{base}/channels/{temp_channel_id}"))
        .bearer_auth(&room_owner_token)
        .json(&json!({ "name": "renamed-by-owner" }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "temp room owner should be able to rename it: {}",
        resp.status()
    );

    // A different plain member without MANAGE_CHANNELS cannot.
    let outsider = Identity::generate();
    let outsider_token = authenticate_http(&base, &outsider).await;
    let resp = reqwest::Client::new()
        .patch(format!("{base}/channels/{temp_channel_id}"))
        .bearer_auth(&outsider_token)
        .json(&json!({ "name": "hijacked" }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a non-owner without MANAGE_CHANNELS must not be able to rename a temp room"
    );
}

/// `channels_updated` is broadcast hub-wide when a spawn creates a new
/// temp room, and again when the GC worker deletes one.
#[tokio::test]
async fn channels_updated_broadcast_on_spawn_and_gc() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let spawner = create_channel(
        &base,
        &owner_token,
        json!({ "name": "voice-lobby", "channel_type": "spawner" }),
    )
    .await;

    // A bystander WS connection subscribed to nothing in particular still
    // gets the hub-wide channels_updated broadcast.
    let (mut watcher_tx, mut watcher_rx) = connect_ws(&base, &owner_token).await;
    // Drain the initial hello/presence frames before triggering the spawn.
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), watcher_rx.next()).await;

    let member = Identity::generate();
    let member_token = authenticate_http(&base, &member).await;
    let (mut tx, mut rx) = connect_ws(&base, &member_token).await;
    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": spawner.id, "udp_port": 0 }),
    )
    .await;
    let joined = next_frame_of_type(&mut rx, "voice_joined", std::time::Duration::from_secs(3))
        .await
        .unwrap();
    let temp_channel_id = joined["channel_id"].as_str().unwrap().to_string();

    let update_frame = next_frame_of_type(
        &mut watcher_rx,
        "channels_updated",
        std::time::Duration::from_secs(3),
    )
    .await;
    assert!(
        update_frame.is_some(),
        "expected a channels_updated broadcast after spawn"
    );

    // Now drive GC directly and confirm a second broadcast on deletion.
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query("UPDATE channels SET empty_since = $1 WHERE id = $2")
        .bind(now - 61)
        .bind(&temp_channel_id)
        .execute(&state.db)
        .await
        .unwrap();

    temp_channel_worker::tick(&state).await.unwrap();

    let update_frame = next_frame_of_type(
        &mut watcher_rx,
        "channels_updated",
        std::time::Duration::from_secs(3),
    )
    .await;
    assert!(
        update_frame.is_some(),
        "expected a channels_updated broadcast after GC deletion"
    );

    let _ = tx.send(TsMessage::Close(None)).await;
    let _ = watcher_tx.send(TsMessage::Close(None)).await;
}

// ---------------------------------------------------------------------------
// /voice/ws spawn-on-join (web client transport, routes/voice_ws.rs) --
// closes the gap where spawn-on-join was only wired into the main hub WS
// path (routes/ws/handlers/voice.rs), leaving web audio joining the
// spawner row itself instead of a fresh temp room.
// ---------------------------------------------------------------------------

/// A web client joining `/voice/ws` against a spawner gets moved into a
/// freshly spawned temp sibling, not the spawner itself: the `voice_ws_ready`
/// frame echoes the spawned room's id, the in-memory voice roster is keyed
/// to that id (never the spawner's), and a `channels_updated` broadcast
/// fires on the main hub WS so other clients refetch their sidebar.
#[tokio::test]
async fn voice_ws_join_to_spawner_creates_temp_sibling() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let spawner = create_channel(
        &base,
        &owner_token,
        json!({ "name": "web-voice-lobby", "channel_type": "spawner" }),
    )
    .await;

    let member = Identity::generate();
    let member_token = authenticate_http(&base, &member).await;
    set_display_name(&base, &member_token, "Bob").await;

    // A bystander on the main hub WS should see the channels_updated
    // broadcast the spawn produces, same as the main-hub-WS spawn path.
    let (mut watcher_tx, mut watcher_rx) = connect_ws(&base, &owner_token).await;
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), watcher_rx.next()).await;

    let (_voice_tx, mut voice_rx) = connect_voice_ws(&base, &member_token, &spawner.id).await;

    let msg = tokio::time::timeout(std::time::Duration::from_secs(3), voice_rx.next())
        .await
        .expect("expected a voice_ws_ready frame before timeout")
        .expect("stream ended without a frame")
        .expect("websocket error");
    let TsMessage::Text(t) = msg else {
        panic!("expected a text frame, got {msg:?}");
    };
    let ready: Value = serde_json::from_str(&t).unwrap();
    assert_eq!(ready["type"], "voice_ws_ready");
    let temp_channel_id = ready["channel_id"]
        .as_str()
        .expect("voice_ws_ready must echo the resolved channel_id")
        .to_string();
    assert_ne!(
        temp_channel_id, spawner.id,
        "voice_ws_ready must carry the spawned room's id, not the spawner's"
    );

    // The spawner itself must never hold voice participants; the spawned
    // room does.
    assert!(
        !state.voice_channels.read().await.contains_key(&spawner.id),
        "spawner must not appear in voice_channels"
    );
    assert!(
        state
            .voice_channels
            .read()
            .await
            .contains_key(&temp_channel_id),
        "the spawned room should hold the joiner"
    );

    let channels = list_channels(&base, &owner_token).await;
    let temp = channels
        .iter()
        .find(|c| c.id == temp_channel_id)
        .expect("spawned room should be listed");
    assert!(temp.is_temporary);
    assert_eq!(
        temp.owner_pubkey.as_deref(),
        Some(member.public_key_hex().as_str())
    );
    assert_eq!(temp.name, "Bob's room");

    let update_frame = next_frame_of_type(
        &mut watcher_rx,
        "channels_updated",
        std::time::Duration::from_secs(3),
    )
    .await;
    assert!(
        update_frame.is_some(),
        "expected a channels_updated broadcast after a /voice/ws spawn"
    );

    let _ = watcher_tx.send(TsMessage::Close(None)).await;
}

/// A member denied `read_messages` on the spawner cannot spawn a room via
/// `/voice/ws` -- no `voice_ws_ready` frame arrives and no temp channel is
/// created. Mirrors the read-gating the main-hub-WS spawn path enforces
/// (temp-voice-channels.md §2 step 1 / §3.4-3.5).
#[tokio::test]
async fn voice_ws_join_to_spawner_denied_without_read_messages() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let spawner = create_channel(
        &base,
        &owner_token,
        json!({ "name": "locked-voice-lobby", "channel_type": "spawner" }),
    )
    .await;
    deny_everyone(&base, &owner_token, &spawner.id, "read_messages").await;

    let outsider = Identity::generate();
    let outsider_token = authenticate_http(&base, &outsider).await;

    let (_voice_tx, mut voice_rx) = connect_voice_ws(&base, &outsider_token, &spawner.id).await;

    // The gate makes the server task return without ever sending a frame,
    // so the connection closes (or the stream ends) instead of yielding a
    // voice_ws_ready message. Close frame, stream end, or a transport error
    // are all acceptable "rejected" outcomes.
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), voice_rx.next()).await;
    if let Ok(Some(Ok(TsMessage::Text(t)))) = outcome {
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_ne!(
            v["type"], "voice_ws_ready",
            "a caller without read_messages on the spawner must not be able to spawn a room"
        );
    }

    // No temp sibling should have been created under the spawner's parent.
    let siblings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM channels WHERE is_temporary = TRUE AND owner_pubkey = $1",
    )
    .bind(outsider.public_key_hex())
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(
        siblings, 0,
        "denied read_messages must not spawn a temp room"
    );
    assert!(
        state.voice_channels.read().await.is_empty(),
        "no voice roster entry should exist for the denied caller"
    );
}

// ---------------------------------------------------------------------------
// Helpers for the DB-only (non-WS) tests.
// ---------------------------------------------------------------------------

/// Builds just enough of an `AppState` to call `spawn_temp_channel` /
/// `temp_channel_worker::tick` directly, without booting a full hub + TCP
/// listener.
async fn db_only_state() -> (Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);
    let state = Arc::new(AppState {
        hub_name: "temp-voice-db-test".to_string(),
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
    (state, guard)
}

/// Seeds a bare `users` row so a fake short pubkey can legally appear as
/// `created_by` / `owner_pubkey` on a `channels` row (both are FK-enforced
/// against `users.public_key`).
async fn seed_user(db: &sqlx::PgPool, pubkey: &str) {
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(pubkey)
    .bind(now)
    .execute(db)
    .await
    .unwrap();
}

/// Seeds a bare user + spawner channel row directly, bypassing HTTP -- used
/// by the DB-only tests that don't need a full hub/WS harness.
async fn seed_spawner(
    db: &sqlx::PgPool,
    parent_id: Option<&str>,
    name_template: Option<&str>,
) -> String {
    let creator = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at) VALUES ($1, $2) ON CONFLICT DO NOTHING",
    )
    .bind(creator)
    .bind(now)
    .execute(db)
    .await
    .unwrap();

    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO channels (id, name, created_by, parent_id, is_category, display_order, channel_type, created_at, spawner_name_template)
         VALUES ($1, $2, $3, $4, FALSE, 0, 'spawner', $5, $6)",
    )
    .bind(&id)
    .bind(format!("spawner-{id}"))
    .bind(creator)
    .bind(parent_id)
    .bind(now)
    .bind(name_template)
    .execute(db)
    .await
    .unwrap();

    id
}
