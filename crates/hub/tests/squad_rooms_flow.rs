/// Integration tests for auto-spawned squad channels (events.md §7.5,
/// updated lifetime) -- `POST /events/:id/squad-rooms`, the event-end sweep,
/// the join-block on an ended event's room, and event-delete cleanup.
use std::collections::HashMap;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---------------------------------------------------------------------------
// Harness -- mirrors voice_move_flow.rs / temp_voice_channels_flow.rs so real
// WS upgrades work over a real TCP listener.
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "squad-rooms-test".to_string(),
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
        online_users: RwLock::new(HashMap::new()),
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
        voice_ws_senders: RwLock::new(HashMap::new()),
        ws_key_senders: RwLock::new(HashMap::new()),
        voice_udp_socket: Arc::new(RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(HashMap::new()),
        search: Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        bots_allow_camera: false,
        bots_allow_video: false,
        bot_video_stream_budget: 2,
        webauthn: {
            let origin = url::Url::parse("http://localhost:3000").unwrap();
            Arc::new(
                webauthn_rs::WebauthnBuilder::new("localhost", &origin)
                    .unwrap()
                    .rp_name("test-hub")
                    .build()
                    .unwrap(),
            )
        },
        webauthn_reg_challenges: RwLock::new(HashMap::new()),
        webauthn_auth_challenges: RwLock::new(HashMap::new()),
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
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

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

async fn create_channel(base: &str, token: &str, name: &str) -> ChannelResponse {
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

#[derive(serde::Deserialize)]
struct EventResponse {
    id: String,
}

async fn create_event(
    base: &str,
    token: &str,
    channel_id: &str,
    title: &str,
    ends_at: Option<i64>,
) -> EventResponse {
    let mut body = json!({
        "channel_id": channel_id,
        "title": title,
        "starts_at": 0,
    });
    if let Some(e) = ends_at {
        body["ends_at"] = json!(e);
    }
    let resp = reqwest::Client::new()
        .post(format!("{base}/events"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "create_event failed: {resp:?}");
    resp.json().await.unwrap()
}

async fn create_squad_rooms(
    base: &str,
    token: &str,
    event_id: &str,
    body: Value,
) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("{base}/events/{event_id}/squad-rooms"))
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap()
}

async fn create_squad_rooms_ok(
    base: &str,
    token: &str,
    event_id: &str,
    body: Value,
) -> Vec<ChannelResponse> {
    let resp = create_squad_rooms(base, token, event_id, body).await;
    assert!(
        resp.status().is_success(),
        "create_squad_rooms failed: {:?}",
        resp.status()
    );
    resp.json().await.unwrap()
}

async fn delete_event(base: &str, token: &str, event_id: &str) {
    let resp = reqwest::Client::new()
        .delete(format!("{base}/events/{event_id}"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "delete_event failed: {resp:?}");
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

async fn channel_exists(state: &AppState, channel_id: &str) -> bool {
    let row: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(channel_id)
        .fetch_optional(&state.db)
        .await
        .unwrap();
    row.is_some()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: the organizer (here also hub admin) spawns 3 squad rooms
/// under the event's anchor channel, gets back created channel objects with
/// `event_id` set and the right parent, and a bystander sees the
/// `channels_updated` broadcast.
#[tokio::test]
async fn squad_rooms_happy_path() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let anchor = create_channel(&base, &owner_token, "raid-planning").await;
    let event = create_event(&base, &owner_token, &anchor.id, "Raid Night", None).await;

    let (mut watcher_tx, mut watcher_rx) = connect_ws(&base, &owner_token).await;
    let _ = tokio::time::timeout(std::time::Duration::from_millis(200), watcher_rx.next()).await;

    let rooms = create_squad_rooms_ok(
        &base,
        &owner_token,
        &event.id,
        json!({ "count": 3, "name_prefix": "Squad" }),
    )
    .await;

    assert_eq!(rooms.len(), 3);
    let mut names: Vec<String> = rooms.iter().map(|r| r.name.clone()).collect();
    names.sort();
    assert_eq!(names, vec!["Squad 1", "Squad 2", "Squad 3"]);
    for room in &rooms {
        assert_eq!(room.event_id.as_deref(), Some(event.id.as_str()));
        assert_eq!(room.parent_id.as_deref(), Some(anchor.id.as_str()));
        assert!(room.is_temporary);
    }

    let update_frame = next_frame_of_type(
        &mut watcher_rx,
        "channels_updated",
        std::time::Duration::from_secs(15),
    )
    .await;
    assert!(
        update_frame.is_some(),
        "expected a channels_updated broadcast after spawning squad rooms"
    );

    let _ = watcher_tx.send(TsMessage::Close(None)).await;
}

/// A member who is neither the event's creator/organizer nor holds
/// `MOVE_MEMBERS` is rejected.
#[tokio::test]
async fn squad_rooms_rejected_for_non_organizer() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let outsider = Identity::generate();
    let outsider_token = authenticate_http(&base, &outsider).await;

    let anchor = create_channel(&base, &owner_token, "gated-anchor").await;
    let event = create_event(&base, &owner_token, &anchor.id, "Raid Night", None).await;

    let resp = create_squad_rooms(&base, &outsider_token, &event.id, json!({ "count": 2 })).await;
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
}

/// `count` outside `1..=20` is rejected with 400.
#[tokio::test]
async fn squad_rooms_count_bound_rejected() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let anchor = create_channel(&base, &owner_token, "bound-anchor").await;
    let event = create_event(&base, &owner_token, &anchor.id, "Raid Night", None).await;

    let resp = create_squad_rooms(&base, &owner_token, &event.id, json!({ "count": 0 })).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    let resp = create_squad_rooms(&base, &owner_token, &event.id, json!({ "count": 21 })).await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);

    // A boundary value is accepted.
    let resp = create_squad_rooms(&base, &owner_token, &event.id, json!({ "count": 1 })).await;
    assert!(resp.status().is_success());
}

/// The reminder worker's sweep deletes an empty squad room belonging to an
/// event whose `ends_at` is already in the past; a room belonging to a still
/// -live event survives the same tick.
#[tokio::test]
async fn event_end_sweep_deletes_empty_squad_room() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let anchor = create_channel(&base, &owner_token, "sweep-anchor").await;
    let now = wavvon_hub::auth::handlers::unix_timestamp();

    let ended_event = create_event(
        &base,
        &owner_token,
        &anchor.id,
        "Ended Raid",
        Some(now - 3600),
    )
    .await;
    let live_event = create_event(
        &base,
        &owner_token,
        &anchor.id,
        "Live Raid",
        Some(now + 3600),
    )
    .await;

    let ended_rooms =
        create_squad_rooms_ok(&base, &owner_token, &ended_event.id, json!({ "count": 1 })).await;
    let live_rooms =
        create_squad_rooms_ok(&base, &owner_token, &live_event.id, json!({ "count": 1 })).await;

    wavvon_hub::reminder_worker::tick(&state)
        .await
        .expect("tick should succeed");

    assert!(
        !channel_exists(&state, &ended_rooms[0].id).await,
        "empty squad room of an ended event should be deleted immediately"
    );
    assert!(
        channel_exists(&state, &live_rooms[0].id).await,
        "squad room of a still-live event must survive"
    );
}

/// A new voice join to a squad room whose event has ended is rejected; the
/// room itself is left in place (only new joins are blocked).
#[tokio::test]
async fn join_to_ended_event_room_rejected() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let member = Identity::generate();
    let member_token = authenticate_http(&base, &member).await;

    let anchor = create_channel(&base, &owner_token, "join-block-anchor").await;
    let now = wavvon_hub::auth::handlers::unix_timestamp();
    let event = create_event(
        &base,
        &owner_token,
        &anchor.id,
        "Already Over",
        Some(now - 60),
    )
    .await;
    let rooms = create_squad_rooms_ok(&base, &owner_token, &event.id, json!({ "count": 1 })).await;
    let room_id = rooms[0].id.clone();

    // Sanity: the room still exists (join-block is independent of the
    // sweep's deletion, which runs on its own worker tick).
    assert!(channel_exists(&state, &room_id).await);

    let mut member_ws = connect_ws(&base, &member_token).await;
    send_ws(
        &mut member_ws.0,
        json!({ "type": "voice_join", "channel_id": room_id, "udp_port": 0 }),
    )
    .await;

    let err = next_frame_of_type(
        &mut member_ws.1,
        "error",
        std::time::Duration::from_secs(15),
    )
    .await
    .expect("expected an error frame rejecting the join");
    assert_eq!(err["context"], "voice_join");

    let joined = next_frame_of_type(
        &mut member_ws.1,
        "voice_joined",
        std::time::Duration::from_millis(300),
    )
    .await;
    assert!(
        joined.is_none(),
        "join must not have succeeded against an ended event's room"
    );
}

/// Deleting an event cleans up its squad rooms explicitly (no FK cascade).
#[tokio::test]
async fn event_delete_cleans_up_squad_rooms() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;

    let anchor = create_channel(&base, &owner_token, "delete-anchor").await;
    let event = create_event(&base, &owner_token, &anchor.id, "Doomed Raid", None).await;
    let rooms = create_squad_rooms_ok(&base, &owner_token, &event.id, json!({ "count": 2 })).await;

    for room in &rooms {
        assert!(channel_exists(&state, &room.id).await);
    }

    delete_event(&base, &owner_token, &event.id).await;

    for room in &rooms {
        assert!(
            !channel_exists(&state, &room.id).await,
            "squad room must be deleted alongside its event"
        );
    }
    // The anchor channel itself is untouched.
    assert!(channel_exists(&state, &anchor.id).await);
}
