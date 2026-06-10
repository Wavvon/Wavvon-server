use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::chat_models::ChannelResponse;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

// ---------------------------------------------------------------------------
// Test harness — real TCP listener so WS upgrades work.
// ---------------------------------------------------------------------------

async fn start_hub() -> (String, Arc<AppState>) {
    sqlx::any::install_default_drivers();
    let db = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let store: Arc<dyn voxply_store::HubStore> =
        Arc::new(voxply_store_sqlite::SqliteStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "voice-relay-test".to_string(),
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
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx,
        dm_tx: broadcast::channel(16).0,
        online_users: RwLock::new(std::collections::HashSet::new()),
        screen_shares: RwLock::new(HashMap::new()),
        screen_share_tx: broadcast::channel(16).0,
        bot_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(RwLock::new(0)),
        active_game_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: RwLock::new(HashMap::new()),
        whisper_target_defs: RwLock::new(HashMap::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(HashMap::new()),
        search: Arc::new(voxply_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    });

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, state)
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

async fn connect_ws(
    base: &str,
    token: &str,
) -> (
    futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TsMessage,
    >,
    futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

async fn send_ws(
    tx: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        TsMessage,
    >,
    msg: Value,
) {
    tx.send(TsMessage::Text(msg.to_string().into()))
        .await
        .unwrap();
}

// ---------------------------------------------------------------------------
// Unit-style helpers that operate directly on AppState.
// ---------------------------------------------------------------------------

/// Simulate a voice_join: insert the pubkey into voice_relay_active (mirrors the WS handler).
async fn sim_join(state: &AppState, pubkey: &str, channel_id: &str) {
    let addr: SocketAddr = "127.0.0.1:19000".parse().unwrap();
    state
        .voice_channels
        .write()
        .await
        .entry(channel_id.to_string())
        .or_default()
        .insert(pubkey.to_string(), addr);
    state
        .voice_addr_map
        .write()
        .await
        .insert(addr, (channel_id.to_string(), pubkey.to_string()));
    state
        .voice_relay_active
        .write()
        .await
        .insert(pubkey.to_string());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// After voice_join the pubkey is present in voice_relay_active.
#[tokio::test]
async fn voice_join_activates_relay_slot() {
    let (_base, state) = start_hub().await;
    let pk = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    sim_join(&state, pk, "ch1").await;

    let active = state.voice_relay_active.read().await;
    assert!(
        active.contains(pk),
        "relay slot should be active after voice_join"
    );
}

/// After WS disconnect (simulated via leave_voice) the slot is removed.
#[tokio::test]
async fn ws_disconnect_removes_relay_slot() {
    let (_base, state) = start_hub().await;
    let pk = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";

    // Setup: directly populate all three maps, then call leave_voice.
    {
        let addr: SocketAddr = "127.0.0.1:19001".parse().unwrap();
        let channel_id = "ch-test";
        state
            .voice_channels
            .write()
            .await
            .entry(channel_id.to_string())
            .or_default()
            .insert(pk.to_string(), addr);
        state
            .voice_addr_map
            .write()
            .await
            .insert(addr, (channel_id.to_string(), pk.to_string()));
        state
            .voice_sender_ids
            .write()
            .await
            .entry(channel_id.to_string())
            .or_default()
            .insert(pk.to_string(), 0u16);
        state
            .voice_relay_active
            .write()
            .await
            .insert(pk.to_string());
    }

    // Verify inserted.
    assert!(state.voice_relay_active.read().await.contains(pk));

    // Simulate WS disconnect by calling leave_voice.
    voxply_hub::routes::ws::leave_voice_for_test(&state, pk, "ch-test").await;

    // Slot must be gone.
    assert!(
        !state.voice_relay_active.read().await.contains(pk),
        "relay slot should be removed after leave_voice"
    );
    // addr_map entry must also be gone.
    let addr: SocketAddr = "127.0.0.1:19001".parse().unwrap();
    assert!(
        !state.voice_addr_map.read().await.contains_key(&addr),
        "voice_addr_map entry should be removed"
    );
}

/// A second join by the same pubkey (re-connect) re-activates the slot.
#[tokio::test]
async fn rejoin_reactivates_relay_slot() {
    let (_base, state) = start_hub().await;
    let pk = "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333";
    let ch = "ch-rejoin";

    // Join then leave.
    {
        let addr: SocketAddr = "127.0.0.1:19002".parse().unwrap();
        state
            .voice_channels
            .write()
            .await
            .entry(ch.to_string())
            .or_default()
            .insert(pk.to_string(), addr);
        state
            .voice_addr_map
            .write()
            .await
            .insert(addr, (ch.to_string(), pk.to_string()));
        state
            .voice_sender_ids
            .write()
            .await
            .entry(ch.to_string())
            .or_default()
            .insert(pk.to_string(), 0u16);
        state
            .voice_relay_active
            .write()
            .await
            .insert(pk.to_string());
    }
    voxply_hub::routes::ws::leave_voice_for_test(&state, pk, ch).await;
    assert!(!state.voice_relay_active.read().await.contains(pk));

    // Re-join.
    {
        let addr2: SocketAddr = "127.0.0.1:19003".parse().unwrap();
        state
            .voice_channels
            .write()
            .await
            .entry(ch.to_string())
            .or_default()
            .insert(pk.to_string(), addr2);
        state
            .voice_addr_map
            .write()
            .await
            .insert(addr2, (ch.to_string(), pk.to_string()));
        state
            .voice_relay_active
            .write()
            .await
            .insert(pk.to_string());
    }
    assert!(
        state.voice_relay_active.read().await.contains(pk),
        "re-joined pubkey should have relay slot"
    );
}

/// End-to-end: user joins voice over WS and the relay slot appears; after
/// explicit voice_leave the slot is gone.
#[tokio::test]
async fn ws_voice_join_leave_updates_relay_active() {
    let (base, state) = start_hub().await;

    let user = Identity::generate();
    let token = authenticate_http(&base, &user).await;
    let _ch = create_channel(&base, &token, "voice-ch").await;

    let (mut tx, mut rx) = connect_ws(&base, &token).await;

    // Drain the hello frame.
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next())
            .await
            .expect("hello timeout")
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == "hello" {
                break;
            }
        }
    }

    // Send voice_join.
    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": _ch.id, "udp_port": 19100 }),
    )
    .await;

    // Wait briefly for the hub to process the join.
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;

    // The pubkey should now be in voice_relay_active.
    let pk = user.public_key_hex();
    assert!(
        state.voice_relay_active.read().await.contains(&pk),
        "voice_relay_active should contain pubkey after voice_join"
    );

    // Send voice_leave.
    send_ws(
        &mut tx,
        json!({ "type": "voice_leave", "channel_id": _ch.id }),
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(60)).await;

    // After voice_leave the slot should be gone.
    assert!(
        !state.voice_relay_active.read().await.contains(&pk),
        "voice_relay_active should not contain pubkey after voice_leave"
    );

    let _ = tx.send(TsMessage::Close(None)).await;
}

/// End-to-end: closing the WS connection (without explicit voice_leave) also
/// removes the relay slot.
#[tokio::test]
async fn ws_close_removes_relay_slot_without_explicit_leave() {
    let (base, state) = start_hub().await;

    let user = Identity::generate();
    let token = authenticate_http(&base, &user).await;
    let ch = create_channel(&base, &token, "voice-ch2").await;

    let (mut tx, mut rx) = connect_ws(&base, &token).await;

    // Drain hello.
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next())
            .await
            .expect("hello timeout")
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == "hello" {
                break;
            }
        }
    }

    // Join voice.
    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 19200 }),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;

    let pk = user.public_key_hex();
    assert!(
        state.voice_relay_active.read().await.contains(&pk),
        "should be active after join"
    );

    // Drop the WS connection without sending voice_leave.
    drop(tx);
    drop(rx);

    // Give the hub time to detect the close and run cleanup.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert!(
        !state.voice_relay_active.read().await.contains(&pk),
        "relay slot should be removed when WS closes without voice_leave"
    );
}
