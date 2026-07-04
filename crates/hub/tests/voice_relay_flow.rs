use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, RwLock};
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::{AppState, ConsumedVoiceToken};
use wavvon_identity::Identity;

// ---------------------------------------------------------------------------
// Test harness — real TCP listener so WS upgrades work.
// ---------------------------------------------------------------------------

#[path = "common.rs"]
mod common;

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
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

/// Simulate a voice_join: insert the pubkey with the sentinel address into voice_channels
/// and mark the relay slot active (mirrors the WS handler after Phase 1).
/// voice_addr_map is NOT populated — that requires a VXRG UDP register packet.
async fn sim_join(state: &AppState, pubkey: &str, channel_id: &str) {
    // Use the sentinel address — same as the WS handler post-Phase 1.
    let sentinel: SocketAddr = "0.0.0.0:0".parse().unwrap();
    state
        .voice_channels
        .write()
        .await
        .entry(channel_id.to_string())
        .or_default()
        .insert(pubkey.to_string(), sentinel);
    state
        .voice_relay_active
        .write()
        .await
        .insert(pubkey.to_string());
}

/// Simulate a completed UDP registration: bind a real address for a previously sim_join'd pubkey.
async fn sim_register(state: &AppState, pubkey: &str, channel_id: &str, addr: SocketAddr) {
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// After voice_join the pubkey is present in voice_relay_active.
#[tokio::test]
async fn voice_join_activates_relay_slot() {
    let (_base, state, _guard) = start_hub().await;
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
    let (_base, state, _guard) = start_hub().await;
    let pk = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";
    let channel_id = "ch-test";
    let bound_addr: SocketAddr = "127.0.0.1:19001".parse().unwrap();

    // Setup: join (sentinel) then simulate UDP registration (real address).
    sim_join(&state, pk, channel_id).await;
    sim_register(&state, pk, channel_id, bound_addr).await;
    state
        .voice_sender_ids
        .write()
        .await
        .entry(channel_id.to_string())
        .or_default()
        .insert(pk.to_string(), 0u16);

    // Verify inserted.
    assert!(state.voice_relay_active.read().await.contains(pk));
    assert!(state.voice_addr_map.read().await.contains_key(&bound_addr));

    // Simulate WS disconnect by calling leave_voice.
    wavvon_hub::routes::ws::leave_voice_for_test(&state, pk, channel_id).await;

    // Slot must be gone.
    assert!(
        !state.voice_relay_active.read().await.contains(pk),
        "relay slot should be removed after leave_voice"
    );
    // addr_map entry must also be gone.
    assert!(
        !state.voice_addr_map.read().await.contains_key(&bound_addr),
        "voice_addr_map entry should be removed after leave_voice"
    );
}

/// A second join by the same pubkey (re-connect) re-activates the slot.
#[tokio::test]
async fn rejoin_reactivates_relay_slot() {
    let (_base, state, _guard) = start_hub().await;
    let pk = "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333";
    let ch = "ch-rejoin";

    // Join then leave.
    sim_join(&state, pk, ch).await;
    sim_register(&state, pk, ch, "127.0.0.1:19002".parse().unwrap()).await;
    state
        .voice_sender_ids
        .write()
        .await
        .entry(ch.to_string())
        .or_default()
        .insert(pk.to_string(), 0u16);
    wavvon_hub::routes::ws::leave_voice_for_test(&state, pk, ch).await;
    assert!(!state.voice_relay_active.read().await.contains(pk));

    // Re-join (sentinel only — UDP registration would happen separately in production).
    sim_join(&state, pk, ch).await;
    assert!(
        state.voice_relay_active.read().await.contains(pk),
        "re-joined pubkey should have relay slot"
    );
}

/// Helper: drain WS frames until voice_joined arrives; return the udp_register_token.
async fn drain_until_voice_joined(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> String {
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(3), rx.next())
            .await
            .expect("voice_joined timeout")
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == "voice_joined" {
                let tok = v["udp_register_token"]
                    .as_str()
                    .expect("voice_joined must carry udp_register_token")
                    .to_string();
                assert_eq!(tok.len(), 64, "token must be 64 hex chars (32 bytes)");
                assert!(
                    tok.chars().all(|c| c.is_ascii_hexdigit()),
                    "token must be hex"
                );
                return tok;
            }
        }
    }
}

/// End-to-end: user joins voice over WS and the relay slot appears; voice_joined
/// reply carries a udp_register_token; after explicit voice_leave the slot is gone.
#[tokio::test]
async fn ws_voice_join_leave_updates_relay_active() {
    let (base, state, _guard) = start_hub().await;

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
        json!({ "type": "voice_join", "channel_id": _ch.id, "udp_port": 0 }),
    )
    .await;

    // Read voice_joined and verify it carries the register token.
    let _register_token = drain_until_voice_joined(&mut rx).await;

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
    let (base, state, _guard) = start_hub().await;

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
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    let _tok = drain_until_voice_joined(&mut rx).await;

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

// ---------------------------------------------------------------------------
// UDP relay harness — spins up a real UDP socket + the relay loop.
// ---------------------------------------------------------------------------

/// Extended harness that also starts the UDP relay loop from main.rs.
/// Returns (http_base_url, udp_port, Arc<AppState>).
async fn start_hub_with_udp() -> (String, u16, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    // Bind a real UDP socket on a random OS-assigned port.
    let voice_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_port = voice_socket.local_addr().unwrap().port();

    let state = Arc::new(AppState {
        hub_name: "voice-udp-test".to_string(),
        hub_identity: wavvon_identity::Identity::generate(),
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
        voice_udp_port: udp_port,
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
    });

    // Spawn the relay loop (mirrors main.rs).
    let relay_state = state.clone();
    tokio::spawn(async move {
        const VXRG_MAGIC: &[u8] = b"VXRG";
        const VXRG_TOKEN_LEN: usize = 64;
        const VXRG_MIN_LEN: usize = 4 + VXRG_TOKEN_LEN;
        const VXRA: &[u8] = b"VXRA";

        let mut buf = [0u8; 2048];
        loop {
            let Ok((len, from_addr)) = voice_socket.recv_from(&mut buf).await else {
                break;
            };
            let packet_data = buf[..len].to_vec();

            if len >= VXRG_MIN_LEN && &packet_data[..4] == VXRG_MAGIC {
                let token_bytes = &packet_data[4..4 + VXRG_TOKEN_LEN];
                let token = match std::str::from_utf8(token_bytes) {
                    Ok(t) => t.to_string(),
                    Err(_) => continue,
                };

                // Idempotent re-ack check.
                {
                    let consumed = relay_state.voice_consumed_tokens.read().await;
                    if consumed.contains_key(&from_addr) {
                        drop(consumed);
                        let _ = voice_socket.send_to(VXRA, from_addr).await;
                        continue;
                    }
                }

                let now = std::time::Instant::now();
                let bind_opt = {
                    let mut binds = relay_state.voice_pending_binds.write().await;
                    binds.retain(|_, v| v.expires_at > now);
                    binds.remove(&token)
                };

                let bind = match bind_opt {
                    Some(b) if b.expires_at > now => b,
                    _ => continue,
                };

                {
                    let mut addr_map = relay_state.voice_addr_map.write().await;
                    addr_map.insert(from_addr, (bind.channel_id.clone(), bind.pubkey.clone()));
                }
                {
                    let mut channels = relay_state.voice_channels.write().await;
                    if let Some(ch_map) = channels.get_mut(&bind.channel_id) {
                        ch_map.insert(bind.pubkey.clone(), from_addr);
                    }
                }
                {
                    let mut consumed = relay_state.voice_consumed_tokens.write().await;
                    consumed.insert(
                        from_addr,
                        ConsumedVoiceToken {
                            bound_addr: from_addr,
                            channel_id: bind.channel_id.clone(),
                            pubkey: bind.pubkey.clone(),
                        },
                    );
                }

                let _ = voice_socket.send_to(VXRA, from_addr).await;
                continue;
            }

            // Audio relay.
            let lookup = {
                let map = relay_state.voice_addr_map.read().await;
                map.get(&from_addr).cloned()
            };
            if let Some((channel_id, sender_pk)) = lookup {
                {
                    let active = relay_state.voice_relay_active.read().await;
                    if !active.contains(&sender_pk) {
                        continue;
                    }
                }
                let sender_id: u16 = {
                    let sids = relay_state.voice_sender_ids.read().await;
                    sids.get(&channel_id)
                        .and_then(|m| m.get(&sender_pk))
                        .copied()
                        .unwrap_or(0)
                };
                let sender_id_bytes = sender_id.to_be_bytes();
                let addr_map_snap = {
                    let map = relay_state.voice_addr_map.read().await;
                    map.clone()
                };
                let dests: Vec<SocketAddr> = {
                    let channels = relay_state.voice_channels.read().await;
                    channels
                        .get(&channel_id)
                        .map(|participants| {
                            participants
                                .values()
                                .filter(|a| **a != from_addr && addr_map_snap.contains_key(*a))
                                .copied()
                                .collect()
                        })
                        .unwrap_or_default()
                };

                let mut outbound = Vec::with_capacity(3 + packet_data.len());
                outbound.extend_from_slice(&sender_id_bytes);
                outbound.push(0x00u8);
                outbound.extend_from_slice(&packet_data);
                for addr in dests {
                    let _ = voice_socket.send_to(&outbound, addr).await;
                }
            }
        }
    });

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (url, udp_port, state, guard)
}

// ---------------------------------------------------------------------------
// Phase 1 UDP register tests (Requirements 7a–7e)
// ---------------------------------------------------------------------------

/// 7a: voice_joined reply carries a udp_register_token (64 hex chars).
#[tokio::test]
async fn voice_joined_carries_udp_register_token() {
    let (base, _udp_port, _state, _guard) = start_hub_with_udp().await;

    let user = Identity::generate();
    let token = authenticate_http(&base, &user).await;
    let ch = create_channel(&base, &token, "tok-ch").await;

    let (mut tx, mut rx) = connect_ws(&base, &token).await;

    // Drain hello.
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            if serde_json::from_str::<Value>(&t).unwrap()["type"] == "hello" {
                break;
            }
        }
    }

    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    let tok = drain_until_voice_joined(&mut rx).await;

    assert_eq!(tok.len(), 64, "token should be 64 hex chars");
    assert!(
        tok.chars().all(|c| c.is_ascii_hexdigit()),
        "token must be hex"
    );

    let _ = tx.send(TsMessage::Close(None)).await;
}

/// 7b: Two clients register with their tokens, both get acks, audio from A
/// relays to B's real socket (not loopback).
#[tokio::test]
async fn two_clients_register_and_audio_relays() {
    let (base, udp_port, state, _guard) = start_hub_with_udp().await;
    let hub_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let tok_a = authenticate_http(&base, &user_a).await;
    let tok_b = authenticate_http(&base, &user_b).await;
    let ch = create_channel(&base, &tok_a, "relay-ch").await;

    // Connect A and B to WS, join voice.
    let (mut tx_a, mut rx_a) = connect_ws(&base, &tok_a).await;
    let (mut tx_b, mut rx_b) = connect_ws(&base, &tok_b).await;

    // Drain hellos.
    for rx in [&mut rx_a, &mut rx_b] {
        loop {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let TsMessage::Text(t) = msg {
                if serde_json::from_str::<Value>(&t).unwrap()["type"] == "hello" {
                    break;
                }
            }
        }
    }

    send_ws(
        &mut tx_a,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    let reg_token_a = drain_until_voice_joined(&mut rx_a).await;

    send_ws(
        &mut tx_b,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    let reg_token_b = drain_until_voice_joined(&mut rx_b).await;

    // Bind real UDP sockets for A and B.
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = sock_a.local_addr().unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    // A sends VXRG to hub with its register token.
    let mut vxrg_a = b"VXRG".to_vec();
    vxrg_a.extend_from_slice(reg_token_a.as_bytes());
    sock_a.send_to(&vxrg_a, hub_addr).await.unwrap();

    // Wait for ack.
    let mut ack_buf = [0u8; 16];
    let (ack_len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sock_a.recv_from(&mut ack_buf),
    )
    .await
    .expect("VXRA ack timeout for A")
    .unwrap();
    assert_eq!(&ack_buf[..ack_len], b"VXRA", "A should receive VXRA ack");

    // B sends VXRG.
    let mut vxrg_b = b"VXRG".to_vec();
    vxrg_b.extend_from_slice(reg_token_b.as_bytes());
    sock_b.send_to(&vxrg_b, hub_addr).await.unwrap();

    let (ack_len_b, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sock_b.recv_from(&mut ack_buf),
    )
    .await
    .expect("VXRA ack timeout for B")
    .unwrap();
    assert_eq!(&ack_buf[..ack_len_b], b"VXRA", "B should receive VXRA ack");

    // Verify both addresses are bound in voice_addr_map.
    {
        let map = state.voice_addr_map.read().await;
        assert!(map.contains_key(&addr_a), "A's address should be bound");
        assert!(map.contains_key(&addr_b), "B's address should be bound");
    }

    // A sends audio; B should receive it relayed.
    let audio_payload = b"OPUS_FAKE_AUDIO_DATA";
    sock_a.send_to(audio_payload, hub_addr).await.unwrap();

    // B listens for the relayed packet (hub prepends [sender_id: 2][pkt_type: 1]).
    let mut relay_buf = [0u8; 512];
    let (relay_len, relay_from) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sock_b.recv_from(&mut relay_buf),
    )
    .await
    .expect("relay timeout: B should receive audio from hub")
    .unwrap();

    assert_eq!(relay_from, hub_addr, "relayed packet should come from hub");
    assert!(
        relay_len >= 3 + audio_payload.len(),
        "relayed packet should contain header + payload"
    );
    assert_eq!(
        &relay_buf[3..relay_len],
        audio_payload,
        "relayed payload should match"
    );

    let _ = tx_a.send(TsMessage::Close(None)).await;
    let _ = tx_b.send(TsMessage::Close(None)).await;
}

/// 7c: Audio sent BEFORE registering is not relayed; no packet ever sent to
/// an unregistered address.
#[tokio::test]
async fn audio_before_register_not_relayed() {
    let (base, udp_port, state, _guard) = start_hub_with_udp().await;
    let hub_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    let user_a = Identity::generate();
    let user_b = Identity::generate();
    let tok_a = authenticate_http(&base, &user_a).await;
    let tok_b = authenticate_http(&base, &user_b).await;
    let ch = create_channel(&base, &tok_a, "early-audio-ch").await;

    let (mut tx_a, mut rx_a) = connect_ws(&base, &tok_a).await;
    let (mut tx_b, mut rx_b) = connect_ws(&base, &tok_b).await;

    for rx in [&mut rx_a, &mut rx_b] {
        loop {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let TsMessage::Text(t) = msg {
                if serde_json::from_str::<Value>(&t).unwrap()["type"] == "hello" {
                    break;
                }
            }
        }
    }

    send_ws(
        &mut tx_a,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    let _tok_a = drain_until_voice_joined(&mut rx_a).await;

    send_ws(
        &mut tx_b,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    let reg_token_b = drain_until_voice_joined(&mut rx_b).await;

    // B registers its address; A does NOT.
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_b = sock_b.local_addr().unwrap();

    let mut vxrg_b = b"VXRG".to_vec();
    vxrg_b.extend_from_slice(reg_token_b.as_bytes());
    sock_b.send_to(&vxrg_b, hub_addr).await.unwrap();
    let mut ack_buf = [0u8; 16];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sock_b.recv_from(&mut ack_buf),
    )
    .await
    .unwrap()
    .unwrap();

    // Verify B is bound, A is not.
    {
        let map = state.voice_addr_map.read().await;
        assert!(map.contains_key(&addr_b), "B should be bound");
        assert!(
            !map.contains_key(&sock_a.local_addr().unwrap()),
            "A should not be bound"
        );
    }

    // A sends audio (not registered — hub should drop it, nothing relayed to B).
    let audio = b"PRE_REGISTER_AUDIO";
    sock_a.send_to(audio, hub_addr).await.unwrap();

    // Give the hub a moment to process, then confirm B receives nothing.
    // A 200 ms timeout on recv is used as the "no packet" assertion.
    let mut rx_buf = [0u8; 512];
    let no_relay = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        sock_b.recv_from(&mut rx_buf),
    )
    .await;
    assert!(
        no_relay.is_err(),
        "B should NOT receive audio from unregistered A (timeout expected)"
    );

    let _ = tx_a.send(TsMessage::Close(None)).await;
    let _ = tx_b.send(TsMessage::Close(None)).await;
}

/// 7d: A register packet with a garbage token gets no reply and no binding.
#[tokio::test]
async fn garbage_token_gets_no_reply() {
    let (base, udp_port, state, _guard) = start_hub_with_udp().await;
    let hub_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    let user = Identity::generate();
    let token = authenticate_http(&base, &user).await;
    let ch = create_channel(&base, &token, "garbage-ch").await;

    let (mut tx, mut rx) = connect_ws(&base, &token).await;
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            if serde_json::from_str::<Value>(&t).unwrap()["type"] == "hello" {
                break;
            }
        }
    }
    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    let _tok = drain_until_voice_joined(&mut rx).await;

    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let attacker_addr = sock.local_addr().unwrap();

    // Send VXRG with a garbage (all-zero) token.
    let mut garbage_pkt = b"VXRG".to_vec();
    garbage_pkt
        .extend_from_slice(b"0000000000000000000000000000000000000000000000000000000000000000");
    sock.send_to(&garbage_pkt, hub_addr).await.unwrap();

    // No reply expected: use a short timeout; expiry means no reply (correct).
    let mut ack_buf = [0u8; 16];
    let no_reply = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        sock.recv_from(&mut ack_buf),
    )
    .await;
    assert!(
        no_reply.is_err(),
        "garbage token should receive no reply (timeout expected)"
    );

    // Attacker's address must not appear in voice_addr_map.
    assert!(
        !state
            .voice_addr_map
            .read()
            .await
            .contains_key(&attacker_addr),
        "garbage token must not create a binding"
    );

    let _ = tx.send(TsMessage::Close(None)).await;
}

/// 7e: A consumed token re-sent from a DIFFERENT source address does not rebind
/// (original binding intact, no ack to the new address).
#[tokio::test]
async fn consumed_token_from_different_addr_does_not_rebind() {
    let (base, udp_port, state, _guard) = start_hub_with_udp().await;
    let hub_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    let user = Identity::generate();
    let token = authenticate_http(&base, &user).await;
    let ch = create_channel(&base, &token, "rebind-ch").await;

    let (mut tx, mut rx) = connect_ws(&base, &token).await;
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            if serde_json::from_str::<Value>(&t).unwrap()["type"] == "hello" {
                break;
            }
        }
    }
    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": ch.id, "udp_port": 0 }),
    )
    .await;
    let reg_token = drain_until_voice_joined(&mut rx).await;

    // Legitimate client registers first.
    let legit_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let legit_addr = legit_sock.local_addr().unwrap();
    let mut vxrg = b"VXRG".to_vec();
    vxrg.extend_from_slice(reg_token.as_bytes());
    legit_sock.send_to(&vxrg, hub_addr).await.unwrap();
    let mut ack_buf = [0u8; 16];
    let (ack_len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        legit_sock.recv_from(&mut ack_buf),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&ack_buf[..ack_len], b"VXRA", "legit client should get VXRA");

    // Attacker tries to re-use the same token from a different address.
    let attacker_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let attacker_addr = attacker_sock.local_addr().unwrap();
    attacker_sock.send_to(&vxrg, hub_addr).await.unwrap();

    // No ack to attacker: short timeout, expiry = no reply (correct).
    let no_ack = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        attacker_sock.recv_from(&mut ack_buf),
    )
    .await;
    assert!(
        no_ack.is_err(),
        "attacker should receive no ack (timeout expected)"
    );

    // Original binding intact; attacker's address must not be bound.
    {
        let map = state.voice_addr_map.read().await;
        assert!(
            map.contains_key(&legit_addr),
            "original binding must still exist"
        );
        assert!(
            !map.contains_key(&attacker_addr),
            "attacker's address must not be bound"
        );
    }

    let _ = tx.send(TsMessage::Close(None)).await;
}

// ---------------------------------------------------------------------------
// Bot audio injection (soundboard.md §2) — /voice/ws gate on can_speak_voice
// ---------------------------------------------------------------------------

/// Invites `bot_identity` as an external bot (admin_token must belong to a
/// member with manage_roles/admin), then completes the normal Ed25519
/// challenge/verify flow with `is_bot: true` and the given capabilities,
/// returning the bot's session token. That token is valid on both `/ws`
/// and `/voice/ws`, exactly like a human session token.
async fn invite_and_auth_bot(
    base: &str,
    admin_token: &str,
    bot_identity: &Identity,
    capabilities: &[&str],
) -> String {
    let client = reqwest::Client::new();
    let pub_key = bot_identity.public_key_hex();

    let invite_resp = client
        .post(format!("{base}/bots"))
        .bearer_auth(admin_token)
        .json(&json!({ "pubkey": pub_key }))
        .send()
        .await
        .unwrap();
    assert!(
        invite_resp.status().is_success(),
        "bot invite should succeed: {}",
        invite_resp.status()
    );

    let challenge: ChallengeResponse = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = bot_identity.sign(&challenge_bytes);

    let verify_resp = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": challenge.challenge,
            "signature": hex::encode(signature.to_bytes()),
            "is_bot": true,
            "bot_meta": {
                "name": "VoiceInjectionBot",
                "capabilities": capabilities,
            },
        }))
        .send()
        .await
        .unwrap();
    assert!(
        verify_resp.status().is_success(),
        "bot auth/verify should succeed: {}",
        verify_resp.status()
    );
    let verify: VerifyResponse = verify_resp.json().await.unwrap();
    verify.token
}

/// Connects to `/voice/ws?token=..&channel_id=..`, the same wire format
/// `/voice/ws` uses for human web clients.
async fn connect_voice_ws(
    base: &str,
    token: &str,
    channel_id: &str,
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
    let ws_url = format!(
        "{}/voice/ws?token={}&channel_id={}",
        base.replace("http://", "ws://"),
        token,
        channel_id
    );
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    ws.split()
}

/// A bot session with the `can_speak_voice` capability can join `/voice/ws`
/// as a first-class participant: it receives `voice_ws_ready` and shows up
/// in the HTTP voice roster.
#[tokio::test]
async fn bot_with_can_speak_voice_registers_as_voice_sender() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let ch = create_channel(&base, &owner_token, "bot-voice-ok").await;

    let bot = Identity::generate();
    let bot_token = invite_and_auth_bot(&base, &owner_token, &bot, &["can_speak_voice"]).await;

    let (_tx, mut rx) = connect_voice_ws(&base, &bot_token, &ch.id).await;

    let msg = tokio::time::timeout(std::time::Duration::from_secs(3), rx.next())
        .await
        .expect("expected a voice_ws_ready frame before timeout")
        .expect("stream ended without a frame")
        .expect("websocket error");
    let TsMessage::Text(t) = msg else {
        panic!("expected a text frame, got {msg:?}");
    };
    let v: Value = serde_json::from_str(&t).unwrap();
    assert_eq!(v["type"], "voice_ws_ready");

    let client = reqwest::Client::new();
    let roster: std::collections::HashMap<String, Vec<Value>> = client
        .get(format!("{base}/voice/participants"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let members = roster
        .get(&ch.id)
        .expect("bot's channel should have a voice roster entry");
    assert!(
        members
            .iter()
            .any(|m| m["public_key"] == bot.public_key_hex()),
        "capable bot should appear in the voice roster"
    );
}

/// A bot session WITHOUT `can_speak_voice` is refused registration: no
/// `voice_ws_ready` frame, and it never appears in the voice roster.
#[tokio::test]
async fn bot_without_can_speak_voice_capability_is_rejected() {
    let (base, _state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let ch = create_channel(&base, &owner_token, "bot-voice-denied").await;

    let bot = Identity::generate();
    // No capabilities at all.
    let bot_token = invite_and_auth_bot(&base, &owner_token, &bot, &[]).await;

    let (_tx, mut rx) = connect_voice_ws(&base, &bot_token, &ch.id).await;

    // The gate makes the server task return without ever sending a frame,
    // so the connection closes (or the stream ends) instead of yielding a
    // voice_ws_ready message.
    // Close frame, stream end, or a transport error are all acceptable
    // "rejected" outcomes -- the important thing is no ready frame.
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(2), rx.next()).await;
    if let Ok(Some(Ok(TsMessage::Text(t)))) = outcome {
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_ne!(
            v["type"], "voice_ws_ready",
            "uncapable bot must not be registered as a voice sender"
        );
    }

    let client = reqwest::Client::new();
    let roster: std::collections::HashMap<String, Vec<Value>> = client
        .get(format!("{base}/voice/participants"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !roster
            .get(&ch.id)
            .map(|m| m.iter().any(|p| p["public_key"] == bot.public_key_hex()))
            .unwrap_or(false),
        "uncapable bot must not appear in the voice roster"
    );
}
