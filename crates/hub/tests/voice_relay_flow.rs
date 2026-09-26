//! Voice join/leave lifecycle over the main hub WS (voice-transport-v2.md).
//!
//! The actual audio relay (WebTransport datagrams, cert-hash trust, token
//! rejection) is covered by `voice_wt_flow.rs`; this file exercises the
//! WS-side bookkeeping that transport sits on top of: `voice_relay_active`
//! lifecycle, roster membership, and the invisible-presence gate on voice
//! surfaces.
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
        app_sessions: RwLock::new(HashMap::new()),
        http_client: reqwest::Client::new(),
        farm_url: None,
        cached_farm_pubkey: Arc::new(RwLock::new(None)),
        last_farm_pubkey_fetch: Arc::new(RwLock::new(0)),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_target_defs: RwLock::new(HashMap::new()),
        whisper_optouts: RwLock::new(std::collections::HashSet::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        voice_outbound_loss: RwLock::new(HashMap::new()),
        staging_voice_grants: RwLock::new(std::collections::HashMap::new()),
        voice_talk_blocked: Default::default(),
        voice_pending_binds: RwLock::new(HashMap::new()),
        ws_key_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(HashMap::new()),
        search: Arc::new(wavvon_hub::search::null_search::NullSearch),
        reindex_running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
        apps_allow_camera: false,
        http_video_stream_budget: 2,
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
    tx.send(TsMessage::Text(msg.to_string())).await.unwrap();
}

// ---------------------------------------------------------------------------
// Unit-style helpers that operate directly on AppState.
// ---------------------------------------------------------------------------

/// Simulate a voice_join: insert the pubkey with no bound WT session into
/// voice_channels and mark the relay slot active (mirrors the WS handler
/// before the client's WebTransport session connects).
async fn sim_join(state: &AppState, pubkey: &str, channel_id: &str) {
    state
        .voice_channels
        .write()
        .await
        .entry(channel_id.to_string())
        .or_default()
        .insert(pubkey.to_string(), None);
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
    let (_base, state, _guard) = start_hub().await;
    let pk = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
    sim_join(&state, pk, "ch1").await;

    let active = state.voice_relay_active.read().await;
    assert!(
        active.contains(pk),
        "relay slot should be active after voice_join"
    );
}

/// After WS disconnect (simulated via leave_voice) the slot and the
/// voice_channels roster entry are both removed.
#[tokio::test]
async fn ws_disconnect_removes_relay_slot() {
    let (_base, state, _guard) = start_hub().await;
    let pk = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";
    let channel_id = "ch-test";

    sim_join(&state, pk, channel_id).await;
    state
        .voice_sender_ids
        .write()
        .await
        .entry(channel_id.to_string())
        .or_default()
        .insert(pk.to_string(), 0u16);

    assert!(state.voice_relay_active.read().await.contains(pk));
    assert!(state
        .voice_channels
        .read()
        .await
        .get(channel_id)
        .is_some_and(|p| p.contains_key(pk)));

    // Simulate WS disconnect by calling leave_voice.
    wavvon_hub::routes::ws::leave_voice_for_test(&state, pk, channel_id).await;

    assert!(
        !state.voice_relay_active.read().await.contains(pk),
        "relay slot should be removed after leave_voice"
    );
    assert!(
        !state
            .voice_channels
            .read()
            .await
            .get(channel_id)
            .is_some_and(|p| p.contains_key(pk)),
        "voice_channels entry should be removed after leave_voice"
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
    state
        .voice_sender_ids
        .write()
        .await
        .entry(ch.to_string())
        .or_default()
        .insert(pk.to_string(), 0u16);
    wavvon_hub::routes::ws::leave_voice_for_test(&state, pk, ch).await;
    assert!(!state.voice_relay_active.read().await.contains(pk));

    // Re-join.
    sim_join(&state, pk, ch).await;
    assert!(
        state.voice_relay_active.read().await.contains(pk),
        "re-joined pubkey should have relay slot"
    );
}

/// Helper: drain WS frames until voice_joined arrives; return the voice_token.
async fn drain_until_voice_joined(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> String {
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(15), rx.next())
            .await
            .expect("voice_joined timeout")
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == "voice_joined" {
                let tok = v["voice_token"]
                    .as_str()
                    .expect("voice_joined must carry voice_token")
                    .to_string();
                assert_eq!(tok.len(), 64, "token must be 64 hex chars (32 bytes)");
                assert!(
                    tok.chars().all(|c| c.is_ascii_hexdigit()),
                    "token must be hex"
                );
                assert!(
                    v["voice_wt_url"].as_str().unwrap().starts_with("https://"),
                    "voice_joined must carry an absolute https voice_wt_url"
                );
                return tok;
            }
        }
    }
}

/// End-to-end: user joins voice over WS and the relay slot appears; voice_joined
/// reply carries a voice_token; after explicit voice_leave the slot is gone.
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

    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": _ch.id }),
    )
    .await;
    let _voice_token = drain_until_voice_joined(&mut rx).await;

    let pk = user.public_key_hex();
    assert!(
        state.voice_relay_active.read().await.contains(&pk),
        "voice_relay_active should contain pubkey after voice_join"
    );

    send_ws(
        &mut tx,
        json!({ "type": "voice_leave", "channel_id": _ch.id }),
    )
    .await;

    tokio::time::sleep(std::time::Duration::from_millis(60)).await;

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

    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": ch.id }),
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

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert!(
        !state.voice_relay_active.read().await.contains(&pk),
        "relay slot should be removed when WS closes without voice_leave"
    );
}

/// Invisible presence gate on the voice surfaces (decisions.md 2026-07-12's
/// flagged known gap): an invisible member who joins voice must be hidden
/// from other members' `/voice/participants`, `/voice/active-users`, and
/// `/voice/populations` — while staying fully registered in voice
/// (functional, just not shown) and still seeing their own entry.
#[tokio::test]
async fn invisible_user_hidden_from_others_voice_participant_lists() {
    let (base, state, _guard) = start_hub().await;
    let owner = Identity::generate();
    let owner_token = authenticate_http(&base, &owner).await;
    let ch = create_channel(&base, &owner_token, "invisible-voice").await;

    let ghost = Identity::generate();
    let ghost_token = authenticate_http(&base, &ghost).await;
    // The gate reads users.presence_status (same column handle_set_status
    // persists — the WS set_status path is covered by
    // presence_multi_session_flow.rs); set it directly.
    sqlx::query("UPDATE users SET presence_status = 'invisible' WHERE public_key = $1")
        .bind(ghost.public_key_hex())
        .execute(&state.db)
        .await
        .unwrap();

    let (mut tx, mut rx) = connect_ws(&base, &ghost_token).await;
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
    send_ws(
        &mut tx,
        json!({ "type": "voice_join", "channel_id": ch.id }),
    )
    .await;

    // Invisible users stay functional in voice: the join succeeds and the
    // reply's participant list still shows the joiner their own entry
    // (viewer self-exemption).
    let v = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            let msg = rx.next().await.unwrap().unwrap();
            if let TsMessage::Text(t) = msg {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["type"] == "voice_joined" {
                    return v;
                }
            }
        }
    })
    .await
    .expect("expected voice_joined before timeout");
    assert!(
        v["participants"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["public_key"] == ghost.public_key_hex()),
        "invisible joiner must still see their own entry in the join reply"
    );
    assert!(
        state
            .voice_channels
            .read()
            .await
            .get(&ch.id)
            .map(|m| m.contains_key(&ghost.public_key_hex()))
            .unwrap_or(false),
        "invisible joiner must remain registered in voice_channels (functional)"
    );

    let client = reqwest::Client::new();

    // Another member's view: the ghost is absent from every voice surface.
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
            .map(|m| m.iter().any(|p| p["public_key"] == ghost.public_key_hex()))
            .unwrap_or(false),
        "invisible user must not appear in another member's /voice/participants"
    );

    let active: Vec<String> = client
        .get(format!("{base}/voice/active-users"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !active.contains(&ghost.public_key_hex()),
        "invisible user must not appear in another member's /voice/active-users"
    );

    let populations: std::collections::HashMap<String, usize> = client
        .get(format!("{base}/voice/populations"))
        .bearer_auth(&owner_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        !populations.contains_key(&ch.id),
        "a channel occupied only by an invisible user must count as empty to others"
    );

    // The invisible user's own view: self-exempt from the gate.
    let own_roster: std::collections::HashMap<String, Vec<Value>> = client
        .get(format!("{base}/voice/participants"))
        .bearer_auth(&ghost_token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        own_roster
            .get(&ch.id)
            .map(|m| m.iter().any(|p| p["public_key"] == ghost.public_key_hex()))
            .unwrap_or(false),
        "invisible user must still see their own entry in /voice/participants"
    );
}

/// Two clients on the SAME identity (the multi-device case) each join a
/// different voice channel. `voice_channels` is keyed by pubkey, so before the
/// fix both entries survived and the user showed up in two rooms of the same
/// hub at once. Latest join wins.
#[tokio::test]
async fn second_device_join_evicts_the_first_channel() {
    let (base, state, _guard) = start_hub().await;

    let user = Identity::generate();
    let token = authenticate_http(&base, &user).await;
    let a = create_channel(&base, &token, "room-a").await;
    let b = create_channel(&base, &token, "room-b").await;
    let pk = user.public_key_hex();

    let (mut tx_a, mut rx_a) = connect_ws(&base, &token).await;
    send_ws(
        &mut tx_a,
        json!({ "type": "voice_join", "channel_id": a.id }),
    )
    .await;
    let _ = drain_until_voice_joined(&mut rx_a).await;

    let (mut tx_b, mut rx_b) = connect_ws(&base, &token).await;
    send_ws(
        &mut tx_b,
        json!({ "type": "voice_join", "channel_id": b.id }),
    )
    .await;
    let _ = drain_until_voice_joined(&mut rx_b).await;

    let rooms: Vec<String> = {
        let vc = state.voice_channels.read().await;
        vc.iter()
            .filter(|(_, participants)| participants.contains_key(&pk))
            .map(|(ch, _)| ch.clone())
            .collect()
    };
    assert_eq!(
        rooms,
        vec![b.id.clone()],
        "one identity must occupy exactly the last-joined voice channel"
    );

    let _ = tx_a.send(TsMessage::Close(None)).await;
    let _ = tx_b.send(TsMessage::Close(None)).await;
}

// ---------------------------------------------------------------------------
// Outbound packet loss reported on `pong` (voice_loss.rs)
// ---------------------------------------------------------------------------

/// Reads frames until a `pong` arrives, and returns it.
async fn wait_for_pong(
    rx: &mut futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
) -> Value {
    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), rx.next())
            .await
            .expect("pong timeout")
            .unwrap()
            .unwrap();
        if let TsMessage::Text(t) = msg {
            let v: Value = serde_json::from_str(&t).unwrap();
            if v["type"] == "pong" {
                return v;
            }
        }
    }
}

/// Not in voice, or in voice and having sent almost nothing, means there is no
/// figure to give — and the field must then be **absent**, not zero.
///
/// This is the whole reason the field is optional. The client cannot tell
/// "this hub does not measure outbound loss" from "your outbound loss is 0.0%"
/// if the hub answers 0.0 either way, and a reassuring zero on a hub that
/// measures nothing is worse than an em dash.
#[tokio::test]
async fn pong_omits_outbound_loss_when_there_is_nothing_to_report() {
    let (base, _state, _guard) = start_hub().await;
    let id = Identity::generate();
    let token = authenticate_http(&base, &id).await;
    let (mut tx, mut rx) = connect_ws(&base, &token).await;

    send_ws(&mut tx, json!({ "type": "ping", "nonce": 1234 })).await;
    let pong = wait_for_pong(&mut rx).await;

    assert_eq!(pong["nonce"], 1234, "the nonce must come back untouched");
    assert!(
        pong.get("outbound_loss_pct").is_none(),
        "no voice traffic means no loss figure, not a zero: {pong}"
    );

    let _ = tx.send(TsMessage::Close(None)).await;
}

/// The relay's counter-gap measurement reaches the sender that it is about,
/// on the probe the client is already sending every two seconds.
#[tokio::test]
async fn pong_carries_the_outbound_loss_the_relay_measured() {
    let (base, state, _guard) = start_hub().await;
    let id = Identity::generate();
    let pk = id.public_key_hex();
    let token = authenticate_http(&base, &id).await;
    let (mut tx, mut rx) = connect_ws(&base, &token).await;

    // What the relay would have accumulated after a span of 100 counters with
    // 10 of them missing. Injected rather than driven through a real
    // WebTransport session: the arithmetic has its own unit tests, and what is
    // untested is whether the number reaches this socket at all.
    {
        let mut losses = state.voice_outbound_loss.write().await;
        losses.insert(
            pk.clone(),
            wavvon_hub::voice_loss::SenderLoss {
                first_ctr: 0,
                highest_ctr: 99,
                received: 90,
            },
        );
    }

    send_ws(&mut tx, json!({ "type": "ping", "nonce": 99 })).await;
    let pong = wait_for_pong(&mut rx).await;

    assert_eq!(
        pong["outbound_loss_pct"].as_f64(),
        Some(10.0),
        "the relay saw 10 of 100 counters missing: {pong}"
    );

    let _ = tx.send(TsMessage::Close(None)).await;
}

/// Another participant's uplink is nobody else's business: the figure is keyed
/// by pubkey and only ever answers the socket it belongs to.
#[tokio::test]
async fn one_participants_outbound_loss_is_not_reported_to_another() {
    let (base, state, _guard) = start_hub().await;
    let noisy = Identity::generate();
    let quiet = Identity::generate();
    let quiet_token = authenticate_http(&base, &quiet).await;

    {
        let mut losses = state.voice_outbound_loss.write().await;
        losses.insert(
            noisy.public_key_hex(),
            wavvon_hub::voice_loss::SenderLoss {
                first_ctr: 0,
                highest_ctr: 99,
                received: 50,
            },
        );
    }

    let (mut tx, mut rx) = connect_ws(&base, &quiet_token).await;
    send_ws(&mut tx, json!({ "type": "ping", "nonce": 7 })).await;
    let pong = wait_for_pong(&mut rx).await;

    assert!(
        pong.get("outbound_loss_pct").is_none(),
        "a socket must only ever hear about its own uplink: {pong}"
    );

    let _ = tx.send(TsMessage::Close(None)).await;
}
