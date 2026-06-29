//! Tests for H2 (presence refcount) and H3 (bot_sessions per-session).
//!
//! H2: `online_users` is now a refcount map (`HashMap<String, usize>`).
//!     A second session's connect increments the count; the first disconnect
//!     decrements it but must not remove the key until the count reaches zero.
//!
//! H3: `bot_sessions` is now nested: `HashMap<pubkey, HashMap<session_id, Sender>>`.
//!     A newer bot WS session no longer overwrites the older sender; the first
//!     disconnect removes only its own entry, leaving the surviving session intact.

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::StreamExt;
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, RwLock};
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

// ---------------------------------------------------------------------------
// Shared harness
// ---------------------------------------------------------------------------

#[path = "common.rs"]
mod common;

async fn start_hub() -> (String, Arc<AppState>) {
    let db = crate::common::create_test_db().await;
    let store: Arc<dyn store::HubStore> = Arc::new(store::PostgresStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "presence-test".to_string(),
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
        bot_sessions: RwLock::new(std::collections::HashMap::new()),
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

async fn authenticate(base: &str, identity: &Identity) -> String {
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

    let sig = identity.sign(&hex::decode(&resp.challenge).unwrap());

    let verify: VerifyResponse = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": resp.challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    verify.token
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Connect and return the unsplit stream so we can properly close() it.
/// Consumes the initial `hello` frame.
async fn connect_ws(base: &str, token: &str) -> WsStream {
    let ws_url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    // Consume the `hello` frame.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(3), ws.next())
        .await
        .expect("timed out waiting for hello");
    ws
}

/// Send a WS close frame and then drop the stream so the server sees a clean close.
async fn close_ws(mut ws: WsStream) {
    let _ = ws.close(None).await;
    // Give the underlying OS socket a chance to deliver the FIN.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    drop(ws);
}

// ---------------------------------------------------------------------------
// H2 — presence refcount: two sessions, close one, user still online
// ---------------------------------------------------------------------------

/// Two concurrent WS sessions for the same identity.  After the first
/// session disconnects, the user must still appear online (refcount > 0).
/// Only after the second session closes should the user go offline.
#[tokio::test]
async fn h2_presence_refcount_two_sessions() {
    let (base, state) = start_hub().await;
    let identity = Identity::generate();
    let pk = identity.public_key_hex();

    // Two tokens for the same identity (simulates two devices / reconnect overlap).
    let token_a = authenticate(&base, &identity).await;
    let token_b = authenticate(&base, &identity).await;

    // Open session A.
    let ws_a = connect_ws(&base, &token_a).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert!(
        state.online_users.read().await.contains_key(&pk),
        "user should be online after session A connects"
    );
    assert_eq!(
        *state.online_users.read().await.get(&pk).unwrap(),
        1,
        "refcount should be 1 with one session"
    );

    // Open session B for the same identity.
    let ws_b = connect_ws(&base, &token_b).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    assert_eq!(
        *state.online_users.read().await.get(&pk).unwrap(),
        2,
        "refcount should be 2 with two sessions"
    );

    // Close session A cleanly.
    close_ws(ws_a).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    assert!(
        state.online_users.read().await.contains_key(&pk),
        "user should still be online after session A disconnects (session B is alive)"
    );
    assert_eq!(
        *state.online_users.read().await.get(&pk).unwrap(),
        1,
        "refcount should be back to 1 after session A closes"
    );

    // Close session B.
    close_ws(ws_b).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    assert!(
        !state.online_users.read().await.contains_key(&pk),
        "user should be offline after both sessions disconnect"
    );
}

// ---------------------------------------------------------------------------
// H2 — members endpoint reflects correct online status
// ---------------------------------------------------------------------------

/// GET /users returns the user as online while at least one session is live,
/// and offline once all sessions close.
#[tokio::test]
async fn h2_users_endpoint_reflects_refcount() {
    let (base, _state) = start_hub().await;
    let identity = Identity::generate();
    let pk = identity.public_key_hex();

    let token_a = authenticate(&base, &identity).await;
    let token_b = authenticate(&base, &identity).await;

    let client = reqwest::Client::new();

    // Before connecting: offline.
    let users: Vec<Value> = client
        .get(format!("{base}/users"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = users.iter().find(|u| u["public_key"] == pk).unwrap();
    assert_eq!(entry["online"], false, "should be offline before any WS");

    // Session A connects.
    let ws_a = connect_ws(&base, &token_a).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Session B connects.
    let ws_b = connect_ws(&base, &token_b).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let users: Vec<Value> = client
        .get(format!("{base}/users"))
        .bearer_auth(&token_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = users.iter().find(|u| u["public_key"] == pk).unwrap();
    assert_eq!(entry["online"], true, "should be online with two sessions");

    // Close session A cleanly.
    close_ws(ws_a).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let users: Vec<Value> = client
        .get(format!("{base}/users"))
        .bearer_auth(&token_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = users.iter().find(|u| u["public_key"] == pk).unwrap();
    assert_eq!(
        entry["online"], true,
        "should still be online after session A closes (session B alive)"
    );

    // Close session B.
    close_ws(ws_b).await;
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    let token_c = authenticate(&base, &identity).await;
    let users: Vec<Value> = client
        .get(format!("{base}/users"))
        .bearer_auth(&token_c)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let entry = users.iter().find(|u| u["public_key"] == pk).unwrap();
    assert_eq!(
        entry["online"], false,
        "should be offline after both sessions close"
    );
}

// ---------------------------------------------------------------------------
// H3 — bot_sessions per-session discriminator
// ---------------------------------------------------------------------------

/// Simulate two concurrent bot WS sessions via direct state manipulation.
/// When the "first" session is dropped (its entry removed), the second
/// session's sender must still be present and functional.
#[tokio::test]
async fn h3_bot_sessions_second_session_survives_first_disconnect() {
    let (base, state) = start_hub().await;
    let _ = base; // not needed for this state-level test

    let pk = "aabbccdd".repeat(8); // fake pubkey, 64 hex chars

    let session_a = "session-a-uuid".to_string();
    let session_b = "session-b-uuid".to_string();

    let (tx_a, mut rx_a) = mpsc::channel::<String>(8);
    let (tx_b, mut rx_b) = mpsc::channel::<String>(8);

    // Register both sessions under the same pubkey.
    {
        let mut sessions = state.bot_sessions.write().await;
        let per_bot = sessions.entry(pk.clone()).or_default();
        per_bot.insert(session_a.clone(), tx_a);
        per_bot.insert(session_b.clone(), tx_b);
    }

    assert_eq!(
        state
            .bot_sessions
            .read()
            .await
            .get(&pk)
            .map(|m| m.len())
            .unwrap_or(0),
        2,
        "both sessions should be registered"
    );

    // Simulate session A disconnecting: remove only session A's entry.
    {
        let mut sessions = state.bot_sessions.write().await;
        if let Some(per_bot) = sessions.get_mut(&pk) {
            per_bot.remove(&session_a);
            if per_bot.is_empty() {
                sessions.remove(&pk);
            }
        }
    }

    // Session B's sender must still be alive.
    assert!(
        state.bot_sessions.read().await.contains_key(&pk),
        "pubkey entry should still exist after session A disconnects"
    );
    assert_eq!(
        state
            .bot_sessions
            .read()
            .await
            .get(&pk)
            .map(|m| m.len())
            .unwrap_or(0),
        1,
        "only session B should remain"
    );

    // Push a message through the surviving session's sender.
    {
        let sessions = state.bot_sessions.read().await;
        let per_bot = sessions.get(&pk).unwrap();
        let tx = per_bot.get(&session_b).unwrap();
        tx.try_send("test-push".to_string()).unwrap();
    }

    let msg = rx_b
        .try_recv()
        .expect("session B should still receive messages");
    assert_eq!(msg, "test-push");

    // session A's channel is gone (dropped) so it gets nothing.
    assert!(
        rx_a.try_recv().is_err(),
        "session A should not receive anything after disconnect"
    );
}

/// publish_hub_event delivers to all active sessions for a bot, not just one.
#[tokio::test]
async fn h3_publish_hub_event_reaches_all_sessions() {
    let (base, state) = start_hub().await;
    let _ = base;

    // Insert a real bot user row (publish_hub_event queries the DB for
    // subscriptions, so we need valid bot_subscriptions rows).
    let pk = Identity::generate().public_key_hex();
    let now = wavvon_hub::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO users (public_key, display_name, is_bot, first_seen_at, last_seen_at)
         VALUES ($1, 'testbot', TRUE, $2, $3)",
    )
    .bind(&pk)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    // Subscribe to message.created hub-wide.
    sqlx::query(
        "INSERT INTO bot_subscriptions (bot_pubkey, event_type, channel_id)
         VALUES ($1, 'message.created', '')",
    )
    .bind(&pk)
    .execute(&state.db)
    .await
    .unwrap();

    // Ensure the audit sequence row exists (migrations create it; guard
    // for any test harness that skips the normal migration path).
    let _ = sqlx::query("INSERT INTO hub_audit_seq (id, seq) VALUES (1, 0)")
        .execute(&state.db)
        .await;

    let session_a = "sess-a".to_string();
    let session_b = "sess-b".to_string();

    let (tx_a, mut rx_a) = mpsc::channel::<String>(8);
    let (tx_b, mut rx_b) = mpsc::channel::<String>(8);

    {
        let mut sessions = state.bot_sessions.write().await;
        let per_bot = sessions.entry(pk.clone()).or_default();
        per_bot.insert(session_a.clone(), tx_a);
        per_bot.insert(session_b.clone(), tx_b);
    }

    // Publish an event — should be delivered to both sessions.
    wavvon_hub::bots::events::publish_hub_event(
        &state,
        "message.created",
        Some(&pk),
        None,
        None,
        json!({ "content": "hello" }),
    )
    .await;

    let msg_a = rx_a.try_recv().expect("session A should receive the event");
    let msg_b = rx_b.try_recv().expect("session B should receive the event");

    let va: Value = serde_json::from_str(&msg_a).unwrap();
    let vb: Value = serde_json::from_str(&msg_b).unwrap();
    assert_eq!(va["type"], "hub_event");
    assert_eq!(vb["type"], "hub_event");
}
