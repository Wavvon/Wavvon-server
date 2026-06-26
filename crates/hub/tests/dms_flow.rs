use std::collections::HashMap;
use std::sync::Arc;

use axum_test::TestServer;
use serde_json::json;
use sqlx::AnyPool;
use tokio::sync::{broadcast, RwLock};
use voxply_hub::auth::models::{ChallengeResponse, VerifyResponse};
use voxply_hub::db;
use voxply_hub::federation::client::FederationClient;
use voxply_hub::routes::dm_models::ConversationResponse;
use voxply_hub::server;
use voxply_hub::state::AppState;
use voxply_identity::Identity;

#[path = "common.rs"]
mod common;

/// Same as common::setup() but also returns the AnyPool so tests can poke the
/// database directly (e.g. to mark a dm_outbox row as bounced for a test
/// that exercises the delivery_failed reporting path).
async fn setup_with_pool() -> (TestServer, AnyPool) {
    sqlx::any::install_default_drivers();
    let db = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&db).await.unwrap();
    let pool_handle = db.clone();
    let store: Arc<dyn voxply_store::HubStore> =
        Arc::new(voxply_store_sqlite::SqliteStore::new(db.clone()));
    let (chat_tx, _) = broadcast::channel(256);
    let (voice_event_tx, _) = broadcast::channel(16);

    let state = Arc::new(AppState {
        hub_name: "test-hub".to_string(),
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
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(voxply_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
    });
    let app = server::create_router(state);
    (TestServer::new(app), pool_handle)
}

#[tokio::test]
async fn create_dm_conversation() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();
    assert_eq!(conv.conv_type, "dm");
    assert_eq!(conv.members.len(), 2);
}

#[tokio::test]
async fn dm_conversation_dedup() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    // First DM creation
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    let conv1: ConversationResponse = resp.json();

    // Second creation between same two users — should reuse
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    let conv2: ConversationResponse = resp.json();

    assert_eq!(
        conv1.id, conv2.id,
        "DM should be deduped between same users"
    );
}

#[tokio::test]
async fn create_group_dm() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let charlie = Identity::generate();
    common::authenticate(&server, &bob).await;
    common::authenticate(&server, &charlie).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex(), charlie.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();
    assert_eq!(conv.conv_type, "group");
    assert_eq!(conv.members.len(), 3);
}

#[tokio::test]
async fn list_my_conversations() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;

    let resp = server
        .get("/conversations")
        .authorization_bearer(&alice_token)
        .await;
    resp.assert_status_ok();
    let conversations: Vec<ConversationResponse> = resp.json();
    assert_eq!(conversations.len(), 1);
}

#[tokio::test]
async fn cannot_send_to_conversation_youre_not_in() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    let bob_token = common::authenticate(&server, &bob).await;
    let charlie = Identity::generate();
    let charlie_token = common::authenticate(&server, &charlie).await;

    // Alice + Bob create a DM
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    let conv: ConversationResponse = resp.json();

    // Alice can send
    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "content": "hi bob" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Bob can send
    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&bob_token)
        .json(&json!({ "content": "hi alice" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Charlie cannot
    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&charlie_token)
        .json(&json!({ "content": "intruder!" }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn cannot_create_empty_conversation() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [] }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

// --- Cross-hub federated DM tests ---

async fn start_real_hub(name: &str) -> String {
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
        hub_name: name.to_string(),
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
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(voxply_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
    });
    let app = server::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    url
}

async fn authenticate_http(hub_url: &str, identity: &Identity) -> String {
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

    let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
    let signature = identity.sign(&challenge_bytes);

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

/// Build a valid `plaintext_signature` for a plaintext DM.
///
/// The canonical form mirrors `voxply_identity::federated_plaintext_dm_signing_bytes`:
/// domain tag + len-prefixed(conversation_id) + len-prefixed(conv_type) + len-prefixed(content).
/// `conv_type` is always `"dm"` for 1:1 conversations and `"group"` for group ones;
/// tests that only deal with 1:1 DMs can pass `"dm"` directly.
fn make_plaintext_sig(
    sender: &Identity,
    conversation_id: &str,
    conv_type: &str,
    content: &str,
) -> String {
    let bytes =
        voxply_identity::federated_plaintext_dm_signing_bytes(conversation_id, conv_type, content);
    hex::encode(sender.sign(&bytes).to_bytes())
}

/// Return the AppState together with the URL so tests can drive the worker manually.
async fn start_real_hub_with_state(name: &str) -> (String, Arc<AppState>) {
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
        hub_name: name.to_string(),
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
        cached_farm_pubkey: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        last_farm_pubkey_fetch: std::sync::Arc::new(tokio::sync::RwLock::new(0)),
        video_channels: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_targets: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        whisper_target_defs: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_relay_active: tokio::sync::RwLock::new(std::collections::HashSet::new()),
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(voxply_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
    });
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    (url, state)
}

#[tokio::test]
async fn dm_delivered_across_hubs() {
    let hub_a = start_real_hub("hub-a").await;
    let hub_b = start_real_hub("hub-b").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;
    let bob_token = authenticate_http(&hub_b, &bob).await;

    // Alice creates a conversation on Hub A that includes Bob, routing to Hub B.
    let mut member_hubs = HashMap::new();
    member_hubs.insert(bob.public_key_hex(), hub_b.clone());
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": member_hubs,
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "Create conversation failed: {status} {body_text}",
    );
    let conv: ConversationResponse = serde_json::from_str(&body_text).unwrap();

    // Alice sends a DM. Hub A persists it locally and federates to Hub B.
    let content = "hi bob, from across hubs";
    let sig = make_plaintext_sig(&alice, &conv.id, &conv.conv_type, content);
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": content, "plaintext_signature": sig }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // Give the async federation request time to land.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Bob reads the thread from Hub B — message should have been federated there.
    let resp = client
        .get(format!("{hub_b}/conversations/{}/messages", conv.id))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Hub B list endpoint failed: {}",
        resp.status()
    );
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().expect("expected an array");
    assert_eq!(arr.len(), 1, "Bob should see the federated DM");
    assert_eq!(arr[0]["content"], content);
    assert_eq!(arr[0]["sender"], alice.public_key_hex());
}

#[tokio::test]
async fn dm_retries_when_recipient_hub_comes_online() {
    use voxply_hub::dm_worker;

    // Hub A is up from the start.
    let (hub_a, hub_a_state) = start_real_hub_with_state("hub-a").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;

    // Pick an address that definitely is not serving anything yet.
    let dead_port = {
        let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = tmp.local_addr().unwrap().port();
        drop(tmp);
        p
    };
    let hub_b_url_planned = format!("http://127.0.0.1:{dead_port}");

    // Alice creates a conversation pointing at Hub B's (currently dead) URL.
    let mut member_hubs = HashMap::new();
    member_hubs.insert(bob.public_key_hex(), hub_b_url_planned.clone());
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": member_hubs,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let conv: ConversationResponse = resp.json().await.unwrap();

    // Send while Hub B is down. POST still succeeds (Hub A accepts and queues).
    let retry_content = "hi from retry land";
    let retry_sig = make_plaintext_sig(&alice, &conv.id, &conv.conv_type, retry_content);
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": retry_content, "plaintext_signature": retry_sig }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    // Confirm the message is parked in the outbox.
    let queued: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dm_outbox")
        .fetch_one(&hub_a_state.db)
        .await
        .unwrap();
    assert_eq!(
        queued, 1,
        "message should be queued while recipient is offline"
    );

    // Bring Hub B up on the previously-chosen port.
    sqlx::any::install_default_drivers();
    let hub_b_db = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    db::migrations::run(&hub_b_db).await.unwrap();
    let hub_b_store: Arc<dyn voxply_store::HubStore> =
        Arc::new(voxply_store_sqlite::SqliteStore::new(hub_b_db.clone()));
    let (chat_tx_b, _) = broadcast::channel(256);
    let (voice_event_tx_b, _) = broadcast::channel(16);
    let hub_b_state = Arc::new(AppState {
        hub_name: "hub-b".to_string(),
        hub_identity: Identity::generate(),
        db: hub_b_db,
        db_read: None,
        store: hub_b_store,
        pending_challenges: RwLock::new(HashMap::new()),
        chat_tx: chat_tx_b,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        voice_channels: RwLock::new(HashMap::new()),
        voice_addr_map: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        voice_udp_port: 0,
        voice_event_tx: voice_event_tx_b,
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
        voice_pending_binds: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_consumed_tokens: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_ws_senders: tokio::sync::RwLock::new(std::collections::HashMap::new()),
        voice_udp_socket: std::sync::Arc::new(tokio::sync::RwLock::new(None)),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search: std::sync::Arc::new(voxply_hub::search::null_search::NullSearch),
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: None,
    });
    let app_b = server::create_router(hub_b_state.clone());
    let listener_b = tokio::net::TcpListener::bind(format!("127.0.0.1:{dead_port}"))
        .await
        .expect("Hub B should be able to claim the chosen port");
    tokio::spawn(async move {
        axum::serve(
            listener_b,
            app_b.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });

    // Force next_attempt_at to now so the worker picks the row up immediately.
    sqlx::query("UPDATE dm_outbox SET next_attempt_at = 0")
        .execute(&hub_a_state.db)
        .await
        .unwrap();

    // Run one worker pass.
    dm_worker::tick(&hub_a_state).await.unwrap();

    // Outbox should be empty now.
    let queued_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dm_outbox")
        .fetch_one(&hub_a_state.db)
        .await
        .unwrap();
    assert_eq!(
        queued_after, 0,
        "worker should have delivered and cleared the outbox"
    );

    // Hub B should have stored the message.
    let bob_token = authenticate_http(&format!("http://127.0.0.1:{dead_port}"), &bob).await;
    let resp = client
        .get(format!(
            "http://127.0.0.1:{dead_port}/conversations/{}/messages",
            conv.id
        ))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["content"], retry_content);
}

#[tokio::test]
async fn list_dm_messages_marks_bounced_as_delivery_failed() {
    let (server, pool) = setup_with_pool().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();

    // Alice creates a DM to Bob with a remote hub URL — Bob isn't on this
    // hub, so the conversation needs hub_url for him.
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": { bob.public_key_hex(): "http://unreachable.example" },
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Send a message. The send_dm path will try to deliver synchronously,
    // fail (unreachable URL), and leave the row in the outbox at attempts=1.
    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "content": "this won't make it" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Pretend the worker exhausted retries — mark the outbox row bounced.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query("UPDATE dm_outbox SET bounced_at = ? WHERE recipient_hub_url = ?")
        .bind(now)
        .bind("http://unreachable.example")
        .execute(&pool)
        .await
        .unwrap();

    // List the conversation — the message should be marked delivery_failed=true.
    let resp = server
        .get(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .await;
    resp.assert_status_ok();
    let messages = resp.json::<serde_json::Value>();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0]["delivery_failed"], true,
        "bounced outbox row should surface as delivery_failed on the message"
    );
}

#[tokio::test]
async fn list_dm_messages_returns_delivery_failed_false_for_local_conversation() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    let bob = Identity::generate();
    common::authenticate(&server, &bob).await;

    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    let conv: ConversationResponse = resp.json();

    server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "content": "hi" }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server
        .get(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .await;
    let messages = resp.json::<serde_json::Value>();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["delivery_failed"], false);
}

// ---------------------------------------------------------------------------
// Phase 5: home-hub designation routing
// ---------------------------------------------------------------------------

/// When a recipient has a home_hub_designations row, send_dm should route via
/// each URL in hubs_json instead of conversation_members.hub_url.
#[tokio::test]
async fn send_dm_uses_home_hub_designation_when_present() {
    let (hub_a, hub_a_state) = start_real_hub_with_state("hub-a-desig").await;
    let hub_b = start_real_hub("hub-b-desig").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let bob_master = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;
    authenticate_http(&hub_b, &bob).await;

    // Alice creates a conversation on Hub A. She supplies an unreachable
    // placeholder as Bob's hub_url — the designation should override it.
    let placeholder_url = "http://placeholder.invalid";
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": { bob.public_key_hex(): placeholder_url },
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let conv: ConversationResponse = resp.json().await.unwrap();

    // Give Bob a master_pubkey in Hub A's users table.
    let bob_master_hex = bob_master.public_key_hex();
    sqlx::query("UPDATE users SET master_pubkey = ? WHERE public_key = ?")
        .bind(&bob_master_hex)
        .bind(bob.public_key_hex())
        .execute(&hub_a_state.db)
        .await
        .unwrap();

    // Insert a designation row pointing at the real Hub B.
    let hubs_json = serde_json::to_string(&vec![hub_b.clone()]).unwrap();
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sqlx::query(
        "INSERT INTO home_hub_designations
         (master_pubkey, hubs_json, issued_at, sequence, signature, updated_at)
         VALUES (?, ?, ?, 1, 'test', ?)",
    )
    .bind(&bob_master_hex)
    .bind(&hubs_json)
    .bind(now_ts)
    .bind(now_ts)
    .execute(&hub_a_state.db)
    .await
    .unwrap();

    // Alice sends a DM. Hub A should route via the designation to Hub B,
    // ignoring the placeholder hub_url.
    let desig_content = "routed via designation";
    let desig_sig = make_plaintext_sig(&alice, &conv.id, &conv.conv_type, desig_content);
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": desig_content, "plaintext_signature": desig_sig }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Bob reads from Hub B — message should have arrived via the designation.
    let bob_token = authenticate_http(&hub_b, &bob).await;
    let resp = client
        .get(format!("{hub_b}/conversations/{}/messages", conv.id))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().unwrap();
    assert_eq!(
        arr.len(),
        1,
        "message should have been routed to Hub B via designation"
    );
    assert_eq!(arr[0]["content"], desig_content);
}

/// When no home_hub_designations row exists, send_dm falls back to the
/// hub_url from conversation_members (existing behaviour, no regression).
#[tokio::test]
async fn send_dm_falls_back_to_hub_url_when_no_designation() {
    let hub_a = start_real_hub("hub-a-fallback").await;
    let hub_b = start_real_hub("hub-b-fallback").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;
    authenticate_http(&hub_b, &bob).await;

    // No designation row — only hub_url in member_hubs.
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&json!({
            "members": [bob.public_key_hex()],
            "member_hubs": { bob.public_key_hex(): hub_b.clone() },
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let conv: ConversationResponse = resp.json().await.unwrap();

    let fallback_content = "fallback delivery";
    let fallback_sig = make_plaintext_sig(&alice, &conv.id, &conv.conv_type, fallback_content);
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&json!({ "content": fallback_content, "plaintext_signature": fallback_sig }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let bob_token = authenticate_http(&hub_b, &bob).await;
    let resp = client
        .get(format!("{hub_b}/conversations/{}/messages", conv.id))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().unwrap();
    assert_eq!(
        arr.len(),
        1,
        "message should have been delivered via fallback hub_url"
    );
    assert_eq!(arr[0]["content"], fallback_content);
}

// ---------------------------------------------------------------------------
// Group E2E: sender-key distribution and encrypted group messages
// ---------------------------------------------------------------------------

/// Helper: build a deterministic (fake) group envelope signed by the given identity.
fn make_group_envelope(
    sender: &Identity,
    conv_id: &str,
    version: u32,
    iteration: u32,
) -> serde_json::Value {
    let ciphertext_hex = "deadbeef".to_string();
    let nonce_hex = "cafebabe000000000000000000000000".to_string();

    // Canonical signing bytes (mirrors group_envelope_signing_bytes in dms.rs)
    let mut signing_msg = b"voxply/group-dm-ciphertext/v1\0".to_vec();
    for s in [
        conv_id,
        &version.to_string(),
        &iteration.to_string(),
        &ciphertext_hex,
        &nonce_hex,
    ] {
        let b = s.as_bytes();
        signing_msg.extend_from_slice(&(b.len() as u32).to_le_bytes());
        signing_msg.extend_from_slice(b);
    }
    let sig = sender.sign(&signing_msg);

    json!({
        "sender_pubkey": sender.public_key_hex(),
        "conv_id": conv_id,
        "sender_key_version": version,
        "iteration": iteration,
        "ciphertext_hex": ciphertext_hex,
        "nonce_hex": nonce_hex,
        "signature_hex": hex::encode(sig.to_bytes()),
    })
}

/// Helper: build a signed sender-key distribution request.
fn make_push_sender_key_request(
    sender: &Identity,
    conv_id: &str,
    version: u32,
    recipients: &[(&Identity, &str, &str)], // (identity, wrapped_key_hex, wrap_nonce_hex)
) -> serde_json::Value {
    let recipient_blobs: Vec<serde_json::Value> = recipients
        .iter()
        .map(|(id, wk, wn)| {
            json!({
                "recipient_pubkey": id.public_key_hex(),
                "wrapped_key_hex": wk,
                "wrap_nonce_hex": wn,
                "iteration": 0u32,
            })
        })
        .collect();

    // Build canonical signing bytes (mirrors sender_key_dist_signing_bytes in dms.rs)
    let mut sorted: Vec<(&Identity, &str, &str)> = recipients.to_vec();
    sorted.sort_by(|a, b| a.0.public_key_hex().cmp(&b.0.public_key_hex()));

    let mut signing_msg = b"voxply/group-key-dist/v1\0".to_vec();
    for s in [conv_id, &version.to_string()] {
        let b = s.as_bytes();
        signing_msg.extend_from_slice(&(b.len() as u32).to_le_bytes());
        signing_msg.extend_from_slice(b);
    }
    for (id, wk, _wn) in &sorted {
        for s in [&id.public_key_hex(), &wk.to_string()] {
            let b = s.as_bytes();
            signing_msg.extend_from_slice(&(b.len() as u32).to_le_bytes());
            signing_msg.extend_from_slice(b);
        }
    }
    let sig = sender.sign(&signing_msg);

    json!({
        "sender_key_version": version,
        "recipients": recipient_blobs,
        "signature_hex": hex::encode(sig.to_bytes()),
    })
}

#[tokio::test]
async fn push_and_get_sender_keys_happy_path() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let charlie = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    common::authenticate(&server, &bob).await;
    common::authenticate(&server, &charlie).await;

    // Create a group conversation
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex(), charlie.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Alice pushes sender keys for Bob and Charlie
    let req = make_push_sender_key_request(
        &alice,
        &conv.id,
        1,
        &[
            (&bob, "aabbccdd", "112233445566778899aabbccddeeff00"),
            (&charlie, "eeff0011", "aabbccddeeff00112233445566778899"),
        ],
    );
    let resp = server
        .put(&format!("/conversations/{}/sender-keys", conv.id))
        .authorization_bearer(&alice_token)
        .json(&req)
        .await;
    resp.assert_status(axum::http::StatusCode::NO_CONTENT);

    // Bob retrieves his sender-key entry from Alice
    let bob_token = common::authenticate(&server, &bob).await;
    let resp = server
        .get(&format!("/conversations/{}/sender-keys", conv.id))
        .authorization_bearer(&bob_token)
        .await;
    resp.assert_status_ok();
    let entries: serde_json::Value = resp.json();
    let arr = entries.as_array().unwrap();
    assert_eq!(
        arr.len(),
        1,
        "Bob should see exactly one sender-key entry (from Alice)"
    );
    assert_eq!(arr[0]["sender_pubkey"], alice.public_key_hex());
    assert_eq!(arr[0]["sender_key_version"], 1);
    assert_eq!(arr[0]["wrapped_key_hex"], "aabbccdd");
}

#[tokio::test]
async fn push_sender_keys_rejected_for_non_member() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let eve = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    common::authenticate(&server, &bob).await;
    let eve_token = common::authenticate(&server, &eve).await;

    // Alice creates a group with Bob
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Eve (not a member) tries to push sender keys
    let req = make_push_sender_key_request(
        &eve,
        &conv.id,
        1,
        &[(&bob, "aabbccdd", "112233445566778899aabbccddeeff00")],
    );
    let resp = server
        .put(&format!("/conversations/{}/sender-keys", conv.id))
        .authorization_bearer(&eve_token)
        .json(&req)
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn push_sender_keys_rejected_for_dm_conversation() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    common::authenticate(&server, &bob).await;

    // Create a 1:1 DM
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();
    assert_eq!(conv.conv_type, "dm");

    // Sender-key distribution must be rejected for 1:1 DMs
    let req = make_push_sender_key_request(
        &alice,
        &conv.id,
        1,
        &[(&bob, "aabbccdd", "112233445566778899aabbccddeeff00")],
    );
    let resp = server
        .put(&format!("/conversations/{}/sender-keys", conv.id))
        .authorization_bearer(&alice_token)
        .json(&req)
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn send_group_encrypted_dm_happy_path() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let charlie = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    common::authenticate(&server, &bob).await;
    common::authenticate(&server, &charlie).await;

    // Create a group conversation
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex(), charlie.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Alice sends a group-encrypted message
    let envelope = make_group_envelope(&alice, &conv.id, 1, 0);
    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "group_encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let msg: serde_json::Value = resp.json();
    assert!(
        msg["group_encrypted_envelope"].is_object(),
        "response should include group envelope"
    );
    assert!(
        msg["encrypted_envelope"].is_null(),
        "1:1 envelope must be absent"
    );

    // Bob reads the conversation
    let bob_token = common::authenticate(&server, &bob).await;
    let resp = server
        .get(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&bob_token)
        .await;
    resp.assert_status_ok();
    let messages: serde_json::Value = resp.json();
    let arr = messages.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert!(arr[0]["group_encrypted_envelope"].is_object());
    assert_eq!(arr[0]["group_encrypted_envelope"]["sender_key_version"], 1);
    assert_eq!(arr[0]["group_encrypted_envelope"]["iteration"], 0);
}

#[tokio::test]
async fn group_encrypted_dm_rejected_for_dm_conversation() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    common::authenticate(&server, &bob).await;

    // 1:1 DM
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Sending a group-encrypted envelope to a 1:1 DM must be rejected
    let envelope = make_group_envelope(&alice, &conv.id, 1, 0);
    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "group_encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn group_encrypted_dm_rejected_for_invalid_signature() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let charlie = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    common::authenticate(&server, &bob).await;
    common::authenticate(&server, &charlie).await;

    // Create a group conversation
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex(), charlie.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Build an envelope then corrupt the signature
    let mut envelope = make_group_envelope(&alice, &conv.id, 1, 0);
    envelope["signature_hex"] = json!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    let resp = server
        .post(&format!("/conversations/{}/messages", conv.id))
        .authorization_bearer(&alice_token)
        .json(&json!({ "group_encrypted_envelope": envelope }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sender_key_upsert_replaces_old_entry() {
    let server = common::setup().await;
    let alice = Identity::generate();
    let bob = Identity::generate();
    let charlie = Identity::generate();
    let alice_token = common::authenticate(&server, &alice).await;
    common::authenticate(&server, &bob).await;
    common::authenticate(&server, &charlie).await;

    // Create a group conversation
    let resp = server
        .post("/conversations")
        .authorization_bearer(&alice_token)
        .json(&json!({ "members": [bob.public_key_hex(), charlie.public_key_hex()] }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let conv: ConversationResponse = resp.json();

    // Push version 1
    let req1 = make_push_sender_key_request(
        &alice,
        &conv.id,
        1,
        &[(&bob, "aabbccdd", "112233445566778899aabbccddeeff00")],
    );
    server
        .put(&format!("/conversations/{}/sender-keys", conv.id))
        .authorization_bearer(&alice_token)
        .json(&req1)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Push version 1 again with different wrapped key (upsert)
    let req2 = make_push_sender_key_request(
        &alice,
        &conv.id,
        1,
        &[(&bob, "11223344", "112233445566778899aabbccddeeff00")],
    );
    server
        .put(&format!("/conversations/{}/sender-keys", conv.id))
        .authorization_bearer(&alice_token)
        .json(&req2)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Bob should see the updated wrapped_key_hex, not the old one
    let bob_token = common::authenticate(&server, &bob).await;
    let resp = server
        .get(&format!("/conversations/{}/sender-keys", conv.id))
        .authorization_bearer(&bob_token)
        .await;
    resp.assert_status_ok();
    let entries: serde_json::Value = resp.json();
    let arr = entries.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0]["wrapped_key_hex"], "11223344",
        "upsert should replace old wrapped_key_hex"
    );
}

// ---------------------------------------------------------------------------
// H4 hardened security: /federation/dm requires a valid sender signature
// ---------------------------------------------------------------------------

/// A normal locally-authenticated user MUST NOT be able to POST to
/// `/federation/dm`.  The `PeerHub` extractor rejects requests whose token
/// doesn't belong to a key in the `peers` table.
#[tokio::test]
async fn federated_dm_rejects_normal_user() {
    let hub = start_real_hub("hub-h4-reject").await;
    let client = reqwest::Client::new();

    // Register a normal user on this hub.
    let alice = Identity::generate();
    let alice_token = authenticate_http(&hub, &alice).await;

    // Craft a spoofed federated-DM payload claiming to be from an arbitrary sender.
    let spoofed_sender = Identity::generate();
    let payload = serde_json::json!({
        "message_id": "aaaabbbbccccdddd0000111122223333",
        "conversation_id": "cccc0000111122223333444455556666",
        "conv_type": "dm",
        "sender": spoofed_sender.public_key_hex(),
        "members": [alice.public_key_hex(), spoofed_sender.public_key_hex()],
        "content": "injected plaintext",
        "attachments": [],
        "signature": null,
        "created_at": 1_700_000_000i64,
    });

    let resp = client
        .post(format!("{hub}/federation/dm"))
        .bearer_auth(&alice_token)
        .json(&payload)
        .send()
        .await
        .unwrap();

    // Must be rejected — 403 Forbidden because alice is not a peer hub.
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "normal user must not be able to post to /federation/dm"
    );
}

/// The critical bypass test: an attacker who calls /auth/verify with is_hub=true
/// lands in the `peers` table and passes the PeerHub extractor.  They must still
/// be rejected when they post a DM with sender=<victim> and a missing or
/// invalid signature, because only the victim can sign with the victim's key.
#[tokio::test]
async fn federated_dm_rejects_is_hub_attacker_with_spoofed_sender() {
    let hub = start_real_hub("hub-h4-bypass").await;
    let client = reqwest::Client::new();

    // Attacker generates their own keypair and authenticates with is_hub=true
    // to self-register in the peers table.
    let attacker = Identity::generate();
    let attacker_token = {
        let challenge: ChallengeResponse = client
            .post(format!("{hub}/auth/challenge"))
            .json(&serde_json::json!({ "public_key": attacker.public_key_hex() }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
        let signature = attacker.sign(&challenge_bytes);
        let verify: VerifyResponse = client
            .post(format!("{hub}/auth/verify"))
            .json(&serde_json::json!({
                "public_key": attacker.public_key_hex(),
                "challenge": challenge.challenge,
                "signature": hex::encode(signature.to_bytes()),
                "is_hub": true,
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        verify.token
    };

    let victim = Identity::generate();
    let conv_id = "cccc0000111122223333444455556666";

    // --- Case 1: missing signature ---
    let payload_no_sig = serde_json::json!({
        "message_id": "aaaabbbbccccdddd0000111122223333",
        "conversation_id": conv_id,
        "conv_type": "dm",
        "sender": victim.public_key_hex(),
        "members": [attacker.public_key_hex(), victim.public_key_hex()],
        "content": "injected without signature",
        "attachments": [],
        "signature": null,
        "created_at": 1_700_000_000i64,
    });

    let resp = client
        .post(format!("{hub}/federation/dm"))
        .bearer_auth(&attacker_token)
        .json(&payload_no_sig)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "federated DM without sender signature must be rejected even when caller passed PeerHub"
    );

    // --- Case 2: attacker signs with their OWN key but claims sender=victim ---
    let wrong_sig = {
        let bytes = voxply_identity::federated_plaintext_dm_signing_bytes(
            conv_id,
            "dm",
            "injected with wrong key",
        );
        hex::encode(attacker.sign(&bytes).to_bytes())
    };
    let payload_wrong_sig = serde_json::json!({
        "message_id": "bbbbbbbbccccdddd0000111122223334",
        "conversation_id": conv_id,
        "conv_type": "dm",
        "sender": victim.public_key_hex(),
        "members": [attacker.public_key_hex(), victim.public_key_hex()],
        "content": "injected with wrong key",
        "attachments": [],
        "signature": wrong_sig,
        "created_at": 1_700_000_001i64,
    });

    let resp = client
        .post(format!("{hub}/federation/dm"))
        .bearer_auth(&attacker_token)
        .json(&payload_wrong_sig)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "federated DM signed by wrong key must be rejected"
    );
}

/// Correctly-signed plaintext DM posted directly to /federation/dm must be
/// accepted when the caller is a registered peer.  This verifies the happy
/// path of the signature check.
#[tokio::test]
async fn federated_dm_accepts_correctly_signed_plaintext() {
    let hub = start_real_hub("hub-h4-signed").await;
    let client = reqwest::Client::new();

    // Register the "sending hub" via is_hub=true.
    let hub_identity = Identity::generate();
    let hub_token = {
        let challenge: ChallengeResponse = client
            .post(format!("{hub}/auth/challenge"))
            .json(&serde_json::json!({ "public_key": hub_identity.public_key_hex() }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let challenge_bytes = hex::decode(&challenge.challenge).unwrap();
        let signature = hub_identity.sign(&challenge_bytes);
        let verify: VerifyResponse = client
            .post(format!("{hub}/auth/verify"))
            .json(&serde_json::json!({
                "public_key": hub_identity.public_key_hex(),
                "challenge": challenge.challenge,
                "signature": hex::encode(signature.to_bytes()),
                "is_hub": true,
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        verify.token
    };

    // The actual sender is a real user with a real keypair.
    let sender = Identity::generate();
    let conv_id = "dddd0000111122223333444455556666";
    let content = "legitimate message from real sender";

    let sig = make_plaintext_sig(&sender, conv_id, "dm", content);

    let payload = serde_json::json!({
        "message_id": "ccccccccddddeeee0000111122223335",
        "conversation_id": conv_id,
        "conv_type": "dm",
        "sender": sender.public_key_hex(),
        "members": [sender.public_key_hex(), hub_identity.public_key_hex()],
        "content": content,
        "attachments": [],
        "signature": sig,
        "created_at": 1_700_000_002i64,
    });

    let resp = client
        .post(format!("{hub}/federation/dm"))
        .bearer_auth(&hub_token)
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "correctly-signed federated DM must be accepted"
    );
}

/// A legitimate peer hub (Hub A) that has gone through the federation
/// challenge-response handshake MUST be able to deliver DMs to Hub B.
/// This is a regression guard: the fix must not break the valid path.
#[tokio::test]
async fn federated_dm_accepts_registered_peer_hub() {
    // This test reuses the cross-hub DM flow which exercises the full
    // federation path.  If the PeerHub extractor incorrectly rejects a
    // registered peer, the message will not appear on Hub B.
    let hub_a = start_real_hub("hub-h4-a").await;
    let hub_b = start_real_hub("hub-h4-b").await;
    let client = reqwest::Client::new();

    let alice = Identity::generate();
    let bob = Identity::generate();
    let alice_token = authenticate_http(&hub_a, &alice).await;
    authenticate_http(&hub_b, &bob).await;

    // Alice creates a cross-hub conversation.
    let mut member_hubs = std::collections::HashMap::new();
    member_hubs.insert(bob.public_key_hex(), hub_b.clone());
    let resp = client
        .post(format!("{hub_a}/conversations"))
        .bearer_auth(&alice_token)
        .json(&serde_json::json!({
            "members": [bob.public_key_hex()],
            "member_hubs": member_hubs,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "create conversation failed");
    let conv: ConversationResponse = resp.json().await.unwrap();

    // Alice sends a DM; Hub A federates it to Hub B.
    let peer_content = "peer delivery test";
    let peer_sig = make_plaintext_sig(&alice, &conv.id, &conv.conv_type, peer_content);
    let resp = client
        .post(format!("{hub_a}/conversations/{}/messages", conv.id))
        .bearer_auth(&alice_token)
        .json(&serde_json::json!({ "content": peer_content, "plaintext_signature": peer_sig }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // Bob reads from Hub B — message must be there.
    let bob_token = authenticate_http(&hub_b, &bob).await;
    let resp = client
        .get(format!("{hub_b}/conversations/{}/messages", conv.id))
        .bearer_auth(&bob_token)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let messages: serde_json::Value = resp.json().await.unwrap();
    let arr = messages.as_array().unwrap();
    assert_eq!(
        arr.len(),
        1,
        "federated DM from registered peer must arrive"
    );
    assert_eq!(arr[0]["content"], peer_content);
}
