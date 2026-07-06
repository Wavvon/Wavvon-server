//! Integration tests: serial-keyed reverse-proxy routing
//! (farm-impl.md "Serial routing — first slice").
//!
//! Spins up a real farm server plus a tiny stub "hub" (also a real axum
//! server on its own random port) so that both the buffered HTTP proxy path
//! and the WebSocket-upgrade socket bridge can be exercised end-to-end over
//! real TCP sockets — the same style as `e2e_server_agent.rs`.
#[path = "common.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message as AxumWsMessage, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::Client;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;
use wavvon_farm::{db, hub_manager::HubManager, server, state::FarmState, unix_now};

// ---------------------------------------------------------------------------
// Test server setup
// ---------------------------------------------------------------------------

async fn start_farm() -> (String, Arc<FarmState>, common::TestDbGuard) {
    let (db_pool, guard) = common::create_test_db().await;
    db::migrations::run(&db_pool).await.unwrap();

    let keypair = SigningKey::generate(&mut OsRng);
    let farm_pubkey = hex::encode(ed25519_dalek::VerifyingKey::from(&keypair).as_bytes());
    let now = unix_now();
    sqlx::query("INSERT INTO farms (id, public_key, created_at) VALUES (1, $1, $2)")
        .bind(&farm_pubkey)
        .bind(now)
        .execute(&db_pool)
        .await
        .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let farm_url = format!("http://127.0.0.1:{port}");

    let hub_manager = Arc::new(HubManager::new(
        "wavvon-hub".to_string(),
        farm_url.clone(),
        9200,
    ));
    let state = Arc::new(FarmState::new(
        db_pool,
        keypair,
        farm_url.clone(),
        hub_manager,
        "/tmp/wavvon-serial-routing-tests".to_string(),
    ));

    let app = server::create_router(state.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(10)).await;

    (farm_url, state, guard)
}

/// Spin up a tiny stub "hub": `GET /info` returns a fixed JSON body, `GET
/// /ws` echoes back every text frame it receives. Returns the port it's
/// listening on.
async fn start_stub_hub() -> u16 {
    async fn info() -> &'static str {
        "{\"name\":\"stub-hub\"}"
    }

    async fn ws_echo(ws: WebSocketUpgrade) -> impl IntoResponse {
        ws.on_upgrade(|mut socket| async move {
            while let Some(Ok(msg)) = socket.recv().await {
                if let AxumWsMessage::Text(text) = msg {
                    if socket.send(AxumWsMessage::Text(text)).await.is_err() {
                        break;
                    }
                }
            }
        })
    }

    let app = Router::new()
        .route("/info", get(info))
        .route("/ws", get(ws_echo));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(10)).await;
    port
}

/// Insert a `hubs` row keyed by `serial` (hub_pubkey). `process_port` is
/// `None` to exercise the "registered but not running" case.
async fn insert_hub_row(
    state: &FarmState,
    id: &str,
    serial: &str,
    process_port: Option<u16>,
    suspended: bool,
) {
    let now = unix_now();
    sqlx::query(
        "INSERT INTO hubs
             (id, owner_pubkey, name, visibility, process_port, db_path, created_at, hub_pubkey, suspended_at)
         VALUES ($1, 'owner', 'Test Hub', 'private', $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(process_port.map(|p| p as i32))
    .bind(format!("/tmp/{id}.db"))
    .bind(now)
    .bind(serial)
    .bind(if suspended { Some(now) } else { None })
    .execute(&state.db)
    .await
    .unwrap();
}

fn random_serial() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// HTTP happy path: /hub/<serial>/info reaches the stub hub's /info verbatim.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn serial_route_reaches_stub_hub_info() {
    let (farm_url, state, _guard) = start_farm().await;
    let hub_port = start_stub_hub().await;
    let serial = random_serial();
    insert_hub_row(&state, "hub00001", &serial, Some(hub_port), false).await;

    let client = Client::new();
    let resp = client
        .get(format!("{farm_url}/hub/{serial}/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "stub-hub");
}

#[tokio::test]
async fn unknown_serial_returns_404_hub_not_found() {
    let (farm_url, _state, _guard) = start_farm().await;
    let client = Client::new();
    let resp = client
        .get(format!("{farm_url}/hub/{}/info", random_serial()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "hub_not_found");
}

#[tokio::test]
async fn suspended_hub_returns_503_hub_suspended() {
    let (farm_url, state, _guard) = start_farm().await;
    let hub_port = start_stub_hub().await;
    let serial = random_serial();
    insert_hub_row(&state, "hub00002", &serial, Some(hub_port), true).await;

    let client = Client::new();
    let resp = client
        .get(format!("{farm_url}/hub/{serial}/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "hub_suspended");
}

#[tokio::test]
async fn registered_but_not_running_returns_503_hub_not_running() {
    let (farm_url, state, _guard) = start_farm().await;
    let serial = random_serial();
    insert_hub_row(&state, "hub00003", &serial, None, false).await;

    let client = Client::new();
    let resp = client
        .get(format!("{farm_url}/hub/{serial}/info"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "hub_not_running");
}

// ---------------------------------------------------------------------------
// WebSocket upgrade bridge: end-to-end echo through the farm proxy.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn websocket_upgrade_bridges_to_stub_hub() {
    let (farm_url, state, _guard) = start_farm().await;
    let hub_port = start_stub_hub().await;
    let serial = random_serial();
    insert_hub_row(&state, "hub00004", &serial, Some(hub_port), false).await;

    let ws_base = farm_url.replacen("http://", "ws://", 1);
    let ws_url = format!("{ws_base}/hub/{serial}/ws");

    let (mut ws_stream, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS upgrade through the farm proxy should succeed");

    ws_stream
        .send(TungsteniteMessage::Text("hello-through-the-bridge".into()))
        .await
        .unwrap();

    let reply = tokio::time::timeout(Duration::from_secs(5), ws_stream.next())
        .await
        .expect("timed out waiting for echo")
        .expect("stream ended before echo arrived")
        .unwrap();

    assert_eq!(
        reply,
        TungsteniteMessage::Text("hello-through-the-bridge".into())
    );
}
