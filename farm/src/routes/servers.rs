/// Server agent routes — registration tokens, agent WebSocket, admin server list.
///
/// POST /farm/admin/server-token — generate a one-time registration token (admin)
/// GET  /farm/admin/servers      — list registered server agents (admin)
/// GET  /ws/agent?token=<hex>   — WebSocket upgrade for remote server agents
use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::routes::admin::require_admin_pub;
use crate::state::FarmState;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// POST /farm/admin/server-token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GenerateTokenRequest {
    pub name: String,
    pub region: Option<String>,
}

#[derive(Serialize)]
pub struct GenerateTokenResponse {
    pub server_id: String,
    pub token: String,
}

pub async fn generate_server_token(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<GenerateTokenRequest>,
) -> Result<Json<GenerateTokenResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_pub(&headers, &state).await?;

    // Random 8-hex-char server ID.
    let server_id = {
        let mut bytes = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };

    // Random 32-byte one-time token — shown once, stored only as a SHA-256 hash.
    let token_bytes = {
        let mut bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        bytes
    };
    let token_hex = hex::encode(&token_bytes);
    let token_hash = sha256_hex(&token_bytes);

    let now = unix_now();

    sqlx::query(
        "INSERT INTO servers (id, token_hash, name, region, registered_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&server_id)
    .bind(&token_hash)
    .bind(&req.name)
    .bind(&req.region)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    Ok(Json(GenerateTokenResponse {
        server_id,
        token: token_hex,
    }))
}

// ---------------------------------------------------------------------------
// GET /farm/admin/servers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ServerEntry {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    pub running_hub_count: i64,
}

#[derive(Serialize)]
pub struct ListServersResponse {
    pub servers: Vec<ServerEntry>,
}

pub async fn list_servers(
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
) -> Result<Json<ListServersResponse>, (StatusCode, Json<serde_json::Value>)> {
    require_admin_pub(&headers, &state).await?;

    let rows: Vec<(String, String, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT id, name, region, last_seen_at FROM servers WHERE deleted_at IS NULL ORDER BY registered_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let connected_ids = {
        let map = state.agent_senders.read().await;
        map.keys().cloned().collect::<std::collections::HashSet<_>>()
    };

    let hub_count_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT server_id, COUNT(*) as cnt
         FROM hubs
         WHERE server_id IS NOT NULL AND process_port IS NOT NULL AND deleted_at IS NULL
         GROUP BY server_id",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("db_error: {e}")})),
        )
    })?;

    let hub_counts: HashMap<String, i64> = hub_count_rows.into_iter().collect();

    let servers = rows
        .into_iter()
        .map(|(id, name, region, last_seen_at)| {
            let connected = connected_ids.contains(&id);
            let running_hub_count = hub_counts.get(&id).copied().unwrap_or(0);
            ServerEntry { id, name, region, connected, last_seen_at, running_hub_count }
        })
        .collect();

    Ok(Json(ListServersResponse { servers }))
}

// ---------------------------------------------------------------------------
// GET /ws/agent?token=<hex>  — WebSocket upgrade for server agents
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AgentTokenQuery {
    pub token: String,
}

pub async fn ws_agent_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<AgentTokenQuery>,
    State(state): State<Arc<FarmState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_agent_socket(socket, state, params.token))
}

async fn handle_agent_socket(socket: WebSocket, state: Arc<FarmState>, token: String) {
    // Validate token: hash it, look up in servers by token_hash.
    let token_bytes = match hex::decode(&token) {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("Agent WebSocket: invalid token hex");
            return;
        }
    };
    let token_hash = sha256_hex(&token_bytes);

    let row: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM servers WHERE token_hash = ? AND deleted_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let server_id = match row {
        Some((id,)) => id,
        None => {
            tracing::warn!("Agent WebSocket: token not found or server deleted");
            return;
        }
    };

    tracing::info!(server_id, "Agent connected");

    // Split the socket into send/receive halves via an mpsc channel.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    state.agent_senders.write().await.insert(server_id.clone(), tx);

    let (mut ws_sender, mut ws_receiver) = {
        use futures_util::StreamExt;
        socket.split()
    };

    // Spawn a task that forwards messages from the channel to the WebSocket.
    let send_task = {
        tokio::spawn(async move {
            use futures_util::SinkExt;
            while let Some(msg) = rx.recv().await {
                if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                    break;
                }
            }
        })
    };

    // Read incoming messages from the agent.
    loop {
        use futures_util::StreamExt;
        match ws_receiver.next().await {
            Some(Ok(Message::Text(txt))) => {
                // Update last_seen_at on any message received.
                let now = unix_now();
                let _ = sqlx::query("UPDATE servers SET last_seen_at = ? WHERE id = ?")
                    .bind(now)
                    .bind(&server_id)
                    .execute(&state.db)
                    .await;

                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
                    let msg_type = val.get("type").and_then(|v| v.as_str()).unwrap_or("");
                    if msg_type == "hub_spawned" {
                        if let (Some(hub_id), Some(port)) = (
                            val.get("hub_id").and_then(|v| v.as_str()),
                            val.get("port").and_then(|v| v.as_u64()),
                        ) {
                            let _ = sqlx::query(
                                "UPDATE hubs SET process_port = ?, server_id = ? WHERE id = ?",
                            )
                            .bind(port as i32)
                            .bind(&server_id)
                            .bind(hub_id)
                            .execute(&state.db)
                            .await;
                            tracing::info!(server_id, hub_id, port, "Hub spawned on remote server");
                        }
                    } else if msg_type == "hub_stopped" {
                        if let Some(hub_id) = val.get("hub_id").and_then(|v| v.as_str()) {
                            let _ = sqlx::query("UPDATE hubs SET process_port = NULL WHERE id = ?")
                                .bind(hub_id)
                                .execute(&state.db)
                                .await;
                            tracing::info!(server_id, hub_id, "Hub stopped on remote server");
                        }
                    }
                }
            }
            Some(Ok(Message::Binary(_))) => {
                // Binary frames not used in this protocol; update last_seen_at anyway.
                let now = unix_now();
                let _ = sqlx::query("UPDATE servers SET last_seen_at = ? WHERE id = ?")
                    .bind(now)
                    .bind(&server_id)
                    .execute(&state.db)
                    .await;
            }
            Some(Ok(Message::Close(_))) | None => {
                break;
            }
            Some(Ok(_)) => {
                // Ping/pong frames handled by axum automatically.
            }
            Some(Err(e)) => {
                tracing::warn!(server_id, error = %e, "Agent WebSocket error");
                break;
            }
        }
    }

    // Cleanup on disconnect.
    state.agent_senders.write().await.remove(&server_id);
    send_task.abort();

    let now = unix_now();
    let _ = sqlx::query("UPDATE servers SET last_seen_at = ? WHERE id = ?")
        .bind(now)
        .bind(&server_id)
        .execute(&state.db)
        .await;

    tracing::info!(server_id, "Agent disconnected");
}

/// Pick any connected agent sender (round-robin is future work; first is fine now).
pub async fn pick_agent(
    senders: &Arc<tokio::sync::RwLock<HashMap<String, tokio::sync::mpsc::UnboundedSender<String>>>>,
) -> Option<(String, tokio::sync::mpsc::UnboundedSender<String>)> {
    let map = senders.read().await;
    map.iter().next().map(|(id, s)| (id.clone(), s.clone()))
}
