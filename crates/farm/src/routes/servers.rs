/// Server agent routes — registration tokens, agent WebSocket, admin server list.
///
/// POST /farm/admin/server-token — generate a one-time registration token (admin)
/// GET  /farm/admin/servers      — list registered server agents (admin)
/// GET  /ws/agent               — WebSocket upgrade for remote server agents (token in first frame)
use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::routes::admin::require_admin_pub;
use crate::state::FarmState;
use crate::unix_now;

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
         VALUES ($1, $2, $3, $4, $5)",
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
    /// How many hubs this server may hold. Absent means unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_hubs: Option<i64>,
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

    #[allow(clippy::type_complexity)]
    let rows: Vec<(String, String, Option<String>, Option<i64>, Option<i32>)> = sqlx::query_as(
        "SELECT id, name, region, last_seen_at, max_hubs FROM servers
         WHERE deleted_at IS NULL ORDER BY registered_at",
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
        map.keys()
            .cloned()
            .collect::<std::collections::HashSet<_>>()
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
        .map(|(id, name, region, last_seen_at, max_hubs)| {
            let connected = connected_ids.contains(&id);
            let running_hub_count = hub_counts.get(&id).copied().unwrap_or(0);
            ServerEntry {
                id,
                name,
                region,
                connected,
                last_seen_at,
                running_hub_count,
                max_hubs: max_hubs.map(|m| m as i64),
            }
        })
        .collect();

    Ok(Json(ListServersResponse { servers }))
}

// ---------------------------------------------------------------------------
// GET /ws/agent  — WebSocket upgrade for server agents (token in first frame)
// ---------------------------------------------------------------------------

pub async fn ws_agent_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<FarmState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_agent_socket(socket, state))
}

async fn handle_agent_socket(socket: WebSocket, state: Arc<FarmState>) {
    use futures_util::{SinkExt, StreamExt};

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // First frame must be {"type":"hello","token":"<hex>",...}.
    // Validating here keeps the token out of the HTTP request URL (and logs).
    // Filled inside the block below, which only falls through once the hello
    // frame has been parsed; every other path returns.
    let hello: serde_json::Value;
    let server_id = {
        let first = match ws_receiver.next().await {
            Some(Ok(Message::Text(txt))) => txt,
            _ => {
                tracing::warn!("Agent WS: connection closed before hello");
                return;
            }
        };
        let val = match serde_json::from_str::<serde_json::Value>(&first) {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!("Agent WS: first message is not valid JSON");
                let _ = ws_sender
                    .send(Message::Text(
                        r#"{"type":"error","code":"auth_failed"}"#.into(),
                    ))
                    .await;
                return;
            }
        };
        if val.get("type").and_then(|v| v.as_str()) != Some("hello") {
            tracing::warn!("Agent WS: first message type is not hello");
            let _ = ws_sender
                .send(Message::Text(
                    r#"{"type":"error","code":"auth_failed"}"#.into(),
                ))
                .await;
            return;
        }
        hello = val.clone();
        let token = match val.get("token").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => {
                tracing::warn!("Agent WS: hello missing token field");
                let _ = ws_sender
                    .send(Message::Text(
                        r#"{"type":"error","code":"auth_failed"}"#.into(),
                    ))
                    .await;
                return;
            }
        };
        let token_bytes = match hex::decode(&token) {
            Ok(b) => b,
            Err(_) => {
                tracing::warn!("Agent WS: invalid token hex");
                let _ = ws_sender
                    .send(Message::Text(
                        r#"{"type":"error","code":"auth_failed"}"#.into(),
                    ))
                    .await;
                return;
            }
        };
        let token_hash = sha256_hex(&token_bytes);
        let lookup = sqlx::query_as::<_, (String,)>(
            "SELECT id FROM servers WHERE token_hash = $1 AND deleted_at IS NULL",
        )
        .bind(&token_hash)
        .fetch_optional(&state.db)
        .await;
        match lookup {
            Ok(Some((id,))) => id,
            Ok(None) => {
                tracing::warn!("Agent WS: token not found or server deleted");
                let _ = ws_sender
                    .send(Message::Text(
                        r#"{"type":"error","code":"auth_failed"}"#.into(),
                    ))
                    .await;
                return;
            }
            Err(e) => {
                tracing::warn!("Agent WS: DB error during token lookup: {e}");
                let _ = ws_sender
                    .send(Message::Text(
                        r#"{"type":"error","code":"auth_failed"}"#.into(),
                    ))
                    .await;
                return;
            }
        }
    };

    // What the agent advertised about itself. Recorded on every connect
    // rather than at registration: a node that moves, gains a certificate or
    // rotates one corrects the farm by reconnecting, and there is no second
    // place for an operator to keep in step by hand.
    //
    // A hello with no host clears the column, which is the honest answer — the
    // agent is telling us it is the farm's own machine, and a stale host left
    // behind would send the proxy somewhere nothing answers.
    {
        let host = hello
            .get("host")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|h| !h.is_empty());
        let tls_mode = hello
            .get("tls_mode")
            .and_then(|v| v.as_str())
            .filter(|m| *m == "pin")
            .unwrap_or("ca");
        let cert_sha256 = hello
            .get("cert_sha256")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|d| !d.is_empty());
        if let Err(e) = sqlx::query(
            "UPDATE servers SET host = $1, tls_mode = $2, cert_sha256 = $3 WHERE id = $4",
        )
        .bind(host)
        .bind(tls_mode)
        .bind(cert_sha256)
        .bind(&server_id)
        .execute(&state.db)
        .await
        {
            tracing::warn!(server_id, error = %e, "Could not record the node's address");
        }
    }

    tracing::info!(server_id, "Agent connected");

    // Split the socket into send/receive halves via a bounded channel.
    // 64 slots is ample for hub spawn/stop commands; if the agent falls behind
    // we drop the oldest queued message rather than growing without bound.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(64);
    state
        .agent_senders
        .write()
        .await
        .insert(server_id.clone(), tx);

    // Spawn a task that forwards messages from the channel to the WebSocket.
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    // Read incoming messages from the agent.
    loop {
        match ws_receiver.next().await {
            Some(Ok(Message::Text(txt))) => {
                // Update last_seen_at on any message received.
                let now = unix_now();
                let _ = sqlx::query("UPDATE servers SET last_seen_at = $1 WHERE id = $2")
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
                            // voice_port is optional in the reply for backward
                            // compatibility with older agents / test mocks —
                            // when absent the column is left NULL and gets
                            // backfilled by `FarmState::resolve_voice_port` on
                            // the next restart.
                            let voice_port = val.get("voice_port").and_then(|v| v.as_u64());
                            let _ = sqlx::query(
                                "UPDATE hubs SET process_port = $1, voice_port = $2, server_id = $3 WHERE id = $4",
                            )
                            .bind(port as i32)
                            .bind(voice_port.map(|v| v as i32))
                            .bind(&server_id)
                            .bind(hub_id)
                            .execute(&state.db)
                            .await;
                            tracing::info!(
                                server_id,
                                hub_id,
                                port,
                                voice_port,
                                "Hub spawned on remote server"
                            );
                        }
                    } else if msg_type == "hub_stopped" {
                        if let Some(hub_id) = val.get("hub_id").and_then(|v| v.as_str()) {
                            let _ = sqlx::query(
                                "UPDATE hubs SET process_port = NULL, voice_port = NULL WHERE id = $1",
                            )
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
                let _ = sqlx::query("UPDATE servers SET last_seen_at = $1 WHERE id = $2")
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
    let _ = sqlx::query("UPDATE servers SET last_seen_at = $1 WHERE id = $2")
        .bind(now)
        .bind(&server_id)
        .execute(&state.db)
        .await;

    tracing::info!(server_id, "Agent disconnected");
}

/// Pick any connected agent sender (round-robin is future work; first is fine now).
pub async fn pick_agent(
    senders: &Arc<tokio::sync::RwLock<HashMap<String, tokio::sync::mpsc::Sender<String>>>>,
) -> Option<(String, tokio::sync::mpsc::Sender<String>)> {
    let map = senders.read().await;
    map.iter().next().map(|(id, s)| (id.clone(), s.clone()))
}

// ---------------------------------------------------------------------------
// PATCH /farm/admin/servers/{server_id}
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateServerRequest {
    /// How many hubs this server may hold. `null` clears the cap (unlimited).
    ///
    /// Tri-state on purpose: omitted means "leave it alone", `null` means
    /// "no limit". Collapsing the two is the omitted-vs-null trap that has
    /// already cost this project two features (CLAUDE.md).
    #[serde(default, deserialize_with = "deserialize_some")]
    pub max_hubs: Option<Option<i64>>,
}

fn deserialize_some<'de, D>(deserializer: D) -> Result<Option<Option<i64>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

/// Set a server's hub capacity (farm admin).
///
/// Lowering it below what the server already holds is allowed and does not
/// move anything: the cap governs *new* placements. Evicting a running
/// community to satisfy a number the operator just typed would be worse than
/// leaving one server briefly over its limit.
pub async fn update_server(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<FarmState>>,
    Json(req): Json<UpdateServerRequest>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    require_admin_pub(&headers, &state).await?;

    let Some(max_hubs) = req.max_hubs else {
        return Ok(StatusCode::NO_CONTENT);
    };

    if let Some(n) = max_hubs {
        if n < 0 {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_value",
                    "details": "max_hubs must be zero or more, or null for unlimited",
                })),
            ));
        }
    }

    let updated =
        sqlx::query("UPDATE servers SET max_hubs = $1 WHERE id = $2 AND deleted_at IS NULL")
            .bind(max_hubs.map(|n| n as i32))
            .bind(&server_id)
            .execute(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("db_error: {e}")})),
                )
            })?;

    if updated.rows_affected() == 0 {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "server_not_found"})),
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}
