//! Tier 2 party-multiplayer game session routes.
//!
//! Session lifecycle: create → join → (state patches) → end/delete.
//! In-memory state lives in `AppState::active_game_sessions`; the DB rows in
//! `game_sessions` are written for durability (snapshot opt-in) and for the
//! authoritative "is this session still open?" check.  The shared KV table
//! (`game_shared_kv`) stores community-axis leaderboard/world data.
//!
//! All WS broadcast goes through the existing `state.chat_tx` broadcast
//! channel using `ChatEvent::Game` so the WS dispatcher filters by channel
//! subscription automatically.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::{AppState, GamePlayer, GameSessionState};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for installing a game (Tier 1 minimal admin route).
/// Only the fields required to create a `hub_games` row. Extended install
/// (manifest-URL fetch, capability grants) is the full Tier 1 admin surface
/// which is designed but not yet built — this endpoint covers the minimal path
/// used by the Tier 2 session tests and the inline-manifest install path.
#[derive(Deserialize)]
pub struct InstallGameRequest {
    pub name: String,
    pub entry_url: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub thumbnail_url: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub min_players: Option<i64>,
    #[serde(default)]
    pub max_players: Option<i64>,
}

#[derive(Serialize)]
pub struct InstalledGameResponse {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    pub version: String,
    pub description: Option<String>,
    pub thumbnail_url: Option<String>,
    pub author: Option<String>,
    pub min_players: i64,
    pub max_players: i64,
}

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub game_id: String,
    /// The channel this session is anchored to.
    pub channel_id: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub channel_id: String,
    pub game_id: String,
    pub host_pubkey: String,
    pub players: Vec<String>,
    pub state_json: serde_json::Value,
    pub created_at: String,
    pub ended_at: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchStateRequest {
    pub patch: serde_json::Value,
}

#[derive(Deserialize)]
pub struct SetKvRequest {
    pub value: String,
}

#[derive(Serialize)]
pub struct KvResponse {
    pub session_id: String,
    pub key: String,
    pub value: String,
    pub updated_at: String,
}

// ---------------------------------------------------------------------------
// Helper: broadcast a WsServerMessage to all channel subscribers via chat_tx.
// ---------------------------------------------------------------------------
fn broadcast_game_event(state: &AppState, channel_id: &str, msg: WsServerMessage) {
    let event = ChatEvent::Game {
        channel_id: channel_id.to_string(),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&msg).unwrap().as_str());
    let _ = state.chat_tx.send((event, json));
}

// ---------------------------------------------------------------------------
// POST /admin/games  (Tier 1 minimal install — manage_games required)
// ---------------------------------------------------------------------------
/// Install a game on this hub. Uses the game's `entry_url` to derive a stable
/// `id` if none is supplied (SHA-256 prefix). This is the inline-manifest path
/// described in the design doc; the full manifest-URL fetch and catalog browse
/// paths are deferred Tier 1 work.
pub async fn install_game(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<InstallGameRequest>,
) -> Result<(StatusCode, Json<InstalledGameResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    // Derive id from entry_url hash if not supplied explicitly.
    let game_id = req.id.unwrap_or_else(|| {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(req.entry_url.as_bytes());
        format!("game-{}", hex::encode(&hash[..8]))
    });
    let version = req.version.unwrap_or_else(|| "1.0.0".to_string());
    let min_players = req.min_players.unwrap_or(1);
    let max_players = req.max_players.unwrap_or(1);
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO hub_games
            (id, name, description, version, entry_url, thumbnail_url, author,
             min_players, max_players, installed_by, installed_at, manifest_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
         ON CONFLICT(id) DO UPDATE SET
             name = excluded.name,
             description = excluded.description,
             version = excluded.version,
             entry_url = excluded.entry_url,
             thumbnail_url = excluded.thumbnail_url,
             author = excluded.author,
             min_players = excluded.min_players,
             max_players = excluded.max_players",
    )
    .bind(&game_id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&version)
    .bind(&req.entry_url)
    .bind(&req.thumbnail_url)
    .bind(&req.author)
    .bind(min_players)
    .bind(max_players)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(InstalledGameResponse {
            id: game_id,
            name: req.name,
            entry_url: req.entry_url,
            version,
            description: req.description,
            thumbnail_url: req.thumbnail_url,
            author: req.author,
            min_players,
            max_players,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /channels/:channel_id/game-sessions
// ---------------------------------------------------------------------------
/// Create a new session for the given game in the given channel.
/// Requires `start_game` permission. Also checks that the game is installed
/// on this hub (present in `hub_games`).
pub async fn create_session(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<(StatusCode, Json<SessionResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::START_GAME)?;

    // Verify the game is installed.
    let game_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM hub_games WHERE id = ?")
            .bind(&req.game_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if game_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Game not found on this hub".to_string()));
    }

    // Verify the channel exists.
    let ch_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if ch_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let session_id = Uuid::new_v4().to_string();
    let now = chrono_now();

    // Persist to DB (state_json starts as empty object; updated by state patches).
    sqlx::query(
        "INSERT INTO game_sessions (id, channel_id, game_id, host_pubkey, state_json, created_at)
         VALUES (?, ?, ?, ?, '{}', ?)",
    )
    .bind(&session_id)
    .bind(&channel_id)
    .bind(&req.game_id)
    .bind(&user.public_key)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let ts_now = now_secs();

    // Insert into in-memory map.
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        sessions.insert(
            session_id.clone(),
            GameSessionState {
                id: session_id.clone(),
                channel_id: channel_id.clone(),
                game_id: req.game_id.clone(),
                host_pubkey: user.public_key.clone(),
                players: {
                    let mut s = HashSet::new();
                    s.insert(user.public_key.clone());
                    s
                },
                player_details: vec![GamePlayer {
                    pubkey: user.public_key.clone(),
                    display_name: None,
                    joined_at: ts_now,
                    connected: true,
                }],
                status: "lobby".to_string(),
                max_players: None,
                created_at: ts_now,
                last_event_at: ts_now,
                snapshot: None,
                in_memory_state: serde_json::Value::Object(Default::default()),
            },
        );
    }

    // Broadcast to channel subscribers.
    broadcast_game_event(
        &state,
        &channel_id,
        WsServerMessage::GameSessionCreated {
            session_id: session_id.clone(),
            channel_id: channel_id.clone(),
            game_id: req.game_id.clone(),
            host_pubkey: user.public_key.clone(),
            max_players: None,
        },
    );

    Ok((
        StatusCode::CREATED,
        Json(SessionResponse {
            id: session_id,
            channel_id,
            game_id: req.game_id,
            host_pubkey: user.public_key,
            players: vec![],
            state_json: serde_json::Value::Object(Default::default()),
            created_at: now,
            ended_at: None,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /game-sessions/:sid/join
// ---------------------------------------------------------------------------
pub async fn join_session(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<(StatusCode, Json<SessionResponse>), (StatusCode, String)> {
    let row = fetch_open_session(&state, &session_id).await?;

    // Add player in-memory.
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        if let Some(s) = sessions.get_mut(&session_id) {
            s.players.insert(user.public_key.clone());
        }
    }

    let channel_id = row.channel_id.clone();

    broadcast_game_event(
        &state,
        &channel_id,
        WsServerMessage::GameSessionJoined {
            session_id: session_id.clone(),
            player_pubkey: user.public_key.clone(),
        },
    );

    Ok((
        StatusCode::OK,
        Json(session_row_to_response(row, &state, &session_id)),
    ))
}

// ---------------------------------------------------------------------------
// GET /game-sessions/:sid
// ---------------------------------------------------------------------------
pub async fn get_session(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<Json<SessionResponse>, (StatusCode, String)> {
    let row = fetch_open_session(&state, &session_id).await?;
    Ok(Json(session_row_to_response(row, &state, &session_id)))
}

// ---------------------------------------------------------------------------
// POST /game-sessions/:sid/state  (host only)
// ---------------------------------------------------------------------------
pub async fn patch_state(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
    Json(req): Json<PatchStateRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row = fetch_open_session(&state, &session_id).await?;

    if row.host_pubkey != user.public_key {
        // Admin can also patch.
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        if !perms.has(permissions::ADMIN) {
            return Err((StatusCode::FORBIDDEN, "Only the host can patch session state".to_string()));
        }
    }

    // Merge patch into DB state_json. We do a simple JSON merge: fetch current,
    // merge top-level keys from the patch, write back. The hub never interprets
    // the payload — it is opaque from the game's perspective.
    let current_json: String = sqlx::query_scalar(
        "SELECT state_json FROM game_sessions WHERE id = ? AND ended_at IS NULL",
    )
    .bind(&session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Session not found or ended".to_string()))?;

    let mut current: serde_json::Value =
        serde_json::from_str(&current_json).unwrap_or(serde_json::Value::Object(Default::default()));

    if let (Some(obj), Some(patch_obj)) = (current.as_object_mut(), req.patch.as_object()) {
        for (k, v) in patch_obj {
            obj.insert(k.clone(), v.clone());
        }
    } else {
        current = req.patch.clone();
    }

    let new_json = serde_json::to_string(&current).unwrap();
    sqlx::query("UPDATE game_sessions SET state_json = ? WHERE id = ?")
        .bind(&new_json)
        .bind(&session_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Update in-memory state too.
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        if let Some(s) = sessions.get_mut(&session_id) {
            s.in_memory_state = current;
        }
    }

    broadcast_game_event(
        &state,
        &row.channel_id,
        WsServerMessage::GameStateUpdated {
            session_id: session_id.clone(),
            patch: req.patch,
        },
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /game-sessions/:sid/shared-kv/:key
// ---------------------------------------------------------------------------
pub async fn set_shared_kv(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path((session_id, key)): Path<(String, String)>,
    Json(req): Json<SetKvRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Verify the session exists and is open.
    let _ = fetch_open_session(&state, &session_id).await?;

    let now = chrono_now();
    sqlx::query(
        "INSERT INTO game_shared_kv (session_id, key, value, updated_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(session_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
    )
    .bind(&session_id)
    .bind(&key)
    .bind(&req.value)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /game-sessions/:sid/shared-kv/:key
// ---------------------------------------------------------------------------
pub async fn get_shared_kv(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path((session_id, key)): Path<(String, String)>,
) -> Result<Json<KvResponse>, (StatusCode, String)> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT value, updated_at FROM game_shared_kv WHERE session_id = ? AND key = ?",
    )
    .bind(&session_id)
    .bind(&key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    match row {
        Some((value, updated_at)) => Ok(Json(KvResponse {
            session_id,
            key,
            value,
            updated_at,
        })),
        None => Err((StatusCode::NOT_FOUND, "Key not found".to_string())),
    }
}

// ---------------------------------------------------------------------------
// DELETE /game-sessions/:sid  (end session, host or admin)
// ---------------------------------------------------------------------------
pub async fn end_session(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row = fetch_open_session(&state, &session_id).await?;

    if row.host_pubkey != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        if !perms.has(permissions::ADMIN) {
            return Err((StatusCode::FORBIDDEN, "Only the host or an admin can end the session".to_string()));
        }
    }

    let now = chrono_now();
    sqlx::query("UPDATE game_sessions SET ended_at = ? WHERE id = ?")
        .bind(&now)
        .bind(&session_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Remove from in-memory map.
    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        sessions.remove(&session_id);
    }

    broadcast_game_event(
        &state,
        &row.channel_id,
        WsServerMessage::GameSessionEnded {
            session_id: session_id.clone(),
            reason: Some("ended".to_string()),
            result: None,
        },
    );

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct SessionRow {
    channel_id: String,
    game_id: String,
    host_pubkey: String,
    state_json: String,
    created_at: String,
    ended_at: Option<String>,
}

async fn fetch_open_session(
    state: &AppState,
    session_id: &str,
) -> Result<SessionRow, (StatusCode, String)> {
    let row: Option<(String, String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT channel_id, game_id, host_pubkey, state_json, created_at, ended_at
         FROM game_sessions WHERE id = ?",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    match row {
        None => Err((StatusCode::NOT_FOUND, "Session not found".to_string())),
        Some((channel_id, game_id, host_pubkey, state_json, created_at, ended_at)) => {
            if ended_at.is_some() {
                return Err((StatusCode::GONE, "Session has ended".to_string()));
            }
            Ok(SessionRow {
                channel_id,
                game_id,
                host_pubkey,
                state_json,
                created_at,
                ended_at,
            })
        }
    }
}

fn session_row_to_response(row: SessionRow, state: &AppState, session_id: &str) -> SessionResponse {
    let players: Vec<String> = {
        let sessions = state.active_game_sessions.lock().unwrap();
        sessions
            .get(session_id)
            .map(|s| s.players.iter().cloned().collect())
            .unwrap_or_default()
    };
    let state_json: serde_json::Value =
        serde_json::from_str(&row.state_json).unwrap_or(serde_json::Value::Object(Default::default()));
    SessionResponse {
        id: session_id.to_string(),
        channel_id: row.channel_id,
        game_id: row.game_id,
        host_pubkey: row.host_pubkey,
        players,
        state_json,
        created_at: row.created_at,
        ended_at: row.ended_at,
    }
}

fn chrono_now() -> String {
    // Use the same unix-seconds string pattern used elsewhere in the hub for
    // TEXT timestamp columns.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    secs.to_string()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ===========================================================================
// Spec Tier 2 session routes
// ===========================================================================

#[derive(Deserialize)]
pub struct CreateSessionV2Request {
    pub channel_id: String,
    #[serde(default)]
    pub max_players: Option<i64>,
}

#[derive(Deserialize)]
pub struct ListSessionsQuery {
    pub channel_id: Option<String>,
}

#[derive(Serialize)]
pub struct SessionV2Response {
    pub session_id: String,
    pub game_id: String,
    pub channel_id: String,
    pub host_pubkey: String,
    pub status: String,
    pub players: Vec<PlayerInfo>,
    pub max_players: Option<i64>,
    pub created_at: i64,
    pub last_event_at: i64,
}

#[derive(Serialize)]
pub struct PlayerInfo {
    pub pubkey: String,
    pub display_name: Option<String>,
    pub joined_at: i64,
    pub connected: bool,
}

#[derive(Serialize)]
pub struct ListSessionsResponse {
    pub sessions: Vec<SessionV2Response>,
}

// POST /games/:game_id/sessions
pub async fn create_session_v2(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(game_id): Path<String>,
    Json(req): Json<CreateSessionV2Request>,
) -> Result<(StatusCode, Json<SessionV2Response>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::START_GAME)?;

    let game_row: Option<(String, i64)> =
        sqlx::query_as("SELECT id, max_players FROM hub_games WHERE id = ?")
            .bind(&game_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if game_row.is_none() {
        return Err((StatusCode::NOT_FOUND, "Game not found on this hub".to_string()));
    }
    let db_max_players = game_row.and_then(|(_, m)| if m > 1 { Some(m) } else { None });

    let ch_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
            .bind(&req.channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if ch_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let max_players = req.max_players.or(db_max_players);
    let session_id = Uuid::new_v4().to_string();
    let now = now_secs();

    let display_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = ?")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    sqlx::query(
        "INSERT INTO game_sessions
            (id, channel_id, game_id, host_pubkey, state_json, created_at, status, updated_at)
         VALUES (?, ?, ?, ?, '{}', ?, 'lobby', ?)",
    )
    .bind(&session_id)
    .bind(&req.channel_id)
    .bind(&game_id)
    .bind(&user.public_key)
    .bind(now.to_string())
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        sessions.insert(
            session_id.clone(),
            GameSessionState {
                id: session_id.clone(),
                channel_id: req.channel_id.clone(),
                game_id: game_id.clone(),
                host_pubkey: user.public_key.clone(),
                players: {
                    let mut s = HashSet::new();
                    s.insert(user.public_key.clone());
                    s
                },
                player_details: vec![GamePlayer {
                    pubkey: user.public_key.clone(),
                    display_name: display_name.clone(),
                    joined_at: now,
                    connected: true,
                }],
                status: "lobby".to_string(),
                max_players,
                created_at: now,
                last_event_at: now,
                snapshot: None,
                in_memory_state: serde_json::Value::Object(Default::default()),
            },
        );
    }

    broadcast_game_event(
        &state,
        &req.channel_id,
        WsServerMessage::GameSessionCreated {
            session_id: session_id.clone(),
            channel_id: req.channel_id.clone(),
            game_id: game_id.clone(),
            host_pubkey: user.public_key.clone(),
            max_players,
        },
    );

    Ok((
        StatusCode::CREATED,
        Json(SessionV2Response {
            session_id,
            game_id,
            channel_id: req.channel_id,
            host_pubkey: user.public_key.clone(),
            status: "lobby".to_string(),
            players: vec![PlayerInfo {
                pubkey: user.public_key,
                display_name,
                joined_at: now,
                connected: true,
            }],
            max_players,
            created_at: now,
            last_event_at: now,
        }),
    ))
}

// GET /games/sessions?channel_id=
pub async fn list_sessions(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(q): Query<ListSessionsQuery>,
) -> Result<Json<ListSessionsResponse>, (StatusCode, String)> {
    let sessions: Vec<SessionV2Response> = {
        let sessions_guard = state.active_game_sessions.lock().unwrap();
        sessions_guard
            .values()
            .filter(|s| {
                if let Some(ref ch) = q.channel_id {
                    &s.channel_id == ch
                } else {
                    true
                }
            })
            .filter(|s| s.status != "ended" && s.status != "abandoned")
            .map(session_state_to_v2_response)
            .collect()
    };
    Ok(Json(ListSessionsResponse { sessions }))
}

// POST /games/sessions/:id/join
pub async fn join_session_v2(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<(StatusCode, Json<SessionV2Response>), (StatusCode, String)> {
    let (channel_id, max_players, current_count, already_in) = {
        let sessions = state.active_game_sessions.lock().unwrap();
        let s = sessions
            .get(&session_id)
            .ok_or((StatusCode::NOT_FOUND, "Session not found".to_string()))?;
        if s.status == "ended" || s.status == "abandoned" {
            return Err((StatusCode::GONE, "Session has ended".to_string()));
        }
        let already_in = s.players.contains(&user.public_key);
        (s.channel_id.clone(), s.max_players, s.players.len() as i64, already_in)
    };

    if !already_in {
        if let Some(max) = max_players {
            if current_count >= max {
                return Err((StatusCode::CONFLICT, "Session is full".to_string()));
            }
        }
    }

    let display_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = ?")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let now = now_secs();

    let resp = {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        let s = sessions
            .get_mut(&session_id)
            .ok_or((StatusCode::NOT_FOUND, "Session not found".to_string()))?;
        if !already_in {
            s.players.insert(user.public_key.clone());
            s.player_details.push(GamePlayer {
                pubkey: user.public_key.clone(),
                display_name: display_name.clone(),
                joined_at: now,
                connected: true,
            });
            s.last_event_at = now;
        }
        session_state_to_v2_response(s)
    };

    if !already_in {
        broadcast_game_event(
            &state,
            &channel_id,
            WsServerMessage::GamePlayerJoined {
                session_id: session_id.clone(),
                pubkey: user.public_key.clone(),
                display_name,
            },
        );
    }

    Ok((StatusCode::OK, Json(resp)))
}

// POST /games/sessions/:id/leave
pub async fn leave_session(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let (channel_id, was_host, remaining, new_host) = {
        let mut sessions = state.active_game_sessions.lock().unwrap();
        let s = sessions
            .get_mut(&session_id)
            .ok_or((StatusCode::NOT_FOUND, "Session not found".to_string()))?;
        if s.status == "ended" || s.status == "abandoned" {
            return Err((StatusCode::GONE, "Session has ended".to_string()));
        }
        let was_host = s.host_pubkey == user.public_key;
        s.players.remove(&user.public_key);
        s.player_details.retain(|p| p.pubkey != user.public_key);
        s.last_event_at = now_secs();

        let remaining = s.players.len();
        let new_host = if was_host && remaining > 0 {
            let new_h = s.player_details.first().map(|p| p.pubkey.clone());
            if let Some(ref nh) = new_h {
                s.host_pubkey = nh.clone();
            }
            new_h
        } else {
            None
        };

        if remaining == 0 {
            s.status = "abandoned".to_string();
        }

        (s.channel_id.clone(), was_host, remaining, new_host)
    };

    broadcast_game_event(
        &state,
        &channel_id,
        WsServerMessage::GamePlayerLeft {
            session_id: session_id.clone(),
            pubkey: user.public_key.clone(),
        },
    );

    if remaining == 0 {
        let _ = sqlx::query(
            "UPDATE game_sessions SET ended_at = ?, status = 'abandoned' WHERE id = ?",
        )
        .bind(chrono_now())
        .bind(&session_id)
        .execute(&state.db)
        .await;

        broadcast_game_event(
            &state,
            &channel_id,
            WsServerMessage::GameSessionEnded {
                session_id: session_id.clone(),
                reason: Some("abandoned".to_string()),
                result: None,
            },
        );
        state.active_game_sessions.lock().unwrap().remove(&session_id);
    } else if was_host {
        if let Some(ref nh) = new_host {
            broadcast_game_event(
                &state,
                &channel_id,
                WsServerMessage::GameHostChanged {
                    session_id: session_id.clone(),
                    new_host_pubkey: nh.clone(),
                },
            );
        }
        // 60-second host-reconnect grace timer.
        let state_c = state.clone();
        let sid = session_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            if let Ok(mut sessions) = state_c.active_game_sessions.lock() {
                if let Some(s) = sessions.get_mut(&sid) {
                    s.last_event_at = now_secs();
                }
            }
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

// GET /games/sessions/:id
pub async fn get_session_v2(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<Json<SessionV2Response>, (StatusCode, String)> {
    let resp = {
        let sessions = state.active_game_sessions.lock().unwrap();
        match sessions.get(&session_id) {
            None => return Err((StatusCode::NOT_FOUND, "Session not found".to_string())),
            Some(s) if s.status == "ended" || s.status == "abandoned" => {
                return Err((StatusCode::GONE, "Session has ended".to_string()));
            }
            Some(s) => session_state_to_v2_response(s),
        }
    };
    Ok(Json(resp))
}

// DELETE /games/sessions/:id  (host or manage_games)
pub async fn force_end_session(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(session_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Extract all needed data under the lock, then drop the lock before any await.
    let (channel_id, is_host) = {
        let sessions = state.active_game_sessions.lock().unwrap();
        match sessions.get(&session_id) {
            None => return Err((StatusCode::NOT_FOUND, "Session not found".to_string())),
            Some(s) => (s.channel_id.clone(), s.host_pubkey == user.public_key),
        }
    };
    if !is_host {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        if !perms.has(permissions::MANAGE_GAMES) {
            return Err((
                StatusCode::FORBIDDEN,
                "Only the host or manage_games can force-end a session".to_string(),
            ));
        }
    }

    let _ = sqlx::query(
        "UPDATE game_sessions SET ended_at = ?, status = 'ended' WHERE id = ?",
    )
    .bind(chrono_now())
    .bind(&session_id)
    .execute(&state.db)
    .await;

    state.active_game_sessions.lock().unwrap().remove(&session_id);

    broadcast_game_event(
        &state,
        &channel_id,
        WsServerMessage::GameSessionEnded {
            session_id: session_id.clone(),
            reason: Some("force_ended".to_string()),
            result: None,
        },
    );

    Ok(StatusCode::NO_CONTENT)
}

fn session_state_to_v2_response(s: &GameSessionState) -> SessionV2Response {
    let players = s
        .player_details
        .iter()
        .map(|p| PlayerInfo {
            pubkey: p.pubkey.clone(),
            display_name: p.display_name.clone(),
            joined_at: p.joined_at,
            connected: p.connected,
        })
        .collect();
    SessionV2Response {
        session_id: s.id.clone(),
        game_id: s.game_id.clone(),
        channel_id: s.channel_id.clone(),
        host_pubkey: s.host_pubkey.clone(),
        status: s.status.clone(),
        players,
        max_players: s.max_players,
        created_at: s.created_at,
        last_event_at: s.last_event_at,
    }
}

// ===========================================================================
// Farm-aware Tier 1 enable/disable routes
// ===========================================================================
//
// When the hub is paired with a farm (`state.farm_url` is `Some`), hub admins
// enable farm-installed games on this hub.  Enabling fetches the manifest from
// the farm and caches the essential fields in `hub_games`, then writes a row
// in `enabled_games`.  The Activities button and `GET /games` list only
// enabled games.
//
// Routes:
//   POST   /games/:id/enable                — hub admin, manage_games
//   DELETE /games/:id/enable                — hub admin, manage_games
//   GET    /games                           — member (player-facing; enabled + channel-scoped)
//   PUT    /admin/games/:id/channels        — hub admin, manage_games
//   GET    /admin/games                     — hub admin, manage_games (full inventory)

// ---------------------------------------------------------------------------
// Shared manifest shape returned by the farm's GET /farm/games/:id
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct FarmGameManifest {
    id: String,
    name: String,
    entry_url: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    thumbnail_url: Option<String>,
    #[serde(default = "default_version")]
    version: String,
    #[serde(default)]
    author: Option<String>,
    #[serde(default = "default_one")]
    min_players: i64,
    #[serde(default = "default_one")]
    max_players: i64,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

fn default_one() -> i64 {
    1
}

// ---------------------------------------------------------------------------
// POST /games/:id/enable
// ---------------------------------------------------------------------------

pub async fn enable_game(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(game_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    // Fetch manifest from the farm and cache it into hub_games.
    let manifest: FarmGameManifest = match &state.farm_url {
        None => {
            // Un-farmed hub: the game must already be in hub_games (installed locally).
            let exists: Option<String> =
                sqlx::query_scalar("SELECT id FROM hub_games WHERE id = ?")
                    .bind(&game_id)
                    .fetch_optional(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
            if exists.is_none() {
                return Err((StatusCode::NOT_FOUND, "Game not installed on this hub".to_string()));
            }
            // Synthesise a manifest from the local row so we can skip the upsert below.
            let row: (String, String, String, Option<String>, Option<String>, String, Option<String>, i64, i64) =
                sqlx::query_as(
                    "SELECT id, name, entry_url, description, thumbnail_url, version, author, min_players, max_players FROM hub_games WHERE id = ?",
                )
                .bind(&game_id)
                .fetch_one(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
            FarmGameManifest {
                id: row.0,
                name: row.1,
                entry_url: row.2,
                description: row.3,
                thumbnail_url: row.4,
                version: row.5,
                author: row.6,
                min_players: row.7,
                max_players: row.8,
            }
        }
        Some(farm_url) => {
            let url = format!("{farm_url}/farm/games/{game_id}");
            let resp = state
                .http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Farm unreachable: {e}")))?;
            if resp.status().as_u16() == 404 {
                return Err((StatusCode::NOT_FOUND, "Game not found on farm".to_string()));
            }
            if !resp.status().is_success() {
                return Err((
                    StatusCode::BAD_GATEWAY,
                    format!("Farm returned {}", resp.status()),
                ));
            }
            resp.json::<FarmGameManifest>()
                .await
                .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Invalid farm response: {e}")))?
        }
    };

    let now = chrono_now();

    // Upsert into hub_games (cache from farm).
    sqlx::query(
        "INSERT INTO hub_games
             (id, name, description, version, entry_url, thumbnail_url, author,
              min_players, max_players, installed_by, installed_at, manifest_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')
         ON CONFLICT(id) DO UPDATE SET
             name          = excluded.name,
             description   = excluded.description,
             version       = excluded.version,
             entry_url     = excluded.entry_url,
             thumbnail_url = excluded.thumbnail_url,
             author        = excluded.author,
             min_players   = excluded.min_players,
             max_players   = excluded.max_players",
    )
    .bind(&manifest.id)
    .bind(&manifest.name)
    .bind(&manifest.description)
    .bind(&manifest.version)
    .bind(&manifest.entry_url)
    .bind(&manifest.thumbnail_url)
    .bind(&manifest.author)
    .bind(manifest.min_players)
    .bind(manifest.max_players)
    .bind(&user.public_key)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Upsert enabled_games row.
    sqlx::query(
        "INSERT INTO enabled_games (game_id, enabled_at, enabled_by)
         VALUES (?, ?, ?)
         ON CONFLICT(game_id) DO UPDATE SET
             enabled_at = excluded.enabled_at,
             enabled_by = excluded.enabled_by",
    )
    .bind(&game_id)
    .bind(&now)
    .bind(&user.public_key)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /games/:id/enable
// ---------------------------------------------------------------------------

pub async fn disable_game(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(game_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    let rows = sqlx::query("DELETE FROM enabled_games WHERE game_id = ?")
        .bind(&game_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .rows_affected();

    if rows == 0 {
        return Err((StatusCode::NOT_FOUND, "Game not enabled on this hub".to_string()));
    }

    // Remove per-channel scope entries for this game too.
    let _ = sqlx::query("DELETE FROM channel_games WHERE game_id = ?")
        .bind(&game_id)
        .execute(&state.db)
        .await;

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /games  (player-facing — enabled + channel-scoped)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct EnabledGameEntry {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub min_players: i64,
    pub max_players: i64,
}

#[derive(serde::Serialize)]
pub struct ListEnabledGamesResponse {
    pub games: Vec<EnabledGameEntry>,
}

pub async fn list_enabled_games(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<ListEnabledGamesResponse>, (StatusCode, String)> {
    // Return all hub-enabled games. Channel-scoped filtering is done client-side
    // (the client knows which channel is open and can call with a channel_id param
    // in the future; for now we return the full enabled list and let the client
    // apply the channel restriction using the /admin/games/:id/channels data).
    let rows: Vec<(String, String, String, Option<String>, Option<String>, String, Option<String>, i64, i64)> = sqlx::query_as(
        "SELECT g.id, g.name, g.entry_url, g.description, g.thumbnail_url, g.version, g.author,
                g.min_players, g.max_players
         FROM hub_games g
         INNER JOIN enabled_games e ON e.game_id = g.id
         ORDER BY g.name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let games = rows
        .into_iter()
        .map(|(id, name, entry_url, description, thumbnail_url, version, author, min_players, max_players)| {
            EnabledGameEntry {
                id,
                name,
                entry_url,
                description,
                thumbnail_url,
                version,
                author,
                min_players,
                max_players,
            }
        })
        .collect();

    Ok(Json(ListEnabledGamesResponse { games }))
}

// ---------------------------------------------------------------------------
// PUT /admin/games/:id/channels   body: { channel_ids: [String] }
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct SetChannelScopeRequest {
    pub channel_ids: Vec<String>,
}

pub async fn set_game_channels(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(game_id): Path<String>,
    Json(req): Json<SetChannelScopeRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    // Game must be enabled on this hub.
    let enabled: Option<String> =
        sqlx::query_scalar("SELECT game_id FROM enabled_games WHERE game_id = ?")
            .bind(&game_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if enabled.is_none() {
        return Err((StatusCode::NOT_FOUND, "Game not enabled on this hub".to_string()));
    }

    // Replace channel scope atomically: delete old rows, insert new ones.
    sqlx::query("DELETE FROM channel_games WHERE game_id = ?")
        .bind(&game_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for channel_id in &req.channel_ids {
        sqlx::query(
            "INSERT OR IGNORE INTO channel_games (channel_id, game_id) VALUES (?, ?)",
        )
        .bind(channel_id)
        .bind(&game_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /admin/games  (manage_games — full inventory with channel scope)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct AdminGameEntry {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub min_players: i64,
    pub max_players: i64,
    pub enabled: bool,
    pub enabled_by: Option<String>,
    pub enabled_at: Option<String>,
    /// Channel IDs this game is restricted to. Empty vec = all channels.
    pub channel_scope: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct AdminListGamesResponse {
    pub games: Vec<AdminGameEntry>,
}

pub async fn admin_list_games(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<AdminListGamesResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_GAMES)?;

    let rows: Vec<(String, String, String, Option<String>, Option<String>, String, Option<String>, i64, i64, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT g.id, g.name, g.entry_url, g.description, g.thumbnail_url, g.version, g.author,
                g.min_players, g.max_players,
                e.enabled_by, e.enabled_at
         FROM hub_games g
         LEFT JOIN enabled_games e ON e.game_id = g.id
         ORDER BY g.name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut games = Vec::with_capacity(rows.len());
    for (id, name, entry_url, description, thumbnail_url, version, author, min_players, max_players, enabled_by, enabled_at) in rows {
        let enabled = enabled_by.is_some();
        let channel_scope: Vec<String> = sqlx::query_scalar(
            "SELECT channel_id FROM channel_games WHERE game_id = ? ORDER BY channel_id",
        )
        .bind(&id)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        games.push(AdminGameEntry {
            id,
            name,
            entry_url,
            description,
            thumbnail_url,
            version,
            author,
            min_players,
            max_players,
            enabled,
            enabled_by,
            enabled_at,
            channel_scope,
        });
    }

    Ok(Json(AdminListGamesResponse { games }))
}
