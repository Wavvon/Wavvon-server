//! Legacy channel-scoped session routes (Tier 1 original shape).

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::WsServerMessage;
use crate::state::{AppState, GamePlayer, GameSessionState};

use super::helpers::{
    broadcast_game_event, chrono_now, fetch_open_session, now_secs, session_row_to_response,
};
use super::models::{
    CreateSessionRequest, KvResponse, PatchStateRequest, SessionResponse, SetKvRequest,
};
use uuid::Uuid;

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
    let game_exists: Option<String> = sqlx::query_scalar("SELECT id FROM hub_games WHERE id = ?")
        .bind(&req.game_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if game_exists.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "Game not found on this hub".to_string(),
        ));
    }

    // Verify the channel exists.
    let ch_exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
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
        let mut sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let mut sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
            return Err((
                StatusCode::FORBIDDEN,
                "Only the host can patch session state".to_string(),
            ));
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
    .ok_or((
        StatusCode::NOT_FOUND,
        "Session not found or ended".to_string(),
    ))?;

    let mut current: serde_json::Value = serde_json::from_str(&current_json)
        .unwrap_or(serde_json::Value::Object(Default::default()));

    if let (Some(obj), Some(patch_obj)) = (current.as_object_mut(), req.patch.as_object()) {
        for (k, v) in patch_obj {
            obj.insert(k.clone(), v.clone());
        }
    } else {
        current = req.patch.clone();
    }

    let new_json = serde_json::to_string(&current).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("JSON error: {e}"),
        )
    })?;
    sqlx::query("UPDATE game_sessions SET state_json = ? WHERE id = ?")
        .bind(&new_json)
        .bind(&session_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Update in-memory state too.
    {
        let mut sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
            return Err((
                StatusCode::FORBIDDEN,
                "Only the host or an admin can end the session".to_string(),
            ));
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
        let mut sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
