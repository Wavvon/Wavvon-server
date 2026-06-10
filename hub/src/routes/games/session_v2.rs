//! Spec Tier 2 session routes.

use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::WsServerMessage;
use crate::state::{AppState, GamePlayer, GameSessionState};

use super::helpers::{broadcast_game_event, chrono_now, now_secs, session_state_to_v2_response};
use super::models::{
    CreateSessionV2Request, ListSessionsQuery, ListSessionsResponse, SessionV2Response,
};
use uuid::Uuid;

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
        return Err((
            StatusCode::NOT_FOUND,
            "Game not found on this hub".to_string(),
        ));
    }
    let db_max_players = game_row.and_then(|(_, m)| if m > 1 { Some(m) } else { None });

    let ch_exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
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
        let mut sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

    use super::models::PlayerInfo;
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
        let sessions_guard = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let s = sessions
            .get(&session_id)
            .ok_or((StatusCode::NOT_FOUND, "Session not found".to_string()))?;
        if s.status == "ended" || s.status == "abandoned" {
            return Err((StatusCode::GONE, "Session has ended".to_string()));
        }
        let already_in = s.players.contains(&user.public_key);
        (
            s.channel_id.clone(),
            s.max_players,
            s.players.len() as i64,
            already_in,
        )
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
        let mut sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let mut sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let _ =
            sqlx::query("UPDATE game_sessions SET ended_at = ?, status = 'abandoned' WHERE id = ?")
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
        state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
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
        let sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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
        let sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

    let _ = sqlx::query("UPDATE game_sessions SET ended_at = ?, status = 'ended' WHERE id = ?")
        .bind(chrono_now())
        .bind(&session_id)
        .execute(&state.db)
        .await;

    state
        .active_game_sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&session_id);

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
