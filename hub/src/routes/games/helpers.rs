use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::{AppState, GameSessionState};

use super::models::{PlayerInfo, SessionResponse, SessionV2Response};

// ---------------------------------------------------------------------------
// Helper: broadcast a WsServerMessage to all channel subscribers via chat_tx.
// ---------------------------------------------------------------------------
pub(super) fn broadcast_game_event(state: &AppState, channel_id: &str, msg: WsServerMessage) {
    let event = ChatEvent::Game {
        channel_id: channel_id.to_string(),
    };
    let serialized = serde_json::to_string(&msg).unwrap_or_else(|e| {
        tracing::error!("game serialize: {e}");
        String::from("{}")
    });
    let json: std::sync::Arc<str> = std::sync::Arc::from(serialized.as_str());
    let _ = state.chat_tx.send((event, json));
}

// ---------------------------------------------------------------------------
// Internal DB row type for legacy session routes.
// ---------------------------------------------------------------------------

pub(super) struct SessionRow {
    pub channel_id: String,
    pub game_id: String,
    pub host_pubkey: String,
    pub state_json: String,
    pub created_at: String,
    pub ended_at: Option<String>,
}

pub(super) async fn fetch_open_session(
    state: &AppState,
    session_id: &str,
) -> Result<SessionRow, (axum::http::StatusCode, String)> {
    let row: Option<(String, String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT channel_id, game_id, host_pubkey, state_json, created_at, ended_at
         FROM game_sessions WHERE id = ?",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("DB error: {e}"),
        )
    })?;

    match row {
        None => Err((
            axum::http::StatusCode::NOT_FOUND,
            "Session not found".to_string(),
        )),
        Some((channel_id, game_id, host_pubkey, state_json, created_at, ended_at)) => {
            if ended_at.is_some() {
                return Err((
                    axum::http::StatusCode::GONE,
                    "Session has ended".to_string(),
                ));
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

pub(super) fn session_row_to_response(
    row: SessionRow,
    state: &AppState,
    session_id: &str,
) -> SessionResponse {
    let players: Vec<String> = {
        let sessions = state
            .active_game_sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        sessions
            .get(session_id)
            .map(|s| s.players.iter().cloned().collect())
            .unwrap_or_default()
    };
    let state_json: serde_json::Value = serde_json::from_str(&row.state_json)
        .unwrap_or(serde_json::Value::Object(Default::default()));
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

pub(super) fn chrono_now() -> String {
    // Use the same unix-seconds string pattern used elsewhere in the hub for
    // TEXT timestamp columns.
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    secs.to_string()
}

pub(super) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(super) fn session_state_to_v2_response(s: &GameSessionState) -> SessionV2Response {
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
