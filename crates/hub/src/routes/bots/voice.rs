use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

use super::models::authenticate_bot;

#[derive(Deserialize)]
pub struct VoiceJoinRequest {
    pub channel_id: String,
}

#[derive(Serialize)]
pub struct VoiceJoinResponse {
    pub voice_ws_url: String,
    pub channel_id: String,
}

/// POST /bots/{id}/voice/join
///
/// Tells the hub which voice channel the bot wants to join. The bot must
/// authenticate as itself via `Authorization: Bearer <bot_token>` and the
/// `{id}` path parameter must match its own public key.
///
/// Returns the WebSocket URL the bot should connect to with its token as
/// `?token=<bot_token>&channel_id=<channel_id>`.
pub async fn bot_voice_join(
    Path(bot_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VoiceJoinRequest>,
) -> Result<Json<VoiceJoinResponse>, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    // Caller must be the bot identified by the path parameter.
    if bot.public_key != bot_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Only the bot itself may call this".into(),
        ));
    }

    // Verify channel exists and is not a category.
    let channel_exists: Option<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE id = $1 AND is_category = false")
            .bind(&req.channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if channel_exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".into()));
    }

    // NOTE: this endpoint serves the pre-existing "self-service bot" system
    // (`/admin/bots`, token-hash auth via `authenticate_bot`) and is
    // deliberately left ungated here, unchanged from its original M3
    // behavior. The `can_speak_voice` capability gate (soundboard.md §2)
    // lives in `voice_ws_task` (`routes/voice_ws.rs`) instead, which is the
    // actual connection/enforcement point and applies to the external-bot
    // system (`is_bot=true` users authenticating via the normal Ed25519 +
    // session-token flow, capabilities in `bot_profiles`) that the
    // soundboard design doc's Part B targets. Self-service bots never
    // populate `bot_profiles`, so gating this REST helper on that table
    // would silently break the existing self-service voice-join flow for a
    // system the capability model doesn't apply to.

    // Return the path the bot should connect to. The bot already knows the hub
    // base URL; it connects to /voice/ws?token=<bot_token>&channel_id=<id>.
    let voice_ws_url = "/voice/ws".to_string();

    Ok(Json(VoiceJoinResponse {
        voice_ws_url,
        channel_id: req.channel_id,
    }))
}

#[derive(Deserialize)]
pub struct VoiceLeaveRequest {
    pub channel_id: String,
}

/// DELETE /bots/{id}/voice/leave
///
/// Removes the bot from the specified voice channel using the same cleanup
/// path as a normal WebSocket disconnect. Idempotent — calling it when the
/// bot is not in the channel is a no-op.
pub async fn bot_voice_leave(
    Path(bot_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<VoiceLeaveRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let bot = authenticate_bot(&state.db, &headers).await?;

    if bot.public_key != bot_id {
        return Err((
            StatusCode::FORBIDDEN,
            "Only the bot itself may call this".into(),
        ));
    }

    // Trigger the same cleanup as a normal voice leave.
    crate::routes::ws::leave_voice(&state, &bot.public_key, &req.channel_id).await;

    Ok(StatusCode::NO_CONTENT)
}
