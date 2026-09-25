use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;

use crate::state::AppState;

use crate::auth::middleware::AuthUser;

#[derive(Deserialize)]
pub struct VoiceLeaveRequest {
    pub channel_id: String,
}

/// DELETE /voice/leave
///
/// Removes the calling identity from the given voice channel through the same
/// cleanup path as a WebSocket disconnect, for a client that has no socket to
/// drop. Idempotent — a caller who is not in the channel gets 204 too.
pub async fn voice_leave(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<VoiceLeaveRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::routes::ws::leave_voice(&state, &user.public_key, &req.channel_id).await;

    Ok(StatusCode::NO_CONTENT)
}
