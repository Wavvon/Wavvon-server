//! The polling transport, for a program that holds no persistent WebSocket.
//! It reads the same audit log that Resume replays, so a poll hands back the
//! `hub_event` envelopes the socket would have pushed, and a program needs one
//! decoder whichever transport it uses. Nothing is queued per app: the caller
//! keeps the last `seq` it saw and passes it back as `cursor`.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::apps::events::ReplayResult;
use crate::auth::middleware::AuthUser;
use crate::state::AppState;

/// One poll hands back at most this many events; a full page means ask again
/// with the last `seq` as `cursor`.
const MAX_EVENTS_PER_POLL: usize = 100;

#[derive(Deserialize)]
pub struct PollQuery {
    pub cursor: Option<i64>,
    pub limit: Option<usize>,
}

/// GET /me/events — the events after `cursor` (or from the start of the
/// 72-hour window), oldest first. A cursor that has fallen out of the window
/// is a 410 carrying the same body as the socket's `replay_unavailable`.
pub async fn poll_events(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<PollQuery>,
) -> Response {
    let limit = params
        .limit
        .unwrap_or(MAX_EVENTS_PER_POLL)
        .clamp(1, MAX_EVENTS_PER_POLL);
    match crate::apps::events::events_for_app(&state, &user.public_key, params.cursor, limit).await
    {
        Ok(events) => Json(events).into_response(),
        Err(ReplayResult::Unavailable {
            earliest_seq,
            earliest_at,
        }) => (
            StatusCode::GONE,
            Json(serde_json::json!({
                "type": "replay_unavailable",
                "earliest_seq": earliest_seq,
                "earliest_at": earliest_at,
            })),
        )
            .into_response(),
        Err(ReplayResult::Complete { .. }) => Json(Vec::<()>::new()).into_response(),
    }
}
