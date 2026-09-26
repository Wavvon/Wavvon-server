//! The polling transport behind `app_subscriptions`, for a client that holds
//! no persistent WebSocket. Rows only exist for an identity that registered
//! subscriptions, so the queue is self-scoped and needs no gate of its own.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;

use crate::state::AppState;

/// One poll hands back at most this many events. A client that finds the
/// page full asks again with `since`; the cap is what stops one long-absent
/// subscriber pulling the whole queue into memory at once.
const MAX_EVENTS_PER_POLL: i64 = 100;

use super::models::{AckRequest, EventInfo, EventRow, PollQuery};
use crate::auth::middleware::AuthUser;

/// GET /me/events — poll undelivered events
pub async fn poll_events(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<PollQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let rows = if let Some(since) = params.since {
        sqlx::query_as::<_, EventRow>(
            "SELECT id, event_type, payload, created_at FROM app_event_queue
             WHERE app_pubkey = $1 AND delivered = FALSE AND created_at > $2
             ORDER BY created_at ASC LIMIT $3",
        )
        .bind(&user.public_key)
        .bind(since)
        .bind(MAX_EVENTS_PER_POLL)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, EventRow>(
            "SELECT id, event_type, payload, created_at FROM app_event_queue
             WHERE app_pubkey = $1 AND delivered = FALSE
             ORDER BY created_at ASC LIMIT $2",
        )
        .bind(&user.public_key)
        .bind(MAX_EVENTS_PER_POLL)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let events: Vec<EventInfo> = rows
        .into_iter()
        .map(|r| EventInfo {
            id: r.id,
            event_type: r.event_type,
            payload: r.payload,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(serde_json::json!({ "events": events })))
}

/// DELETE /me/events — acknowledge events as delivered
pub async fn ack_events(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<AckRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    for id in &req.ids {
        let _ = sqlx::query(
            "UPDATE app_event_queue SET delivered = TRUE
             WHERE id = $1 AND app_pubkey = $2",
        )
        .bind(id)
        .bind(&user.public_key)
        .execute(&state.db)
        .await;
    }

    Ok(StatusCode::OK)
}
