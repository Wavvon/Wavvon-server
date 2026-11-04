use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// Not found unless the operator set `WAVVON_METRICS=true`: a hub that has
/// not opted in looks the same as one built without the route.
pub async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    if !state.metrics_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    let online_users = state.online_users.read().await.len();
    let voice_participants: usize = state
        .voice_channels
        .read()
        .await
        .values()
        .map(|c| c.len())
        .sum();
    let active_video_channels = state
        .video_channels
        .read()
        .await
        .values()
        .filter(|s| !s.is_empty())
        .count();
    let uptime_secs = state.started_at.elapsed().as_secs();

    let messages_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let attachments = crate::attachments::usage(&state.db).await;
    let attachments_used = attachments.used_bytes;
    let attachments_cap = attachments.cap_bytes;
    let attachments_evictions = attachments.evictions;

    let body = format!(
        "# HELP wavvon_online_users Currently connected users\n\
         # TYPE wavvon_online_users gauge\nwavvon_online_users {online_users}\n\
         # HELP wavvon_voice_participants Users in voice channels\n\
         # TYPE wavvon_voice_participants gauge\nwavvon_voice_participants {voice_participants}\n\
         # HELP wavvon_active_video_channels Channels with video enabled\n\
         # TYPE wavvon_active_video_channels gauge\nwavvon_active_video_channels {active_video_channels}\n\
         # HELP wavvon_messages_total Total messages stored\n\
         # TYPE wavvon_messages_total counter\nwavvon_messages_total {messages_total}\n\
         # HELP wavvon_attachments_bytes Bytes of stored attachment blobs\n\
         # TYPE wavvon_attachments_bytes gauge\nwavvon_attachments_bytes {attachments_used}\n\
         # HELP wavvon_attachments_cap_bytes Configured attachment disk budget\n\
         # TYPE wavvon_attachments_cap_bytes gauge\nwavvon_attachments_cap_bytes {attachments_cap}\n\
         # HELP wavvon_attachments_evictions_total Blobs evicted for space since start\n\
         # TYPE wavvon_attachments_evictions_total counter\nwavvon_attachments_evictions_total {attachments_evictions}\n\
         # HELP wavvon_uptime_seconds Hub uptime in seconds\n\
         # TYPE wavvon_uptime_seconds gauge\nwavvon_uptime_seconds {uptime_secs}\n"
    );

    axum::response::Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(body))
        .unwrap()
}
