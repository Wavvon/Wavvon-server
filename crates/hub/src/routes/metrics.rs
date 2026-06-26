use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;

use crate::state::AppState;

pub async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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

    let db_size = std::fs::metadata("hub.db").map(|m| m.len()).unwrap_or(0);

    let messages_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let body = format!(
        "# HELP voxply_online_users Currently connected users\n\
         # TYPE voxply_online_users gauge\nvoxply_online_users {online_users}\n\
         # HELP voxply_voice_participants Users in voice channels\n\
         # TYPE voxply_voice_participants gauge\nvoxply_voice_participants {voice_participants}\n\
         # HELP voxply_active_video_channels Channels with video enabled\n\
         # TYPE voxply_active_video_channels gauge\nvoxply_active_video_channels {active_video_channels}\n\
         # HELP voxply_messages_total Total messages stored\n\
         # TYPE voxply_messages_total counter\nvoxply_messages_total {messages_total}\n\
         # HELP voxply_uptime_seconds Hub uptime in seconds\n\
         # TYPE voxply_uptime_seconds gauge\nvoxply_uptime_seconds {uptime_secs}\n\
         # HELP voxply_db_size_bytes SQLite database file size\n\
         # TYPE voxply_db_size_bytes gauge\nvoxply_db_size_bytes {db_size}\n"
    );

    axum::response::Response::builder()
        .header("content-type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(body))
        .unwrap()
}
