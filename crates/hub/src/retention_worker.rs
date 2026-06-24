use std::sync::Arc;

use crate::state::AppState;

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400)); // 24h
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            run_sweep(&state).await;
        }
    });
}

async fn run_sweep(state: &AppState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Delete old messages per channel retention policy.
    let _ = sqlx::query(
        "DELETE FROM messages WHERE id IN (
            SELECT m.id FROM messages m
            JOIN channels c ON c.id = m.channel_id
            WHERE c.retention_days IS NOT NULL
              AND m.created_at < ? - (c.retention_days * 86400)
        )",
    )
    .bind(now)
    .execute(&state.db)
    .await;

    // Delete old forum posts (replies cascade via ON DELETE CASCADE).
    let _ = sqlx::query(
        "DELETE FROM posts WHERE id IN (
            SELECT p.id FROM posts p
            JOIN channels c ON c.id = p.channel_id
            WHERE c.retention_days IS NOT NULL
              AND p.created_at < ? - (c.retention_days * 86400)
        )",
    )
    .bind(now)
    .execute(&state.db)
    .await;

    tracing::info!("Data retention sweep complete");
}
