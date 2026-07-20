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

/// Single sweep pass. Public for tests.
pub async fn run_sweep(state: &AppState) {
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
              AND m.created_at < $1 - (c.retention_days * 86400)
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
              AND p.created_at < $1 - (c.retention_days * 86400)
        )",
    )
    .bind(now)
    .execute(&state.db)
    .await;

    // Expire stale key-rotation requests (recovery-attestation.md §4
    // "Expiry: 14-day sweep"). A request that never gathers enough
    // attestations to reach admin review shouldn't linger indefinitely --
    // only 'pending' rows are touched, never 'ready_for_review' (already
    // earned admin attention) or a decided/expired terminal state.
    const ROTATION_REQUEST_EXPIRY_SECS: i64 = 14 * 86400;
    let _ = sqlx::query(
        "UPDATE key_rotation_requests
         SET status = 'expired'
         WHERE status = 'pending' AND created_at < $1 - $2",
    )
    .bind(now)
    .bind(ROTATION_REQUEST_EXPIRY_SECS)
    .execute(&state.db)
    .await;

    tracing::info!("Data retention sweep complete");
}
