//! Background worker that manages bot session token expiry.
//!
//! Two sweeps per tick (every 15 minutes):
//!
//! 1. **Warning sweep** — finds bot sessions expiring within 72 hours that
//!    haven't been warned in the last 24 hours. Pushes
//!    `{ "type": "token_expiring_soon", "expires_at": <ts> }` over the bot's
//!    WS connection, then marks `expiry_warned_at = now`.
//!
//! 2. **Expiry sweep** — finds bot sessions whose `expires_at` is in the
//!    past. Pushes `{ "type": "bot_removed", "reason": "token_expired" }`,
//!    drops the WS sender (causing the WS task to close), and deletes the
//!    session row.
//!
//! The `tick` function is public so tests can drive it directly without
//! waiting for the real timer.

use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(15 * 60); // 15 minutes
const WARN_WINDOW_SECS: i64 = 72 * 3600; // 72 hours before expiry
const REWARN_COOLDOWN_SECS: i64 = 24 * 3600; // don't re-warn within 24 h

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Err(e) = tick(&state).await {
                tracing::warn!("token_expiry tick failed: {e}");
            }
        }
    });
}

/// One pass: warn about expiring sessions, then close expired ones.
pub async fn tick(state: &AppState) -> Result<(), sqlx::Error> {
    let now = crate::auth::handlers::unix_timestamp();
    sweep_warnings(state, now).await?;
    sweep_expired(state, now).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Warning sweep
// ---------------------------------------------------------------------------

async fn sweep_warnings(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    let warn_before = now + WARN_WINDOW_SECS;
    let rewarn_cutoff = now - REWARN_COOLDOWN_SECS;

    #[derive(sqlx::FromRow)]
    struct SessionRow {
        token: String,
        public_key: String,
        expires_at: i64,
    }

    let rows: Vec<SessionRow> = sqlx::query_as::<_, SessionRow>(
        "SELECT s.token, s.public_key, s.expires_at
         FROM sessions s
         JOIN users u ON u.public_key = s.public_key
         WHERE u.is_bot = 1
           AND s.expires_at IS NOT NULL
           AND s.expires_at > ?
           AND s.expires_at <= ?
           AND (s.expiry_warned_at IS NULL OR s.expiry_warned_at < ?)",
    )
    .bind(now) // not yet expired
    .bind(warn_before) // but within the 72-hour window
    .bind(rewarn_cutoff) // and not warned in the last 24 h
    .fetch_all(&state.db)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    let sessions = state.bot_sessions.read().await;

    for row in &rows {
        // Deliver to all active WS sessions for this bot pubkey.
        if let Some(per_bot) = sessions.get(&row.public_key) {
            let msg = serde_json::json!({
                "type": "token_expiring_soon",
                "expires_at": row.expires_at,
            })
            .to_string();
            for tx in per_bot.values() {
                let _ = tx.try_send(msg.clone());
            }
        }

        // Mark warned regardless of whether the bot is currently connected.
        let _ = sqlx::query("UPDATE sessions SET expiry_warned_at = ? WHERE token = ?")
            .bind(now)
            .bind(&row.token)
            .execute(&state.db)
            .await;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Expiry sweep
// ---------------------------------------------------------------------------

async fn sweep_expired(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct ExpiredRow {
        token: String,
        public_key: String,
    }

    let rows: Vec<ExpiredRow> = sqlx::query_as::<_, ExpiredRow>(
        "SELECT s.token, s.public_key
         FROM sessions s
         JOIN users u ON u.public_key = s.public_key
         WHERE u.is_bot = 1
           AND s.expires_at IS NOT NULL
           AND s.expires_at < ?",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await?;

    if rows.is_empty() {
        return Ok(());
    }

    // We need a write lock to remove the sender entries from bot_sessions.
    let mut sessions = state.bot_sessions.write().await;

    for row in &rows {
        // Token expiry is pubkey-wide: remove all WS sessions for this pubkey
        // and push bot_removed to each, so every live connection is closed.
        if let Some(per_bot) = sessions.remove(&row.public_key) {
            let msg = serde_json::json!({
                "type": "bot_removed",
                "reason": "token_expired",
            })
            .to_string();
            // Best-effort: the channel may already be full or the bot gone.
            // Dropping each `tx` closes its mpsc channel; the WS write loop
            // in ws.rs will see `None` from `rx.recv()` and close the socket.
            for tx in per_bot.into_values() {
                let _ = tx.try_send(msg.clone());
            }
        }

        // Delete the expired session row.
        let _ = sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(&row.token)
            .execute(&state.db)
            .await;

        tracing::info!(
            pubkey = &row.public_key[..16.min(row.public_key.len())],
            "Bot session expired — removed and WS closed"
        );
    }

    Ok(())
}
