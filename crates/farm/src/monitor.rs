//! Hub process supervision — the missing piece of farm-impl.md Phase 2
//! "process supervision". `hub_manager.rs` already has spawn/stop/restart;
//! `routes/heartbeat.rs` already tracks online/offline (180s threshold); this
//! module is what acts on offline status.
//!
//! Wakes every 30s, finds non-suspended, non-deleted hubs with
//! `auto_restart_enabled` whose last heartbeat is stale, and restarts them
//! with exponential backoff: farm-local hubs (`server_id IS NULL`) via
//! `HubManager::restart_hub`, agent-hosted hubs (`server_id` set) via a
//! `restart_hub` command sent over the owning agent's WebSocket
//! (`FarmState::send_restart_to_agent`). If that agent isn't connected the
//! attempt is logged and skipped — the next tick tries again. After 5
//! attempts auto-restart disables itself for that hub. The counter is reset
//! to zero elsewhere — in `routes::heartbeat::receive_heartbeat`, the moment
//! a hub is seen online again.

use std::sync::Arc;
use std::time::Duration;

use crate::state::FarmState;
use crate::unix_now;

const POLL_INTERVAL: Duration = Duration::from_secs(30);
const OFFLINE_THRESHOLD_SECS: i64 = 180;
const BASE_BACKOFF_SECS: i64 = 10;
const MAX_BACKOFF_SECS: i64 = 300;
const MAX_ATTEMPTS: i32 = 5;

pub fn spawn(state: Arc<FarmState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Err(e) = tick(&state).await {
                tracing::warn!("Hub supervision tick failed: {e}");
            }
        }
    });
}

/// What supervision should do about one hub on this tick. Pure function of
/// the hub's observed state — no I/O — so it's unit-testable directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Heartbeat is within the offline threshold — nothing to do.
    Healthy,
    /// Offline, but still inside the backoff window since the last attempt.
    Backoff,
    /// Offline, backoff elapsed (or no restart tried yet) — restart now.
    Restart,
    /// Offline and out of attempts — disable auto-restart for this hub.
    GiveUp,
}

/// `10s * 2^attempts`, capped at 5 minutes.
fn backoff_secs(attempts: i32) -> i64 {
    (BASE_BACKOFF_SECS * 2i64.pow(attempts.max(0) as u32)).min(MAX_BACKOFF_SECS)
}

/// `effective_last_seen` is the hub's last heartbeat, falling back to its
/// `created_at` when it has never reported one (so a hub that hasn't sent
/// its first 60s heartbeat yet isn't immediately flagged offline).
pub fn decide(
    effective_last_seen: i64,
    attempts: i32,
    last_restart_at: Option<i64>,
    now: i64,
) -> Decision {
    if now - effective_last_seen < OFFLINE_THRESHOLD_SECS {
        return Decision::Healthy;
    }
    if attempts >= MAX_ATTEMPTS {
        return Decision::GiveUp;
    }
    if let Some(last_restart) = last_restart_at {
        if now - last_restart < backoff_secs(attempts) {
            return Decision::Backoff;
        }
    }
    Decision::Restart
}

/// One supervision pass. Public so it can be driven directly in tests.
pub async fn tick(state: &FarmState) -> Result<(), sqlx::Error> {
    let now = unix_now();

    #[allow(clippy::type_complexity)]
    let rows: Vec<(
        String,
        String,
        i32,
        i32,
        Option<i64>,
        i64,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT h.id, h.db_path, h.process_port, h.restart_attempts, h.last_restart_at,
                COALESCE(hb.last_seen_at, h.created_at) AS effective_last_seen,
                h.server_id, h.owner_pubkey
         FROM hubs h
         LEFT JOIN hub_heartbeats hb ON hb.hub_pubkey = h.hub_pubkey
         WHERE h.suspended_at IS NULL
           AND h.deleted_at IS NULL
           AND h.auto_restart_enabled = TRUE
           AND h.process_port IS NOT NULL",
    )
    .fetch_all(&state.db)
    .await?;

    for (
        hub_id,
        db_path,
        port,
        attempts,
        last_restart_at,
        effective_last_seen,
        server_id,
        owner_pubkey,
    ) in rows
    {
        match decide(effective_last_seen, attempts, last_restart_at, now) {
            Decision::Healthy | Decision::Backoff => {}
            Decision::Restart => {
                tracing::warn!(hub_id, attempts, "Hub offline — attempting auto-restart");
                if let Some(ref server_id) = server_id {
                    if state
                        .send_restart_to_agent(
                            server_id,
                            &hub_id,
                            &db_path,
                            port as u16,
                            Some(&owner_pubkey),
                        )
                        .await
                        .is_err()
                    {
                        tracing::warn!(
                            hub_id,
                            server_id,
                            "Auto-restart failed — owning agent offline"
                        );
                    }
                } else if let Err(e) = state
                    .hub_manager
                    .restart_hub(&hub_id, &db_path, port as u16)
                    .await
                {
                    tracing::warn!(hub_id, error = %e, "Auto-restart failed to spawn hub");
                }
                let _ = sqlx::query(
                    "UPDATE hubs SET restart_attempts = restart_attempts + 1, last_restart_at = $1
                     WHERE id = $2",
                )
                .bind(now)
                .bind(&hub_id)
                .execute(&state.db)
                .await;
            }
            Decision::GiveUp => {
                tracing::error!(
                    hub_id,
                    attempts,
                    "Hub exceeded max auto-restart attempts ({MAX_ATTEMPTS}); disabling auto-restart"
                );
                let _ = sqlx::query("UPDATE hubs SET auto_restart_enabled = FALSE WHERE id = $1")
                    .bind(&hub_id)
                    .execute(&state.db)
                    .await;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_within_threshold() {
        let now = 1_000_000;
        assert_eq!(decide(now - 100, 0, None, now), Decision::Healthy);
        // Even with attempts maxed out, a fresh heartbeat means healthy.
        assert_eq!(decide(now - 179, 9, Some(now - 1), now), Decision::Healthy);
    }

    #[test]
    fn restart_when_offline_and_never_attempted() {
        let now = 1_000_000;
        assert_eq!(decide(now - 180, 0, None, now), Decision::Restart);
        assert_eq!(decide(now - 500, 3, None, now), Decision::Restart);
    }

    #[test]
    fn backoff_window_blocks_immediate_retry() {
        let now = 1_000_000;
        // attempts=1 -> backoff = 20s. Restarted 5s ago -> still backing off.
        assert_eq!(decide(now - 300, 1, Some(now - 5), now), Decision::Backoff);
        // Restarted 25s ago (past the 20s window) -> retry now.
        assert_eq!(decide(now - 300, 1, Some(now - 25), now), Decision::Restart);
    }

    #[test]
    fn gives_up_after_max_attempts() {
        let now = 1_000_000;
        assert_eq!(
            decide(now - 300, 5, Some(now - 1000), now),
            Decision::GiveUp
        );
        assert_eq!(decide(now - 300, 6, None, now), Decision::GiveUp);
    }

    #[test]
    fn backoff_grows_exponentially_and_caps_at_five_minutes() {
        assert_eq!(backoff_secs(0), 10);
        assert_eq!(backoff_secs(1), 20);
        assert_eq!(backoff_secs(2), 40);
        assert_eq!(backoff_secs(4), 160);
        assert_eq!(backoff_secs(10), 300); // capped
    }
}
