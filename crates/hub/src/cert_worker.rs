//! Background worker that periodically issues certifications to eligible members.
//!
//! Eligibility criteria:
//!  1. Member has existed at least `cert_standing_days` days.
//!  2. Member is `approval_status = 'approved'` and not banned.
//!  3. No existing non-expired, non-revoked cert from this hub.
//!  4. `cert_auto_issue` setting is 'true'.
//!  5. Member's pow_level >= `cert_min_pow_level` setting (when set).
//!
//! The worker wakes once per hour and sweeps all eligible members,
//! skipping any that already have a fresh cert.

use std::sync::Arc;
use std::time::Duration;

use crate::routes::certs::issue_cert_for;
use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(3600); // 1 hour

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Err(e) = tick(&state).await {
                tracing::warn!("Cert worker tick failed: {e}");
            }
        }
    });
}

/// Run a single issuance sweep. Public for tests.
pub async fn tick(state: &AppState) -> anyhow::Result<()> {
    // Check auto-issue setting
    let auto_issue: bool = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_auto_issue'",
    )
    .fetch_optional(&state.db)
    .await?
    .map(|v| v == "true")
    .unwrap_or(true);

    if !auto_issue {
        return Ok(());
    }

    let standing_days: i64 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_standing_days'",
    )
    .fetch_optional(&state.db)
    .await?
    .and_then(|v| v.parse().ok())
    .unwrap_or(30);

    // Minimum pow_level required for auto-issuance; 0 means no restriction.
    let min_pow_level: i64 = sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'cert_min_pow_level'",
    )
    .fetch_optional(&state.db)
    .await?
    .and_then(|v| v.parse().ok())
    .unwrap_or(0);

    let now = crate::auth::handlers::unix_timestamp();
    let threshold = now - standing_days * 86400;

    // Candidates: approved, non-bot users who joined before the standing threshold
    // and whose pow_level meets the minimum (COALESCE to 0 when column absent/null),
    // and who have no non-revoked, non-expired cert currently active.
    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT u.public_key
         FROM users u
         WHERE u.approval_status = 'approved'
           AND COALESCE(u.is_bot, FALSE) = FALSE
           AND u.first_seen_at <= $1
           AND COALESCE(u.pow_level, 0) >= $2
           AND NOT EXISTS (
               SELECT 1 FROM cert_issuances ci
               WHERE ci.subject_pubkey = u.public_key
                 AND ci.standing = 'good'
                 AND ci.revoked_at IS NULL
                 AND ci.expires_at > $3
           )
         LIMIT 500",
    )
    .bind(threshold)
    .bind(min_pow_level)
    .bind(now)
    .fetch_all(&state.db)
    .await?;

    if candidates.is_empty() {
        return Ok(());
    }

    tracing::info!("Cert worker: sweeping {} candidates", candidates.len());

    // Load banned pubkeys in one query to avoid per-user ban checks.
    let banned: std::collections::HashSet<String> =
        sqlx::query_scalar::<_, String>("SELECT target_public_key FROM bans")
            .fetch_all(&state.db)
            .await?
            .into_iter()
            .collect();

    let mut issued = 0usize;
    for pubkey in candidates {
        if banned.contains(&pubkey) {
            continue;
        }
        match issue_cert_for(state, &pubkey).await {
            Ok(_) => {
                issued += 1;
            }
            Err((code, msg)) => {
                tracing::debug!(
                    "Cert worker skipped {}: HTTP {} — {msg}",
                    &pubkey[..16.min(pubkey.len())],
                    code,
                );
            }
        }
    }

    tracing::info!("Cert worker: issued {issued} new certs");
    Ok(())
}
