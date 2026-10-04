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

    prune_personal_axis(state, now - PERSONAL_AXIS_RETENTION_SECS).await;

    tracing::info!("Data retention sweep complete");
}

/// How long a master's personal-axis rows must have sat untouched before a
/// master with no tie to this hub is forgotten (Wavvon-server#87).
const PERSONAL_AXIS_RETENTION_SECS: i64 = 90 * 86400;

/// Drop `home_hub_designations`, `subkey_certs` and `prefs_blobs` rows of
/// masters whose newest row is older than `cutoff` and who have no
/// relationship to this hub. A master survives if ANY holds:
/// - it, or a device it certified, is a current member (`users.is_member`);
/// - its designation names THIS hub: we are its home hub and hold its prefs
///   and certs on its behalf;
/// - undelivered DM work (a non-bounced `dm_outbox` row) involves it, either
///   through a local conversation member that resolves to it (the `master_of`
///   forms: `users.master_pubkey` or a `subkey_certs` row) or because the row
///   is addressed to one of its designated home hubs (the mirror path);
/// - any of its rows is younger than `cutoff` (age is per master, so a fresh
///   prefs write keeps the whole set).
///
/// `subkey_revocations` are never dropped. Auth carries a device cert inline
/// and checks revocation by device key alone, so a revoked device whose cert
/// row is gone could still present its master-signed cert and sign in as
/// that master. A revocation is small and is the security record; it stays.
pub async fn prune_personal_axis(state: &AppState, cutoff: i64) {
    // Without our own URL we cannot tell whether a designation names us.
    let Some(own_url) = state.canonical_url.read().await.clone() else {
        return;
    };
    let norm = |u: &str| u.trim_end_matches('/').to_string();
    let own_url = norm(&own_url);

    let candidates: Result<Vec<String>, _> = sqlx::query_scalar(
        "SELECT m.master_pubkey FROM (
             SELECT master_pubkey, MAX(ts) AS newest FROM (
                 SELECT master_pubkey, updated_at AS ts FROM home_hub_designations
                 UNION ALL SELECT master_pubkey, registered_at FROM subkey_certs
                 UNION ALL SELECT master_pubkey, registered_at FROM subkey_revocations
                 UNION ALL SELECT master_pubkey, updated_at FROM prefs_blobs
             ) t GROUP BY master_pubkey
         ) m
         WHERE m.newest < $1
           AND NOT EXISTS (
               SELECT 1 FROM users u
               WHERE u.is_member
                 AND (u.master_pubkey = m.master_pubkey
                      OR u.public_key = m.master_pubkey
                      OR u.public_key IN (SELECT subkey_pubkey FROM subkey_certs c
                                          WHERE c.master_pubkey = m.master_pubkey)))
           AND NOT EXISTS (
               SELECT 1 FROM dm_outbox o
               JOIN dm_messages dm ON dm.id = o.message_id
               JOIN conversation_members cm ON cm.conversation_id = dm.conversation_id
               JOIN users u ON u.public_key = cm.public_key
               WHERE o.bounced_at IS NULL
                 AND (u.master_pubkey = m.master_pubkey
                      OR u.public_key = m.master_pubkey
                      OR u.public_key IN (SELECT subkey_pubkey FROM subkey_certs c
                                          WHERE c.master_pubkey = m.master_pubkey)))",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await;
    let Ok(candidates) = candidates else {
        return;
    };
    if candidates.is_empty() {
        return;
    }

    // Designations are JSON lists of URLs, so the two URL-based rules are
    // checked here rather than in SQL.
    let designations: Vec<(String, String)> =
        sqlx::query_as("SELECT master_pubkey, hubs_json FROM home_hub_designations")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
    let pending_urls: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT recipient_hub_url FROM dm_outbox WHERE bounced_at IS NULL",
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let pending_urls: Vec<String> = pending_urls.iter().map(|u| norm(u)).collect();

    let keep: std::collections::HashSet<&str> = designations
        .iter()
        .filter(
            |(_, json)| match serde_json::from_str::<Vec<String>>(json) {
                // An unparseable list is kept: we cannot prove we are not named.
                Err(_) => true,
                Ok(hubs) => hubs
                    .iter()
                    .map(|h| norm(h))
                    .any(|h| h == own_url || pending_urls.contains(&h)),
            },
        )
        .map(|(m, _)| m.as_str())
        .collect();
    let doomed: Vec<String> = candidates
        .into_iter()
        .filter(|m| !keep.contains(m.as_str()))
        .collect();
    if doomed.is_empty() {
        return;
    }

    for sql in [
        "DELETE FROM subkey_certs WHERE master_pubkey = ANY($1)",
        "DELETE FROM home_hub_designations WHERE master_pubkey = ANY($1)",
        "DELETE FROM prefs_blobs WHERE master_pubkey = ANY($1)",
    ] {
        if let Err(e) = sqlx::query(sql).bind(&doomed).execute(&state.db).await {
            tracing::warn!("personal-axis retention: {e}");
        }
    }
}
