//! Background worker that polls remote hub issuers for cert revocations and
//! removes stale user_certs rows.
//!
//! Every 6 hours the worker:
//!   1. Discovers all distinct (issuer_pubkey, issuer_url) pairs in user_certs.
//!   2. Fetches `GET {issuer_url}/certs/revocations?since={last_synced_at}` from each.
//!   3. Deletes matching user_certs rows for each returned revocation.
//!   4. Advances the last_synced_at cursor in cert_revocation_sync.
//!
//! This closes the gap where Hub A revokes a cert but Hub B — which holds a
//! copy in user_certs — never finds out.

use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

const POLL_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const INITIAL_DELAY: Duration = Duration::from_secs(120);

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        tokio::time::sleep(INITIAL_DELAY).await;
        loop {
            tick(&state).await;
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
}

/// Single revocation-sync pass. Public for tests.
pub async fn tick(state: &AppState) {
    let issuers: Vec<(String, String)> = match sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT issuer_pubkey, issuer_url FROM user_certs",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("cert_revocation_worker: failed to list issuers: {e}");
            return;
        }
    };

    for (issuer_pubkey, issuer_url) in &issuers {
        sync_one(state, issuer_pubkey, issuer_url).await;
    }
}

#[derive(serde::Deserialize)]
struct RevocationEntry {
    subject_pubkey: String,
    revoked_at: i64,
}

async fn sync_one(state: &AppState, issuer_pubkey: &str, issuer_url: &str) {
    let last_synced: i64 = sqlx::query_scalar(
        "SELECT last_synced_at FROM cert_revocation_sync WHERE issuer_pubkey = $1",
    )
    .bind(issuer_pubkey)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(0);

    let url = format!(
        "{}/certs/revocations?since={}",
        issuer_url.trim_end_matches('/'),
        last_synced
    );

    let resp = match state
        .http_client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("cert_revocation_worker: could not reach {issuer_url}: {e}");
            return;
        }
    };

    if !resp.status().is_success() {
        tracing::warn!(
            "cert_revocation_worker: {issuer_url} /certs/revocations returned {}",
            resp.status()
        );
        return;
    }

    let entries: Vec<RevocationEntry> = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "cert_revocation_worker: failed to parse revocations from {issuer_url}: {e}"
            );
            return;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut removed = 0usize;
    let mut max_revoked_at = last_synced;

    for entry in &entries {
        if let Ok(r) =
            sqlx::query("DELETE FROM user_certs WHERE issuer_pubkey = $1 AND master_pubkey = $2")
                .bind(issuer_pubkey)
                .bind(&entry.subject_pubkey)
                .execute(&state.db)
                .await
        {
            removed += r.rows_affected() as usize;
        }
        if entry.revoked_at > max_revoked_at {
            max_revoked_at = entry.revoked_at;
        }
    }

    if removed > 0 {
        tracing::info!(
            "cert_revocation_worker: removed {removed} revoked cert(s) from issuer {}…",
            &issuer_pubkey[..16.min(issuer_pubkey.len())]
        );
    }

    // Advance the cursor. Use `now` for empty responses so the window always
    // moves forward. Use max(revoked_at) + 1 when entries were returned so the
    // next poll doesn't re-fetch the same entries.
    let new_cursor = if entries.is_empty() {
        now
    } else {
        max_revoked_at + 1
    };

    let _ = sqlx::query(
        "INSERT INTO cert_revocation_sync (issuer_pubkey, issuer_url, last_synced_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (issuer_pubkey) DO UPDATE SET
           issuer_url     = excluded.issuer_url,
           last_synced_at = GREATEST(cert_revocation_sync.last_synced_at, excluded.last_synced_at)",
    )
    .bind(issuer_pubkey)
    .bind(issuer_url)
    .bind(new_cursor)
    .execute(&state.db)
    .await;
}
