//! Background worker: polls each known master key's home hub for subkey
//! revocations and inserts them into the local subkey_revocations table.

use std::sync::Arc;
use std::time::Duration;

use wavvon_identity::RevocationEntry;

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
    let targets: Vec<(String, String)> = match sqlx::query_as::<_, (String, String)>(
        "SELECT DISTINCT master_pubkey, home_hub_url FROM subkey_certs WHERE home_hub_url != ''",
    )
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("subkey_revocation_worker: failed to list targets: {e}");
            return;
        }
    };

    for (master_pubkey, home_hub_url) in &targets {
        sync_one(state, master_pubkey, home_hub_url).await;
    }
}

async fn sync_one(state: &AppState, master_pubkey: &str, home_hub_url: &str) {
    // Load cursor
    let last_synced: i64 = sqlx::query_scalar(
        "SELECT last_synced_at FROM subkey_revocation_sync
         WHERE master_pubkey = $1 AND home_hub_url = $2",
    )
    .bind(master_pubkey)
    .bind(home_hub_url)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(0);

    let url = format!(
        "{}/identity/{}/revocations?since={}",
        home_hub_url.trim_end_matches('/'),
        master_pubkey,
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
            tracing::warn!("subkey_revocation_worker: could not reach {home_hub_url}: {e}");
            return;
        }
    };

    if !resp.status().is_success() {
        tracing::warn!(
            "subkey_revocation_worker: {home_hub_url} /identity/{}/revocations returned {}",
            &master_pubkey[..16.min(master_pubkey.len())],
            resp.status()
        );
        return;
    }

    let entries: Vec<RevocationEntry> = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "subkey_revocation_worker: failed to parse revocations from {home_hub_url}: {e}"
            );
            return;
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut applied = 0usize;
    let mut max_revoked_at = last_synced;

    for entry in &entries {
        // Verify signature before trusting the data.
        if entry.verify().is_err() {
            tracing::warn!(
                "subkey_revocation_worker: invalid signature in revocation from {home_hub_url}, skipping"
            );
            continue;
        }
        let _ = sqlx::query(
            "INSERT INTO subkey_revocations
                (master_pubkey, subkey_pubkey, revoked_at, signature, registered_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(master_pubkey, subkey_pubkey) DO NOTHING",
        )
        .bind(&entry.master_pubkey)
        .bind(&entry.subkey_pubkey)
        .bind(entry.revoked_at as i64)
        .bind(&entry.signature)
        .bind(now)
        .execute(&state.db)
        .await;
        applied += 1;
        let ra = entry.revoked_at as i64;
        if ra > max_revoked_at {
            max_revoked_at = ra;
        }
    }

    if applied > 0 {
        tracing::info!(
            "subkey_revocation_worker: applied {applied} revocation(s) for master {}…",
            &master_pubkey[..16.min(master_pubkey.len())]
        );
    }

    let new_cursor = if entries.is_empty() {
        now
    } else {
        max_revoked_at + 1
    };

    let _ = sqlx::query(
        "INSERT INTO subkey_revocation_sync (master_pubkey, home_hub_url, last_synced_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (master_pubkey, home_hub_url) DO UPDATE SET
           last_synced_at = GREATEST(subkey_revocation_sync.last_synced_at, excluded.last_synced_at)",
    )
    .bind(master_pubkey)
    .bind(home_hub_url)
    .bind(new_cursor)
    .execute(&state.db)
    .await;
}
