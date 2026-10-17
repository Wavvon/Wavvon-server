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
    // The whole list, every time. A cursor on `revoked_at` -- a timestamp the
    // revoking client signs -- skipped any revocation signed before the last
    // poll and posted after it (an offline device is enough). A subkey once
    // revoked stays revoked, the inserts are idempotent and the list is a
    // master's revoked devices, so there is nothing to page.
    let url = format!(
        "{}/identity/{}/revocations",
        home_hub_url.trim_end_matches('/'),
        master_pubkey
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

    for entry in &entries {
        // Verify signature before trusting the data.
        if entry.verify().is_err() {
            tracing::warn!(
                "subkey_revocation_worker: invalid signature in revocation from {home_hub_url}, skipping"
            );
            continue;
        }
        if let Ok(r) = sqlx::query(
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
        .await
        {
            applied += r.rows_affected() as usize;
        }
    }

    if applied > 0 {
        tracing::info!(
            "subkey_revocation_worker: applied {applied} revocation(s) for master {}…",
            &master_pubkey[..16.min(master_pubkey.len())]
        );
    }
}
