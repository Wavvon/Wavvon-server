use std::sync::Arc;

use crate::state::AppState;

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        // Short initial delay so the hub is fully ready before the first sync.
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        loop {
            sync_banlists(&state).await;
            tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
        }
    });
}

async fn sync_banlists(state: &AppState) {
    // Read from the new per-source policy table. Fall back to the legacy
    // `banlist_sources` JSON setting for operators that haven't migrated yet.
    let sources: Vec<(String, String)> = load_sources(state).await;

    for (source_url, _policy) in &sources {
        sync_one_source(state, source_url).await;
    }
}

/// Load sources from `federated_ban_sources`. If that table is empty, fall
/// back to the legacy `banlist_sources` JSON array in `hub_settings` (treating
/// all legacy entries as `hard-reject`).
async fn load_sources(state: &AppState) -> Vec<(String, String)> {
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT url, policy FROM federated_ban_sources ORDER BY added_at")
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    if !rows.is_empty() {
        return rows;
    }

    // Legacy fallback: plain JSON array of URL strings in hub_settings.
    let sources_json: Option<String> =
        sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'banlist_sources'")
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let urls: Vec<String> = sources_json
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    urls.into_iter()
        .map(|u| (u, "hard-reject".to_string()))
        .collect()
}

/// Sync a single banlist source. Called both from the periodic worker loop and
/// from the POST /admin/banlist/sources route (immediate trigger on add).
///
/// On a successful fetch the `issuer_pubkey` column in `federated_ban_sources`
/// is updated with the value returned by the remote hub.
pub async fn sync_one_source(state: &AppState, source_url: &str) {
    match state
        .http_client
        .get(format!("{source_url}/federation/banlist"))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) => match resp.json::<serde_json::Value>().await {
            Ok(body) => {
                if let Some(payload) = body.get("payload") {
                    let issuer = payload
                        .get("issuer_pubkey")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    if issuer.is_empty() {
                        tracing::warn!(
                            "banlist_worker: {source_url} returned payload without issuer_pubkey"
                        );
                        return;
                    }

                    // Persist the issuer_pubkey on first successful sync.
                    let _ = sqlx::query(
                        "UPDATE federated_ban_sources SET issuer_pubkey = $1 WHERE url = $2",
                    )
                    .bind(&issuer)
                    .bind(source_url)
                    .execute(&state.db)
                    .await;

                    if let Some(entries) = payload.get("entries").and_then(|e| e.as_array()) {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;

                        // Replace: delete existing rows for this source then
                        // re-insert the current set (handles un-bans).
                        let _ =
                            sqlx::query("DELETE FROM federated_bans WHERE source_hub_pubkey = $1")
                                .bind(&issuer)
                                .execute(&state.db)
                                .await;

                        let mut upserted = 0usize;
                        for entry in entries {
                            let pubkey = entry
                                .get("master_pubkey")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let reason = entry.get("reason").and_then(|v| v.as_str());
                            let added_at = entry
                                .get("added_at")
                                .and_then(|v| v.as_i64())
                                .unwrap_or(now);

                            if !pubkey.is_empty() {
                                let result = sqlx::query(
                                    "INSERT INTO federated_bans \
                                     (source_hub_pubkey, target_master_pubkey, reason, added_at, synced_at) \
                                     VALUES($1,$2,$3,$4,$5) \
                                     ON CONFLICT (source_hub_pubkey, target_master_pubkey) \
                                     DO UPDATE SET reason = excluded.reason, added_at = excluded.added_at, synced_at = excluded.synced_at",
                                )
                                .bind(&issuer)
                                .bind(pubkey)
                                .bind(reason)
                                .bind(added_at)
                                .bind(now)
                                .execute(&state.db)
                                .await;

                                if result.is_ok() {
                                    upserted += 1;
                                }
                            }
                        }

                        tracing::info!(
                            "banlist_worker: synced {upserted} entries from {source_url}"
                        );
                    }
                } else {
                    tracing::warn!("banlist_worker: {source_url} response missing 'payload' field");
                }
            }
            Err(e) => {
                tracing::warn!("banlist_worker: failed to parse response from {source_url}: {e}");
            }
        },
        Err(e) => {
            tracing::warn!("banlist_worker: failed to fetch {source_url}/federation/banlist: {e}");
        }
    }
}
