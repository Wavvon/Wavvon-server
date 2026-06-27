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
    let sources_json: Option<String> =
        sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = 'banlist_sources'")
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let sources: Vec<String> = sources_json
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    for source_url in &sources {
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
                        // v1: store without live signature verification.
                        // Operator opt-in means trust is explicit; full
                        // sig verification (fetching issuer /info) is deferred.
                        let issuer = payload
                            .get("issuer_pubkey")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        if issuer.is_empty() {
                            tracing::warn!(
                                "banlist_worker: {source_url} returned payload without issuer_pubkey"
                            );
                            continue;
                        }

                        if let Some(entries) = payload.get("entries").and_then(|e| e.as_array()) {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as i64;

                            // Remove entries that this source no longer lists
                            // (they un-banned the user). We'll re-insert the
                            // current set, so first delete existing rows for
                            // this source and replace with what came back.
                            let _ = sqlx::query(
                                "DELETE FROM federated_bans WHERE source_hub_pubkey = $1",
                            )
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
                        tracing::warn!(
                            "banlist_worker: {source_url} response missing 'payload' field"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "banlist_worker: failed to parse response from {source_url}: {e}"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    "banlist_worker: failed to fetch {source_url}/federation/banlist: {e}"
                );
            }
        }
    }
}
