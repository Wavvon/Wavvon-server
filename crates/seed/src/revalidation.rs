/// Background revalidation task for the discovery aggregator.
///
/// Runs every 6 hours. For each registered farm:
///   - Fetches `GET {farm_url}/farm/public-info`.
///   - If the fetch fails or `allow_discovery_listing != true`: removes the row.
///   - If successful: updates hub_count, max_hubs_total, capacity_pct, last_verified_at.
///
/// Mirrors the dm_worker.rs spawn-loop pattern.
use std::sync::Arc;
use std::time::Duration;

use crate::state::SeedState;

/// Interval between revalidation sweeps.
const REVALIDATION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

pub fn spawn(state: Arc<SeedState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(REVALIDATION_INTERVAL).await;
            match tick(&state).await {
                Ok((checked, removed)) => {
                    tracing::info!("Revalidated {checked} farms, removed {removed}");
                }
                Err(e) => {
                    tracing::warn!("Revalidation tick failed: {e}");
                }
            }
        }
    });
}

/// One sweep. Returns `(farms_checked, farms_removed)`.
pub async fn tick(state: &SeedState) -> anyhow::Result<(usize, usize)> {
    // Load all registered farm URLs and their pubkeys.
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT farm_url FROM registered_farms ORDER BY farm_url")
            .fetch_all(&state.db)
            .await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let mut checked = 0usize;
    let mut removed = 0usize;

    for (farm_url,) in rows {
        checked += 1;
        let probe_url = format!("{}/farm/public-info", farm_url.trim_end_matches('/'));

        // Single fetch per farm per sweep: the same response decides whether
        // the farm stays listed AND supplies the fresh hub counts.
        let info: Option<serde_json::Value> = match state.http_client.get(&probe_url).send().await {
            Ok(resp) if resp.status().is_success() => resp.json::<serde_json::Value>().await.ok(),
            _ => None,
        };

        // Keep only farms that responded with a parseable body that opts in
        // to discovery listing.
        let info = info.filter(|i| {
            i.get("allow_discovery_listing")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        });

        let Some(info) = info else {
            sqlx::query("DELETE FROM registered_farms WHERE farm_url = $1")
                .bind(&farm_url)
                .execute(&state.db)
                .await?;
            removed += 1;
            tracing::debug!("Removed stale/opted-out farm: {farm_url}");
            continue;
        };

        let (hub_count, max_hubs_total, capacity_pct) = extract_counts(&info);

        let _ = sqlx::query(
            "UPDATE registered_farms
             SET hub_count = $1, max_hubs_total = $2, capacity_pct = $3, last_verified_at = $4
             WHERE farm_url = $5",
        )
        .bind(hub_count)
        .bind(max_hubs_total)
        .bind(capacity_pct)
        .bind(now)
        .bind(&farm_url)
        .execute(&state.db)
        .await;
    }

    Ok((checked, removed))
}

/// Pull `(hub_count, max_hubs_total, capacity_pct)` out of a farm's
/// public-info payload. `max_hubs_total` <= 0 means "unlimited" and yields
/// no capacity percentage.
fn extract_counts(info: &serde_json::Value) -> (i64, Option<i64>, Option<i64>) {
    let hub_count = info.get("hub_count").and_then(|v| v.as_i64()).unwrap_or(0);
    let max_hubs_total: Option<i64> = info
        .get("max_hubs_total")
        .and_then(|v| v.as_i64())
        .filter(|&v| v > 0);
    let capacity_pct: Option<i64> = max_hubs_total.map(|cap| ((hub_count * 100) / cap).min(100));
    (hub_count, max_hubs_total, capacity_pct)
}

#[cfg(test)]
mod tests {
    use super::extract_counts;
    use serde_json::json;

    #[test]
    fn extract_counts_with_cap() {
        let info = json!({ "hub_count": 7, "max_hubs_total": 50 });
        assert_eq!(extract_counts(&info), (7, Some(50), Some(14)));
    }

    #[test]
    fn extract_counts_caps_percentage_at_100() {
        let info = json!({ "hub_count": 200, "max_hubs_total": 50 });
        assert_eq!(extract_counts(&info), (200, Some(50), Some(100)));
    }

    #[test]
    fn extract_counts_unlimited_when_cap_missing_or_nonpositive() {
        let missing = json!({ "hub_count": 3 });
        assert_eq!(extract_counts(&missing), (3, None, None));

        let zero = json!({ "hub_count": 3, "max_hubs_total": 0 });
        assert_eq!(extract_counts(&zero), (3, None, None));
    }

    #[test]
    fn extract_counts_defaults_hub_count_to_zero() {
        let info = json!({ "allow_discovery_listing": true });
        assert_eq!(extract_counts(&info), (0, None, None));
    }
}
