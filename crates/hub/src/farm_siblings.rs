//! Wiring this hub to the other hubs on its farm.
//!
//! A farm reports its other hubs in the heartbeat response. This hub then, for
//! each sibling it has not seen before:
//!
//! - subscribes to that sibling's ban list in **`soft-flag`** — history a
//!   moderator can read, never an admission block;
//! - adds that sibling to `cert_trusted_issuers`, so a member vouched for on
//!   one hub of a farm is not a stranger on the next.
//!
//! That is the anti-abuse story assembled from primitives that already exist —
//! federated ban lists and hub certifications — rather than a farm-level
//! reputation store, which decisions.md rules out. The trust decision stays
//! local to each hub; the farm only saves its owner from wiring it by hand.
//!
//! **Once, and only once, per sibling.** Every offered pubkey is recorded
//! whether or not it was acted on, so an owner who unsubscribes stays
//! unsubscribed. A compromised sibling has to be cuttable, and an admin
//! decision the farm silently reverts on the next heartbeat is not a decision
//! at all — it is a setting that lies.
//!
//! Note what this does *not* do: it never touches what this hub **requires**.
//! Trusting an issuer means its certificates can be read, not that they let
//! anyone past a bar the owner set. Auto-granting good standing would turn one
//! complacent hub into a pass factory for the whole farm.

use std::collections::HashSet;

use sqlx::PgPool;

/// Setting holding every sibling pubkey the farm has ever offered us.
const OFFERED_KEY: &str = "farm_siblings_seen";

/// One sibling as the farm describes it.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct Sibling {
    pub hub_pubkey: String,
    pub hub_url: String,
}

async fn read_set(db: &PgPool, key: &str) -> HashSet<String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = $1")
        .bind(key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<Vec<String>>(&raw).ok())
        .map(|v| v.into_iter().collect())
        .unwrap_or_default()
}

async fn read_url_map(db: &PgPool) -> std::collections::HashMap<String, String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'cert_issuer_urls'")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Which of these siblings have never been offered before.
///
/// Pure so the "once, and only once" rule is testable without a farm, a
/// database, or a sibling.
pub fn unseen<'a>(siblings: &'a [Sibling], already_seen: &HashSet<String>) -> Vec<&'a Sibling> {
    siblings
        .iter()
        .filter(|s| !already_seen.contains(&s.hub_pubkey))
        .collect()
}

/// Subscribe to any sibling we have not been offered before.
///
/// Errors are swallowed deliberately: this runs off a heartbeat, and failing
/// to wire a sibling must never cost the hub its heartbeat. An unwired sibling
/// is offered again on the next one, because it is only recorded as seen once
/// the write succeeds.
pub async fn reconcile(db: &PgPool, siblings: &[Sibling]) {
    if siblings.is_empty() {
        return;
    }
    let seen = read_set(db, OFFERED_KEY).await;
    let fresh = unseen(siblings, &seen);
    if fresh.is_empty() {
        return;
    }

    let now = crate::auth::handlers::unix_timestamp();
    let mut wired = Vec::new();

    for sibling in &fresh {
        let banlist_url = format!(
            "{}/federation/banlist",
            sibling.hub_url.trim_end_matches('/')
        );
        let added = sqlx::query(
            "INSERT INTO federated_ban_sources (url, policy, added_at, issuer_pubkey)
             VALUES ($1, 'soft-flag', $2, $3)
             ON CONFLICT(url) DO NOTHING",
        )
        .bind(&banlist_url)
        .bind(now)
        .bind(&sibling.hub_pubkey)
        .execute(db)
        .await;

        if let Err(e) = added {
            tracing::warn!(sibling = %sibling.hub_pubkey, error = %e, "Could not subscribe to sibling ban list");
            continue;
        }
        wired.push(sibling.hub_pubkey.clone());
    }

    if wired.is_empty() {
        return;
    }

    // Trusted cert issuers: additive, never replacing what the owner set.
    let mut issuers = read_set(db, "cert_trusted_issuers").await;
    let before = issuers.len();
    issuers.extend(wired.iter().cloned());
    if issuers.len() != before {
        let list: Vec<String> = issuers.into_iter().collect();
        let _ = crate::routes::hub::upsert_setting(
            db,
            "cert_trusted_issuers",
            &serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string()),
        )
        .await;
    }

    // Where each of them can be reached, so the admission gate can pull a
    // candidate's portfolio (hub-certifications.md §11). A separate setting
    // from the trust list on purpose: trusting an issuer and knowing its
    // address are different facts, and the list that decides admission stays
    // the flat array of pubkeys it has to be. Additive here too — an address
    // the owner corrected by hand is not overwritten by a heartbeat.
    let mut urls = read_url_map(db).await;
    let before = urls.len();
    for sibling in &fresh {
        if wired.contains(&sibling.hub_pubkey) {
            urls.entry(sibling.hub_pubkey.clone())
                .or_insert_with(|| sibling.hub_url.trim_end_matches('/').to_string());
        }
    }
    if urls.len() != before {
        let _ = crate::routes::hub::upsert_setting(
            db,
            "cert_issuer_urls",
            &serde_json::to_string(&urls).unwrap_or_else(|_| "{}".to_string()),
        )
        .await;
    }

    // Recorded last: a sibling is "seen" only once it is actually wired, so a
    // failure above gets another attempt rather than being silently skipped
    // forever.
    let mut all: Vec<String> = read_set(db, OFFERED_KEY).await.into_iter().collect();
    all.extend(wired.iter().cloned());
    all.sort();
    all.dedup();
    let _ = crate::routes::hub::upsert_setting(
        db,
        OFFERED_KEY,
        &serde_json::to_string(&all).unwrap_or_else(|_| "[]".to_string()),
    )
    .await;

    tracing::info!(
        count = wired.len(),
        "Wired farm siblings (soft-flag + trusted issuer)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sibling(pk: &str) -> Sibling {
        Sibling {
            hub_pubkey: pk.to_string(),
            hub_url: format!("https://farm.test/hub/{pk}"),
        }
    }

    #[test]
    fn every_sibling_is_new_the_first_time() {
        let siblings = vec![sibling("a"), sibling("b")];
        let fresh = unseen(&siblings, &HashSet::new());
        assert_eq!(fresh.len(), 2);
    }

    /// The rule that keeps an owner's decision a decision: a sibling already
    /// offered is never offered again, so unsubscribing sticks.
    #[test]
    fn an_already_offered_sibling_is_not_offered_again() {
        let siblings = vec![sibling("a"), sibling("b")];
        let seen: HashSet<String> = ["a".to_string()].into_iter().collect();
        let fresh = unseen(&siblings, &seen);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].hub_pubkey, "b");
    }

    #[test]
    fn nothing_new_means_nothing_to_do() {
        let siblings = vec![sibling("a")];
        let seen: HashSet<String> = ["a".to_string()].into_iter().collect();
        assert!(unseen(&siblings, &seen).is_empty());
    }
}
