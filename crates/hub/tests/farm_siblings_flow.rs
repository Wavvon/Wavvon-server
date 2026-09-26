//! Wiring a hub to its farm siblings, against a real database.
//!
//! The unit tests in `farm_siblings` cover which siblings are new. These cover
//! what actually happens to the hub: the ban-list subscription it creates, the
//! trusted issuer it adds, and — the property the whole design rests on — that
//! an owner who undoes either of those is not overruled sixty seconds later.
//!
//! That promise is the reason this file exists. "Once per sibling" is easy to
//! write and easy to break by moving one line, and breaking it turns an admin
//! decision into a setting the farm silently reverts. A test that only checked
//! the happy path would not notice.

use wavvon_hub::farm_siblings::{reconcile, Sibling};

#[path = "common.rs"]
mod common;

fn sibling(pk: &str) -> Sibling {
    Sibling {
        hub_pubkey: pk.to_string(),
        hub_url: format!("https://farm.test/hub/{pk}"),
    }
}

async fn sources(db: &sqlx::PgPool) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as("SELECT url, policy, issuer_pubkey FROM federated_ban_sources ORDER BY url")
        .fetch_all(db)
        .await
        .unwrap()
}

async fn setting(db: &sqlx::PgPool, key: &str) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM hub_settings WHERE key = $1")
        .bind(key)
        .fetch_optional(db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_new_sibling_is_subscribed_as_soft_flag_and_trusted_as_an_issuer() {
    let (db, _guard) = common::create_test_db().await;

    reconcile(&db, &[sibling("aaa"), sibling("bbb")]).await;

    let rows = sources(&db).await;
    assert_eq!(rows.len(), 2, "both siblings subscribed");
    for (url, policy, issuer) in &rows {
        assert!(url.ends_with("/federation/banlist"), "got {url}");
        assert_eq!(
            policy, "soft-flag",
            "a sibling's list must inform, never block — that is what keeps \
             this clear of a farm-level reputation store"
        );
        assert!(
            issuer.is_some(),
            "an issuer we cannot verify is not an issuer"
        );
    }

    let issuers: Vec<String> =
        serde_json::from_str(&setting(&db, "cert_trusted_issuers").await.unwrap()).unwrap();
    assert!(issuers.contains(&"aaa".to_string()));
    assert!(issuers.contains(&"bbb".to_string()));
}

/// The steady state: the farm re-reports its siblings every heartbeat, forever.
#[tokio::test]
async fn repeated_reconciles_change_nothing() {
    let (db, _guard) = common::create_test_db().await;

    reconcile(&db, &[sibling("aaa")]).await;
    let first = sources(&db).await;
    for _ in 0..3 {
        reconcile(&db, &[sibling("aaa")]).await;
    }

    assert_eq!(
        sources(&db).await,
        first,
        "nothing should move after the first"
    );
}

/// The property that makes this safe to run off a heartbeat: an owner who
/// unsubscribes from a sibling stays unsubscribed.
///
/// A compromised sibling has to be cuttable. If the farm re-added it on the
/// next beat, the admin panel would be showing a choice the operator does not
/// actually have.
#[tokio::test]
async fn a_sibling_the_owner_removed_is_not_added_back() {
    let (db, _guard) = common::create_test_db().await;

    reconcile(&db, &[sibling("aaa")]).await;
    assert_eq!(sources(&db).await.len(), 1);

    // The owner cuts it.
    sqlx::query("DELETE FROM federated_ban_sources")
        .execute(&db)
        .await
        .unwrap();

    // The farm keeps reporting it, as it will every minute.
    reconcile(&db, &[sibling("aaa")]).await;
    reconcile(&db, &[sibling("aaa")]).await;

    assert!(
        sources(&db).await.is_empty(),
        "an admin decision the farm reverts every minute is not a decision"
    );
}

/// Trusted issuers set by hand must survive; the farm adds, it does not
/// replace.
#[tokio::test]
async fn existing_trusted_issuers_are_kept() {
    let (db, _guard) = common::create_test_db().await;
    wavvon_hub::routes::hub::upsert_setting(&db, "cert_trusted_issuers", r#"["chosen-by-hand"]"#)
        .await
        .unwrap();

    reconcile(&db, &[sibling("aaa")]).await;

    let issuers: Vec<String> =
        serde_json::from_str(&setting(&db, "cert_trusted_issuers").await.unwrap()).unwrap();
    assert!(
        issuers.contains(&"chosen-by-hand".to_string()),
        "the owner's own issuer must not be replaced, got {issuers:?}"
    );
    assert!(issuers.contains(&"aaa".to_string()));
}

/// A hub on a farm with one hub gets an empty list every minute; it must not
/// write anything at all.
#[tokio::test]
async fn no_siblings_writes_nothing() {
    let (db, _guard) = common::create_test_db().await;

    reconcile(&db, &[]).await;

    assert!(sources(&db).await.is_empty());
    assert_eq!(setting(&db, "farm_siblings_seen").await, None);
}

/// The test that was missing, and its absence is why farm sibling trust never
/// worked: every other test here reads `cert_trusted_issuers` back with its
/// own `serde_json::from_str::<Vec<String>>`, so they all agreed with the
/// writer and none of them agreed with the hub.
///
/// `load_trusted_issuers` is the only reader whose answer matters — it is what
/// the auth gate consults in `cert_mode = "trusted"` — and it parsed a
/// different shape, swallowed the mismatch in `unwrap_or_default()`, and
/// returned an empty list. Go through it, not around it.
#[tokio::test]
async fn a_wired_sibling_is_trusted_by_the_reader_the_auth_gate_uses() {
    let h = common::setup().await;

    reconcile(&h.state().db, &[sibling("sibling-pubkey")]).await;

    let trusted = wavvon_hub::routes::certs::load_trusted_issuers(h.state()).await;
    assert!(
        trusted.contains(&"sibling-pubkey".to_string()),
        "the farm wired this sibling in, so the auth gate has to see it; got {trusted:?}"
    );
}

/// Trusting a sibling is useless if the hub cannot reach it: the admission
/// gate pulls a candidate's portfolio from `{issuer_url}/identity/{pk}/certs`
/// (hub-certifications.md §11), and until this the address the farm already
/// reports was thrown away.
#[tokio::test]
async fn a_wired_sibling_records_the_address_it_can_be_pulled_from() {
    let (db, _guard) = common::create_test_db().await;

    reconcile(&db, &[sibling("aaa")]).await;

    let urls: std::collections::HashMap<String, String> =
        serde_json::from_str(&setting(&db, "cert_issuer_urls").await.unwrap()).unwrap();
    assert_eq!(
        urls.get("aaa").map(String::as_str),
        Some("https://farm.test/hub/aaa"),
        "the sibling's own hub_url is what the pull dereferences"
    );
}

/// An address the owner corrected by hand outlives the next heartbeat — the
/// same promise the trust list itself makes, for the same reason.
#[tokio::test]
async fn an_address_the_owner_set_is_not_overwritten() {
    let (db, _guard) = common::create_test_db().await;

    sqlx::query(
        "INSERT INTO hub_settings (key, value) VALUES ('cert_issuer_urls', $1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    )
    .bind(r#"{"aaa":"https://direct.example"}"#)
    .execute(&db)
    .await
    .unwrap();

    reconcile(&db, &[sibling("aaa"), sibling("bbb")]).await;

    let urls: std::collections::HashMap<String, String> =
        serde_json::from_str(&setting(&db, "cert_issuer_urls").await.unwrap()).unwrap();
    assert_eq!(
        urls.get("aaa").map(String::as_str),
        Some("https://direct.example"),
        "a farm heartbeat must not silently re-point an issuer the owner set"
    );
    assert_eq!(
        urls.get("bbb").map(String::as_str),
        Some("https://farm.test/hub/bbb"),
        "and the new sibling is still recorded"
    );
}
