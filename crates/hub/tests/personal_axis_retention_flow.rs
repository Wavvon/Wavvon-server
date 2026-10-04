#[path = "common.rs"]
mod common;

use sqlx::PgPool;
use wavvon_hub::retention_worker::prune_personal_axis;

const OLD: i64 = 1_000;
const CUTOFF: i64 = 5_000;
const OWN: &str = "https://home.example";

async fn harness() -> common::TestHarness {
    let h = common::setup().await;
    *h.state().canonical_url.write().await = Some(format!("{OWN}/"));
    h
}

async fn seed(db: &PgPool, master: &str, designated: &[&str], at: i64) {
    let hubs = serde_json::to_string(designated).unwrap();
    sqlx::query("INSERT INTO home_hub_designations VALUES ($1, $2, 1, 1, 'sig', $3)")
        .bind(master)
        .bind(hubs)
        .bind(at)
        .execute(db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO subkey_certs (master_pubkey, subkey_pubkey, device_label, issued_at,
            fallback_hubs_json, signature, registered_at)
         VALUES ($1, $2, 'd', 1, '[]', 'sig', $3)",
    )
    .bind(master)
    .bind(format!("{master}-dev"))
    .bind(at)
    .execute(db)
    .await
    .unwrap();
    sqlx::query("INSERT INTO subkey_revocations VALUES ($1, $2, 1, 'sig', $3)")
        .bind(master)
        .bind(format!("{master}-dev"))
        .bind(at)
        .execute(db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO prefs_blobs VALUES ($1, 1, 'aa', 'sig', $2)")
        .bind(master)
        .bind(at)
        .execute(db)
        .await
        .unwrap();
}

/// Rows left for `master`, one count per table.
async fn left(db: &PgPool, master: &str) -> [i64; 4] {
    let mut out = [0; 4];
    for (i, t) in [
        "home_hub_designations",
        "subkey_certs",
        "subkey_revocations",
        "prefs_blobs",
    ]
    .iter()
    .enumerate()
    {
        out[i] = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {t} WHERE master_pubkey = $1"
        ))
        .bind(master)
        .fetch_one(db)
        .await
        .unwrap();
    }
    out
}

async fn add_user(db: &PgPool, pk: &str, master: Option<&str>, member: bool) {
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, master_pubkey, is_member)
         VALUES ($1, 1, $2, $3)",
    )
    .bind(pk)
    .bind(master)
    .bind(member)
    .execute(db)
    .await
    .unwrap();
}

#[tokio::test]
async fn stranger_with_old_rows_is_pruned() {
    let h = harness().await;
    let db = &h.state().db;
    seed(db, "stranger", &["https://elsewhere.example"], OLD).await;
    seed(db, "other", &["https://elsewhere.example"], OLD).await;

    prune_personal_axis(h.state(), CUTOFF).await;
    prune_personal_axis(h.state(), CUTOFF).await;
    // Everything but the revocation, which is never pruned.
    assert_eq!(left(db, "stranger").await, [0, 0, 1, 0]);
    assert_eq!(left(db, "other").await, [0, 0, 1, 0]);
}

/// A revoked device's cert could still be presented inline at auth, so the
/// revocation must outlive the cert row, indefinitely.
#[tokio::test]
async fn a_revocation_without_a_cert_is_kept() {
    let h = harness().await;
    let db = &h.state().db;
    sqlx::query("INSERT INTO subkey_revocations VALUES ('m', 'dev', 1, 'sig', $1)")
        .bind(OLD)
        .execute(db)
        .await
        .unwrap();
    prune_personal_axis(h.state(), CUTOFF).await;
    assert_eq!(left(db, "m").await, [0, 0, 1, 0]);
}

#[tokio::test]
async fn home_hub_keeps_revocation_with_cert() {
    let h = harness().await;
    let db = &h.state().db;
    seed(db, "m", &[OWN], OLD).await;
    prune_personal_axis(h.state(), CUTOFF).await;
    assert_eq!(left(db, "m").await, [1, 1, 1, 1]);
}

#[tokio::test]
async fn member_keeps_rows_via_users_master_and_via_cert() {
    let h = harness().await;
    let db = &h.state().db;
    seed(db, "m1", &[], OLD).await;
    seed(db, "m2", &[], OLD).await;
    add_user(db, "roster1", Some("m1"), true).await;
    add_user(db, "m2-dev", None, true).await; // linked by cert only
    seed(db, "m3", &[], OLD).await;
    add_user(db, "roster3", Some("m3"), false).await; // left: not a member

    prune_personal_axis(h.state(), CUTOFF).await;
    assert_eq!(left(db, "m1").await, [1, 1, 1, 1]);
    assert_eq!(left(db, "m2").await, [1, 1, 1, 1]);
    assert_eq!(left(db, "m3").await, [0, 0, 1, 0]);
}

#[tokio::test]
async fn designation_naming_this_hub_keeps_rows() {
    let h = harness().await;
    let db = &h.state().db;
    seed(
        db,
        "home",
        &["https://a.example", "https://home.example"],
        OLD,
    )
    .await;
    prune_personal_axis(h.state(), CUTOFF).await;
    assert_eq!(left(db, "home").await, [1, 1, 1, 1]);
}

#[tokio::test]
async fn pending_outbox_keeps_rows() {
    let h = harness().await;
    let db = &h.state().db;
    // Local conversation member that resolves to the master.
    seed(db, "m", &[], OLD).await;
    add_user(db, "roster", Some("m"), false).await;
    sqlx::query("INSERT INTO conversations (id, created_at) VALUES ('c', 1)")
        .execute(db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO conversation_members VALUES ('c', 'roster', 1, NULL)")
        .execute(db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO dm_messages (id, conversation_id, sender, created_at)
         VALUES ('msg', 'c', 'x', 1)",
    )
    .execute(db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO dm_outbox (message_id, recipient_hub_url, next_attempt_at)
         VALUES ('msg', 'https://far.example/', 1)",
    )
    .execute(db)
    .await
    .unwrap();
    // And a master whose designated home hub is the pending recipient.
    seed(db, "mirrored", &["https://far.example"], OLD).await;
    seed(db, "unrelated", &["https://elsewhere.example"], OLD).await;

    prune_personal_axis(h.state(), CUTOFF).await;
    assert_eq!(left(db, "m").await, [1, 1, 1, 1]);
    assert_eq!(left(db, "mirrored").await, [1, 1, 1, 1]);
    assert_eq!(left(db, "unrelated").await, [0, 0, 1, 0]);

    // Once the work is bounced, nothing holds them.
    sqlx::query("UPDATE dm_outbox SET bounced_at = 2")
        .execute(db)
        .await
        .unwrap();
    prune_personal_axis(h.state(), CUTOFF).await;
    prune_personal_axis(h.state(), CUTOFF).await;
    assert_eq!(left(db, "m").await, [0, 0, 1, 0]);
    assert_eq!(left(db, "mirrored").await, [0, 0, 1, 0]);
}

#[tokio::test]
async fn young_rows_survive_and_one_fresh_row_keeps_the_set() {
    let h = harness().await;
    let db = &h.state().db;
    seed(db, "young", &[], CUTOFF + 1).await;
    seed(db, "mixed", &[], OLD).await;
    sqlx::query("UPDATE prefs_blobs SET updated_at = $1 WHERE master_pubkey = 'mixed'")
        .bind(CUTOFF + 1)
        .execute(db)
        .await
        .unwrap();
    prune_personal_axis(h.state(), CUTOFF).await;
    assert_eq!(left(db, "young").await, [1, 1, 1, 1]);
    assert_eq!(left(db, "mixed").await, [1, 1, 1, 1]);
}

#[tokio::test]
async fn unknown_own_url_prunes_nothing() {
    let h = common::setup().await;
    let db = &h.state().db;
    seed(db, "stranger", &[], OLD).await;
    prune_personal_axis(h.state(), CUTOFF).await;
    assert_eq!(left(db, "stranger").await, [1, 1, 1, 1]);
}
