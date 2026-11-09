//! Raid response (Wavvon-server#316): the lockdown switch stops arrivals and
//! can hold back recent joiners; a join-rate alert can throw it by itself.

use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn lockdown_refuses_newcomers_and_holds_back_recent_joiners() {
    let (h, owner) = common::setup_with_owner().await;
    let created = h
        .post("/channels")
        .authorization_bearer(&owner)
        .json(&json!({ "name": "general" }))
        .await;
    let channel = created.json::<Value>()["id"].as_str().unwrap().to_string();

    // A member who joined just before the raid.
    let early = common::authenticate(&h, &Identity::generate()).await;

    let put = |body: Value| {
        let req = h
            .put("/admin/settings/lockdown")
            .authorization_bearer(&owner)
            .json(&body);
        async move { req.await }
    };
    // Only moderators may throw it.
    h.put("/admin/settings/lockdown")
        .authorization_bearer(&early)
        .json(&json!({ "enabled": true, "freeze_minutes": 0, "raid_join_threshold": 0, "auto_lockdown": false }))
        .await
        .assert_status_forbidden();
    put(json!({ "enabled": true, "freeze_minutes": 30, "raid_join_threshold": 0, "auto_lockdown": false }))
        .await
        .assert_status_ok();

    // A newcomer cannot join...
    let stranger = Identity::generate();
    let ch: Value = h
        .post("/auth/challenge")
        .json(&json!({ "public_key": stranger.public_key_hex() }))
        .await
        .json();
    let bytes = hex::decode(ch["challenge"].as_str().unwrap()).unwrap();
    h.post("/auth/verify")
        .json(&json!({
            "public_key": stranger.public_key_hex(),
            "challenge": ch["challenge"],
            "signature": hex::encode(
                stranger.sign(&wavvon_identity::auth_challenge_signing_bytes(&bytes).unwrap()).to_bytes()
            ),
        }))
        .await
        .assert_status_forbidden();

    // ...the recent joiner cannot post, and the owner (not recent) can.
    h.post(&format!("/channels/{channel}/messages"))
        .authorization_bearer(&early)
        .json(&json!({ "content": "spam" }))
        .await
        .assert_status_forbidden();
    h.post(&format!("/channels/{channel}/messages"))
        .authorization_bearer(&owner)
        .json(&json!({ "content": "we are on it" }))
        .await
        .assert_status_success();

    // Clearing it restores both.
    put(json!({ "enabled": false, "freeze_minutes": 30, "raid_join_threshold": 0, "auto_lockdown": false }))
        .await
        .assert_status_ok();
    common::authenticate(&h, &Identity::generate()).await;
    h.post(&format!("/channels/{channel}/messages"))
        .authorization_bearer(&early)
        .json(&json!({ "content": "hello" }))
        .await
        .assert_status_success();
    let events: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM hub_audit_log WHERE event_type = 'hub.lockdown'")
            .fetch_one(&h.state().db)
            .await
            .unwrap();
    assert_eq!(events, 2);
}

#[tokio::test]
async fn a_join_burst_raises_the_alert_and_can_lock_the_hub() {
    let (h, owner) = common::setup_with_owner().await;
    h.put("/admin/settings/lockdown")
        .authorization_bearer(&owner)
        .json(&json!({ "enabled": false, "freeze_minutes": 0, "raid_join_threshold": 3, "auto_lockdown": true }))
        .await
        .assert_status_ok();
    // The owner joined a moment ago too: two more make three in a minute.
    for _ in 0..2 {
        common::authenticate(&h, &Identity::generate()).await;
    }
    let alerts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hub_audit_log WHERE event_type = 'raid.suspected'",
    )
    .fetch_one(&h.state().db)
    .await
    .unwrap();
    assert_eq!(alerts, 1);
    let settings: Value = h
        .get("/admin/settings/lockdown")
        .authorization_bearer(&owner)
        .await
        .json();
    assert_eq!(settings["enabled"], true);
}
