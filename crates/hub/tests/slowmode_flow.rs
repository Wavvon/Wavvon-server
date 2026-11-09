//! Per-channel slowmode (Wavvon-server#315): one message per member per
//! `slowmode_secs`, with `messages.slowmode.bypass` exempt.

use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn slowmode_holds_members_back_but_not_moderators() {
    let (h, owner) = common::setup_with_owner().await;
    let created = h
        .post("/channels")
        .authorization_bearer(&owner)
        .json(&json!({ "name": "busy" }))
        .await;
    assert_eq!(created.status_code(), 201, "{}", created.text());
    let channel = created.json::<Value>()["id"].as_str().unwrap().to_string();

    h.patch(&format!("/channels/{channel}"))
        .authorization_bearer(&owner)
        .json(&json!({ "slowmode_secs": 100_000 }))
        .await
        .assert_status_bad_request();
    h.patch(&format!("/channels/{channel}"))
        .authorization_bearer(&owner)
        .json(&json!({ "slowmode_secs": 60 }))
        .await
        .assert_status_success();
    let listed: Vec<Value> = h.get("/channels").authorization_bearer(&owner).await.json();
    let row = listed.iter().find(|c| c["id"] == channel.as_str()).unwrap();
    assert_eq!(row["slowmode_secs"], 60);

    let send = |token: String, text: &'static str| {
        let req = h
            .post(&format!("/channels/{channel}/messages"))
            .authorization_bearer(&token)
            .json(&json!({ "content": text }));
        async move { req.await }
    };

    let member = common::authenticate(&h, &Identity::generate()).await;
    send(member.clone(), "first").await.assert_status_success();
    let held = send(member.clone(), "second").await;
    held.assert_status(axum::http::StatusCode::TOO_MANY_REQUESTS);
    let body: Value = serde_json::from_str(&held.text()).unwrap();
    assert_eq!(body["error"], "slowmode");
    let left = body["retry_after_secs"].as_u64().unwrap();
    assert!((1..=60).contains(&left), "{left}");

    // The owner holds every permission, the bypass included.
    send(owner.clone(), "one").await.assert_status_success();
    send(owner.clone(), "two").await.assert_status_success();
}
