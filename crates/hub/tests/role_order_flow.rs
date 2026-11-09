//! `PUT /roles/order` (Wavvon-clients#286): reorder every role below the
//! caller in one call, without touching the roles above.

use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

async fn create(
    h: &common::TestHarness,
    token: &str,
    name: &str,
    priority: i64,
    perms: &[&str],
) -> String {
    let r = h
        .post("/roles")
        .authorization_bearer(token)
        .json(&json!({ "name": name, "priority": priority, "permissions": perms }))
        .await;
    assert_eq!(r.status_code(), 201, "{}", r.text());
    r.json::<Value>()["id"].as_str().unwrap().to_string()
}

async fn order(h: &common::TestHarness, token: &str) -> Vec<String> {
    let roles: Vec<Value> = h.get("/roles").authorization_bearer(token).await.json();
    roles
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .filter(|n| ["A", "B", "C", "Admin"].contains(&n.as_str()))
        .collect()
}

#[tokio::test]
async fn roles_reorder_in_one_call_below_the_caller_only() {
    let (h, owner) = common::setup_with_owner().await;
    let admin_role = create(&h, &owner, "Admin", 100, &["roles.manage"]).await;
    let a = create(&h, &owner, "A", 30, &[]).await;
    let b = create(&h, &owner, "B", 20, &[]).await;
    let c = create(&h, &owner, "C", 20, &[]).await;

    // The owner holds every role below it; C, A, B with Admin kept on top.
    let body: Vec<Value> = h
        .put("/roles/order")
        .authorization_bearer(&owner)
        .json(&json!({ "role_ids": [admin_role, c, a, b] }))
        .await
        .json();
    assert!(!body.is_empty());
    assert_eq!(order(&h, &owner).await, ["Admin", "C", "A", "B"]);

    // An admin below the owner may move only the roles under Admin; naming
    // Admin itself, or leaving one out, is refused.
    let admin = Identity::generate();
    let admin_token = common::authenticate(&h, &admin).await;
    h.put(&format!(
        "/users/{}/roles/{admin_role}",
        admin.public_key_hex()
    ))
    .authorization_bearer(&owner)
    .await
    .assert_status_success();
    h.put("/roles/order")
        .authorization_bearer(&admin_token)
        .json(&json!({ "role_ids": [admin_role, b, a, c] }))
        .await
        .assert_status_bad_request();
    h.put("/roles/order")
        .authorization_bearer(&admin_token)
        .json(&json!({ "role_ids": [b, a] }))
        .await
        .assert_status_bad_request();
    h.put("/roles/order")
        .authorization_bearer(&admin_token)
        .json(&json!({ "role_ids": [b, a, c] }))
        .await
        .assert_status_success();
    assert_eq!(order(&h, &owner).await, ["Admin", "B", "A", "C"]);

    // Without roles.manage, nothing.
    let member = common::authenticate(&h, &Identity::generate()).await;
    h.put("/roles/order")
        .authorization_bearer(&member)
        .json(&json!({ "role_ids": [] }))
        .await
        .assert_status_forbidden();
}
