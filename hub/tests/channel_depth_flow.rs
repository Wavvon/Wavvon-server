
use serde_json::json;
use voxply_identity::Identity;

#[path = "common.rs"] mod common;

// ---- Admin settings endpoints ----

#[tokio::test]
async fn get_channel_depth_defaults_to_zero() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .get("/admin/settings/channel-depth")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["max_channel_depth"], 0);
}

#[tokio::test]
async fn patch_and_get_channel_depth() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .patch("/admin/settings/channel-depth")
        .authorization_bearer(&token)
        .json(&json!({ "max_channel_depth": 4 }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/admin/settings/channel-depth")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["max_channel_depth"], 4);
}

#[tokio::test]
async fn channel_depth_admin_routes_reject_non_admin() {
    let server = common::setup().await;
    let non_admin = Identity::generate();
    let token = common::authenticate(&server, &non_admin).await;

    // The first user is auto-promoted to owner, so we need a second user who is
    // not the owner/admin.
    let second = Identity::generate();
    let second_token = common::authenticate(&server, &second).await;

    // second user should get 403
    server
        .get("/admin/settings/channel-depth")
        .authorization_bearer(&second_token)
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    server
        .patch("/admin/settings/channel-depth")
        .authorization_bearer(&second_token)
        .json(&json!({ "max_channel_depth": 2 }))
        .await
        .assert_status(axum::http::StatusCode::FORBIDDEN);

    let _ = non_admin;
    let _ = token;
}

// ---- Depth enforcement on channel create ----

#[tokio::test]
async fn depth_enforcement_create_channel() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Build a two-level category chain while depth is unlimited (default 0).
    // root-cat (depth 0) -> mid-cat (depth 1) -> mid-cat is a category at depth 1.
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "root-cat", "is_category": true }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let root_cat_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "mid-cat", "is_category": true, "parent_id": root_cat_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let mid_cat_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Now restrict to max_depth=2.  mid-cat is at depth 1 (= max_depth - 1).
    // A new child under mid-cat would land at depth 2 which exceeds max_depth-1=1,
    // so depth_exceeded must fire (not category_at_max_depth, since the new item
    // is NOT a category).
    server
        .patch("/admin/settings/channel-depth")
        .authorization_bearer(&token)
        .json(&json!({ "max_channel_depth": 2 }))
        .await
        .assert_status_ok();

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "too-deep", "parent_id": mid_cat_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.text(), "depth_exceeded");
}

#[tokio::test]
async fn depth_enforcement_category_at_max_depth() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // max_depth = 2: categories may only go to depth 0 (i.e. depth <= max-1 = 1,
    // but a category at depth 1 would leave no room for children at depth 2
    // — actually the rule is: category depth must be < (max_depth - 1).
    // With max_depth=2, category can be at depth 0 only (depth < 1).
    server
        .patch("/admin/settings/channel-depth")
        .authorization_bearer(&token)
        .json(&json!({ "max_channel_depth": 2 }))
        .await
        .assert_status_ok();

    // Root category (depth 0) is fine
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "root-cat", "is_category": true }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let cat_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Category at depth 1 (= max_depth - 1) is forbidden: category_at_max_depth
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "nested-cat", "is_category": true, "parent_id": cat_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.text(), "category_at_max_depth");
}

#[tokio::test]
async fn depth_enforcement_disabled_when_zero() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Default is 0 = unlimited — deeply nested creates must succeed
    let mut parent_id: Option<String> = None;
    for i in 0..10 {
        let name = format!("level-{i}");
        let mut body = json!({ "name": name, "is_category": true });
        if let Some(ref pid) = parent_id {
            body["parent_id"] = json!(pid);
        }
        let resp = server
            .post("/channels")
            .authorization_bearer(&token)
            .json(&body)
            .await;
        resp.assert_status(axum::http::StatusCode::CREATED);
        parent_id = Some(
            resp.json::<serde_json::Value>()["id"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
}

// ---- Depth enforcement on channel move (PATCH /channels/:id) ----

#[tokio::test]
async fn depth_enforcement_move_channel() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Build a two-level category chain while depth is unlimited.
    // root-cat (depth 0) -> mid-cat (depth 1, category)
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "root-cat", "is_category": true }))
        .await;
    let root_cat_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "mid-cat", "is_category": true, "parent_id": root_cat_id }))
        .await;
    let mid_cat_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Create a root-level channel that we'll try to move under mid-cat
    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "roaming-channel" }))
        .await;
    let channel_id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Now restrict to max_depth=2. Moving roaming-channel under mid-cat
    // would put it at depth 2 which exceeds max_code_depth=1 → depth_exceeded.
    server
        .patch("/admin/settings/channel-depth")
        .authorization_bearer(&token)
        .json(&json!({ "max_channel_depth": 2 }))
        .await
        .assert_status_ok();

    let resp = server
        .patch(&format!("/channels/{channel_id}"))
        .authorization_bearer(&token)
        .json(&json!({ "parent_id": mid_cat_id }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(resp.text(), "depth_exceeded");
}
