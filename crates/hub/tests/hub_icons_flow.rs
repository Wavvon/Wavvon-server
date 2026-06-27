use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

const SAMPLE_SVG: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/></svg>"#;

#[tokio::test]
async fn owner_can_create_list_rename_and_delete_icon() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    // Create an icon
    let resp = server
        .post("/hub/icons")
        .authorization_bearer(&token)
        .json(&json!({ "name": "My Icon", "svg_content": SAMPLE_SVG }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body: serde_json::Value = resp.json();
    let icon_id = body["id"].as_str().unwrap().to_string();
    assert_eq!(body["name"], "My Icon");
    assert_eq!(body["svg_content"], SAMPLE_SVG);
    assert!(!icon_id.is_empty());

    // List shows the icon
    let list: serde_json::Value = server
        .get("/hub/icons")
        .authorization_bearer(&token)
        .await
        .json();
    let arr = list.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], icon_id);

    // Rename it
    server
        .patch(&format!("/hub/icons/{icon_id}"))
        .authorization_bearer(&token)
        .json(&json!({ "name": "Renamed Icon" }))
        .await
        .assert_status(axum::http::StatusCode::OK);

    // List reflects the new name
    let list: serde_json::Value = server
        .get("/hub/icons")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list[0]["name"], "Renamed Icon");

    // Delete it
    server
        .delete(&format!("/hub/icons/{icon_id}"))
        .authorization_bearer(&token)
        .await
        .assert_status(axum::http::StatusCode::NO_CONTENT);

    // Gone
    let list: serde_json::Value = server
        .get("/hub/icons")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn non_admin_cannot_create_icon() {
    let server = common::setup().await;
    // First user gets Owner role; second gets @everyone only.
    let _owner_token = common::authenticate(&server, &Identity::generate()).await;
    let rando_token = common::authenticate(&server, &Identity::generate()).await;

    let resp = server
        .post("/hub/icons")
        .authorization_bearer(&rando_token)
        .json(&json!({ "name": "Sneaky", "svg_content": SAMPLE_SVG }))
        .await;
    resp.assert_status(axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_icon_rejects_empty_name() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp = server
        .post("/hub/icons")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "   ", "svg_content": SAMPLE_SVG }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rename_icon_returns_404_for_unknown_id() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp = server
        .patch("/hub/icons/nonexistent-id")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "Whatever" }))
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_icon_returns_404_for_unknown_id() {
    let server = common::setup().await;
    let owner_token = common::authenticate(&server, &Identity::generate()).await;

    let resp = server
        .delete("/hub/icons/nonexistent-id")
        .authorization_bearer(&owner_token)
        .await;
    resp.assert_status(axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn any_authenticated_user_can_list_icons() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let owner_token = common::authenticate(&server, &owner).await;
    let rando_token = common::authenticate(&server, &Identity::generate()).await;

    // Owner creates one
    server
        .post("/hub/icons")
        .authorization_bearer(&owner_token)
        .json(&json!({ "name": "Public Icon", "svg_content": SAMPLE_SVG }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    // Regular user can list
    let list: serde_json::Value = server
        .get("/hub/icons")
        .authorization_bearer(&rando_token)
        .await
        .json();
    assert_eq!(list.as_array().unwrap().len(), 1);
}
