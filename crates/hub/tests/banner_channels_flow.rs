use serde_json::json;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

// ---- Create banner channel: happy paths ----

#[tokio::test]
async fn create_banner_channel_no_source() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "promo-banner", "channel_type": "banner" }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["channel_type"], "banner");
    assert!(body.get("banner_url").is_none() || body["banner_url"].is_null());
    assert!(body.get("banner_file_id").is_none() || body["banner_file_id"].is_null());
}

#[tokio::test]
async fn create_banner_channel_with_external_url() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "url-banner",
            "channel_type": "banner",
            "banner_url": "https://example.com/banner.png"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::CREATED);
    let body = resp.json::<serde_json::Value>();
    assert_eq!(body["channel_type"], "banner");
    assert_eq!(body["banner_url"], "https://example.com/banner.png");
}

// ---- Create banner channel: rejection paths ----

#[tokio::test]
async fn create_banner_channel_rejects_http_url() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "bad-banner",
            "channel_type": "banner",
            "banner_url": "http://example.com/banner.png"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("https://"));
}

#[tokio::test]
async fn create_banner_channel_rejects_both_sources() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "both-sources",
            "channel_type": "banner",
            "banner_url": "https://example.com/a.png",
            "banner_file_id": "some-file-id"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("mutually exclusive"));
}

#[tokio::test]
async fn create_non_banner_channel_rejects_banner_url() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "text-with-banner",
            "channel_type": "text",
            "banner_url": "https://example.com/a.png"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("only valid for banner"));
}

#[tokio::test]
async fn create_non_banner_channel_rejects_banner_file_id() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "text-with-file",
            "banner_file_id": "some-file-id"
        }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("only valid for banner"));
}

// ---- Banner channels appear in list ----

#[tokio::test]
async fn banner_channel_appears_in_list() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "event-banner",
            "channel_type": "banner",
            "banner_url": "https://cdn.example.com/event.webp"
        }))
        .await
        .assert_status(axum::http::StatusCode::CREATED);

    let resp = server.get("/channels").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let channels = resp.json::<Vec<serde_json::Value>>();
    let banner = channels
        .iter()
        .find(|c| c["name"] == "event-banner")
        .unwrap();
    assert_eq!(banner["channel_type"], "banner");
    assert_eq!(banner["banner_url"], "https://cdn.example.com/event.webp");
}

// ---- Update banner channel: happy paths ----

#[tokio::test]
async fn patch_banner_url_on_banner_channel() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "patch-banner", "channel_type": "banner" }))
        .await;
    let id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    server
        .patch(&format!("/channels/{id}"))
        .authorization_bearer(&token)
        .json(&json!({ "banner_url": "https://example.com/new.png" }))
        .await
        .assert_status_ok();
}

// ---- Update banner channel: rejection paths ----

#[tokio::test]
async fn patch_banner_url_on_text_channel_rejected() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "text-chan" }))
        .await;
    let id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .patch(&format!("/channels/{id}"))
        .authorization_bearer(&token)
        .json(&json!({ "banner_url": "https://example.com/x.png" }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("only valid for banner"));
}

#[tokio::test]
async fn patch_banner_with_invalid_https_rejected() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "patch-banner2", "channel_type": "banner" }))
        .await;
    let id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .patch(&format!("/channels/{id}"))
        .authorization_bearer(&token)
        .json(&json!({ "banner_url": "ftp://bad.example.com/img.png" }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("https://"));
}

#[tokio::test]
async fn patch_banner_file_id_invalid_reference_rejected() {
    let server = common::setup().await;
    let owner = Identity::generate();
    let token = common::authenticate(&server, &owner).await;

    let resp = server
        .post("/channels")
        .authorization_bearer(&token)
        .json(&json!({ "name": "file-banner", "channel_type": "banner" }))
        .await;
    let id = resp.json::<serde_json::Value>()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .patch(&format!("/channels/{id}"))
        .authorization_bearer(&token)
        .json(&json!({ "banner_file_id": "nonexistent-file-id" }))
        .await;
    resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("image uploaded to this channel"));
}
