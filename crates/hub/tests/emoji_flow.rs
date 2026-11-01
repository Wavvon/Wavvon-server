use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;

#[path = "common.rs"]
mod common;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\nbody";

fn body(name: &str, mime: &str, bytes: &[u8]) -> serde_json::Value {
    json!({ "name": name, "mime": mime, "data_b64": STANDARD.encode(bytes) })
}

#[tokio::test]
async fn emoji_upload_accepts_a_matching_image_and_serves_it_with_nosniff() {
    let (server, token) = common::setup_with_owner().await;
    server
        .post("/admin/emojis")
        .authorization_bearer(&token)
        .json(&body("ok", "image/png", PNG))
        .await
        .assert_status(StatusCode::CREATED);

    let list: serde_json::Value = server.get("/emojis").await.json();
    let url = list[0]["url"].as_str().unwrap().to_string();
    let resp = server.get(&url).await;
    resp.assert_status_ok();
    assert_eq!(resp.headers()["content-type"], "image/png");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn emoji_upload_refuses_other_types_and_mismatched_signatures() {
    let (server, token) = common::setup_with_owner().await;
    for (mime, bytes) in [
        ("text/html", &b"<html></html>"[..]),
        (
            "image/svg+xml",
            &b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"[..],
        ),
        (
            "image/png",
            &b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"[..],
        ),
        ("image/gif", PNG),
    ] {
        server
            .post("/admin/emojis")
            .authorization_bearer(&token)
            .json(&body("bad", mime, bytes))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    let list: serde_json::Value = server.get("/emojis").await.json();
    assert!(list.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_legacy_emoji_row_with_a_bad_type_is_served_as_a_download() {
    let (server, _token) = common::setup_with_owner().await;
    sqlx::query(
        "INSERT INTO hub_emojis(id, name, uploader, mime, data_b64, created_at) SELECT 'legacy','x',public_key,'text/html',$1,0 FROM users LIMIT 1",
    )
    .bind(STANDARD.encode(b"<html></html>"))
    .execute(&server.state().db)
    .await
    .unwrap();
    let resp = server.get("/emojis/legacy/image").await;
    assert_eq!(resp.headers()["content-type"], "application/octet-stream");
    assert_eq!(resp.headers()["content-disposition"], "attachment");
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn every_response_carries_nosniff() {
    let server = common::setup().await;
    let resp = server.get("/no-such-route").await;
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
    let resp = server.get("/info").await;
    assert_eq!(resp.headers()["x-content-type-options"], "nosniff");
}
