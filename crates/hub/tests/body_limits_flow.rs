/// Body-size limits: each route's own cap must be the one that answers.
///
/// Axum applies a 2 MB `DefaultBodyLimit` to every extractor unless the router
/// says otherwise, and for a long time it did not. So `/upload` advertised
/// 25 MB and refused anything over 2 MB with a bare 413, and an operator who
/// raised `max_attachment_bytes` saw no effect past ~1.5 MB of file. These
/// tests send bodies between axum's default and the hub's own caps.
mod common;

use axum::http::StatusCode;
use axum_test::multipart::{MultipartForm, Part};
use serde_json::{json, Value};
use wavvon_identity::Identity;

const MB: usize = 1024 * 1024;

async fn channel(server: &axum_test::TestServer, token: &str) -> String {
    let resp = server
        .post("/channels")
        .authorization_bearer(token)
        .json(&json!({ "name": "general" }))
        .await;
    resp.json::<Value>()["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn an_upload_over_two_megabytes_reaches_the_hubs_own_cap() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let channel_id = channel(&server, &token).await;

    let form = MultipartForm::new().add_part(
        "file",
        Part::bytes(vec![0u8; 3 * MB])
            .file_name("big.png")
            .mime_type("image/png"),
    );
    let resp = server
        .post(&format!("/channels/{channel_id}/upload"))
        .authorization_bearer(&token)
        .multipart(form)
        .await;
    resp.assert_status(StatusCode::CREATED);

    let filename = resp.json::<Value>()["filename"]
        .as_str()
        .unwrap()
        .to_string();
    let _ = std::fs::remove_file(
        std::path::Path::new(&wavvon_hub::routes::uploads::uploads_dir()).join(filename),
    );
}

#[tokio::test]
async fn an_upload_over_the_cap_gets_the_hubs_message() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let channel_id = channel(&server, &token).await;

    let form = MultipartForm::new().add_part(
        "file",
        Part::bytes(vec![0u8; 26 * MB])
            .file_name("huge.png")
            .mime_type("image/png"),
    );
    let resp = server
        .post(&format!("/channels/{channel_id}/upload"))
        .authorization_bearer(&token)
        .multipart(form)
        .await;
    resp.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        resp.text().contains("25MB"),
        "the hub's own check should answer, got {:?}",
        resp.text()
    );
}

#[tokio::test]
async fn an_attachment_under_a_raised_cap_is_accepted() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let channel_id = channel(&server, &token).await;

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "max_attachment_bytes": 5 * MB }))
        .await
        .assert_status_ok();

    let resp = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&token)
        .json(&json!({
            "content": "big screenshot",
            "attachments": [{ "name": "shot.png", "mime": "image/png", "data_b64": "A".repeat(4 * MB) }],
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn an_attachment_at_the_ceiling_gets_the_hubs_message() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let channel_id = channel(&server, &token).await;

    let resp = server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(&token)
        .json(&json!({
            "content": "too big",
            "attachments": [{ "name": "shot.png", "mime": "image/png", "data_b64": "A".repeat(9 * MB) }],
        }))
        .await;
    resp.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        resp.text().contains("cap"),
        "the hub's own check should answer, got {:?}",
        resp.text()
    );
}

#[tokio::test]
async fn an_operator_lowered_upload_cap_is_the_one_enforced() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let channel_id = channel(&server, &token).await;

    let settings: Value = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(settings["max_upload_bytes"], 25 * MB);

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "max_upload_bytes": 2 * MB }))
        .await
        .assert_status_ok();

    let form = MultipartForm::new().add_part(
        "file",
        Part::bytes(vec![0u8; 3 * MB])
            .file_name("big.png")
            .mime_type("image/png"),
    );
    let resp = server
        .post(&format!("/channels/{channel_id}/upload"))
        .authorization_bearer(&token)
        .multipart(form)
        .await;
    resp.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert!(resp.text().contains("2MB"), "got {:?}", resp.text());
}

#[tokio::test]
async fn the_upload_cap_rejects_values_outside_its_bounds() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;

    for bytes in [1024, 26 * MB] {
        server
            .patch("/hub")
            .authorization_bearer(&token)
            .json(&json!({ "max_upload_bytes": bytes }))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    let settings: Value = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(settings["max_upload_bytes"], 25 * MB);
}
