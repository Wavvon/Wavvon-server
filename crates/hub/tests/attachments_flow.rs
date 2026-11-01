//! Attachments on disk (attachments.md): ingest, serving headers, dedup,
//! tombstones, the budget and retention.
//!
//! Every test uploads bytes of its own (a nonce in the pixels or the header):
//! the blobs of all tests share one uploads directory, so identical content in
//! two tests would be one file whose deletion one test would see from the other.

use std::io::Cursor;

use axum::http::StatusCode;
use axum_test::multipart::{MultipartForm, Part};
use image::{ImageFormat, Rgba, RgbaImage};
use serde_json::{json, Value};
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

const MB: usize = 1024 * 1024;

fn nonce() -> [u8; 4] {
    let u = uuid::Uuid::new_v4();
    let b = u.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

fn png(w: u32, h: u32) -> Vec<u8> {
    let n = nonce();
    let img = RgbaImage::from_fn(w, h, |x, y| {
        Rgba([(x % 251) as u8, (y % 251) as u8, n[0] ^ n[1], n[2] ^ n[3]])
    });
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
        .unwrap();
    out
}

/// `size` bytes no sniffer takes for anything, unique per call.
fn blob(size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    v[1..17].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    v
}

async fn channel(server: &common::TestHarness, token: &str, kind: &str) -> String {
    let ch: Value = server
        .post("/channels")
        .authorization_bearer(token)
        .json(&json!({ "name": format!("c-{}", uuid::Uuid::new_v4().simple()), "channel_type": kind }))
        .await
        .json();
    ch["id"].as_str().unwrap().to_string()
}

async fn upload_raw(
    server: &common::TestHarness,
    token: &str,
    channel_id: &str,
    name: &str,
    bytes: Vec<u8>,
    as_file: bool,
) -> axum_test::TestResponse {
    let mut form = MultipartForm::new().add_part("file", Part::bytes(bytes).file_name(name));
    if as_file {
        form = form.add_text("as_file", "true");
    }
    server
        .post(&format!("/channels/{channel_id}/upload"))
        .authorization_bearer(token)
        .multipart(form)
        .await
}

async fn upload(
    server: &common::TestHarness,
    token: &str,
    channel_id: &str,
    name: &str,
    bytes: Vec<u8>,
) -> Value {
    let resp = upload_raw(server, token, channel_id, name, bytes, false).await;
    resp.assert_status(StatusCode::CREATED);
    resp.json()
}

fn header(resp: &axum_test::TestResponse, name: &str) -> String {
    resp.header(name).to_str().unwrap_or_default().to_string()
}

async fn send(
    server: &common::TestHarness,
    token: &str,
    channel_id: &str,
    ids: &[&str],
) -> axum_test::TestResponse {
    server
        .post(&format!("/channels/{channel_id}/messages"))
        .authorization_bearer(token)
        .json(&json!({ "content": "look", "attachment_ids": ids }))
        .await
}

async fn blob_count(server: &common::TestHarness) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM attachment_blobs")
        .fetch_one(&server.state().db)
        .await
        .unwrap()
}

#[tokio::test]
async fn a_png_is_reencoded_to_webp_and_served_inline_with_hardening_headers() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;

    let up = upload(&server, &token, &ch, "photo.png", png(64, 48)).await;
    assert_eq!(up["mime"], "image/webp");
    assert_eq!(up["kind"], "image");
    assert_eq!(
        (up["width"].as_i64(), up["height"].as_i64()),
        (Some(64), Some(48))
    );
    assert_eq!(up["state"], "ok");

    let got = server.get(up["url"].as_str().unwrap()).await;
    got.assert_status_ok();
    assert_eq!(header(&got, "content-type"), "image/webp");
    assert_eq!(header(&got, "content-disposition"), "inline");
    assert_eq!(header(&got, "x-content-type-options"), "nosniff");
    assert_eq!(
        header(&got, "content-security-policy"),
        "default-src 'none'; sandbox"
    );
    assert_eq!(
        header(&got, "cache-control"),
        "private, max-age=31536000, immutable"
    );
    assert_eq!(&got.as_bytes()[..4], b"RIFF");
}

#[tokio::test]
async fn send_as_file_keeps_the_original_and_is_download_only() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;

    let original = png(32, 32);
    let resp = upload_raw(&server, &token, &ch, "shot.png", original.clone(), true).await;
    resp.assert_status(StatusCode::CREATED);
    let up: Value = resp.json();
    assert_eq!(up["kind"], "file");
    assert_eq!(up["mime"], "image/png");

    let got = server.get(up["url"].as_str().unwrap()).await;
    assert!(
        header(&got, "content-disposition").starts_with("attachment; filename*=UTF-8''shot.png")
    );
    assert_eq!(header(&got, "content-type"), "image/png");
    assert_eq!(header(&got, "x-content-type-options"), "nosniff");
    assert_eq!(got.as_bytes().as_ref(), original.as_slice());
}

#[tokio::test]
async fn an_extension_that_contradicts_the_bytes_is_refused_with_415() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;

    let mut pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    pe.extend_from_slice(&nonce());
    upload_raw(&server, &token, &ch, "holiday.png", pe, false)
        .await
        .assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // The magic bytes of a PNG followed by nothing decodable.
    let mut fake = b"\x89PNG\r\n\x1a\n".to_vec();
    fake.extend_from_slice(&[7u8; 40]);
    upload_raw(&server, &token, &ch, "fake.png", fake, false)
        .await
        .assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);

    upload_raw(&server, &token, &ch, "words.txt", png(8, 8), false)
        .await
        .assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn executables_and_svg_are_accepted_and_only_ever_downloaded() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;

    let mut exe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    exe.extend_from_slice(&nonce());
    let up = upload(&server, &token, &ch, "setup.exe", exe).await;
    assert_eq!(up["kind"], "file");
    let got = server.get(up["url"].as_str().unwrap()).await;
    assert!(header(&got, "content-disposition").starts_with("attachment;"));
    assert_eq!(header(&got, "x-content-type-options"), "nosniff");
    assert!(header(&got, "content-security-policy").contains("sandbox"));

    // The declared type is never consulted: this part claims to be a PNG.
    let svg = format!(
        "<svg xmlns='http://www.w3.org/2000/svg'><script>1</script><!--{}--></svg>",
        uuid::Uuid::new_v4()
    );
    let form = MultipartForm::new().add_part(
        "file",
        Part::bytes(svg.into_bytes())
            .file_name("logo.svg")
            .mime_type("image/png"),
    );
    let resp = server
        .post(&format!("/channels/{ch}/upload"))
        .authorization_bearer(&token)
        .multipart(form)
        .await;
    resp.assert_status(StatusCode::CREATED);
    let up: Value = resp.json();
    assert_eq!(up["mime"], "image/svg+xml");
    assert_eq!(up["kind"], "file");
    let got = server.get(up["url"].as_str().unwrap()).await;
    assert!(header(&got, "content-disposition").starts_with("attachment;"));
    assert_eq!(header(&got, "content-type"), "image/svg+xml");

    let text = upload(
        &server,
        &token,
        &ch,
        "notes.txt",
        format!("hi {}", uuid::Uuid::new_v4()).into_bytes(),
    )
    .await;
    let got = server.get(text["url"].as_str().unwrap()).await;
    assert_eq!(header(&got, "content-type"), "text/plain; charset=utf-8");
}

#[tokio::test]
async fn the_same_file_twice_is_two_rows_and_one_blob() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;

    let bytes = blob(4096);
    let a = upload(&server, &token, &ch, "a.bin", bytes.clone()).await;
    let b = upload(&server, &token, &ch, "b.bin", bytes).await;
    assert_ne!(a["id"], b["id"]);
    assert_eq!(blob_count(&server).await, 1);
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM attachments")
        .fetch_one(&server.state().db)
        .await
        .unwrap();
    assert_eq!(rows, 2);
}

#[tokio::test]
async fn a_message_carries_what_was_uploaded_and_only_once() {
    let server = common::setup().await;
    let alice = common::authenticate(&server, &Identity::generate()).await;
    let bob = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &alice, "text").await;
    let other = channel(&server, &alice, "text").await;

    let a = upload(&server, &alice, &ch, "one.bin", blob(100)).await;
    let b = upload(&server, &alice, &ch, "two.bin", blob(100)).await;
    let (a_id, b_id) = (a["id"].as_str().unwrap(), b["id"].as_str().unwrap());

    // Not the sender's, and not for this channel.
    send(&server, &bob, &ch, &[a_id])
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    send(&server, &alice, &other, &[a_id])
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    // The retired inline form is a sentence, not a silently empty message.
    server
        .post(&format!("/channels/{ch}/messages"))
        .authorization_bearer(&alice)
        .json(&json!({ "content": "x", "attachments": [{ "name": "a", "mime": "a/b", "data_b64": "AA" }] }))
        .await
        .assert_status(StatusCode::BAD_REQUEST);

    // Order is the order sent.
    let sent = send(&server, &alice, &ch, &[b_id, a_id]).await;
    sent.assert_status(StatusCode::CREATED);
    let msg: Value = sent.json();
    let names: Vec<&str> = msg["attachments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["two.bin", "one.bin"]);

    let history: Value = server
        .get(&format!("/channels/{ch}/messages"))
        .authorization_bearer(&alice)
        .await
        .json();
    assert_eq!(history[0]["attachments"].as_array().unwrap().len(), 2);

    send(&server, &alice, &ch, &[a_id])
        .await
        .assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn the_count_limit_applies_per_message() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;
    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "max_attachments_per_message": 2 }))
        .await
        .assert_status_ok();
    let mut ids = Vec::new();
    for i in 0..3 {
        let up = upload(&server, &token, &ch, &format!("f{i}.bin"), blob(50)).await;
        ids.push(up["id"].as_str().unwrap().to_string());
    }
    let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    send(&server, &token, &ch, &refs)
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    send(&server, &token, &ch, &refs[..2])
        .await
        .assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn a_moderator_removal_leaves_a_tombstone_and_a_410() {
    let server = common::setup().await;
    let owner = common::authenticate(&server, &Identity::generate()).await;
    let member = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &owner, "text").await;

    let up = upload(&server, &member, &ch, "bad.bin", blob(200)).await;
    let id = up["id"].as_str().unwrap();
    let sent: Value = send(&server, &member, &ch, &[id]).await.json();

    server
        .delete(&format!("/uploads/{id}"))
        .authorization_bearer(&member)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    server
        .delete(&format!("/uploads/{id}"))
        .authorization_bearer(&owner)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    server
        .get(&format!("/uploads/{id}"))
        .await
        .assert_status(StatusCode::GONE);
    server
        .get("/uploads/no-such-id")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    assert_eq!(blob_count(&server).await, 0, "unshared bytes go with it");

    let history: Value = server
        .get(&format!("/channels/{ch}/messages"))
        .authorization_bearer(&owner)
        .await
        .json();
    assert_eq!(history[0]["id"], sent["id"]);
    assert_eq!(history[0]["attachments"][0]["state"], "removed");
    assert_eq!(history[0]["attachments"][0]["name"], "bad.bin");
}

#[tokio::test]
async fn deleting_a_message_frees_its_blob_at_the_next_sweep() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;
    let up = upload(&server, &token, &ch, "x.bin", blob(300)).await;
    let id = up["id"].as_str().unwrap();
    let sent: Value = send(&server, &token, &ch, &[id]).await.json();
    server
        .delete(&format!(
            "/channels/{ch}/messages/{}",
            sent["id"].as_str().unwrap()
        ))
        .authorization_bearer(&token)
        .await
        .assert_status(StatusCode::NO_CONTENT);
    assert_eq!(blob_count(&server).await, 1);
    wavvon_hub::retention_worker::run_sweep(server.state()).await;
    assert_eq!(blob_count(&server).await, 0);
    server
        .get(&format!("/uploads/{id}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

async fn set_cap_to_floor(server: &common::TestHarness, token: &str) {
    server
        .patch("/hub")
        .authorization_bearer(token)
        .json(&json!({ "attachments_cap_bytes": 64 * MB }))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn a_full_budget_expires_the_oldest_and_the_upload_succeeds() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;
    set_cap_to_floor(&server, &token).await;

    let first = upload(&server, &token, &ch, "first.bin", blob(24 * MB)).await;
    let second = upload(&server, &token, &ch, "second.bin", blob(24 * MB)).await;
    let (first_id, second_id) = (
        first["id"].as_str().unwrap(),
        second["id"].as_str().unwrap(),
    );
    let msg1: Value = send(&server, &token, &ch, &[first_id]).await.json();
    send(&server, &token, &ch, &[second_id])
        .await
        .assert_status(StatusCode::CREATED);
    // Uploads within one second tie; make "oldest" unambiguous.
    for (id, at) in [(first_id, 100), (second_id, 200)] {
        sqlx::query(
            "UPDATE attachment_blobs SET last_linked_at = $2
             WHERE sha256 = (SELECT sha256 FROM attachments WHERE id = $1)",
        )
        .bind(id)
        .bind(at)
        .execute(&server.state().db)
        .await
        .unwrap();
    }

    let third = upload(&server, &token, &ch, "third.bin", blob(24 * MB)).await;
    assert_eq!(third["state"], "ok", "a member is never refused for space");

    server
        .get(&format!("/uploads/{first_id}"))
        .await
        .assert_status(StatusCode::GONE);
    server
        .get(&format!("/uploads/{second_id}"))
        .await
        .assert_status_ok();
    let history: Value = server
        .get(&format!("/channels/{ch}/messages"))
        .authorization_bearer(&token)
        .await
        .json();
    let old = history
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == msg1["id"])
        .unwrap();
    assert_eq!(old["attachments"][0]["state"], "expired");
    assert_eq!(old["attachments"][0]["name"], "first.bin");

    let settings: Value = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(settings["attachments_usage"]["used_bytes"], 48 * MB as u64);
    assert!(settings["attachments_usage"]["evictions"].as_u64().unwrap() >= 1);
}

#[tokio::test]
async fn orphans_are_dropped_before_anything_linked_is_expired() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;
    set_cap_to_floor(&server, &token).await;

    let orphan = upload(&server, &token, &ch, "orphan.bin", blob(24 * MB)).await;
    let kept = upload(&server, &token, &ch, "kept.bin", blob(24 * MB)).await;
    let (orphan_id, kept_id) = (orphan["id"].as_str().unwrap(), kept["id"].as_str().unwrap());
    send(&server, &token, &ch, &[kept_id])
        .await
        .assert_status(StatusCode::CREATED);
    // The orphan is the *newest* blob but has sat unclaimed past the delay.
    sqlx::query("UPDATE attachments SET created_at = 1 WHERE id = $1")
        .bind(orphan_id)
        .execute(&server.state().db)
        .await
        .unwrap();
    sqlx::query("UPDATE attachment_blobs SET last_linked_at = 100 WHERE sha256 = (SELECT sha256 FROM attachments WHERE id = $1)")
        .bind(kept_id)
        .execute(&server.state().db)
        .await
        .unwrap();

    upload(&server, &token, &ch, "third.bin", blob(24 * MB)).await;

    server
        .get(&format!("/uploads/{orphan_id}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .get(&format!("/uploads/{kept_id}"))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn retention_expires_old_attachments_and_sweeps_orphans() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let ch = channel(&server, &token, "text").await;

    let old = upload(&server, &token, &ch, "old.bin", blob(500)).await;
    let fresh = upload(&server, &token, &ch, "fresh.bin", blob(500)).await;
    let orphan = upload(&server, &token, &ch, "orphan.bin", blob(500)).await;
    let (old_id, fresh_id, orphan_id) = (
        old["id"].as_str().unwrap(),
        fresh["id"].as_str().unwrap(),
        orphan["id"].as_str().unwrap(),
    );
    send(&server, &token, &ch, &[old_id])
        .await
        .assert_status(StatusCode::CREATED);
    send(&server, &token, &ch, &[fresh_id])
        .await
        .assert_status(StatusCode::CREATED);
    for id in [old_id, orphan_id] {
        sqlx::query("UPDATE attachments SET created_at = 1 WHERE id = $1")
            .bind(id)
            .execute(&server.state().db)
            .await
            .unwrap();
    }

    // Never by default: nothing expires by age.
    wavvon_hub::retention_worker::run_sweep(server.state()).await;
    server
        .get(&format!("/uploads/{old_id}"))
        .await
        .assert_status_ok();
    server
        .get(&format!("/uploads/{orphan_id}"))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    server
        .patch("/hub")
        .authorization_bearer(&token)
        .json(&json!({ "attachments_retention_days": 30 }))
        .await
        .assert_status_ok();
    wavvon_hub::retention_worker::run_sweep(server.state()).await;
    server
        .get(&format!("/uploads/{old_id}"))
        .await
        .assert_status(StatusCode::GONE);
    server
        .get(&format!("/uploads/{fresh_id}"))
        .await
        .assert_status_ok();
    assert_eq!(blob_count(&server).await, 1);
}

#[tokio::test]
async fn a_banner_upload_is_reachable_at_the_url_clients_build() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    let banner = channel(&server, &token, "banner").await;

    let up = upload(&server, &token, &banner, "banner.png", png(120, 40)).await;
    let id = up["id"].as_str().unwrap();
    server
        .patch(&format!("/channels/{banner}"))
        .authorization_bearer(&token)
        .json(&json!({ "banner_file_id": id }))
        .await
        .assert_status_ok();
    let list: Value = server
        .get("/channels")
        .authorization_bearer(&token)
        .await
        .json();
    let row = list
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == banner.as_str())
        .unwrap();
    assert_eq!(row["banner_file_id"], id);
    server
        .get(&format!("/uploads/{id}"))
        .await
        .assert_status_ok();

    // Always an image, and the banner survives a sweep with no message on it.
    upload_raw(&server, &token, &banner, "x.bin", blob(100), false)
        .await
        .assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    sqlx::query("UPDATE attachments SET created_at = 1")
        .execute(&server.state().db)
        .await
        .unwrap();
    wavvon_hub::retention_worker::run_sweep(server.state()).await;
    server
        .get(&format!("/uploads/{id}"))
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn settings_have_bounds_and_the_capability_is_advertised() {
    let server = common::setup().await;
    let token = common::authenticate(&server, &Identity::generate()).await;
    for body in [
        json!({ "max_attachments_per_message": 0 }),
        json!({ "max_attachments_per_message": 26 }),
        json!({ "attachments_cap_bytes": 1024 }),
        json!({ "attachments_warn_percent": 100 }),
        json!({ "attachments_retention_days": 4000 }),
    ] {
        server
            .patch("/hub")
            .authorization_bearer(&token)
            .json(&body)
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    let settings: Value = server
        .get("/hub/settings")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(settings["max_attachments_per_message"], 10);
    assert_eq!(settings["attachments_retention_days"], 0);
    assert_eq!(settings["attachments_usage"]["used_bytes"], 0);

    let info: Value = server.get("/info").await.json();
    assert!(info["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "attachments.stored"));
}
