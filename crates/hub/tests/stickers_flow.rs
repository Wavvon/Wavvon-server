//! Stickers (stickers.md, sticker-storage.md): packs, the ingest, copies
//! fetched from the hub that published them, the two disk budgets, and the
//! moderation page. Real listeners, because the fetch is hub to hub.

use std::io::Cursor;
use std::sync::Arc;

use serde_json::{json, Value};
use wavvon_hub::routes::stickers::gc_orphans;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

#[path = "common.rs"]
mod common;

struct Hub {
    url: String,
    state: Arc<AppState>,
    owner: String,
    _guard: common::TestDbGuard,
}

fn use_temp_uploads() {
    static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let dir = DIR.get_or_init(|| tempfile::tempdir().unwrap());
    std::env::set_var("WAVVON_UPLOADS_DIR", dir.path());
}

async fn start_hub(name: &str) -> Hub {
    use_temp_uploads();
    let (db, guard) = common::create_test_db().await;
    let state = Arc::new(AppState {
        allow_private_webhooks: true,
        ..common::base_state(db)
    });
    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let owner = login(&url, &Identity::generate()).await;
    let h = Hub {
        url,
        state,
        owner,
        _guard: guard,
    };
    let r = h.patch("/hub", &h.owner, json!({ "name": name })).await;
    assert!(r.status().is_success());
    h
}

async fn login(base: &str, identity: &Identity) -> String {
    let c = reqwest::Client::new();
    let pk = identity.public_key_hex();
    let ch: Value = c
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": pk }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge = ch["challenge"].as_str().unwrap();
    let sig = identity.sign(
        &wavvon_identity::auth_challenge_signing_bytes(&hex::decode(challenge).unwrap()).unwrap(),
    );
    let v: Value = c
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pk,
            "challenge": challenge,
            "signature": hex::encode(sig.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["token"].as_str().unwrap().to_string()
}

impl Hub {
    fn req(&self, m: reqwest::Method, path: &str, token: &str) -> reqwest::RequestBuilder {
        let r = reqwest::Client::new().request(m, format!("{}{path}", self.url));
        if token.is_empty() {
            r
        } else {
            r.bearer_auth(token)
        }
    }
    async fn get(&self, path: &str, token: &str) -> reqwest::Response {
        self.req(reqwest::Method::GET, path, token)
            .send()
            .await
            .unwrap()
    }
    async fn post(&self, path: &str, token: &str, body: Value) -> reqwest::Response {
        self.req(reqwest::Method::POST, path, token)
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn patch(&self, path: &str, token: &str, body: Value) -> reqwest::Response {
        self.req(reqwest::Method::PATCH, path, token)
            .json(&body)
            .send()
            .await
            .unwrap()
    }
    async fn delete(&self, path: &str, token: &str) -> reqwest::Response {
        self.req(reqwest::Method::DELETE, path, token)
            .send()
            .await
            .unwrap()
    }
    async fn member(&self) -> String {
        login(&self.url, &Identity::generate()).await
    }
    async fn channel(&self) -> String {
        let v: Value = self
            .post("/channels", &self.owner, json!({ "name": "general" }))
            .await
            .json()
            .await
            .unwrap();
        v["id"].as_str().unwrap().to_string()
    }
    async fn pack(&self, name: &str) -> String {
        let r = self
            .post("/stickers/packs", &self.owner, json!({ "name": name }))
            .await;
        assert_eq!(r.status(), 201);
        r.json::<Value>().await.unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    }
    async fn upload(
        &self,
        token: &str,
        pack: &str,
        bytes: Vec<u8>,
        name: &str,
    ) -> reqwest::Response {
        let form = reqwest::multipart::Form::new()
            .text("name", name.to_string())
            .part(
                "file",
                reqwest::multipart::Part::bytes(bytes).file_name(format!("{name}.png")),
            );
        self.req(
            reqwest::Method::POST,
            &format!("/stickers/packs/{pack}/stickers"),
            token,
        )
        .multipart(form)
        .send()
        .await
        .unwrap()
    }
    async fn setting(&self, body: Value) {
        let r = self.patch("/hub", &self.owner, body).await;
        assert_eq!(r.status(), 200, "{:?}", r.text().await);
    }
}

fn png(seed: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_fn(32, 32, |x, y| {
        image::Rgba([
            (seed % 251) as u8,
            (seed / 251 % 251) as u8,
            ((x + y) % 256) as u8,
            255,
        ])
    });
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
        .unwrap();
    out
}

fn gif() -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut enc = image::codecs::gif::GifEncoder::new(&mut out);
        for i in 0..3u8 {
            let img = image::RgbaImage::from_pixel(16, 16, image::Rgba([i * 80, 9, 9, 255]));
            enc.encode_frame(image::Frame::new(img)).unwrap();
        }
    }
    out
}

async fn send(h: &Hub, token: &str, channel: &str, sticker_id: &str) -> reqwest::Response {
    h.post(
        &format!("/channels/{channel}/messages"),
        token,
        json!({ "content": "", "sticker_id": sticker_id }),
    )
    .await
}

/// Uploads a fresh sticker into `pack` and returns its JSON.
async fn upload_ok(h: &Hub, pack: &str, seed: u32) -> Value {
    let r = h.upload(&h.owner, pack, png(seed), "s").await;
    assert_eq!(r.status(), 201, "{:?}", r.text().await);
    r.json().await.unwrap()
}

/// A stub origin: serves `body` for any sticker hash and a fixed `/info`.
async fn stub_origin(body: Vec<u8>) -> String {
    use axum::routing::get;
    let b = body.clone();
    let app = axum::Router::new()
        .route(
            "/federation/stickers/{sha}",
            get(move || {
                let b = b.clone();
                async move { b }
            }),
        )
        .route(
            "/info",
            get(|| async { axum::Json(json!({ "name": "stub-hub" })) }),
        );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

#[tokio::test]
async fn pack_lifecycle_serves_webp_and_converts_animation() {
    let h = start_hub("a").await;
    let member = h.member().await;
    let pack = h.pack("cats").await;

    // Happy path: a PNG becomes a WebP served publicly, immutable, nosniff.
    let s = upload_ok(&h, &pack, 1001).await;
    assert_eq!(s["state"], "ok");
    let url = s["url"].as_str().unwrap();
    assert_eq!(url, format!("/stickers/{}", s["sha256"].as_str().unwrap()));
    let r = h.get(url, "").await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "image/webp");
    assert!(r.headers()["cache-control"]
        .to_str()
        .unwrap()
        .contains("immutable"));
    assert_eq!(r.headers()["x-content-type-options"], "nosniff");
    let bytes = r.bytes().await.unwrap();
    assert_eq!(&bytes[..4], b"RIFF");
    assert_eq!(&bytes[8..12], b"WEBP");

    // An animated GIF is stored as an animated WebP.
    let g = h.upload(&h.owner, &pack, gif(), "wave").await;
    assert_eq!(g.status(), 201);
    let g: Value = g.json().await.unwrap();
    let gb = h
        .get(g["url"].as_str().unwrap(), "")
        .await
        .bytes()
        .await
        .unwrap();
    assert!(gb.windows(4).any(|w| w == b"ANMF"));

    // A member lists packs; rename, then remove one sticker, then the pack.
    let packs: Value = h
        .get("/stickers/packs", &member)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(packs[0]["stickers"].as_array().unwrap().len(), 2);
    assert_eq!(
        h.patch(
            &format!("/stickers/packs/{pack}"),
            &h.owner,
            json!({ "name": "dogs" })
        )
        .await
        .status(),
        204
    );
    let sid = s["id"].as_str().unwrap();
    assert_eq!(
        h.delete(&format!("/stickers/packs/{pack}/stickers/{sid}"), &h.owner)
            .await
            .status(),
        204
    );
    assert_eq!(
        h.delete(&format!("/stickers/packs/{pack}/stickers/{sid}"), &h.owner)
            .await
            .status(),
        404
    );
    assert_eq!(
        h.delete(&format!("/stickers/packs/{pack}"), &h.owner)
            .await
            .status(),
        204
    );
    assert_eq!(
        h.delete(&format!("/stickers/packs/{pack}"), &h.owner)
            .await
            .status(),
        404
    );
    // Its stickers became copies and are still served.
    assert_eq!(h.get(url, "").await.status(), 200);
}

#[tokio::test]
async fn pack_routes_need_the_permission() {
    let h = start_hub("a").await;
    let member = h.member().await;
    assert_eq!(
        h.post("/stickers/packs", &member, json!({ "name": "x" }))
            .await
            .status(),
        403
    );
    let pack = h.pack("p").await;
    assert_eq!(h.upload(&member, &pack, png(1002), "s").await.status(), 403);
    assert_eq!(
        h.patch(
            &format!("/stickers/packs/{pack}"),
            &member,
            json!({ "name": "y" })
        )
        .await
        .status(),
        403
    );
    assert_eq!(
        h.delete(&format!("/stickers/packs/{pack}"), &member)
            .await
            .status(),
        403
    );
    assert_eq!(h.get("/stickers/packs", "").await.status(), 401);
    assert_eq!(
        h.post("/stickers/packs", &h.owner, json!({ "name": "  " }))
            .await
            .status(),
        400
    );
}

#[tokio::test]
async fn a_non_image_disguised_as_one_is_refused() {
    let h = start_hub("a").await;
    let pack = h.pack("p").await;
    let r = h
        .upload(
            &h.owner,
            &pack,
            b"<html><script>alert(1)</script></html>".to_vec(),
            "x",
        )
        .await;
    assert_eq!(r.status(), 400);
    let mut fake = b"\x89PNG\r\n\x1a\n".to_vec();
    fake.extend_from_slice(&[7u8; 100]);
    assert_eq!(h.upload(&h.owner, &pack, fake, "x").await.status(), 400);
    // Over the file cap (floor 64 KB): a big PNG of noise.
    let big = {
        let img = image::RgbaImage::from_fn(300, 300, |x, y| {
            image::Rgba([(x * 7 + y * 13) as u8, (x ^ y) as u8, (x * y) as u8, 255])
        });
        let mut out = Vec::new();
        img.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    };
    h.setting(json!({ "stickers_max_file_bytes": 64 * 1024 }))
        .await;
    assert!(big.len() > 64 * 1024);
    assert_eq!(h.upload(&h.owner, &pack, big, "x").await.status(), 413);
}

#[tokio::test]
async fn dedup_and_blocklist() {
    let h = start_hub("a").await;
    let pack = h.pack("p").await;
    let other = h.pack("q").await;
    let s = upload_ok(&h, &pack, 1003).await;

    // The same image again is the same row: refused as already in a pack, and
    // there is still exactly one.
    assert_eq!(
        h.upload(&h.owner, &other, png(1003), "again")
            .await
            .status(),
        409
    );
    let all: Value = h
        .get("/admin/stickers", &h.owner)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(all.as_array().unwrap().len(), 1);

    // Delete and block: tombstone, then the hash is refused at every ingest.
    let id = s["id"].as_str().unwrap();
    let sha = s["sha256"].as_str().unwrap();
    assert_eq!(
        h.delete(&format!("/admin/stickers/{id}?block=true"), &h.owner)
            .await
            .status(),
        204
    );
    assert_eq!(h.get(&format!("/stickers/{sha}"), "").await.status(), 404);
    assert_eq!(
        h.upload(&h.owner, &other, png(1003), "again")
            .await
            .status(),
        403
    );
    let bl: Value = h
        .get("/admin/stickers/blocklist", &h.owner)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(bl[0]["sha256"], sha);
    assert_eq!(
        h.delete(&format!("/admin/stickers/blocklist/{sha}"), &h.owner)
            .await
            .status(),
        204
    );
    assert_eq!(
        h.delete(&format!("/admin/stickers/blocklist/{sha}"), &h.owner)
            .await
            .status(),
        404
    );
    assert_eq!(
        h.delete("/admin/stickers/nope", &h.owner).await.status(),
        404
    );
}

#[tokio::test]
async fn pack_additions_are_refused_at_the_caps() {
    let h = start_hub("a").await;
    let pack = h.pack("p").await;

    h.setting(json!({ "stickers_per_pack": 1 })).await;
    upload_ok(&h, &pack, 1004).await;
    let r = h.upload(&h.owner, &pack, png(1005), "s").await;
    assert_eq!(r.status(), 409);
    assert_eq!(r.text().await.unwrap(), "pack_full");

    h.setting(json!({ "stickers_per_pack": 60, "stickers_packs_cap_bytes": 16 * 1024 * 1024 }))
        .await;
    sqlx::query(
        "INSERT INTO stickers (id, sha256, name, mime, size_bytes, width, height, pack_id,
            uploader, created_at, last_used_at)
         VALUES ('fat', $1, 'fat', 'image/webp', $2, 1, 1, $3, 'x', 0, 0)",
    )
    .bind("a".repeat(64))
    .bind(16i64 * 1024 * 1024)
    .bind(&pack)
    .execute(&h.state.db)
    .await
    .unwrap();
    let r = h.upload(&h.owner, &pack, png(1006), "s").await;
    assert_eq!(r.status(), 409);
    assert_eq!(r.text().await.unwrap(), "packs_full");

    let usage: Value = h
        .get("/admin/stickers/usage", &h.owner)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(usage["packs_warning"], true);
    assert_eq!(usage["packs"]["cap_bytes"], 16 * 1024 * 1024);

    h.setting(json!({ "sticker_packs_per_hub": 1 })).await;
    assert_eq!(
        h.post("/stickers/packs", &h.owner, json!({ "name": "two" }))
            .await
            .status(),
        409
    );
}

#[tokio::test]
async fn settings_are_bounded_and_listed() {
    let h = start_hub("a").await;
    for bad in [
        json!({ "stickers_max_file_bytes": 1024 }),
        json!({ "stickers_max_file_bytes": 5 * 1024 * 1024 }),
        json!({ "stickers_packs_warn_percent": 100 }),
        json!({ "stickers_per_pack": 0 }),
        json!({ "stickers_orphan_gc_days": 366 }),
    ] {
        assert_eq!(h.patch("/hub", &h.owner, bad).await.status(), 400);
    }
    h.setting(json!({ "stickers_export": false, "stickers_orphan_gc_days": 7 }))
        .await;
    let s: Value = h.get("/hub/settings", &h.owner).await.json().await.unwrap();
    assert_eq!(s["stickers_export"], false);
    assert_eq!(s["stickers_orphan_gc_days"], 7);
    assert_eq!(s["stickers_max_file_bytes"], 512 * 1024);
    let member = h.member().await;
    assert_eq!(
        h.patch("/hub", &member, json!({ "stickers_export": true }))
            .await
            .status(),
        403
    );
}

#[tokio::test]
async fn federation_route_serves_only_own_pack_stickers() {
    let h = start_hub("a").await;
    let pack = h.pack("p").await;
    let s = upload_ok(&h, &pack, 1007).await;
    let sha = s["sha256"].as_str().unwrap();

    // Public: no token.
    let r = h.get(&format!("/federation/stickers/{sha}"), "").await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "image/webp");

    // A copy is not served onward, nor is an unknown or malformed hash.
    let id = s["id"].as_str().unwrap();
    h.delete(&format!("/stickers/packs/{pack}/stickers/{id}"), &h.owner)
        .await;
    assert_eq!(
        h.get(&format!("/federation/stickers/{sha}"), "")
            .await
            .status(),
        404
    );
    assert_eq!(
        h.get(&format!("/federation/stickers/{}", "b".repeat(64)), "")
            .await
            .status(),
        404
    );
    assert_eq!(h.get("/federation/stickers/nothex", "").await.status(), 404);

    // Export off: 403 for everything, whether we hold it or not.
    let s2 = upload_ok(&h, &pack, 1008).await;
    h.setting(json!({ "stickers_export": false })).await;
    let sha2 = s2["sha256"].as_str().unwrap();
    assert_eq!(
        h.get(&format!("/federation/stickers/{sha2}"), "")
            .await
            .status(),
        403
    );
    assert_eq!(
        h.get(&format!("/federation/stickers/{}", "b".repeat(64)), "")
            .await
            .status(),
        403
    );
    assert_eq!(h.get(&format!("/stickers/{sha2}"), "").await.status(), 200);
}

#[tokio::test]
async fn a_hub_sends_a_sticker_from_another_hubs_pack() {
    let a = start_hub("origin-hub").await;
    let b = start_hub("home-hub").await;
    let pack = a.pack("p").await;
    let s = upload_ok(&a, &pack, 1009).await;
    let sha = s["sha256"].as_str().unwrap();
    let a_bytes = a
        .get(&format!("/stickers/{sha}"), "")
        .await
        .bytes()
        .await
        .unwrap();

    let chan = b.channel().await;
    let member = b.member().await;
    // @everyone holds stickers.external from the migration, so a member can.
    let ask = json!({ "sha256": sha, "origin_hub_url": a.url, "name": "wave" });
    let r = b
        .post(&format!("/channels/{chan}/stickers"), &member, ask.clone())
        .await;
    assert_eq!(r.status(), 201, "{:?}", r.text().await);
    let copy: Value = r.json().await.unwrap();
    assert_eq!(copy["origin_hub_url"], a.url);
    assert_eq!(copy["origin_hub_name"], "origin-hub");
    assert_eq!(copy["sha256"], sha);

    // Stored here, byte for byte what the origin has, and the second ask
    // answers 200 with the same row.
    let b_bytes = b
        .get(&format!("/stickers/{sha}"), "")
        .await
        .bytes()
        .await
        .unwrap();
    assert_eq!(a_bytes, b_bytes);
    let again = b
        .post(&format!("/channels/{chan}/stickers"), &member, ask)
        .await;
    assert_eq!(again.status(), 200);
    assert_eq!(again.json::<Value>().await.unwrap()["id"], copy["id"]);

    // The message carries the sticker, in the response and in history.
    let id = copy["id"].as_str().unwrap();
    let m = send(&b, &member, &chan, id).await;
    assert_eq!(m.status(), 201, "{:?}", m.text().await);
    let m: Value = m.json().await.unwrap();
    assert_eq!(m["sticker"]["origin_hub_name"], "origin-hub");
    let hist: Value = b
        .get(&format!("/channels/{chan}/messages"), &member)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(hist[0]["sticker"]["id"], id);

    // The origin does not serve the copy onward: B's copy is not a pack sticker.
    assert_eq!(
        b.get(&format!("/federation/stickers/{sha}"), "")
            .await
            .status(),
        404
    );

    // The origin is unavailable, or lacks the hash: 502, nothing stored.
    let missing = json!({ "sha256": "c".repeat(64), "origin_hub_url": a.url });
    assert_eq!(
        b.post(&format!("/channels/{chan}/stickers"), &member, missing)
            .await
            .status(),
        502
    );
    let dead = json!({ "sha256": "d".repeat(64), "origin_hub_url": "http://127.0.0.1:9" });
    assert_eq!(
        b.post(&format!("/channels/{chan}/stickers"), &member, dead)
            .await
            .status(),
        502
    );
    let junk = json!({ "sha256": "d".repeat(64), "origin_hub_url": "ftp://x" });
    assert_eq!(
        b.post(&format!("/channels/{chan}/stickers"), &member, junk)
            .await
            .status(),
        400
    );

    // Origin turns export off: a hub that does not hold it cannot get it.
    let s2 = upload_ok(&a, &pack, 1010).await;
    a.setting(json!({ "stickers_export": false })).await;
    let ask2 = json!({ "sha256": s2["sha256"], "origin_hub_url": a.url });
    assert_eq!(
        b.post(&format!("/channels/{chan}/stickers"), &member, ask2)
            .await
            .status(),
        502
    );
}

#[tokio::test]
async fn external_stickers_need_the_permission_but_own_packs_do_not() {
    let b = start_hub("home").await;
    let chan = b.channel().await;
    let member = b.member().await;
    let pack = b.pack("p").await;
    let own = upload_ok(&b, &pack, 1011).await;
    let origin = stub_origin(wavvon_png_as_webp(1012).await).await;
    let ext_sha = hash_of_webp(1012).await;

    sqlx::query("DELETE FROM role_permissions WHERE permission = 'stickers.external'")
        .execute(&b.state.db)
        .await
        .unwrap();

    // Own pack sticker: no stickers.external anywhere.
    let r = b
        .post(
            &format!("/channels/{chan}/stickers"),
            &member,
            json!({ "sha256": own["sha256"], "origin_hub_url": origin }),
        )
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(
        send(&b, &member, &chan, own["id"].as_str().unwrap())
            .await
            .status(),
        201
    );

    // A fetch is refused, and so is sending a copy that is already here.
    let ask = json!({ "sha256": ext_sha, "origin_hub_url": origin });
    assert_eq!(
        b.post(&format!("/channels/{chan}/stickers"), &member, ask.clone())
            .await
            .status(),
        403
    );
    let owner_copy = b
        .post(&format!("/channels/{chan}/stickers"), &b.owner, ask)
        .await;
    assert_eq!(owner_copy.status(), 201);
    let copy_id = owner_copy.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(send(&b, &member, &chan, &copy_id).await.status(), 403);

    // Sending needs messages.send as well: unknown id is 404.
    assert_eq!(send(&b, &member, &chan, "nope").await.status(), 404);
    assert_eq!(
        b.post(&format!("/channels/{chan}/stickers"), "", json!({}))
            .await
            .status(),
        401
    );
}

async fn wavvon_png_as_webp(seed: u32) -> Vec<u8> {
    wavvon_hub::sticker_image::canonicalize(png(seed), 512 * 1024)
        .await
        .unwrap()
        .bytes
}

async fn hash_of_webp(seed: u32) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(wavvon_png_as_webp(seed).await))
}

#[tokio::test]
async fn a_fetched_copy_must_hash_to_the_request_and_be_an_image() {
    let b = start_hub("home").await;
    let chan = b.channel().await;
    let good = wavvon_png_as_webp(1013).await;
    let other_hash = hash_of_webp(1014).await;

    // A valid canonical image, but not the one that was asked for.
    let origin = stub_origin(good.clone()).await;
    let r = b
        .post(
            &format!("/channels/{chan}/stickers"),
            &b.owner,
            json!({ "sha256": other_hash, "origin_hub_url": origin }),
        )
        .await;
    assert_eq!(r.status(), 502);
    assert_eq!(r.text().await.unwrap(), "origin_hash_mismatch");

    // Hashes right, but the bytes are not a canonical sticker: a plain PNG
    // does not "come out unchanged".
    let raw = png(1015);
    let raw_hash = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&raw))
    };
    let origin = stub_origin(raw).await;
    let r = b
        .post(
            &format!("/channels/{chan}/stickers"),
            &b.owner,
            json!({ "sha256": raw_hash, "origin_hub_url": origin }),
        )
        .await;
    assert_eq!(r.status(), 502);
    assert_eq!(r.text().await.unwrap(), "origin_not_canonical");

    // Not an image at all.
    let html = b"<html>hi</html>".to_vec();
    let html_hash = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&html))
    };
    let origin = stub_origin(html).await;
    let r = b
        .post(
            &format!("/channels/{chan}/stickers"),
            &b.owner,
            json!({ "sha256": html_hash, "origin_hub_url": origin }),
        )
        .await;
    assert_eq!(r.status(), 502);

    // Over the file cap: refused, not truncated.
    b.setting(json!({ "stickers_max_file_bytes": 64 * 1024 }))
        .await;
    let origin = stub_origin(vec![0u8; 70 * 1024]).await;
    let r = b
        .post(
            &format!("/channels/{chan}/stickers"),
            &b.owner,
            json!({ "sha256": "e".repeat(64), "origin_hub_url": origin }),
        )
        .await;
    assert_eq!(r.status(), 413);

    let none: Value = b
        .get("/admin/stickers", &b.owner)
        .await
        .json()
        .await
        .unwrap();
    assert!(none.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_send_at_the_copies_cap_evicts_lru_and_an_evicted_copy_comes_back() {
    let b = start_hub("home").await;
    let chan = b.channel().await;
    let file_a = wavvon_png_as_webp(1016).await;
    let file_b = wavvon_png_as_webp(1017).await;
    let (sha_a, sha_b) = (hash_of_webp(1016).await, hash_of_webp(1017).await);
    let origin_a = stub_origin(file_a).await;
    let origin_b = stub_origin(file_b).await;
    let cap = 64i64 * 1024 * 1024;
    b.setting(json!({ "stickers_copies_cap_bytes": cap })).await;

    let ra = b
        .post(
            &format!("/channels/{chan}/stickers"),
            &b.owner,
            json!({ "sha256": sha_a, "origin_hub_url": origin_a }),
        )
        .await;
    assert_eq!(ra.status(), 201);
    let id_a = ra.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let m = send(&b, &b.owner, &chan, &id_a).await;
    assert_eq!(m.status(), 201);

    // Pretend A fills the cache; the next copy must push it out, and the
    // send still succeeds.
    sqlx::query("UPDATE stickers SET size_bytes = $1, last_used_at = 1 WHERE id = $2")
        .bind(cap - 10)
        .bind(&id_a)
        .execute(&b.state.db)
        .await
        .unwrap();
    let rb = b
        .post(
            &format!("/channels/{chan}/stickers"),
            &b.owner,
            json!({ "sha256": sha_b, "origin_hub_url": origin_b }),
        )
        .await;
    assert_eq!(rb.status(), 201);
    let id_b = rb.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(send(&b, &b.owner, &chan, &id_b).await.status(), 201);

    // A is evicted: tombstoned in history, 404 on the bytes, 410 to send.
    assert_eq!(b.get(&format!("/stickers/{sha_a}"), "").await.status(), 404);
    let hist: Value = b
        .get(&format!("/channels/{chan}/messages"), &b.owner)
        .await
        .json()
        .await
        .unwrap();
    let states: Vec<&str> = hist
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["sticker"]["state"].as_str().unwrap())
        .collect();
    assert!(states.contains(&"evicted") && states.contains(&"ok"));
    assert_eq!(send(&b, &b.owner, &chan, &id_a).await.status(), 410);
    let usage: Value = b
        .get("/admin/stickers/usage", &b.owner)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(usage["evictions"], 1);

    // Asking again fetches it from its origin into the same row.
    let back = b
        .post(
            &format!("/channels/{chan}/stickers"),
            &b.owner,
            json!({ "sha256": sha_a, "origin_hub_url": origin_a }),
        )
        .await;
    assert_eq!(back.status(), 201);
    assert_eq!(back.json::<Value>().await.unwrap()["id"], id_a);
    assert_eq!(b.get(&format!("/stickers/{sha_a}"), "").await.status(), 200);
    assert_eq!(send(&b, &b.owner, &chan, &id_a).await.status(), 201);
}

#[tokio::test]
async fn a_removed_sticker_cannot_be_sent_and_history_says_so() {
    let h = start_hub("a").await;
    let chan = h.channel().await;
    let pack = h.pack("p").await;
    let s = upload_ok(&h, &pack, 1018).await;
    let id = s["id"].as_str().unwrap();
    assert_eq!(send(&h, &h.owner, &chan, id).await.status(), 201);
    assert_eq!(
        h.delete(&format!("/admin/stickers/{id}"), &h.owner)
            .await
            .status(),
        204
    );
    assert_eq!(send(&h, &h.owner, &chan, id).await.status(), 410);
    let hist: Value = h
        .get(&format!("/channels/{chan}/messages"), &h.owner)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(hist[0]["sticker"]["state"], "removed");
    let member = h.member().await;
    assert_eq!(
        h.delete(&format!("/admin/stickers/{id}"), &member)
            .await
            .status(),
        403
    );
    assert_eq!(h.get("/admin/stickers", &member).await.status(), 403);
    assert_eq!(h.get("/admin/stickers/usage", &member).await.status(), 403);
    assert_eq!(
        h.get("/admin/stickers/blocklist", &member).await.status(),
        403
    );
}

#[tokio::test]
async fn orphans_are_deleted_after_the_gc_delay_and_nothing_else() {
    let h = start_hub("a").await;
    let chan = h.channel().await;
    let pack = h.pack("p").await;
    let in_pack = upload_ok(&h, &pack, 1019).await;
    let used = upload_ok(&h, &pack, 1020).await;
    let orphan = upload_ok(&h, &pack, 1021).await;
    assert_eq!(
        send(&h, &h.owner, &chan, used["id"].as_str().unwrap())
            .await
            .status(),
        201
    );
    // Orphan and used leave the pack; everything is old.
    for s in [&used, &orphan] {
        h.delete(
            &format!(
                "/stickers/packs/{pack}/stickers/{}",
                s["id"].as_str().unwrap()
            ),
            &h.owner,
        )
        .await;
    }
    sqlx::query("UPDATE stickers SET last_used_at = 1")
        .execute(&h.state.db)
        .await
        .unwrap();
    assert_eq!(gc_orphans(&h.state).await, 1);
    let left: Vec<String> = sqlx::query_scalar("SELECT id FROM stickers ORDER BY id")
        .fetch_all(&h.state.db)
        .await
        .unwrap();
    assert!(left.contains(&in_pack["id"].as_str().unwrap().to_string()));
    assert!(left.contains(&used["id"].as_str().unwrap().to_string()));
    assert!(!left.contains(&orphan["id"].as_str().unwrap().to_string()));
    assert_eq!(
        h.get(
            &format!("/stickers/{}", orphan["sha256"].as_str().unwrap()),
            ""
        )
        .await
        .status(),
        404
    );
}

#[tokio::test]
async fn admin_list_filters_sorts_and_pages() {
    let h = start_hub("a").await;
    let pack = h.pack("p").await;
    for seed in 1022..1025 {
        upload_ok(&h, &pack, seed).await;
    }
    let p1: Value = h
        .get("/admin/stickers?limit=2&sort=size", &h.owner)
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(p1.as_array().unwrap().len(), 2);
    let cursor = p1[1]["id"].as_str().unwrap();
    let p2: Value = h
        .get(
            &format!("/admin/stickers?limit=2&sort=size&cursor={cursor}"),
            &h.owner,
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(p2.as_array().unwrap().len(), 1);
    let none: Value = h
        .get("/admin/stickers?state=evicted", &h.owner)
        .await
        .json()
        .await
        .unwrap();
    assert!(none.as_array().unwrap().is_empty());
    assert_eq!(
        h.get("/admin/stickers?sort=bogus", &h.owner).await.status(),
        400
    );
    assert_eq!(p1[0]["message_count"], 0);
}

#[tokio::test]
async fn capability_permissions_and_the_one_time_grant() {
    let h = start_hub("a").await;
    let info: Value = h.get("/info", "").await.json().await.unwrap();
    assert!(info["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c == "stickers"));
    let cat: Value = h.get("/permissions", &h.owner).await.json().await.unwrap();
    for id in [
        "stickers.packs.manage",
        "stickers.external",
        "stickers.moderate",
    ] {
        assert!(
            cat["permissions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p["id"] == id),
            "{id}"
        );
    }
    let granted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_permissions
         WHERE role_id = 'builtin-everyone' AND permission = 'stickers.external'",
    )
    .fetch_one(&h.state.db)
    .await
    .unwrap();
    assert_eq!(granted, 1);

    // An admin revokes it; the next start must not hand it back.
    sqlx::query("DELETE FROM role_permissions WHERE permission = 'stickers.external'")
        .execute(&h.state.db)
        .await
        .unwrap();
    wavvon_hub::db::migrations::run(&h.state.db).await.unwrap();
    let granted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_permissions WHERE permission = 'stickers.external'",
    )
    .fetch_one(&h.state.db)
    .await
    .unwrap();
    assert_eq!(granted, 0);
}
