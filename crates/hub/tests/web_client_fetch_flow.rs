//! Pinned web-client download: verify, refuse, cache. A local axum server
//! stands in for the archive host, so no internet is needed.

use std::path::Path;

use axum::routing::get;
use axum::Router;
use sha2::{Digest, Sha256};
use wavvon_hub::web_client_fetch::ensure;

async fn serve(body: Vec<u8>) -> String {
    let app = Router::new().route("/c.tgz", get(move || async move { body.clone() }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    format!("http://{addr}/c.tgz")
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (name, data) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        // Written raw: `set_path` itself refuses `..`, and the point is to
        // hand the hub an archive that does not.
        h.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
        h.set_cksum();
        tar.append(&h, *data).unwrap();
    }
    let raw = tar.into_inner().unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    std::io::Write::write_all(&mut gz, &raw).unwrap();
    gz.finish().unwrap()
}

fn zipped(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut z = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data) in entries {
        z.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        std::io::Write::write_all(&mut z, data).unwrap();
    }
    z.finish().unwrap().into_inner()
}

fn cache() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn read(dir: &Path, f: &str) -> String {
    std::fs::read_to_string(dir.join(f)).unwrap()
}

#[tokio::test]
async fn matching_hash_unpacks_and_second_boot_needs_no_network() {
    let archive = tgz(&[("index.html", b"<html></html>"), ("app/a.js", b"1")]);
    let url = serve(archive.clone()).await;
    let c = cache();
    let dir = ensure(&url, &sha(&archive), true, c.path()).await.unwrap();
    assert_eq!(read(&dir, "index.html"), "<html></html>");
    assert_eq!(read(&dir, "app/a.js"), "1");

    let again = ensure(
        "http://127.0.0.1:1/gone.tgz",
        &sha(&archive),
        true,
        c.path(),
    )
    .await
    .unwrap();
    assert_eq!(again, dir);
}

#[tokio::test]
async fn zip_with_a_single_top_level_directory_works() {
    let archive = zipped(&[("dist/index.html", b"hi")]);
    let url = serve(archive.clone()).await;
    let c = cache();
    let dir = ensure(&url, &sha(&archive), true, c.path()).await.unwrap();
    assert_eq!(read(&dir, "index.html"), "hi");
}

#[tokio::test]
async fn mismatch_is_refused_naming_url_and_both_hashes() {
    let archive = tgz(&[("index.html", b"x")]);
    let url = serve(archive.clone()).await;
    let pin = "ab".repeat(32);
    let c = cache();
    let e = format!(
        "{:#}",
        ensure(&url, &pin, true, c.path()).await.unwrap_err()
    );
    assert!(
        e.contains(&url) && e.contains(&pin) && e.contains(&sha(&archive)),
        "{e}"
    );
    assert!(!c.path().join(&pin).exists(), "nothing cached on mismatch");
}

#[tokio::test]
async fn unreachable_url_is_an_error() {
    let c = cache();
    let pin = "cd".repeat(32);
    let e = ensure("http://127.0.0.1:1/c.tgz", &pin, true, c.path()).await;
    assert!(e.is_err());
}

#[tokio::test]
async fn private_hosts_and_plain_http_need_the_operator_opt_in() {
    let archive = tgz(&[("index.html", b"x")]);
    let url = serve(archive.clone()).await;
    let c = cache();
    assert!(ensure(&url, &sha(&archive), false, c.path()).await.is_err());
}

#[tokio::test]
async fn parent_dir_entries_are_refused() {
    let archive = tgz(&[("index.html", b"x"), ("../evil", b"y")]);
    let url = serve(archive.clone()).await;
    let c = cache();
    let e = ensure(&url, &sha(&archive), true, c.path())
        .await
        .unwrap_err();
    assert!(format!("{e:#}").contains("escapes"), "{e:#}");
    assert!(!c.path().join("evil").exists());
    assert!(!c.path().join(sha(&archive)).exists());
}

#[tokio::test]
async fn an_archive_without_index_html_is_refused() {
    let archive = tgz(&[("readme.txt", b"x")]);
    let url = serve(archive.clone()).await;
    let c = cache();
    assert!(ensure(&url, &sha(&archive), true, c.path()).await.is_err());
}
