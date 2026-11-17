//! Serving a web client downloaded from a pinned URL
//! (`WAVVON_WEB_CLIENT_URL` + `WAVVON_WEB_CLIENT_SHA256`).
//!
//! The web client holds its users' keys, so the hash is not optional: the
//! operator pins an exact build, and the archive is unpacked only after its
//! SHA-256 matches. The result is a directory handed to
//! `WebClientConfig::load`, exactly like `WAVVON_WEB_CLIENT_DIR`.

use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use sha2::{Digest, Sha256};

/// Directory (relative to the working dir) holding one subdirectory per hash.
pub const CACHE_DIR: &str = "web-client-cache";
const MAX_DOWNLOAD: usize = 200 * 1024 * 1024;
const MAX_UNPACKED: u64 = 600 * 1024 * 1024;
const TIMEOUT: Duration = Duration::from_secs(120);

/// Where the served client comes from.
#[derive(Debug, PartialEq, Eq)]
pub enum Source {
    None,
    Dir(String),
    Pinned { url: String, sha256: String },
}

/// Apply the settings rules: a URL needs a hash, and a directory plus a URL
/// are two sources, which is an error rather than a precedence.
pub fn pick(dir: Option<&str>, url: Option<&str>, sha256: Option<&str>) -> anyhow::Result<Source> {
    match (dir, url, sha256) {
        (Some(_), Some(_), _) => bail!(
            "WAVVON_WEB_CLIENT_DIR and WAVVON_WEB_CLIENT_URL are both set; pick one source \
             (in the official image, clear the directory with WAVVON_WEB_CLIENT_DIR=)"
        ),
        (_, Some(_), None) => bail!(
            "WAVVON_WEB_CLIENT_URL needs WAVVON_WEB_CLIENT_SHA256: the web client holds its \
             users' keys, so the hub only serves an exact, pinned build"
        ),
        (_, None, Some(_)) => {
            bail!("WAVVON_WEB_CLIENT_SHA256 is set without WAVVON_WEB_CLIENT_URL")
        }
        (_, Some(u), Some(h)) => {
            let h = h.trim().to_ascii_lowercase();
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("WAVVON_WEB_CLIENT_SHA256 must be 64 hex characters");
            }
            Ok(Source::Pinned {
                url: u.to_string(),
                sha256: h,
            })
        }
        (Some(d), None, None) => Ok(Source::Dir(d.to_string())),
        (None, None, None) => Ok(Source::None),
    }
}

/// Make sure the pinned client is unpacked under `cache_root` and return the
/// directory holding its `index.html`. A cache hit makes no network request.
/// `allow_private` is `WAVVON_ALLOW_PRIVATE_WEBHOOKS`: http and private hosts.
pub async fn ensure(
    url: &str,
    sha256: &str,
    allow_private: bool,
    cache_root: &Path,
) -> anyhow::Result<PathBuf> {
    let final_dir = cache_root.join(sha256);
    if final_dir.is_dir() {
        return client_root(&final_dir);
    }
    if !allow_private && !url.starts_with("https://") {
        bail!("WAVVON_WEB_CLIENT_URL must be an https URL: {url}");
    }
    let bytes = download(url, allow_private)
        .await
        .with_context(|| format!("downloading web client from {url}"))?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if actual != sha256 {
        bail!(
            "web client from {url} does not match its pin: expected sha256 {sha256}, got \
             {actual}. Refusing to serve it"
        );
    }

    std::fs::create_dir_all(cache_root)?;
    let tmp = cache_root.join(format!(".tmp-{sha256}"));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    if let Err(e) = unpack(&bytes, &tmp).and_then(|()| client_root(&tmp).map(|_| ())) {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e.context(format!("unpacking web client from {url}")));
    }
    std::fs::rename(&tmp, &final_dir)?;
    client_root(&final_dir)
}

/// The directory to serve for these settings, downloading the pinned client
/// when that is the configured source. `None` = API-only.
pub async fn resolve_settings(s: &crate::settings::Settings) -> anyhow::Result<Option<PathBuf>> {
    match pick(
        s.web_client_dir.as_deref(),
        s.web_client_url.as_deref(),
        s.web_client_sha256.as_deref(),
    )? {
        Source::None => Ok(None),
        Source::Dir(d) => Ok(Some(PathBuf::from(d))),
        Source::Pinned { url, sha256 } => ensure(
            &url,
            &sha256,
            s.allow_private_webhooks,
            Path::new(CACHE_DIR),
        )
        .await
        .map(Some),
    }
}

async fn download(url: &str, allow_private: bool) -> anyhow::Result<Vec<u8>> {
    use futures_util::StreamExt;
    let resp = crate::routes::preview::fetch_checked(url, allow_private, TIMEOUT)
        .await
        .map_err(|(_, m)| anyhow::anyhow!(m))?;
    if !resp.status().is_success() {
        bail!("server answered {}", resp.status());
    }
    let mut buf = Vec::new();
    let mut body = resp.bytes_stream();
    while let Some(chunk) = body.next().await {
        buf.extend_from_slice(&chunk?);
        if buf.len() > MAX_DOWNLOAD {
            bail!("archive is larger than {} MiB", MAX_DOWNLOAD >> 20);
        }
    }
    Ok(buf)
}

/// `index.html` at the root, or under the single top-level directory.
fn client_root(dir: &Path) -> anyhow::Result<PathBuf> {
    if dir.join("index.html").is_file() {
        return Ok(dir.to_path_buf());
    }
    let mut entries = std::fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() == 1 && entries[0].path().join("index.html").is_file() {
        return Ok(entries.remove(0).path());
    }
    bail!("archive has no index.html at its root (or under a single top-level directory)")
}

/// A relative path made of plain names only: no root, no `..`.
fn safe_rel(p: &Path) -> anyhow::Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            _ => bail!("archive entry '{}' escapes the archive root", p.display()),
        }
    }
    Ok(out)
}

fn write_file(dest: &Path, rel: &Path, src: &mut impl Read, total: &mut u64) -> anyhow::Result<()> {
    let path = dest.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut out = std::fs::File::create(&path)?;
    let mut limited = src.take(MAX_UNPACKED + 1 - *total);
    *total += std::io::copy(&mut limited, &mut out)?;
    out.flush()?;
    if *total > MAX_UNPACKED {
        bail!("archive unpacks to more than {} MiB", MAX_UNPACKED >> 20);
    }
    Ok(())
}

fn unpack(bytes: &[u8], dest: &Path) -> anyhow::Result<()> {
    let mut total = 0u64;
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(bytes));
        for entry in ar.entries()? {
            let mut entry = entry?;
            let kind = entry.header().entry_type();
            let rel = safe_rel(&entry.path()?)?;
            if kind.is_dir() {
                std::fs::create_dir_all(dest.join(rel))?;
            } else if kind.is_file() {
                write_file(dest, &rel, &mut entry, &mut total)?;
            } else if !(kind.is_pax_global_extensions() || kind.is_pax_local_extensions()) {
                bail!(
                    "archive entry '{}' is a link or special file",
                    rel.display()
                );
            }
        }
    } else if bytes.starts_with(b"PK") {
        let mut ar = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
        for i in 0..ar.len() {
            let mut f = ar.by_index(i)?;
            let name = f.name().to_string();
            let rel = match f.enclosed_name() {
                Some(p) => safe_rel(&p)?,
                None => bail!("archive entry '{name}' escapes the archive root"),
            };
            if f.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000) {
                bail!("archive entry '{name}' is a symlink");
            }
            if f.is_dir() {
                std::fs::create_dir_all(dest.join(rel))?;
            } else {
                write_file(dest, &rel, &mut f, &mut total)?;
            }
        }
    } else {
        bail!("archive is neither .tar.gz nor .zip");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "00000000000000000000000000000000000000000000000000000000000000ab";

    #[test]
    fn pick_enforces_the_source_rules() {
        assert!(pick(Some("d"), Some("https://x"), Some(H)).is_err());
        assert!(pick(None, Some("https://x"), None).is_err());
        assert!(pick(None, Some("https://x"), Some("nothex")).is_err());
        assert!(pick(None, None, Some(H)).is_err());
        assert_eq!(pick(None, None, None).unwrap(), Source::None);
        assert_eq!(
            pick(Some("d"), None, None).unwrap(),
            Source::Dir("d".into())
        );
        assert!(matches!(
            pick(None, Some("https://x"), Some(&H.to_uppercase())).unwrap(),
            Source::Pinned { sha256, .. } if sha256 == H
        ));
    }
}
