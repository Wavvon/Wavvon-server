use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::state::AppState;

const MAX_BODY_BYTES: usize = 64 * 1024; // 64 KB
const CACHE_TTL_SECS: u64 = 30 * 60; // 30 minutes
const FETCH_TIMEOUT_SECS: u64 = 5;
const MAX_AVATAR_BYTES: usize = 1024 * 1024; // 1 MB
const MAX_CACHED_IMAGE_BYTES: usize = 128 * 1024 * 1024;
/// SVG is left out on purpose: it is a document that can carry script.
const IMAGE_TYPES: [&str; 5] = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
];

/// Preview images by id: (content type, bytes, fetched at). Bounded by total
/// bytes (`MAX_CACHED_IMAGE_BYTES`), oldest evicted first.
type ImageCache = Mutex<HashMap<String, (String, Vec<u8>, Instant)>>;
static PREVIEW_IMAGES: std::sync::LazyLock<ImageCache> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkPreview {
    pub url: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image_url: Option<String>,
}

pub type PreviewCache = Mutex<HashMap<String, (LinkPreview, Instant)>>;

#[derive(Deserialize)]
pub struct PreviewQuery {
    pub url: String,
}

/// Returns true unless the address is a global unicast one: deny by default,
/// so loopback, private, link-local, CGNAT, benchmarking, reserved, multicast,
/// broadcast, unspecified, NAT64 and the like are all refused. IPv4-mapped and
/// NAT64-embedded IPv6 forms are judged by their embedded v4 address.
///
/// `pub(crate)` so other outbound-URL validators (e.g. `webhook_url`) share
/// the same rule instead of duplicating it.
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !is_global_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return !is_global_v4(v4);
            }
            let s = v6.segments();
            // 64:ff9b::/96 NAT64 well-known prefix: judge the embedded v4.
            if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let [a, b] = [s[6].to_be_bytes(), s[7].to_be_bytes()];
                return !is_global_v4(Ipv4Addr::new(a[0], a[1], b[0], b[1]));
            }
            // Only 2000::/3 is global unicast today; everything else (::, ::1,
            // fc00::/7, fe80::/10, ff00::/8, 64:ff9b:1::/48, ...) is refused.
            if s[0] & 0xe000 != 0x2000 {
                return true;
            }
            // Documentation (2001:db8::/32) and 6to4 (2002::/16, embeds v4).
            (s[0] == 0x2001 && s[1] == 0x0db8) || s[0] == 0x2002
        }
    }
}

fn is_global_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    !(o[0] == 0 // 0.0.0.0/8
        || o[0] == 10
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (o[1] & 0xf0) == 16)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 192 && o[1] == 0 && o[2] == 2) // TEST-NET-1
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15
        || (o[0] == 198 && o[1] == 51 && o[2] == 100) // TEST-NET-2
        || (o[0] == 203 && o[1] == 0 && o[2] == 113) // TEST-NET-3
        || o[0] >= 224) // multicast, 240.0.0.0/4 reserved, broadcast
}

/// Perform SSRF-safe DNS resolution without blocking the runtime. Returns the
/// validated SocketAddrs (all checked to be global) so the caller can pin the
/// connection to them, preventing DNS-rebinding between check and connect.
async fn resolve_and_check_ssrf(
    host: &str,
    port: u16,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, &'static str> {
    resolve_and_check(host, port, &|a| allow_private || !is_private_ip(a.ip())).await
}

/// [`resolve_and_check_ssrf`] with the verdict passed in, so a test can let
/// one loopback server through and refuse the next.
async fn resolve_and_check(
    host: &str,
    port: u16,
    allowed: &(dyn Fn(SocketAddr) -> bool + Sync),
) -> Result<Vec<SocketAddr>, &'static str> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "dns_failed")?
        .collect();

    if addrs.is_empty() {
        return Err("dns_failed");
    }

    if !addrs.iter().all(|a| allowed(*a)) {
        return Err("ssrf_blocked");
    }

    Ok(addrs)
}

/// Extract OG/meta tags and title from raw HTML bytes.
/// Only scans up to the end of the `<head>` section for efficiency.
fn parse_og_tags(html: &str) -> (Option<String>, Option<String>, Option<String>) {
    // Work only within the <head> if possible
    let head_end = html
        .find("</head>")
        .or_else(|| html.find("</HEAD>"))
        .unwrap_or(html.len())
        .min(html.len());
    let head = &html[..head_end];

    let mut og_title: Option<String> = None;
    let mut og_description: Option<String> = None;
    let mut og_image: Option<String> = None;
    let mut page_title: Option<String> = None;

    // Parse <meta> tags
    let mut pos = 0;
    while let Some(tag_start) = find_ci(head, pos, "<meta") {
        let tag_end = match head[tag_start..].find('>') {
            Some(e) => tag_start + e + 1,
            None => break,
        };
        let tag = &head[tag_start..tag_end];

        // og:title
        if attr_matches(tag, "property", "og:title") || attr_matches(tag, "name", "og:title") {
            og_title = get_attr(tag, "content");
        }
        // og:description
        if attr_matches(tag, "property", "og:description")
            || attr_matches(tag, "name", "og:description")
        {
            og_description = get_attr(tag, "content");
        }
        // og:image
        if attr_matches(tag, "property", "og:image") || attr_matches(tag, "name", "og:image") {
            og_image = get_attr(tag, "content");
        }
        // fallback description
        if og_description.is_none() && attr_matches(tag, "name", "description") {
            og_description = get_attr(tag, "content");
        }

        pos = tag_end;
    }

    // Parse <title>
    if let Some(title_start) = find_ci(head, 0, "<title") {
        if let Some(close) = head[title_start..].find('>') {
            let content_start = title_start + close + 1;
            if let Some(end) = find_ci(head, content_start, "</title") {
                let raw = &head[content_start..end];
                let t = raw.trim().to_string();
                if !t.is_empty() {
                    page_title = Some(t);
                }
            }
        }
    }

    // og:title takes priority over <title>
    let title = og_title.or(page_title);
    (title, og_description, og_image)
}

/// Case-insensitive substring search.
fn find_ci(haystack: &str, start: usize, needle: &str) -> Option<usize> {
    if start >= haystack.len() {
        return None;
    }
    let lower_hay = haystack[start..].to_lowercase();
    let lower_needle = needle.to_lowercase();
    lower_hay.find(&lower_needle).map(|i| i + start)
}

/// Check if a tag has `attr="value"` (case-insensitive value comparison).
fn attr_matches(tag: &str, attr: &str, value: &str) -> bool {
    get_attr(tag, attr)
        .map(|v| v.to_lowercase() == value.to_lowercase())
        .unwrap_or(false)
}

/// Extract the value of an attribute from an HTML tag string.
fn get_attr(tag: &str, attr: &str) -> Option<String> {
    let lower_tag = tag.to_lowercase();
    let lower_attr = attr.to_lowercase();

    // Try attr="value" and attr='value'
    for quote in &['"', '\''] {
        let pattern = format!("{}={}", lower_attr, quote);
        if let Some(idx) = lower_tag.find(&pattern) {
            let value_start = idx + pattern.len();
            if value_start < tag.len() {
                if let Some(end) = tag[value_start..].find(*quote) {
                    let val = tag[value_start..value_start + end].trim().to_string();
                    if !val.is_empty() {
                        return Some(html_decode(&val));
                    }
                }
            }
        }
    }
    None
}

/// Minimal HTML entity decoding for common entities in attribute values.
fn html_decode(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
}

/// Per-user burst cap for preview fetches.
/// 10 requests per 60-second window is generous for normal link-unfurl UX
/// while bounding the outbound-fetch fan-out a single user can cause.
const PREVIEW_RATE_LIMIT: u32 = 10;
const PREVIEW_RATE_WINDOW_SECS: u64 = 60;

/// Fetches `url_str` under the SSRF rules (http(s) only, no non-global
/// address, the connection pinned to the addresses that were checked) and
/// returns at most `max` bytes of the body with its content type. Redirects are
/// followed by hand (max 3) so every hop is re-resolved, re-checked and pinned.
async fn fetch_capped(
    url_str: &str,
    max: usize,
) -> Result<(Vec<u8>, Option<String>), (StatusCode, String)> {
    fetch_capped_opts(url_str, max, false).await
}

/// [`fetch_capped`] with the operator opt-in for private and loopback
/// addresses (`WAVVON_ALLOW_PRIVATE_WEBHOOKS`: LAN hubs, test harnesses). The
/// connection is still pinned to the resolved addresses and redirects are
/// still followed by hand; only the "must be global" verdict is waived.
pub(crate) async fn fetch_capped_opts(
    url_str: &str,
    max: usize,
    allow_private: bool,
) -> Result<(Vec<u8>, Option<String>), (StatusCode, String)> {
    let resp = fetch_checked(
        url_str,
        allow_private,
        std::time::Duration::from_secs(FETCH_TIMEOUT_SECS),
    )
    .await?;
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Read up to `max` bytes
    let bytes = {
        use futures_util::StreamExt;
        let mut body = resp.bytes_stream();
        let mut buf = Vec::with_capacity(max);
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| (StatusCode::BAD_GATEWAY, format!("read_error: {e}")))?;
            let remaining = max - buf.len();
            if chunk.len() >= remaining {
                buf.extend_from_slice(&chunk[..remaining]);
                break;
            } else {
                buf.extend_from_slice(&chunk);
            }
        }
        buf
    };
    Ok((bytes, content_type))
}

/// The SSRF-checked request behind [`fetch_capped_opts`], handing back the
/// response unread so a caller can stream it. After more than 3 redirects the
/// last redirect response itself is returned.
pub(crate) async fn fetch_checked(
    url_str: &str,
    allow_private: bool,
    timeout: std::time::Duration,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let host_ok = |h: &str| allow_private || !h.eq_ignore_ascii_case("localhost");
    let addr_ok = |a: SocketAddr| allow_private || !is_private_ip(a.ip());
    fetch_checked_with(url_str, &host_ok, &addr_ok, timeout).await
}

async fn fetch_checked_with(
    url_str: &str,
    host_ok: &(dyn Fn(&str) -> bool + Sync),
    addr_ok: &(dyn Fn(SocketAddr) -> bool + Sync),
    timeout: std::time::Duration,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let mut url = reqwest::Url::parse(url_str).map_err(|_| bad("invalid_url"))?;
    let mut hops = 0;
    let resp = loop {
        if !matches!(url.scheme(), "http" | "https") {
            return Err(bad("invalid_scheme"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| bad("missing_host"))?
            .to_string();
        if !host_ok(&host) {
            return Err(bad("ssrf_blocked"));
        }
        let port = url.port_or_known_default().unwrap_or(80);
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        let validated = resolve_and_check(bare, port, addr_ok).await.map_err(bad)?;

        // no_proxy(): a system proxy must not forward to addresses that passed
        // the check. Redirects are off: this loop is the redirect policy.
        let client = reqwest::Client::builder()
            .resolve_to_addrs(&host, &validated)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("client_build_error: {e}"),
                )
            })?;
        let resp = client
            .get(url.clone())
            .header("User-Agent", "Mozilla/5.0 Wavvon-Hub LinkPreview/1.0")
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("fetch_error: {e}")))?;

        if !resp.status().is_redirection() {
            break resp;
        }
        let next = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|l| url.join(l).ok());
        hops += 1;
        match next {
            Some(n) if hops <= 3 => url = n,
            // Too many hops or no usable Location: stop and read this response.
            _ => break resp,
        }
    };
    Ok(resp)
}

/// Per-user budget for anything that makes this hub fetch a URL on a member's
/// behalf: link previews and sticker copies share it. It bounds outbound
/// traffic; it is not a storage quota.
pub(crate) fn check_fetch_rate(state: &AppState, key: &str) -> Result<(), (StatusCode, String)> {
    {
        let mut map = state
            .rate_limiters
            .preview
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(PREVIEW_RATE_WINDOW_SECS);

        // Opportunistic eviction (same pattern as the messages limiter).
        const EVICTION_THRESHOLD: usize = 5_000;
        if map.len() >= EVICTION_THRESHOLD {
            map.retain(|_, (_, ts)| now.duration_since(*ts) <= window);
        }

        let entry = map.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > window {
            *entry = (0, now);
        }
        if entry.0 >= PREVIEW_RATE_LIMIT {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "preview_rate_limited".to_string(),
            ));
        }
        entry.0 += 1;
    }
    Ok(())
}

pub async fn get_preview(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<PreviewQuery>,
) -> Result<Json<LinkPreview>, (StatusCode, String)> {
    check_fetch_rate(&state, &user.public_key)?;

    let url_str = params.url.trim().to_string();

    // Check cache
    {
        let cache = state
            .preview_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some((cached, inserted_at)) = cache.get(&url_str) {
            if inserted_at.elapsed().as_secs() < CACHE_TTL_SECS {
                return Ok(Json(cached.clone()));
            }
        }
    }

    let (bytes, content_type) = fetch_capped(&url_str, MAX_BODY_BYTES).await?;

    let (title, description, image_url) = if is_image_type(content_type.as_deref()) {
        // Fetched a second time under the image cap: the first read stopped at
        // MAX_BODY_BYTES, and a GIF is usually larger than that.
        (None, None, proxy_image(&state, &url_str, &url_str).await)
    } else {
        let html = String::from_utf8_lossy(&bytes);
        let (title, description, og_image) = parse_og_tags(&html);
        let image_url = match og_image {
            Some(image) => proxy_image(&state, &url_str, &image).await,
            None => None,
        };
        (title, description, image_url)
    };

    let preview = LinkPreview {
        url: url_str.clone(),
        title,
        description,
        image_url,
    };

    // Store in cache
    {
        let mut cache = state
            .preview_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        cache.insert(url_str, (preview.clone(), Instant::now()));
    }

    Ok(Json(preview))
}

fn is_image_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|c| c.split(';').next())
        .is_some_and(|c| IMAGE_TYPES.contains(&c.trim().to_ascii_lowercase().as_str()))
}

/// The normalised content type when the response is an allowed raster type
/// that fits `cap`; `None` otherwise.
fn accepted_image_type(content_type: Option<&str>, len: usize, cap: usize) -> Option<String> {
    let ct = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    (len <= cap && IMAGE_TYPES.contains(&ct.as_str())).then_some(ct)
}

type CachedImage = (String, Vec<u8>, Instant);

/// Adds an image, dropping expired entries and then the oldest until the total
/// stays within `max_total`.
fn insert_image(
    images: &mut HashMap<String, CachedImage>,
    id: String,
    entry: CachedImage,
    max_total: usize,
) {
    images.retain(|_, (_, _, at)| at.elapsed().as_secs() < CACHE_TTL_SECS);
    images.remove(&id);
    let mut total: usize = images.values().map(|(_, b, _)| b.len()).sum();
    while total + entry.1.len() > max_total {
        let Some(oldest) = images
            .iter()
            .min_by_key(|(_, (_, _, at))| *at)
            .map(|(k, _)| k.clone())
        else {
            break;
        };
        if let Some((_, b, _)) = images.remove(&oldest) {
            total -= b.len();
        }
    }
    images.insert(id, entry);
}

/// Fetches a preview's image on the hub and returns the hub's own URL for it,
/// so a reader's client never contacts the third-party host. `None` (no image
/// on the card) when the hub has no public URL to offer, or the image is not
/// a raster type within the `max_preview_image_bytes` setting.
async fn proxy_image(state: &AppState, page_url: &str, image: &str) -> Option<String> {
    let base = state.canonical_url.read().await.clone()?;
    let absolute = reqwest::Url::parse(page_url).ok()?.join(image).ok()?;
    let cap = crate::routes::hub::read_preview_image_cap(&state.db).await as usize;
    let (bytes, content_type) = fetch_capped(absolute.as_str(), cap + 1).await.ok()?;
    let content_type = accepted_image_type(content_type.as_deref(), bytes.len(), cap)?;
    use sha2::{Digest, Sha256};
    let id = hex::encode(&Sha256::digest(absolute.as_str().as_bytes())[..16]);
    {
        let mut images = PREVIEW_IMAGES.lock().unwrap_or_else(|e| e.into_inner());
        let entry = (content_type, bytes, Instant::now());
        insert_image(&mut images, id.clone(), entry, MAX_CACHED_IMAGE_BYTES);
    }
    Some(format!("{}/preview/image/{id}", base.trim_end_matches('/')))
}

/// Fetches an image on the hub, under the same rules as preview images, and
/// keeps it in the uploads directory under a name derived from its source URL
/// (so the same avatar is stored once). Returns its hub-relative URL,
/// `/uploads/<name>`, or `None` when it cannot be fetched or is not a raster
/// image within `MAX_AVATAR_BYTES`.
pub(crate) async fn store_remote_image(url: &str) -> Option<String> {
    let (bytes, content_type) = fetch_capped(url, MAX_AVATAR_BYTES + 1).await.ok()?;
    let content_type = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    if bytes.len() > MAX_AVATAR_BYTES || !IMAGE_TYPES.contains(&content_type.as_str()) {
        return None;
    }
    let ext = content_type
        .trim_start_matches("image/")
        .replace("jpeg", "jpg");
    use sha2::{Digest, Sha256};
    let name = format!(
        "remote-{}.{ext}",
        hex::encode(&Sha256::digest(url.as_bytes())[..16])
    );
    let dir = crate::routes::uploads::uploads_dir();
    tokio::fs::create_dir_all(&dir).await.ok()?;
    let path = format!("{}/{name}", dir.trim_end_matches('/'));
    if tokio::fs::metadata(&path).await.is_err() {
        tokio::fs::write(&path, &bytes).await.ok()?;
    }
    Some(format!("/uploads/{name}"))
}

/// `GET /preview/image/{id}`: an image the hub fetched for a link preview.
/// No auth: an `<img>` cannot send a bearer token, and only images a member's
/// authenticated `/preview` already fetched are ever served, so this is not
/// an open proxy.
pub async fn get_preview_image(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::http::header;
    use axum::response::IntoResponse;
    let images = PREVIEW_IMAGES.lock().unwrap_or_else(|e| e.into_inner());
    match images.get(&id) {
        Some((content_type, bytes, at)) if at.elapsed().as_secs() < CACHE_TTL_SECS => (
            [
                (header::CONTENT_TYPE, content_type.clone()),
                (
                    header::CACHE_CONTROL,
                    format!("public, max-age={CACHE_TTL_SECS}"),
                ),
                (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_string()),
            ],
            bytes.clone(),
        )
            .into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked(s: &str) -> bool {
        is_private_ip(s.parse().unwrap())
    }

    #[test]
    fn non_global_addresses_are_blocked() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fc00::1",
            "fd12::1",
            "fe80::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b::c0a8:1",
            "2001:db8::1",
            "64:ff9b:1::1",
        ] {
            assert!(blocked(ip), "{ip} should be blocked");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.17.0.1",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
        ] {
            assert!(!blocked(ip), "{ip} should be allowed");
        }
    }

    /// Every redirect hop is re-resolved and re-checked: a public first hop
    /// answering 3xx to a private address is refused at the second hop,
    /// before anything connects to it. Loopback stands in for both, with the
    /// verdict letting only the first server through.
    #[tokio::test]
    async fn a_redirect_to_a_refused_address_is_cut_before_connecting() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let target_app = axum::Router::new().fallback(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { "secret" }
        });
        tokio::spawn(async move { axum::serve(target, target_app).await.unwrap() });

        let first = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_addr = first.local_addr().unwrap();
        let location = format!("http://localhost:{}/", target_addr.port());
        let first_app = axum::Router::new().fallback(move || {
            let location = location.clone();
            async move {
                (
                    axum::http::StatusCode::FOUND,
                    [(axum::http::header::LOCATION, location)],
                )
            }
        });
        tokio::spawn(async move { axum::serve(first, first_app).await.unwrap() });

        let result = fetch_checked_with(
            &format!("http://{first_addr}/"),
            &|_| true,
            &|a| a.port() == first_addr.port(),
            std::time::Duration::from_secs(5),
        )
        .await;
        assert_eq!(result.err().map(|e| e.1).as_deref(), Some("ssrf_blocked"));
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn private_targets_are_refused_before_any_connection() {
        assert_eq!(
            resolve_and_check_ssrf("localhost", 80, false).await,
            Err("ssrf_blocked")
        );
        for u in [
            "http://user@127.0.0.1/",
            "http://0.0.0.0/",
            "http://[::]/",
            "http://100.64.0.1/",
        ] {
            assert_eq!(fetch_capped(u, 10).await.unwrap_err().1, "ssrf_blocked");
        }
    }

    #[test]
    fn image_types_are_recognised_with_parameters() {
        assert!(is_image_type(Some("image/gif")));
        assert!(is_image_type(Some("Image/GIF; charset=x")));
        assert!(!is_image_type(Some("image/svg+xml")));
        assert!(!is_image_type(Some("text/html")));
        assert!(!is_image_type(None));
    }

    #[test]
    fn an_image_over_the_cap_or_of_a_wrong_type_is_refused() {
        assert_eq!(
            accepted_image_type(Some("image/gif"), 100, 100).as_deref(),
            Some("image/gif")
        );
        assert!(accepted_image_type(Some("image/gif"), 101, 100).is_none());
        assert!(accepted_image_type(Some("text/html"), 10, 100).is_none());
        assert!(accepted_image_type(None, 10, 100).is_none());
    }

    #[test]
    fn image_cache_stays_under_its_byte_bound_and_evicts_oldest() {
        let mut m = HashMap::new();
        for i in 0..10 {
            let e = ("image/gif".to_string(), vec![0u8; 400], Instant::now());
            insert_image(&mut m, format!("k{i}"), e, 1000);
            assert!(m.values().map(|(_, b, _)| b.len()).sum::<usize>() <= 1000);
        }
        assert_eq!(m.len(), 2);
        assert!(m.contains_key("k9") && m.contains_key("k8"));
    }

    #[tokio::test]
    async fn a_fetched_image_is_served_with_its_type_and_an_unknown_one_is_not() {
        PREVIEW_IMAGES.lock().unwrap().insert(
            "abc".to_string(),
            ("image/png".to_string(), vec![1, 2, 3], Instant::now()),
        );
        let resp = get_preview_image(axum::extract::Path("abc".to_string())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "image/png");
        assert_eq!(resp.headers()["x-content-type-options"], "nosniff");

        let resp = get_preview_image(axum::extract::Path("nope".to_string())).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
