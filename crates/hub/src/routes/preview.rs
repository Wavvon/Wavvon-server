use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
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
const MAX_IMAGE_BYTES: usize = 1024 * 1024; // 1 MB
const MAX_CACHED_IMAGES: usize = 128;
/// SVG is left out on purpose: it is a document that can carry script.
const IMAGE_TYPES: [&str; 5] = [
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
];

/// Preview images by id: (content type, bytes, fetched at). Bounded by count
/// and by `MAX_IMAGE_BYTES`, so at most 128 MB.
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

/// Returns true if the IP address falls within a private/loopback/link-local range.
/// Covers IPv4 private ranges, IPv6 unique-local (fc00::/7), IPv6 link-local
/// (fe80::/10), and IPv4-mapped IPv6 (::ffff:x.x.x.x treated as their embedded v4).
///
/// `pub(crate)` so other outbound-URL validators (e.g.
/// `outgoing_webhooks::routes`) can reuse the same private-range rule instead
/// of duplicating it.
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            // ::1 loopback
            if v6.is_loopback() {
                return true;
            }
            // IPv4-mapped: ::ffff:x.x.x.x — validate the embedded v4 address
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_v4(v4);
            }
            let segs = v6.segments();
            // fc00::/7 — unique local (fc00:: through fdff::)
            if segs[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // fe80::/10 — link local
            if segs[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            false
        }
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    // 127.0.0.0/8 loopback
    octets[0] == 127
    // 10.0.0.0/8
    || octets[0] == 10
    // 172.16.0.0/12
    || (octets[0] == 172 && (octets[1] & 0xf0) == 16)
    // 192.168.0.0/16
    || (octets[0] == 192 && octets[1] == 168)
    // 169.254.0.0/16 (link-local)
    || (octets[0] == 169 && octets[1] == 254)
}

/// Perform SSRF-safe DNS resolution. Returns the list of validated SocketAddrs
/// (all checked to be non-private) so the caller can connect to a specific one,
/// preventing DNS-rebinding between the check and the connection.
fn resolve_and_check_ssrf(host: &str, port: u16) -> Result<Vec<SocketAddr>, &'static str> {
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|_| "dns_failed")?
        .collect();

    if addrs.is_empty() {
        return Err("dns_failed");
    }

    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            return Err("ssrf_blocked");
        }
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

/// Fetches `url_str` under the SSRF rules (http(s) only, no private or
/// loopback address, the connection pinned to the address that was checked)
/// and returns at most `max` bytes of the body with its content type.
async fn fetch_capped(
    url_str: &str,
    max: usize,
) -> Result<(Vec<u8>, Option<String>), (StatusCode, String)> {
    let url_str = url_str.to_string();

    // Validate scheme
    let is_https = if url_str.starts_with("https://") {
        true
    } else if url_str.starts_with("http://") {
        false
    } else {
        return Err((StatusCode::BAD_REQUEST, "invalid_scheme".to_string()));
    };

    // Extract host and optional port from the URL string.
    // Strip scheme, then take the authority part (up to first '/', '?', '#').
    let after_scheme = if is_https {
        &url_str["https://".len()..]
    } else {
        &url_str["http://".len()..]
    };

    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];

    if authority.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "missing_host".to_string()));
    }

    // Split host:port — account for IPv6 like [::1]:8080
    let (host, port) = if authority.starts_with('[') {
        // IPv6 literal
        let bracket_end = authority.find(']').unwrap_or(authority.len());
        let host_part = &authority[1..bracket_end];
        let port_part = authority
            .get(bracket_end + 2..)
            .and_then(|p| p.parse::<u16>().ok());
        let default_port = if is_https { 443u16 } else { 80u16 };
        (host_part.to_string(), port_part.unwrap_or(default_port))
    } else if let Some(colon) = authority.rfind(':') {
        let port_str = &authority[colon + 1..];
        if let Ok(p) = port_str.parse::<u16>() {
            (authority[..colon].to_string(), p)
        } else {
            let default_port = if is_https { 443u16 } else { 80u16 };
            (authority.to_string(), default_port)
        }
    } else {
        let default_port = if is_https { 443u16 } else { 80u16 };
        (authority.to_string(), default_port)
    };

    // Reject "localhost" hostname directly
    if host.eq_ignore_ascii_case("localhost") {
        return Err((StatusCode::BAD_REQUEST, "ssrf_blocked".to_string()));
    }

    // SSRF check — DNS resolve once, validate all IPs, keep the result.
    // We then pin reqwest to one of the validated addresses so a second DNS
    // lookup at connection time cannot return a different (private) IP.
    let validated_addrs = resolve_and_check_ssrf(&host, port)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Build a one-shot client that is pinned to the first validated address.
    // This prevents DNS-rebinding: the hostname in the URL resolves to the
    // address we already validated, not whatever the DNS says at connect time.
    //
    // no_proxy(): disable HTTP_PROXY / HTTPS_PROXY env vars so a system proxy
    // cannot forward requests to private IPs that passed the DNS check.
    //
    // Custom redirect policy: cap at 3 hops and block redirects to private IP
    // literals (covers 301 → http://127.0.0.1/ attacks). Hostname-based
    // redirects are allowed — a follow-on DNS resolution would require async
    // code that is unavailable in the policy callback; the small hop cap limits
    // exposure. IPv6 bracket notation is handled by stripping [ ].
    let pinned_addr = validated_addrs[0];
    let pinned_client = reqwest::Client::builder()
        .resolve(&host, pinned_addr)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 {
                return attempt.stop();
            }
            if let Some(h) = attempt.url().host_str() {
                let bare = h.trim_start_matches('[').trim_end_matches(']');
                if bare.eq_ignore_ascii_case("localhost") {
                    return attempt.stop();
                }
                if let Ok(ip) = bare.parse::<IpAddr>() {
                    if is_private_ip(ip) {
                        return attempt.stop();
                    }
                }
            }
            attempt.follow()
        }))
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .build()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("client_build_error: {e}"),
            )
        })?;

    // Fetch with timeout
    let resp = pinned_client
        .get(&url_str)
        .header("User-Agent", "Mozilla/5.0 Wavvon-Hub LinkPreview/1.0")
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("fetch_error: {e}")))?;

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

pub async fn get_preview(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<PreviewQuery>,
) -> Result<Json<LinkPreview>, (StatusCode, String)> {
    // Per-user rate limit: 10 preview fetches per 60 seconds.
    // Cache hits are counted too — they're cheap, but the outer window
    // keeps one user from monopolising the endpoint.
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

        let entry = map.entry(user.public_key.clone()).or_insert((0, now));
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

    let (bytes, _) = fetch_capped(&url_str, MAX_BODY_BYTES).await?;

    let html = String::from_utf8_lossy(&bytes);
    let (title, description, og_image) = parse_og_tags(&html);
    let image_url = match og_image {
        Some(image) => proxy_image(&state, &url_str, &image).await,
        None => None,
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

/// Fetches a preview's image on the hub and returns the hub's own URL for it,
/// so a reader's client never contacts the third-party host. `None` (no image
/// on the card) when the hub has no public URL to offer, or the image is not
/// a raster type within `MAX_IMAGE_BYTES`.
async fn proxy_image(state: &AppState, page_url: &str, image: &str) -> Option<String> {
    let base = state.canonical_url.read().await.clone()?;
    let absolute = reqwest::Url::parse(page_url).ok()?.join(image).ok()?;
    let (bytes, content_type) = fetch_capped(absolute.as_str(), MAX_IMAGE_BYTES + 1)
        .await
        .ok()?;
    let content_type = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    if bytes.len() > MAX_IMAGE_BYTES || !IMAGE_TYPES.contains(&content_type.as_str()) {
        return None;
    }
    use sha2::{Digest, Sha256};
    let id = hex::encode(&Sha256::digest(absolute.as_str().as_bytes())[..16]);
    {
        let mut images = PREVIEW_IMAGES.lock().unwrap_or_else(|e| e.into_inner());
        images.retain(|_, (_, _, at)| at.elapsed().as_secs() < CACHE_TTL_SECS);
        if images.len() >= MAX_CACHED_IMAGES {
            let oldest = images
                .iter()
                .min_by_key(|(_, (_, _, at))| *at)
                .map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                images.remove(&oldest);
            }
        }
        images.insert(id.clone(), (content_type, bytes, Instant::now()));
    }
    Some(format!("{}/preview/image/{id}", base.trim_end_matches('/')))
}

/// Fetches an image on the hub, under the same rules as preview images, and
/// keeps it in the uploads directory under a name derived from its source URL
/// (so the same avatar is stored once). Returns its hub-relative URL,
/// `/uploads/<name>`, or `None` when it cannot be fetched or is not a raster
/// image within `MAX_IMAGE_BYTES`.
pub(crate) async fn store_remote_image(url: &str) -> Option<String> {
    let (bytes, content_type) = fetch_capped(url, MAX_IMAGE_BYTES + 1).await.ok()?;
    let content_type = content_type?.split(';').next()?.trim().to_ascii_lowercase();
    if bytes.len() > MAX_IMAGE_BYTES || !IMAGE_TYPES.contains(&content_type.as_str()) {
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
