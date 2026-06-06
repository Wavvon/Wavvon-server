use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
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

/// Returns true if the IP address falls within a private/loopback range.
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 127.0.0.0/8
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
        IpAddr::V6(v6) => {
            // ::1 loopback
            v6.is_loopback()
        }
    }
}

/// Perform SSRF-safe DNS resolution. Returns Err with "ssrf_blocked" if any
/// resolved address is in a private range, or Err with "dns_failed" if
/// resolution fails entirely.
fn check_ssrf(host: &str, port: u16) -> Result<(), &'static str> {
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

    Ok(())
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
        let pattern = format!("{}={}",  lower_attr, quote);
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

pub async fn get_preview(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(params): Query<PreviewQuery>,
) -> Result<Json<LinkPreview>, (StatusCode, String)> {
    let url_str = params.url.trim().to_string();

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
        .find(|c| c == '/' || c == '?' || c == '#')
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
        let port_part = authority.get(bracket_end + 2..).and_then(|p| p.parse::<u16>().ok());
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

    // SSRF check — DNS resolve before fetching
    check_ssrf(&host, port)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Check cache
    {
        let cache = state.preview_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((cached, inserted_at)) = cache.get(&url_str) {
            if inserted_at.elapsed().as_secs() < CACHE_TTL_SECS {
                return Ok(Json(cached.clone()));
            }
        }
    }

    // Fetch with timeout
    let resp = state
        .http_client
        .get(&url_str)
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .header("User-Agent", "Mozilla/5.0 Voxply-Hub LinkPreview/1.0")
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("fetch_error: {e}")))?;

    // Read up to MAX_BODY_BYTES
    let bytes = {
        use futures_util::StreamExt;
        let mut body = resp.bytes_stream();
        let mut buf = Vec::with_capacity(MAX_BODY_BYTES);
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| (StatusCode::BAD_GATEWAY, format!("read_error: {e}")))?;
            let remaining = MAX_BODY_BYTES - buf.len();
            if chunk.len() >= remaining {
                buf.extend_from_slice(&chunk[..remaining]);
                break;
            } else {
                buf.extend_from_slice(&chunk);
            }
        }
        buf
    };

    let html = String::from_utf8_lossy(&bytes);
    let (title, description, image_url) = parse_og_tags(&html);

    let preview = LinkPreview {
        url: url_str.clone(),
        title,
        description,
        image_url,
    };

    // Store in cache
    {
        let mut cache = state.preview_cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(url_str, (preview.clone(), Instant::now()));
    }

    Ok(Json(preview))
}
