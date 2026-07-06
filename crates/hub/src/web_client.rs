//! Optional static web-client serving.
//!
//! When `WAVVON_WEB_CLIENT_DIR` is set the hub serves a pre-built SPA from
//! that directory at the root.  All named API routes take precedence; only
//! requests that fall through to the axum fallback reach this handler.
//!
//! SPA fallback rule (critical for API 404 semantics):
//! - If the request's `Accept` header contains `"text/html"` (browser
//!   navigation), return `index.html` with status 200 so deep links work.
//! - Otherwise return a plain 404 so API clients see a proper error status
//!   when they typo a path — a stray `fetch("/apii/channels")` must NOT
//!   silently receive an HTML document with 200.
//!
//! `index.html` has `<script>window.__WAVVON_HOME_HUB__=window.location.origin;</script>`
//! injected immediately before `</head>` so the served client knows the hub
//! it was served from.  The transformed bytes are cached at startup.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use tower::ServiceExt as _;
use tower_http::services::ServeDir;

/// Pre-loaded, config-injected bytes of index.html.
/// Cached once at startup since directory contents are static for the process.
#[derive(Clone)]
pub struct WebClientConfig {
    pub dir: PathBuf,
    /// index.html bytes with the config script injected.
    pub index_html: Arc<[u8]>,
}

impl WebClientConfig {
    /// Load the web client directory and prepare the injected index.html.
    ///
    /// Returns `Err` if the directory does not exist or index.html is missing
    /// or unreadable.
    pub fn load(dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let dir = dir.into();
        if !dir.exists() {
            anyhow::bail!("WAVVON_WEB_CLIENT_DIR '{}' does not exist", dir.display());
        }
        let index_path = dir.join("index.html");
        let raw = std::fs::read(&index_path).map_err(|e| {
            anyhow::anyhow!(
                "WAVVON_WEB_CLIENT_DIR: cannot read '{}': {e}",
                index_path.display()
            )
        })?;

        let index_html = inject_hub_config(raw);
        Ok(Self {
            dir,
            index_html: Arc::from(index_html),
        })
    }
}

/// Insert the hub-origin config script immediately before `</head>`.
///
/// The injected script sets `window.__WAVVON_HOME_HUB__` to
/// `window.location.origin` so the client defaults to the hub it was served
/// from without any server-side origin detection.
fn inject_hub_config(mut html: Vec<u8>) -> Vec<u8> {
    const SCRIPT: &[u8] = b"<script>window.__WAVVON_HOME_HUB__=window.location.origin;</script>";
    const MARKER: &[u8] = b"</head>";

    if let Some(pos) = html.windows(MARKER.len()).position(|w| w == MARKER) {
        html.splice(pos..pos, SCRIPT.iter().copied());
    } else {
        // No </head> tag — append to end as a safe fallback.
        html.extend_from_slice(SCRIPT);
    }
    html
}

/// Check whether the request's `Accept` header includes `text/html`.
fn accepts_html(headers: &HeaderMap) -> bool {
    headers
        .get_all(axum::http::header::ACCEPT)
        .iter()
        .any(|v| v.to_str().map(|s| s.contains("text/html")).unwrap_or(false))
}

/// Build the axum `Router::fallback_service` for static asset serving.
///
/// The returned service is meant to be used with `.fallback_service(...)` on
/// the main router so all named routes (the full API) take priority.
///
/// Serving logic:
/// 1. Try to serve the file from `dir` via `ServeDir` (assets, JS, CSS, …).
/// 2. If `ServeDir` would return 404:
///    - If the client sends `Accept: text/html` → serve `index.html` (200).
///    - Otherwise → plain 404 text response.
///
/// Note: `/` is handled by `ServeDir`'s built-in index-file support for the
/// asset path, but index.html is served through our custom handler in the
/// router so the injected script is present.  We wrap the whole thing in a
/// single tower `Service` implementation via axum's `fallback_service`.
pub fn build_fallback(cfg: Arc<WebClientConfig>) -> axum::routing::Router {
    let dir = cfg.dir.clone();
    axum::Router::new().fallback(move |req: Request| {
        let cfg = cfg.clone();
        let dir = dir.clone();
        async move { serve_request(cfg, dir, req).await }
    })
}

async fn serve_request(cfg: Arc<WebClientConfig>, dir: PathBuf, req: Request) -> Response {
    let accepts = accepts_html(req.headers());
    let path = req.uri().path().to_owned();

    // If the path is exactly "/" or we are serving the root, return index.html
    // directly (with config injection).  This also catches the case where the
    // browser navigates to the hub's root URL.
    if path == "/" || path.is_empty() {
        return index_response(cfg.index_html.clone());
    }

    // For all other paths, try ServeDir first.
    let serve_dir = ServeDir::new(&dir);
    // ServeDir::oneshot returns Result<Response<ServeFileSystemResponseBody>, _>.
    // We map its response into axum's Response via IntoResponse.
    let sd_result: Result<_, std::convert::Infallible> = serve_dir.oneshot(req).await;
    match sd_result {
        Ok(sd_resp) => {
            let status = sd_resp.status();
            if status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED {
                // Asset not found — apply SPA fallback rule.
                if accepts {
                    index_response(cfg.index_html.clone())
                } else {
                    (StatusCode::NOT_FOUND, "Not Found").into_response()
                }
            } else {
                sd_resp.into_response()
            }
        }
        Err(e) => match e {},
    }
}

fn index_response(bytes: Arc<[u8]>) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Body::from(bytes.to_vec()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injects_script_before_head_close() {
        let html = b"<html><head><title>Test</title></head><body></body></html>".to_vec();
        let result = inject_hub_config(html);
        let s = std::str::from_utf8(&result).unwrap();
        assert!(s.contains(
            "<script>window.__WAVVON_HOME_HUB__=window.location.origin;</script></head>"
        ));
    }

    #[test]
    fn injects_script_when_no_head_close() {
        let html = b"<html><body></body></html>".to_vec();
        let result = inject_hub_config(html);
        let s = std::str::from_utf8(&result).unwrap();
        assert!(s.ends_with("<script>window.__WAVVON_HOME_HUB__=window.location.origin;</script>"));
    }

    #[test]
    fn accepts_html_detects_text_html() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                .parse()
                .unwrap(),
        );
        assert!(accepts_html(&headers));
    }

    #[test]
    fn accepts_html_rejects_json() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            "application/json".parse().unwrap(),
        );
        assert!(!accepts_html(&headers));
    }

    #[test]
    fn accepts_html_rejects_empty() {
        let headers = HeaderMap::new();
        assert!(!accepts_html(&headers));
    }
}
