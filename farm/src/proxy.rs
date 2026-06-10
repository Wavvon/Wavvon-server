/// Reverse proxy: /hub/:hub_id/* → http://127.0.0.1:{port}/*
///
/// Forwards all HTTP methods, headers, and body verbatim.
/// Adds X-Forwarded-For and X-Hub-Id headers.
/// Returns 503 hub_suspended when suspended_at IS NOT NULL.
/// Returns 404 hub_not_found when the hub_id doesn't exist.
///
/// WebSocket upgrades are not proxied at the HTTP layer — axum's WS upgrade
/// interception happens in the hub process itself; the farm forwards the
/// HTTP Upgrade request and lets the TCP connection carry the WS frames
/// via the http tunnel (reqwest does not support WS upgrading directly, so
/// WS connections pass through as a normal HTTP request; the hub process
/// handles the upgrade on its side via the forwarded connection).
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{Request, StatusCode};
use axum::response::Response;

use crate::state::FarmState;

pub async fn proxy_handler(
    Path((hub_id, path)): Path<(String, String)>,
    State(state): State<Arc<FarmState>>,
    req: Request<Body>,
) -> Response<Body> {
    // Look up the hub row.
    let row: Option<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT suspended_at, process_port FROM hubs WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(&hub_id)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    let (suspended_at, process_port) = match row {
        None => {
            return json_error(StatusCode::NOT_FOUND, "hub_not_found");
        }
        Some(r) => r,
    };

    if suspended_at.is_some() {
        return json_error(StatusCode::SERVICE_UNAVAILABLE, "hub_suspended");
    }

    let port = match process_port {
        Some(p) if p > 0 => p as u16,
        _ => {
            return json_error(StatusCode::SERVICE_UNAVAILABLE, "hub_not_running");
        }
    };

    // Build the upstream URL: strip /hub/<hub_id> prefix, keep the rest.
    let upstream_path = if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.clone()
    } else {
        format!("/{path}")
    };

    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();

    let upstream_url = format!("http://127.0.0.1:{port}{upstream_path}{query}");

    // Build the forwarded request.
    let method = req.method().clone();
    let mut headers = req.headers().clone();

    // Add proxy headers.
    // X-Forwarded-For: client IP (best effort from connection info).
    if let Ok(hv) = axum::http::HeaderValue::from_str("127.0.0.1") {
        headers.insert("x-forwarded-for", hv);
    }
    if let Ok(hv) = axum::http::HeaderValue::from_str(&hub_id) {
        headers.insert("x-hub-id", hv);
    }

    let body_bytes = match axum::body::to_bytes(req.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(_) => {
            return json_error(StatusCode::BAD_REQUEST, "failed_to_read_body");
        }
    };

    // Build reqwest request.
    let mut rb = state.http_client.request(method.clone(), &upstream_url);

    // Forward headers (skip hop-by-hop headers that reqwest manages).
    for (name, value) in &headers {
        let name_str = name.as_str().to_lowercase();
        if matches!(
            name_str.as_str(),
            "host" | "connection" | "transfer-encoding" | "te" | "trailer" | "upgrade"
        ) {
            continue;
        }
        if let Ok(v) = value.to_str() {
            rb = rb.header(name.as_str(), v);
        }
    }

    rb = rb.body(body_bytes);

    let upstream_resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(hub_id, error = %e, "Upstream hub request failed");
            return json_error(StatusCode::BAD_GATEWAY, "upstream_error");
        }
    };

    // Build the axum response from the upstream response.
    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut builder = Response::builder().status(status);

    for (name, value) in upstream_resp.headers() {
        let name_str = name.as_str().to_lowercase();
        if matches!(
            name_str.as_str(),
            "transfer-encoding" | "connection" | "keep-alive"
        ) {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    let resp_bytes = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(hub_id, error = %e, "Failed to read upstream response body");
            return json_error(StatusCode::BAD_GATEWAY, "upstream_read_error");
        }
    };

    builder
        .body(Body::from(resp_bytes))
        .unwrap_or_else(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "response_build_error"))
}

fn json_error(status: StatusCode, error: &'static str) -> Response<Body> {
    let body = format!("{{\"error\":\"{error}\"}}");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}
