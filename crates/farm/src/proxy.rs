/// Reverse proxy: /hub/:serial/* → the hub process, wherever it runs.
///
/// Routes by the hub's Ed25519 pubkey ("serial"), resolved via the unique
/// partial index on `hubs.hub_pubkey` — see docs/docs/farm-impl.md,
/// "Serial routing — first slice". The opaque `hubs.id` PK is no longer the
/// proxy key; it survives only as the farm-internal management handle under
/// `/farm/hubs/{id}`.
///
/// Forwards all HTTP methods, headers, and body verbatim.
/// Returns 503 hub_suspended when suspended_at IS NOT NULL.
/// Returns 404 hub_not_found when the serial doesn't resolve to a known,
/// non-deleted hub.
/// Returns 503 hub_not_running when the row exists but has no live
/// process_port.
///
/// `Connection: Upgrade` requests (WebSocket) take a separate path
/// (`bridge_upgrade`) that hands the client's raw connection off to a
/// bidirectional byte copy against a fresh TCP connection to the hub
/// process — the buffered reqwest path used for ordinary requests cannot
/// carry an Upgrade handshake.
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::node::NodeTarget;
use crate::state::FarmState;

/// One resolved row: whether the hub is suspended, which port it listens
/// on, and — since the farm became multi-node — *which machine* that port is
/// on and how to trust it.
type ResolvedHub = (
    Option<i64>,
    Option<i32>,
    Option<String>,
    String,
    Option<String>,
);

/// Resolve an address segment to a hub row.
///
/// A released slug does not resolve: that is the point of releasing it. The
/// pubkey always does, which is what makes it the address of last resort — a
/// client that has lost track of a hub's current name still has its key.
///
/// The join to `servers` is a LEFT join and every node column is optional: a
/// hub with no server row is one this farm runs itself, which is every hub a
/// single-node farm has.
async fn resolve_hub(state: &FarmState, segment: &str) -> Option<ResolvedHub> {
    if crate::slug::looks_like_pubkey(segment) {
        return sqlx::query_as(
            "SELECT h.suspended_at, h.process_port, s.host,
                    COALESCE(s.tls_mode, 'ca'), s.cert_sha256
             FROM hubs h LEFT JOIN servers s ON s.id = h.server_id
             WHERE h.hub_pubkey = $1 AND h.deleted_at IS NULL",
        )
        .bind(segment)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
    }

    // Slugs are stored lowercase, so an address typed with different capitals
    // reaches the same hub instead of a stranger's.
    let lowered = segment.to_ascii_lowercase();
    let row: Option<ResolvedHub> = sqlx::query_as(
        "SELECT h.suspended_at, h.process_port, n.host,
                COALESCE(n.tls_mode, 'ca'), n.cert_sha256
         FROM hub_slugs s JOIN hubs h ON h.id = s.hub_id
         LEFT JOIN servers n ON n.id = h.server_id
         WHERE s.slug = $1 AND s.released_at IS NULL AND h.deleted_at IS NULL",
    )
    .bind(&lowered)
    .fetch_optional(&state.db)
    .await
    .unwrap_or(None);

    if row.is_some() {
        // Best-effort usage stamp. This is the data that would let a future
        // "prune slugs nobody follows any more" have a real criterion instead
        // of a guess; nothing depends on it today, and a failed write must
        // never cost a request.
        let _ = sqlx::query("UPDATE hub_slugs SET last_resolved_at = $1 WHERE slug = $2")
            .bind(crate::unix_now())
            .bind(&lowered)
            .execute(&state.db)
            .await;
    }
    row
}

pub async fn proxy_handler(
    Path((serial, path)): Path<(String, String)>,
    State(state): State<Arc<FarmState>>,
    req: Request<Body>,
) -> Response<Body> {
    // The address segment is either the hub's pubkey or one of its slugs; the
    // two key spaces cannot overlap (`slug::normalize` refuses anything
    // shaped like a key), so one lookup function serves both. Deliberately
    // not two route families — that mistake has already cost this repo a
    // pair of ban endpoints that silently disagreed.
    //
    // `suspended_at` is BIGINT, `process_port` is INTEGER — decoding both as
    // i64 (as a prior version of this query did) makes sqlx's runtime type
    // check reject every row with a non-null process_port, silently
    // degrading to a false "not found" via `unwrap_or(None)` below.
    let (suspended_at, process_port, host, tls_mode, cert_sha256) =
        match resolve_hub(&state, &serial).await {
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

    // Build the upstream path: strip /hub/<serial> prefix, keep the rest.
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
    let upstream_path_and_query = format!("{upstream_path}{query}");

    let node = NodeTarget {
        host,
        port,
        tls_mode,
        cert_sha256,
    };

    if is_upgrade_request(req.headers()) {
        return bridge_upgrade(req, &serial, &node, upstream_path_and_query).await;
    }

    proxy_buffered(req, &serial, &node, upstream_path_and_query, &state).await
}

/// True when the request is an HTTP `Upgrade` request (WebSocket, etc.) —
/// the buffered reqwest path below cannot carry these (it has no way to
/// hand back the raw socket after the 101 response).
fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let has_upgrade_header = headers.contains_key(axum::http::header::UPGRADE);
    let connection_says_upgrade = headers
        .get(axum::http::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    has_upgrade_header && connection_says_upgrade
}

// ---------------------------------------------------------------------------
// Buffered HTTP proxy (the common case: everything except Upgrade requests).
// ---------------------------------------------------------------------------

async fn proxy_buffered(
    req: Request<Body>,
    serial: &str,
    node: &NodeTarget,
    upstream_path_and_query: String,
    state: &FarmState,
) -> Response<Body> {
    let upstream_url = format!(
        "{}://{}{upstream_path_and_query}",
        node.scheme(),
        node.authority()
    );

    // A hub on this machine keeps using the farm's shared client. A remote one
    // needs a client whose TLS configuration matches *that node* — pinning is
    // per-node by construction — so they are built once each and cached.
    let client = match node_client(state, node).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(serial, host = ?node.host, error = %e, "No usable TLS configuration for node");
            return json_error(StatusCode::BAD_GATEWAY, "upstream_error");
        }
    };

    // Build the forwarded request.
    let method = req.method().clone();
    let mut headers = req.headers().clone();

    // Add proxy headers.
    // X-Forwarded-For: client IP (best effort from connection info).
    if let Ok(hv) = axum::http::HeaderValue::from_str("127.0.0.1") {
        headers.insert("x-forwarded-for", hv);
    }
    if let Ok(hv) = axum::http::HeaderValue::from_str(serial) {
        headers.insert("x-hub-serial", hv);
    }

    // Limit forwarded request body to 32 MiB; larger payloads are rejected before
    // they reach the upstream hub process.
    const MAX_BODY: usize = 32 * 1024 * 1024;
    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return json_error(StatusCode::BAD_REQUEST, "failed_to_read_body");
        }
    };

    // Build reqwest request.
    let mut rb = client.request(method.clone(), &upstream_url);

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
            tracing::warn!(serial, error = %e, "Upstream hub request failed");
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
            tracing::warn!(serial, error = %e, "Failed to read upstream response body");
            return json_error(StatusCode::BAD_GATEWAY, "upstream_read_error");
        }
    };

    builder
        .body(Body::from(resp_bytes))
        .unwrap_or_else(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "response_build_error"))
}

// ---------------------------------------------------------------------------
// Upgrade (WebSocket) socket bridge.
// ---------------------------------------------------------------------------

/// Bridge an `Upgrade` request through to the hub process.
///
/// The farm cannot terminate/re-implement the WebSocket handshake itself —
/// the hub owns that protocol logic. Instead the farm opens its own raw TCP
/// connection to the hub, replays the client's request line/headers over
/// it verbatim, relays the hub's response headers back to the client, and
/// — once both sides have completed their half of the HTTP Upgrade — copies
/// bytes bidirectionally between the two sockets for the lifetime of the
/// connection. Same serial → port resolution as the buffered path; only the
/// transport differs.
async fn bridge_upgrade(
    mut req: Request<Body>,
    serial: &str,
    node: &NodeTarget,
    upstream_path_and_query: String,
) -> Response<Body> {
    let method = req.method().clone();
    let mut headers = req.headers().clone();
    if let Ok(hv) = axum::http::HeaderValue::from_str("127.0.0.1") {
        headers.insert("x-forwarded-for", hv);
    }
    if let Ok(hv) = axum::http::HeaderValue::from_str(serial) {
        headers.insert("x-hub-serial", hv);
    }

    // Take ownership of hyper's pending upgrade for the client-facing
    // connection before we return our (empty-body) response — hyper hands
    // over the raw socket once it sees we've replied with a matching
    // Upgrade response.
    let on_upgrade = hyper::upgrade::on(&mut req);

    // The forgettable half. Everything above this line is shared with the
    // buffered path, and a WebSocket that still went to loopback would look
    // fine on every REST call and fail only for the live connection — which is
    // the connection a chat client spends its whole session on.
    let mut hub_stream = match connect_upstream(node).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(serial, upstream = %node.authority(), error = %e, "Failed to connect to hub for upgrade");
            return json_error(StatusCode::BAD_GATEWAY, "upstream_error");
        }
    };

    // Replay the request line + headers to the hub over the raw socket.
    // WebSocket upgrade requests carry no body, so we don't forward one.
    let mut request_text = format!("{method} {upstream_path_and_query} HTTP/1.1\r\n");
    for (name, value) in headers.iter() {
        if name.as_str().eq_ignore_ascii_case("host") {
            continue; // rewritten below to point at the hub's own address.
        }
        if let Ok(v) = value.to_str() {
            request_text.push_str(&format!("{}: {}\r\n", name.as_str(), v));
        }
    }
    request_text.push_str(&format!("host: {}\r\n\r\n", node.authority()));

    if let Err(e) = hub_stream.write_all(request_text.as_bytes()).await {
        tracing::warn!(serial, upstream = %node.authority(), error = %e, "Failed to send upgrade request to hub");
        return json_error(StatusCode::BAD_GATEWAY, "upstream_error");
    }

    let (status, resp_headers, leftover) = match read_response_head(&mut hub_stream).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(serial, upstream = %node.authority(), error = %e, "Failed to read upgrade response from hub");
            return json_error(StatusCode::BAD_GATEWAY, "upstream_error");
        }
    };

    let mut builder = Response::builder().status(status);
    for (name, value) in &resp_headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let response = match builder.body(Body::empty()) {
        Ok(r) => r,
        Err(_) => {
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "response_build_error");
        }
    };

    // Only bridge sockets if the hub actually agreed to the upgrade —
    // otherwise this is a normal (non-101) response and there is nothing to
    // hand off.
    if status == 101 {
        let serial = serial.to_string();
        tokio::spawn(async move {
            let client_upgraded = match on_upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(serial, error = %e, "Client-side upgrade failed");
                    return;
                }
            };
            let mut client_io = hyper_util::rt::TokioIo::new(client_upgraded);

            if !leftover.is_empty() {
                if let Err(e) = client_io.write_all(&leftover).await {
                    tracing::warn!(serial, error = %e, "Failed to flush buffered hub bytes to client");
                    return;
                }
            }

            if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut hub_stream).await {
                tracing::debug!(serial, error = %e, "Upgrade bridge connection closed");
            }
        });
    }

    response
}

/// Read a raw HTTP/1.x response head (status line + headers) off `stream`,
/// returning the status code, the headers, and any bytes already read past
/// the header terminator. Those trailing bytes belong to the upgraded
/// protocol (e.g. the first WS frame, if the hub wrote eagerly) and must be
/// replayed to the client before the raw byte copy starts.
async fn read_response_head<S: tokio::io::AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
) -> std::io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    let header_end = loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "hub closed connection during upgrade handshake",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_double_crlf(&buf) {
            break pos + 4;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "upgrade response headers too large",
            ));
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(502);

    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();

    Ok((status, headers, buf[header_end..].to_vec()))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// A byte stream to a hub: a plain socket on this machine, a TLS session to
/// another one.
trait Upstream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Upstream for T {}

/// Open the socket the upgrade bridge copies bytes over.
async fn connect_upstream(node: &NodeTarget) -> anyhow::Result<Box<dyn Upstream>> {
    let tcp = TcpStream::connect(node.authority()).await?;
    let Some(host) = node.tls_host() else {
        return Ok(Box::new(tcp));
    };

    let config = crate::node::client_config(node)?;
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(host)?;
    Ok(Box::new(connector.connect(name, tcp).await?))
}

/// The HTTP client for a node, built once and kept.
///
/// A per-request client would be a fresh TLS handshake and a fresh connection
/// pool on every call — and for a pinned node it would rebuild the verifier
/// each time too. Keyed by everything that changes the configuration, so a
/// node that rotates its certificate gets a new client rather than a stale
/// one that trusts the old digest.
async fn node_client(state: &FarmState, node: &NodeTarget) -> anyhow::Result<reqwest::Client> {
    if node.is_local() {
        return Ok(state.http_client.clone());
    }
    let key = format!(
        "{}|{}|{}",
        node.authority(),
        node.tls_mode,
        node.cert_sha256.as_deref().unwrap_or("")
    );
    if let Some(client) = state.node_clients.read().await.get(&key) {
        return Ok(client.clone());
    }

    let config = crate::node::client_config(node)?;
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()?;
    state.node_clients.write().await.insert(key, client.clone());
    Ok(client)
}

fn json_error(status: StatusCode, error: &'static str) -> Response<Body> {
    let body = format!("{{\"error\":\"{error}\"}}");
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}
