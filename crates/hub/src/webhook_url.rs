//! Shared validation for outbound webhook URLs: outgoing webhooks and an app's
//! `webhook_url` (outgoing-webhooks.md §1/§7) follow the same rule — https
//! only, no private/loopback hosts — unless the operator opts in with
//! `WAVVON_ALLOW_PRIVATE_WEBHOOKS`. `routes::preview` owns the canonical
//! private-IP-range check; it is reused here rather than duplicated.

use std::net::{IpAddr, ToSocketAddrs};

use axum::http::StatusCode;
use url::Url;

pub fn validate_webhook_url(raw: &str, allow_private: bool) -> Result<(), (StatusCode, String)> {
    let parsed =
        Url::parse(raw).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid URL".to_string()))?;

    if !allow_private && parsed.scheme() != "https" {
        return Err((StatusCode::BAD_REQUEST, "URL must use https://".to_string()));
    }

    let host = parsed
        .host_str()
        .ok_or((StatusCode::BAD_REQUEST, "URL must have a host".to_string()))?;

    // Operator opt-in (WAVVON_ALLOW_PRIVATE_WEBHOOKS): LAN hubs and test
    // harnesses talk to plain-http / private receivers.
    if allow_private {
        return Ok(());
    }

    // Reject bare "localhost" outright (matches the redirect-guard rule in
    // routes::preview).
    if host.eq_ignore_ascii_case("localhost") {
        return Err((
            StatusCode::BAD_REQUEST,
            "URL host must not be a private or loopback address".to_string(),
        ));
    }

    // If the host is a literal IP, check it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if crate::routes::preview::is_private_ip(ip) {
            return Err((
                StatusCode::BAD_REQUEST,
                "URL host must not be a private or loopback address".to_string(),
            ));
        }
        return Ok(());
    }

    // Otherwise resolve the hostname and reject if any resolved address is
    // private/loopback. Best-effort: DNS failure here is a validation error,
    // not a delivery-time concern.
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = (host, port).to_socket_addrs().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "Could not resolve host".to_string(),
        )
    })?;

    let mut any = false;
    for addr in addrs {
        any = true;
        if crate::routes::preview::is_private_ip(addr.ip()) {
            return Err((
                StatusCode::BAD_REQUEST,
                "URL host must not be a private or loopback address".to_string(),
            ));
        }
    }
    if !any {
        return Err((
            StatusCode::BAD_REQUEST,
            "Could not resolve host".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_webhook_url as v;

    #[test]
    fn strict_rejects_http_and_private_opt_in_allows() {
        for u in [
            "http://example.com/h",
            "https://localhost/h",
            "https://127.0.0.1/h",
            "https://10.0.0.5/h",
            "https://169.254.169.254/h",
        ] {
            assert!(v(u, false).is_err(), "{u}");
            assert!(v(u, true).is_ok(), "{u}");
        }
        assert!(v("https://1.1.1.1/h", false).is_ok());
        assert!(v("not a url", true).is_err());
    }
}
