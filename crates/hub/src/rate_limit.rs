//! Per-IP token-bucket rate limiter with reverse-proxy support.
//!
//! # IP source
//!
//! When `WAVVON_TRUSTED_PROXY=true` the limiter reads the client IP from the
//! **`X-Forwarded-For`** header instead of the raw socket peer address.
//!
//! ## XFF parsing rule (single trusted-proxy assumption)
//!
//! The hub assumes **exactly one trusted reverse proxy** (Caddy, nginx, …) sits
//! in front.  That proxy appends the real client IP as the last entry in XFF:
//!
//! ```text
//! X-Forwarded-For: <real-client-IP>
//! X-Forwarded-For: <spoofed>, <real-client-IP>   ← if client sent its own XFF
//! ```
//!
//! We take the **last comma-separated entry** — the hop the proxy itself saw —
//! because the proxy is trusted and always appends the address it received the
//! connection from.  Any earlier entries were supplied by the client and MUST
//! NOT be trusted.
//!
//! **Security**: when `WAVVON_TRUSTED_PROXY` is `false` (the default) the header
//! is completely ignored and the raw socket peer address is used.  Never set the
//! flag unless you have a real proxy that terminates TLS in front.
//!
//! # IPv6 / IPv4-mapped canonicalization
//!
//! Before a key is inserted into the bucket map the IP is canonicalized:
//!
//! * **IPv4-mapped IPv6** (`::ffff:a.b.c.d`) → collapsed to the plain IPv4
//!   address `a.b.c.d` so both representations share the same bucket.
//! * **Genuine IPv6** → masked to the /64 prefix (high 64 bits, low 64 bits
//!   zeroed).  A single consumer-/64 therefore uses one bucket regardless of
//!   which /128 it sources from.
//! * **IPv4** → used as-is (per-/32, i.e. full address).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::RequestExt;
use tokio::sync::Mutex;

// ── IP canonicalization ───────────────────────────────────────────────────────

/// Return the canonical bucket key for a given `IpAddr`.
///
/// * IPv4-mapped IPv6 (`::ffff:a.b.c.d`) → `IpAddr::V4(a.b.c.d)`
/// * Genuine IPv6 → /64 prefix (low 64 bits zeroed)
/// * IPv4 → unchanged
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            // Unwrap the IPv4-mapped form first.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            // Genuine IPv6: bucket at /64 by zeroing the low 64 bits.
            let segs = v6.octets();
            let masked = [
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7], 0, 0, 0, 0,
                0, 0, 0, 0,
            ];
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

// ── XFF parsing ──────────────────────────────────────────────────────────────

/// Extract the real client IP from `X-Forwarded-For` using the single
/// trusted-proxy rule: take the **last** comma-separated entry.
///
/// Returns `None` if the header is absent, empty, or contains no parseable IP.
fn xff_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let val = headers.get("x-forwarded-for")?.to_str().ok()?;
    // The last entry is the one appended by our trusted proxy.
    val.split(',')
        .map(|s| s.trim())
        .rfind(|s| !s.is_empty())?
        .parse()
        .ok()
}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct Config {
    /// Maximum number of requests a single IP can burst through at once.
    pub burst: u32,
    /// How many tokens refill per second (sustained rate).
    pub refill_per_sec: f64,
}

impl Config {
    /// Strict limits for the auth handshake: 10 attempts, refilling 1/s.
    pub const AUTH: Config = Config {
        burst: 10,
        refill_per_sec: 1.0,
    };

    /// `AUTH`, unless the operator raised it.
    ///
    /// The budget is per IP and one authentication spends **two** tokens
    /// (`/auth/challenge`, then `/auth/verify`), so behind a shared address
    /// the default is a handful of people opening the app at once — and the
    /// client cannot tell a 429 from a hub that will not have it, so it
    /// retries into the same wall. The default is unchanged; this only gives
    /// an operator who knows their users share an address a way to say so.
    pub fn auth() -> Config {
        Config {
            burst: env_num(wavvon_hub_env::AUTH_RATE_BURST).unwrap_or(Self::AUTH.burst as f64)
                as u32,
            refill_per_sec: env_num(wavvon_hub_env::AUTH_RATE_PER_SEC)
                .unwrap_or(Self::AUTH.refill_per_sec),
        }
    }

    /// Moderate limits for write endpoints: 30 burst, 10/s sustained.
    pub const WRITE: Config = Config {
        burst: 30,
        refill_per_sec: 10.0,
    };
}

/// A positive number from the environment, or nothing. A malformed or
/// nonsensical value keeps the default rather than disabling the limiter —
/// `WAVVON_AUTH_RATE_BURST=0` is far more likely a typo than an intent to
/// refuse every login.
fn env_num(key: &str) -> Option<f64> {
    let raw = std::env::var(key).ok()?;
    match raw.trim().parse::<f64>() {
        Ok(v) if v > 0.0 && v.is_finite() => Some(v),
        _ => {
            tracing::warn!("{key}={raw:?} is not a positive number — keeping the default");
            None
        }
    }
}

// ── Bucket ────────────────────────────────────────────────────────────────────

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

pub struct RateLimiter {
    /// Keyed by the *canonical* IP (see `canonicalize_ip`).
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    config: Config,
    /// When true, derive the client IP from `X-Forwarded-For` (single trusted
    /// proxy assumption) rather than the raw socket address.
    trusted_proxy: bool,
}

impl RateLimiter {
    /// Create a new limiter.  `trusted_proxy` should be taken from
    /// `Settings::trusted_proxy` (loaded from `WAVVON_TRUSTED_PROXY`).
    pub fn new(config: Config, trusted_proxy: bool) -> Arc<Self> {
        Arc::new(Self {
            buckets: Mutex::new(HashMap::new()),
            config,
            trusted_proxy,
        })
    }

    /// Whether trusted-proxy mode is active.  Used by the startup banner.
    pub fn is_trusted_proxy(&self) -> bool {
        self.trusted_proxy
    }

    /// Returns `true` if the request is allowed; `false` if rate-limited.
    async fn check(&self, ip: IpAddr) -> bool {
        let key = canonicalize_ip(ip);
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets.entry(key).or_insert_with(|| Bucket {
            tokens: self.config.burst as f64,
            last_refill: now,
        });

        // Refill based on elapsed time.
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.config.refill_per_sec).min(self.config.burst as f64);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            // Opportunistic cleanup so the map doesn't grow forever for idle IPs.
            if buckets.len() > 10_000 {
                buckets.retain(|_, b| now.duration_since(b.last_refill) < Duration::from_secs(600));
            }
            true
        } else {
            false
        }
    }

    /// Resolve the effective client IP for this request.
    ///
    /// In trusted-proxy mode, use XFF; fall back to the socket peer address.
    /// In direct mode, always use the socket peer address.
    fn resolve_ip(&self, socket_ip: Option<IpAddr>, headers: &HeaderMap) -> Option<IpAddr> {
        if self.trusted_proxy {
            xff_ip(headers).or(socket_ip)
        } else {
            socket_ip
        }
    }
}

// ── Middleware ────────────────────────────────────────────────────────────────

/// Middleware that enforces the given limiter.  If the request has no
/// `ConnectInfo` extension (e.g., under `axum_test::TestServer`, or behind a
/// transport that didn't add one), the request is passed through — the
/// operator is expected to rate-limit at the edge proxy in that case.
pub async fn enforce(
    limiter: Arc<RateLimiter>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let socket_ip = req
        .extract_parts::<ConnectInfo<std::net::SocketAddr>>()
        .await
        .ok()
        .map(|ConnectInfo(addr)| addr.ip());

    let ip = limiter.resolve_ip(socket_ip, req.headers());

    if let Some(ip) = ip {
        if !limiter.check(ip).await {
            return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
        }
    }
    Ok(next.run(req).await)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // ---- H6 canonicalization ------------------------------------------------

    /// Two different /128 addresses in the same /64 must map to the same key.
    #[test]
    fn ipv6_same_64_same_bucket_key() {
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        assert_eq!(
            canonicalize_ip(a),
            canonicalize_ip(b),
            "different /128 addresses in the same /64 should share one bucket key"
        );
    }

    /// Two addresses in *different* /64s must map to different keys.
    #[test]
    fn ipv6_different_64_different_bucket_key() {
        let a: IpAddr = "2001:db8:0:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:0:2::1".parse().unwrap();
        assert_ne!(
            canonicalize_ip(a),
            canonicalize_ip(b),
            "addresses in different /64s must have different bucket keys"
        );
    }

    /// IPv4-mapped IPv6 and the plain IPv4 address must map to the same key.
    #[test]
    fn ipv4_mapped_collapses_to_ipv4() {
        let plain = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // ::ffff:1.2.3.4
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304));
        assert_eq!(
            canonicalize_ip(mapped),
            canonicalize_ip(plain),
            "::ffff:1.2.3.4 and 1.2.3.4 must map to the same bucket key"
        );
    }

    /// IPv4 addresses are unchanged (per-/32).
    #[test]
    fn ipv4_unchanged() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(canonicalize_ip(ip), ip);
    }

    // ---- H5 XFF / trusted-proxy ---------------------------------------------

    /// With trusted-proxy ON, XFF is honored and overrides the socket IP.
    #[test]
    fn trusted_proxy_on_xff_honored() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.42".parse().unwrap());
        let socket_ip: IpAddr = "10.0.0.1".parse().unwrap(); // proxy's LAN IP

        let limiter = RateLimiter {
            buckets: Mutex::new(HashMap::new()),
            config: Config::AUTH,
            trusted_proxy: true,
        };

        let result = limiter.resolve_ip(Some(socket_ip), &headers);
        assert_eq!(
            result,
            Some("203.0.113.42".parse::<IpAddr>().unwrap()),
            "trusted-proxy mode must use XFF over the socket address"
        );
    }

    /// With trusted-proxy OFF, XFF is ignored and the socket IP is used.
    #[test]
    fn trusted_proxy_off_xff_ignored() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.42".parse().unwrap());
        let socket_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let limiter = RateLimiter {
            buckets: Mutex::new(HashMap::new()),
            config: Config::AUTH,
            trusted_proxy: false,
        };

        let result = limiter.resolve_ip(Some(socket_ip), &headers);
        assert_eq!(
            result,
            Some(socket_ip),
            "direct mode must always use the socket address, never XFF"
        );
    }

    /// XFF with multiple entries (client-supplied prefix + proxy-appended last entry).
    #[test]
    fn trusted_proxy_xff_multi_entry_takes_last() {
        let mut headers = axum::http::HeaderMap::new();
        // Client spoofed 1.1.1.1 as the first entry; proxy appended the real IP last.
        headers.insert("x-forwarded-for", "1.1.1.1, 203.0.113.99".parse().unwrap());
        let socket_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let limiter = RateLimiter {
            buckets: Mutex::new(HashMap::new()),
            config: Config::AUTH,
            trusted_proxy: true,
        };

        let result = limiter.resolve_ip(Some(socket_ip), &headers);
        assert_eq!(
            result,
            Some("203.0.113.99".parse::<IpAddr>().unwrap()),
            "must take the last XFF entry (the one the proxy appended)"
        );
    }

    /// trusted-proxy ON with no XFF falls back to the socket IP.
    #[test]
    fn trusted_proxy_on_no_xff_falls_back_to_socket() {
        let headers = axum::http::HeaderMap::new();
        let socket_ip: IpAddr = "10.0.0.1".parse().unwrap();

        let limiter = RateLimiter {
            buckets: Mutex::new(HashMap::new()),
            config: Config::AUTH,
            trusted_proxy: true,
        };

        let result = limiter.resolve_ip(Some(socket_ip), &headers);
        assert_eq!(result, Some(socket_ip));
    }

    /// Canonicalization is applied to XFF-sourced IPs too.
    #[test]
    fn xff_ip_is_canonicalized() {
        // XFF delivers an IPv4-mapped address; it should collapse to plain IPv4.
        let raw_xff_ip: IpAddr = "::ffff:203.0.113.42".parse().unwrap();
        let canonical = canonicalize_ip(raw_xff_ip);
        let expected: IpAddr = "203.0.113.42".parse().unwrap();
        assert_eq!(canonical, expected);
    }

    // ---- auth budget from the environment -----------------------------------

    /// These mutate process-wide environment state, so they run as one test.
    #[test]
    fn auth_budget_is_overridable_but_never_accidentally_disabled() {
        // Unset: exactly the compiled-in default, which is the promise this
        // knob makes to every operator who never touches it.
        std::env::remove_var(wavvon_hub_env::AUTH_RATE_BURST);
        std::env::remove_var(wavvon_hub_env::AUTH_RATE_PER_SEC);
        let d = Config::auth();
        assert_eq!(d.burst, Config::AUTH.burst);
        assert_eq!(d.refill_per_sec, Config::AUTH.refill_per_sec);

        std::env::set_var(wavvon_hub_env::AUTH_RATE_BURST, "120");
        std::env::set_var(wavvon_hub_env::AUTH_RATE_PER_SEC, "20");
        let raised = Config::auth();
        assert_eq!(raised.burst, 120);
        assert_eq!(raised.refill_per_sec, 20.0);

        // A typo must not become a hub that refuses every login, nor one with
        // no limiter at all.
        for bad in ["0", "-5", "lots", ""] {
            std::env::set_var(wavvon_hub_env::AUTH_RATE_BURST, bad);
            assert_eq!(
                Config::auth().burst,
                Config::AUTH.burst,
                "{bad:?} should have kept the default burst"
            );
        }

        std::env::remove_var(wavvon_hub_env::AUTH_RATE_BURST);
        std::env::remove_var(wavvon_hub_env::AUTH_RATE_PER_SEC);
    }
}
