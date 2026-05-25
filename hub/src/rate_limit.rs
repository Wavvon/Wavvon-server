//! Simple per-IP token bucket rate limiter.
//!
//! Each endpoint protected by this middleware tracks how many requests
//! an IP has made in a sliding window. Crossing the burst cap returns 429.
//! No external store — every hub process keeps its own map, which is fine
//! for single-node deployments and prevents accidental self-DoS.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use axum::RequestExt;
use tokio::sync::Mutex;

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

    /// Moderate limits for write endpoints: 30 burst, 10/s sustained.
    pub const WRITE: Config = Config {
        burst: 30,
        refill_per_sec: 10.0,
    };
}

struct Bucket {
    tokens: f64,
    last_refill: Instant,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
    config: Config,
}

impl RateLimiter {
    pub fn new(config: Config) -> Arc<Self> {
        Arc::new(Self {
            buckets: Mutex::new(HashMap::new()),
            config,
        })
    }

    /// Returns true if the request is allowed; false if rate-limited.
    async fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
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
                buckets.retain(|_, b| {
                    now.duration_since(b.last_refill) < Duration::from_secs(600)
                });
            }
            true
        } else {
            false
        }
    }
}

/// Middleware that enforces the given limiter. If the request has no
/// `ConnectInfo` extension (e.g., under axum_test::TestServer, or behind a
/// transport that didn't add one), the request is passed through — the
/// operator is expected to rate-limit at the edge proxy in that case.
pub async fn enforce(
    limiter: Arc<RateLimiter>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let ip = req
        .extract_parts::<ConnectInfo<std::net::SocketAddr>>()
        .await
        .ok()
        .map(|ConnectInfo(addr)| addr.ip());

    if let Some(ip) = ip {
        if !limiter.check(ip).await {
            return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded"));
        }
    }
    Ok(next.run(req).await)
}
