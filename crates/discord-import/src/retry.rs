//! 429-resilient send helper, modeled on `demo-seed`'s (see
//! `crates/demo-seed/src/main.rs`). Shared by `discord_client` (Discord's
//! bot-API rate limits) and `hub_client` (the hub's own auth/route rate
//! limits) since both speak plain HTTP + `Retry-After`.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::time::sleep;

pub const MAX_RETRIES: u32 = 8;

/// Send `builder`, retrying transparently on HTTP 429.
///
/// `RequestBuilder::send()` consumes the builder, so each retry attempt
/// clones the original via `try_clone()`; this always succeeds for our
/// requests since none use a streaming body.
///
/// Retry schedule:
///   - Honour a numeric `Retry-After` header (seconds, integer or
///     fractional -- Discord sends fractional values) when present.
///   - Otherwise exponential backoff: 2s, 4s, 8s, 16s, 30s (capped).
///   - Give up after `MAX_RETRIES` attempts.
pub async fn send(builder: reqwest::RequestBuilder) -> Result<reqwest::Response> {
    let mut backoff_secs: f64 = 2.0;

    for attempt in 0..=MAX_RETRIES {
        let clone = builder
            .try_clone()
            .context("RequestBuilder::try_clone() returned None -- streaming body not supported")?;

        let resp = clone.send().await.context("HTTP send failed")?;

        if resp.status().as_u16() != 429 {
            return Ok(resp);
        }

        if attempt == MAX_RETRIES {
            bail!(
                "Still receiving 429 after {} retries -- giving up",
                MAX_RETRIES
            );
        }

        let wait = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(backoff_secs);

        println!(
            "  [rate-limit] 429 received (attempt {}/{}), waiting {:.1}s ...",
            attempt + 1,
            MAX_RETRIES,
            wait
        );

        sleep(Duration::from_secs_f64(wait.max(0.0))).await;

        backoff_secs = (backoff_secs * 2.0).min(30.0);
    }

    unreachable!()
}
