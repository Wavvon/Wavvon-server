//! 429-resilient send helper, modeled on `demo-seed`'s (see
//! `crates/demo-seed/src/main.rs`). Shared by `discord_client` (Discord's
//! bot-API rate limits) and `hub_client` (the hub's own auth/route rate
//! limits) since both speak plain HTTP + `Retry-After`.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::time::sleep;

pub const MAX_RETRIES: u32 = 8;

/// Cap applied to a `Retry-After` value (and to the fallback exponential
/// backoff) before it's ever handed to `Duration::from_secs_f64`.
pub const MAX_WAIT_SECS: f64 = 30.0;

/// Resolves the header-supplied `Retry-After` value (if present and
/// parseable) against the current exponential-backoff fallback, rejecting
/// non-finite input and clamping to `MAX_WAIT_SECS`.
///
/// `Duration::from_secs_f64` panics on NaN, infinite, or negative input,
/// and an unbounded value (e.g. a hub-supplied `999999`) would stall the
/// tool for days -- see docs/docs/security-audit-2026-07-04.md D3. The hub
/// (or, worst case, a network MITM sitting in front of it) controls this
/// header, so it must never be trusted uncapped.
fn resolve_wait_secs(header_value: Option<&str>, backoff_fallback: f64) -> f64 {
    header_value
        .and_then(|s| s.parse::<f64>().ok())
        .filter(|w| w.is_finite())
        .unwrap_or(backoff_fallback)
        .clamp(0.0, MAX_WAIT_SECS)
}

/// Send `builder`, retrying transparently on HTTP 429.
///
/// `RequestBuilder::send()` consumes the builder, so each retry attempt
/// clones the original via `try_clone()`; this always succeeds for our
/// requests since none use a streaming body.
///
/// Retry schedule:
///   - Honour a numeric `Retry-After` header (seconds, integer or
///     fractional -- Discord sends fractional values) when present, capped
///     at `MAX_WAIT_SECS` and rejected (falling back to backoff) if
///     non-finite.
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

        let header_value = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok());
        let wait = resolve_wait_secs(header_value, backoff_secs);

        println!(
            "  [rate-limit] 429 received (attempt {}/{}), waiting {:.1}s ...",
            attempt + 1,
            MAX_RETRIES,
            wait
        );

        sleep(Duration::from_secs_f64(wait)).await;

        backoff_secs = (backoff_secs * 2.0).min(30.0);
    }

    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honours_a_sane_header_value() {
        assert_eq!(resolve_wait_secs(Some("5"), 2.0), 5.0);
        assert_eq!(resolve_wait_secs(Some("1.5"), 2.0), 1.5);
    }

    #[test]
    fn falls_back_to_backoff_when_header_missing_or_unparseable() {
        assert_eq!(resolve_wait_secs(None, 4.0), 4.0);
        assert_eq!(resolve_wait_secs(Some("not-a-number"), 4.0), 4.0);
    }

    #[test]
    fn clamps_an_oversized_header_value_instead_of_stalling() {
        assert_eq!(resolve_wait_secs(Some("999999"), 2.0), MAX_WAIT_SECS);
        assert_eq!(resolve_wait_secs(Some("1e12"), 2.0), MAX_WAIT_SECS);
    }

    #[test]
    fn rejects_non_finite_header_values_without_panicking() {
        // NaN and +/-Infinity must never reach Duration::from_secs_f64.
        assert_eq!(resolve_wait_secs(Some("NaN"), 3.0), 3.0);
        assert_eq!(resolve_wait_secs(Some("inf"), 3.0), 3.0);
        assert_eq!(resolve_wait_secs(Some("infinity"), 3.0), 3.0);
        assert_eq!(resolve_wait_secs(Some("-inf"), 3.0), 3.0);

        // And the result must always be constructible into a Duration.
        let wait = resolve_wait_secs(Some("1e400"), 3.0);
        let _ = Duration::from_secs_f64(wait);
    }

    #[test]
    fn clamps_negative_values_to_zero() {
        assert_eq!(resolve_wait_secs(Some("-5"), 2.0), 0.0);
    }
}
