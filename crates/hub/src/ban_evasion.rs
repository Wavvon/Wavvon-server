//! The ban-evasion flag (decisions.md, "A ban stays on the identity; an IP is
//! a signal, never a wall").
//!
//! A ban targets a key, and a new key costs nothing. What this adds is a hint
//! for moderators: a *new* identity arriving from the address a banned one
//! last used is seated `pending`, with the match beside it in the approval
//! queue. Nobody is refused by address; a moderator decides.
//!
//! No address is stored. Every table holds an HMAC of the canonical address
//! (IPv6 at /64, as the rate limiter buckets it) under a key derived from the
//! hub's own identity, so a leaked table cannot be reversed by hashing the
//! IPv4 space, and two hubs' hashes of one address do not match.

use std::net::IpAddr;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;

use crate::rate_limit::canonicalize_ip;
use crate::state::AppState;

/// How long the last-seen hash of an identity is kept when nobody bans it.
const SIGHTING_TTL_SECS: i64 = 7 * 24 * 3600;
/// How long a ban keeps flagging its address.
const FLAG_TTL_SECS: i64 = 30 * 24 * 3600;

pub fn ip_hash(state: &AppState, ip: IpAddr) -> String {
    // A signature is deterministic for Ed25519, so this is a stable secret only
    // the hub can produce. Rotating the hub key starts a fresh set of hashes.
    let key = state.hub_identity.sign(b"wavvon/ip-hash/v1\0").to_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC takes any key length");
    mac.update(canonicalize_ip(ip).to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Remember the address an identity was last seen from. Best-effort: a
/// failure here must never fail the sign-in or the socket that triggered it.
pub async fn record_sighting(db: &PgPool, public_key: &str, ip_hash: &str, now: i64) {
    if let Err(e) = sqlx::query(
        "INSERT INTO ip_sightings (public_key, ip_hash, seen_at) VALUES ($1, $2, $3)
         ON CONFLICT (public_key) DO UPDATE SET ip_hash = excluded.ip_hash, seen_at = excluded.seen_at",
    )
    .bind(public_key)
    .bind(ip_hash)
    .bind(now)
    .execute(db)
    .await
    {
        tracing::warn!("could not record ip sighting: {e}");
    }
}

/// On a ban, start flagging the address the banned identity was last seen
/// from, for the flag window or until a temporary ban ends, whichever comes
/// first. Nothing to copy if it was never seen within the sighting window.
pub async fn flag_banned(
    db: &PgPool,
    banned: &str,
    ban_expires_at: Option<i64>,
    now: i64,
) -> Result<(), sqlx::Error> {
    let until = ban_expires_at.map_or(now + FLAG_TTL_SECS, |end| end.min(now + FLAG_TTL_SECS));
    sqlx::query(
        "INSERT INTO ban_ip_flags (ip_hash, banned_pubkey, expires_at)
         SELECT ip_hash, public_key, $2 FROM ip_sightings
         WHERE public_key = $1 AND seen_at > $3
         ON CONFLICT (ip_hash, banned_pubkey) DO UPDATE SET expires_at = excluded.expires_at",
    )
    .bind(banned)
    .bind(until)
    .bind(now - SIGHTING_TTL_SECS)
    .execute(db)
    .await?;
    Ok(())
}

/// Lifting a ban lifts its flag.
pub async fn unflag(db: &PgPool, banned: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM ban_ip_flags WHERE banned_pubkey = $1")
        .bind(banned)
        .execute(db)
        .await?;
    Ok(())
}

/// The banned identity a newcomer's address matches, if any.
pub async fn matching_ban(
    db: &PgPool,
    ip_hash: &str,
    newcomer: &str,
    now: i64,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT banned_pubkey FROM ban_ip_flags
         WHERE ip_hash = $1 AND banned_pubkey <> $2 AND expires_at > $3
         ORDER BY expires_at DESC LIMIT 1",
    )
    .bind(ip_hash)
    .bind(newcomer)
    .bind(now)
    .fetch_optional(db)
    .await
}

/// Drop what has outlived its window. Run by the retention sweep.
pub async fn sweep(db: &PgPool, now: i64) {
    for (sql, cutoff) in [
        (
            "DELETE FROM ip_sightings WHERE seen_at <= $1",
            now - SIGHTING_TTL_SECS,
        ),
        ("DELETE FROM ban_ip_flags WHERE expires_at <= $1", now),
    ] {
        if let Err(e) = sqlx::query(sql).bind(cutoff).execute(db).await {
            tracing::warn!("ban-evasion sweep failed: {e}");
        }
    }
}
