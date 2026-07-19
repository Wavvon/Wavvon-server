//! Effective-capability resolver (bot-capability-layer.md §1).
//!
//! Capabilities are requested by the bot (self-declared,
//! `bot_profiles.capabilities`) and granted by an admin
//! (`bot_capability_grants`). The only set any gate should trust is the
//! *effective* one -- the runtime never reads either source table directly.
//!
//! Two bot systems share this table (see the migration backfill in
//! `db/migrations.rs` for the full rationale):
//!
//! - **External bots** (`users.is_bot=1` + `bot_profiles`, invited by
//!   pubkey, bots.md) self-declare what they want in `bot_profiles.capabilities`
//!   at auth/profile-update time. The gate is requested ∩ granted -- an
//!   admin can never silently hand this bot a capability it never asked for.
//! - **Self-service bots** (`bots` table, token-auth, bot-mini-apps.md /
//!   bots.md §18) have no self-declaration mechanism at all -- an admin
//!   creates the row directly via `POST /admin/bots`, which is itself the
//!   consent step. For a pubkey with no `bot_profiles` row, a grant is
//!   effective on its own.

use std::collections::HashSet;

use sqlx::PgPool;

/// The bot's effective capability set: requested ∩ granted for external
/// bots, granted-only for self-service bots (no `bot_profiles` row), empty
/// for an unknown pubkey.
pub async fn effective_capabilities(db: &PgPool, bot_pubkey: &str) -> HashSet<String> {
    let granted: HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT capability FROM bot_capability_grants WHERE bot_pubkey = $1",
    )
    .bind(bot_pubkey)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect();

    if granted.is_empty() {
        return granted;
    }

    let requested_json: Option<String> =
        sqlx::query_scalar("SELECT capabilities FROM bot_profiles WHERE pubkey = $1")
            .bind(bot_pubkey)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();

    match requested_json {
        Some(json) => {
            let requested: HashSet<String> = serde_json::from_str::<Vec<String>>(&json)
                .unwrap_or_default()
                .into_iter()
                .collect();
            requested.intersection(&granted).cloned().collect()
        }
        // No bot_profiles row: self-service bot (or a stale grant for a
        // pubkey that never became a bot at all, harmless either way).
        None => granted,
    }
}

/// Convenience: whether `capability` is in the bot's effective set.
pub async fn has_capability(db: &PgPool, bot_pubkey: &str, capability: &str) -> bool {
    effective_capabilities(db, bot_pubkey)
        .await
        .contains(capability)
}
