//! The names of the hub's environment configuration keys.
//!
//! A hub is configured entirely through `WAVVON_*` environment variables (see
//! `wavvon_hub::settings`). The farm and the agent configure hubs by *setting*
//! those variables on a child process — so the key names are a contract
//! between three crates that never share a type.
//!
//! They were written as string literals on both sides, and they drifted:
//! farm and agent spent months setting `WAVVON_HUB_DB` and
//! `WAVVON_HUB_HTTP_PORT`, names the hub has never read. Nothing failed
//! loudly — a spawned hub simply ignored its assigned port, bound the
//! default, and connected to the default database alongside every other hub
//! on the box. This crate exists so that class of bug cannot recur: there is
//! one spelling of each name, and a typo is a compile error.
//!
//! Deliberately dependency-free and tiny. It holds names only — defaults,
//! parsing and validation stay in each binary's own settings module.

/// HTTP / WebSocket port the hub listens on.
pub const HTTP_PORT: &str = "WAVVON_HTTP_PORT";

/// UDP port for the hub's voice relay.
pub const VOICE_UDP_PORT: &str = "WAVVON_VOICE_UDP_PORT";

/// PostgreSQL connection URL for the hub.
pub const DATABASE_URL: &str = "WAVVON_DATABASE_URL";

/// Read-replica PostgreSQL URL. Optional.
pub const DATABASE_READ_URL: &str = "WAVVON_DATABASE_READ_URL";

/// Size of the hub's PostgreSQL connection pool.
pub const DB_MAX_CONNECTIONS: &str = "WAVVON_DB_MAX_CONNECTIONS";

/// URL of the farm managing this hub, when it is farm-managed.
pub const FARM_URL: &str = "WAVVON_FARM_URL";

/// Public key seeded as the hub owner on first boot.
pub const OWNER_PUBKEY: &str = "WAVVON_OWNER_PUBKEY";

/// Publicly-reachable base URL of this hub, when an operator front-ends it.
///
/// A farm-spawned hub does **not** need this set: it derives its own from
/// `FARM_URL` plus its pubkey (see `wavvon_hub::settings::effective_public_url`),
/// because the farm cannot know the URL at spawn time — the pubkey in it does
/// not exist until the hub's first boot. It is here so a launcher *can*
/// override, and because a hub that has no public URL silently loses voice,
/// invite links and passkeys.
pub const PUBLIC_URL: &str = "WAVVON_PUBLIC_URL";

/// The farm's own row id for this hub, handed to it at spawn.
///
/// The farm allocates a hub row before the process exists, so it cannot know
/// the hub's Ed25519 key — that is generated on first boot. The hub reports
/// this id back on its first heartbeat, which is how the farm learns the
/// pubkey and can finally route to it: the proxy keys on `hubs.hub_pubkey`,
/// and until it is filled every farm-routed request 404s.
pub const FARM_HUB_ID: &str = "WAVVON_FARM_HUB_ID";

/// Path to the `wavvon-hub` binary. Read by the farm and the agent to decide
/// what to launch — not read by the hub itself.
pub const HUB_BIN: &str = "WAVVON_HUB_BIN";

/// The auth handshake's per-IP budget: burst, and tokens refilled per second.
/// Defaults live in `wavvon_hub::rate_limit::Config::auth`.
///
/// A knob because the limiter keys on IP and one authentication costs **two**
/// requests (`/auth/challenge` then `/auth/verify`), so behind a shared
/// address — an office, a school, CGNAT — the default budget is spent by a
/// handful of people opening the app at once, and the hub answers a legitimate
/// arrival exactly as it answers an attacker.
pub const AUTH_RATE_BURST: &str = "WAVVON_AUTH_RATE_BURST";
pub const AUTH_RATE_PER_SEC: &str = "WAVVON_AUTH_RATE_PER_SEC";

/// Every key a launcher may set on a hub child process.
///
/// `wavvon_hub::settings` has a test asserting each of these appears in the
/// hub's own `ENV_VAR_HELP` table — i.e. that everything a launcher can set
/// is something the hub actually reads. That assertion is what would have
/// caught `WAVVON_HUB_HTTP_PORT`.
pub const SPAWNABLE: &[&str] = &[
    HTTP_PORT,
    VOICE_UDP_PORT,
    DATABASE_URL,
    DATABASE_READ_URL,
    DB_MAX_CONNECTIONS,
    FARM_URL,
    OWNER_PUBKEY,
    FARM_HUB_ID,
    PUBLIC_URL,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name is prefixed and uppercase — the `config` crate derives hub
    /// settings fields from `WAVVON_`-prefixed keys, so a name without the
    /// prefix would silently never be read.
    #[test]
    fn names_are_prefixed_and_uppercase() {
        for name in SPAWNABLE.iter().chain([&HUB_BIN]) {
            assert!(
                name.starts_with("WAVVON_"),
                "{name} lacks the WAVVON_ prefix"
            );
            assert_eq!(*name, name.to_uppercase(), "{name} is not uppercase");
        }
    }

    #[test]
    fn spawnable_has_no_duplicates() {
        let mut seen = SPAWNABLE.to_vec();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "SPAWNABLE contains a duplicate");
    }
}
