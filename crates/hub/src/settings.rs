use anyhow::Result;
use serde::Deserialize;

/// Single source of truth for every `WAVVON_*` env var the hub reads.
///
/// This slice is used by both `load()` (for defaults) and `--help` (for the
/// env-var table).  When you add a field to `Settings`, add a row here too.
///
/// Keys that another process sets when launching a hub — the farm and the
/// agent do — come from [`wavvon_hub_env`] rather than being spelled here as
/// literals, so the two ends cannot disagree. They did: the farm spent months
/// setting `WAVVON_HUB_DB` and `WAVVON_HUB_HTTP_PORT`, names this table has
/// never contained, and nothing failed loudly.
///
/// Fields: (env-var name without prefix, default value or "" if unset, purpose)
/// Connection URL used when nothing configures one.
///
/// **Provisional.** Per
/// [decisions.md](../../../../docs/docs/decisions.md), an unset
/// `WAVVON_DATABASE_URL` is going to mean *"start and manage an embedded
/// PostgreSQL"*, not *"guess localhost with the default superuser
/// credentials"*. Until that lands this keeps the historical behaviour, but
/// every caller that falls back to it says so on stderr — silently operating
/// on whatever database happens to answer at localhost is how
/// `wavvon-hub admin` came to target the wrong one.
pub const DEFAULT_DATABASE_URL: &str = "postgres://postgres:postgres@localhost:5432/wavvon";

pub const ENV_VAR_HELP: &[(&str, &str, &str)] = &[
    (
        wavvon_hub_env::HTTP_PORT,
        "3000",
        "HTTP / WebSocket port the hub listens on",
    ),
    (
        wavvon_hub_env::VOICE_UDP_PORT,
        "3001",
        "UDP port for the voice relay",
    ),
    (
        "WAVVON_TLS_CERT",
        "(unset)",
        "Path to TLS certificate PEM. Both cert and key must be set to enable HTTPS",
    ),
    (
        "WAVVON_TLS_KEY",
        "(unset)",
        "Path to TLS private key PEM. Required together with WAVVON_TLS_CERT",
    ),
    (
        "WAVVON_CORS_ORIGINS",
        "*",
        "Comma-separated allowed CORS origins for the main API, or `*` for any origin. \
         Default is permissive (`*`) because the API is bearer-token authenticated, \
         not cookie-based, so there is no CSRF surface",
    ),
    (
        wavvon_hub_env::FARM_URL,
        "(unset)",
        "URL of the farm this hub is managed by. Enables farm-issued token acceptance",
    ),
    (
        wavvon_hub_env::OWNER_PUBKEY,
        "(unset)",
        "Ed25519 public key (64 hex chars) seeded as builtin-owner on first boot",
    ),
    (
        wavvon_hub_env::FARM_HUB_ID,
        "(unset)",
        "The farm's row id for this hub. Reported on heartbeat so the farm can route to it",
    ),
    (
        "WAVVON_DISCOVERY_URL",
        "https://discovery.wavvon.io",
        "Discovery service base URL",
    ),
    (
        "WAVVON_TEMPLATE_URL",
        "(unset)",
        "Bootstrap template URL applied on first boot when the channels table is empty",
    ),
    (
        "WAVVON_TEMPLATE_FILE",
        "(unset)",
        "Path to a local bootstrap template JSON file, applied on first boot when the \
         channels table is empty. Second in precedence, behind \n         WAVVON_TEMPLATE_URL. No signature verification — local files are already trusted \
         by the operator who placed them on disk.",
    ),
    (
        "WAVVON_TEMPLATE",
        "(unset)",
        "Built-in bootstrap template preset applied on first boot when the channels table \
         is empty and no other bootstrap source resolved: `gaming`, `community`, or \
         `minimal`. Lowest precedence, and the only no-network option. An unrecognized \
         value is a startup error.",
    ),
    (
        "WAVVON_LOG_FORMAT",
        "text",
        "Logging format: `text` (default) or `json`",
    ),
    (
        "WAVVON_OTLP_ENDPOINT",
        "(unset)",
        "OpenTelemetry OTLP collector endpoint (e.g. http://localhost:4318). Leave unset to disable",
    ),
    (
        "WAVVON_SEARCH_BACKEND",
        "tantivy",
        "Full-text search backend: `tantivy` (default) or `none` to disable search",
    ),
    (
        wavvon_hub_env::DATABASE_URL,
        DEFAULT_DATABASE_URL,
        "PostgreSQL connection URL (required). Example: postgres://user:pass@host/dbname",
    ),
    (
        wavvon_hub_env::DATABASE_READ_URL,
        "(unset)",
        "Read-replica URL (PostgreSQL only). All queries go to the primary when unset",
    ),
    (
        wavvon_hub_env::DB_MAX_CONNECTIONS,
        "5",
        "Size of the PostgreSQL connection pool (applies to the read-replica pool too). \
         Every request borrows a connection for the duration of a query and returns it, \
         so this caps concurrent database work, not concurrent users. Raise it for a busy \
         hub — but keep the total across all hubs sharing one PostgreSQL server under that \
         server's own max_connections (default 100), or connections will be refused",
    ),
    (
        "WAVVON_SFU_URL",
        "(unset)",
        "Optional SFU URL for WebRTC video. Advertised in /info; clients connect there directly",
    ),
    (
        "WAVVON_TRUSTED_PROXY",
        "false",
        "Set to `true` when a single reverse proxy (Caddy/nginx) terminates TLS in front of the hub. \
         The rate limiter will derive the real client IP from the last X-Forwarded-For entry \
         (the hop the proxy observed) instead of the raw socket address. \
         NEVER set this if the hub is directly internet-facing — XFF is client-controlled and \
         would allow limiter bypass.",
    ),
    (
        wavvon_hub_env::AUTH_RATE_BURST,
        "10",
        "Per-IP burst for the auth handshake. Raise it when your users share an address \
         (an office, a school, CGNAT): the limiter keys on IP and one login spends TWO \
         tokens (/auth/challenge then /auth/verify), so the default is a handful of people \
         opening the app at once, and a rate-limited arrival looks to them like a hub that \
         will not have them.",
    ),
    (
        wavvon_hub_env::AUTH_RATE_PER_SEC,
        "1",
        "Tokens refilled per second for the auth handshake — the sustained rate, where the \
         burst above is the allowance for a crowd arriving together.",
    ),
    (
        "WAVVON_WEB_CLIENT_DIR",
        "(unset)",
        "Path to a directory of pre-built web-client assets. When set, the hub serves the \
         client at / with SPA fallback (Accept: text/html gets index.html; other requests get \
         a plain 404). Unset = API-only, no static serving. The official Docker image sets \
         this to /web-client automatically.",
    ),
    (
        "WAVVON_BOTS_ALLOW_CAMERA",
        "false",
        "Set to `true` to allow bot mini-apps that declare `requires_camera: true` to \
         receive camera access in the client webview/iframe sandbox. Defaults to false; \
         operators who trust all registered bots on this hub can enable it hub-wide.",
    ),
    (
        "WAVVON_BOTS_ALLOW_VIDEO",
        "false",
        "Set to `true` to allow bots granted `can_inject_video` to push frames into the \
         screen-share relay via `screen_share_start` (bot-capability-layer.md §6 Phase 2). \
         Defaults to false; a per-bot capability grant is necessary but not sufficient -- \
         this operator-level flag must also be on.",
    ),
    (
        "WAVVON_BOT_VIDEO_STREAM_BUDGET",
        "2",
        "Max number of concurrent bot-initiated video streams across the whole hub \
         (bot-capability-layer.md §4 media budget). `screen_share_start` is rejected once \
         this many bot streams are already active; human screen shares are never counted.",
    ),
    (
        wavvon_hub_env::PUBLIC_URL,
        "(unset)",
        "Public base URL of this hub (e.g. https://wavvon.example.com). Drives the \
         voice endpoint, invite links and the WebAuthn relying-party ID. \
         Farm-hosted hubs derive it from WAVVON_FARM_URL and need not set it",
    ),
    (
        "WAVVON_WEBAUTHN_RP_ID",
        "(unset)",
        "WebAuthn Relying Party ID override (e.g. example.com). \
         Defaults to the hostname extracted from WAVVON_PUBLIC_URL, \
         or `localhost` when neither is set",
    ),
    (
        "WAVVON_DEVICE_TOKEN_TTL_DAYS",
        "30",
        "Lifetime of 'Trust this device' tokens in days. Default: 30",
    ),
    (
        "WAVVON_LAN_MODE",
        "false",
        "Explicit opt-in for LAN/offline mode. When true, the hub refuses to start unless its \
         advertise address is private/loopback/link-local, and self-signed or plaintext trust \
         become available for that address only. Never inferred, never default — see lan-mode.md",
    ),
    (
        "WAVVON_LAN_ADVERTISE_ADDR",
        "(unset)",
        "The literal private IP this LAN-mode hub is reached at (e.g. 192.168.1.50). \
         Auto-detected when unset. Must be private/loopback/link-local or the hub refuses to start",
    ),
    (
        "WAVVON_LAN_TLS_MODE",
        "self",
        "LAN-mode trust tier when no CA cert is configured: `self` (self-signed cert + \
         fingerprint pinning, default) or `none` (gated plaintext HTTP). Ignored unless \
         WAVVON_LAN_MODE=true",
    ),
    (
        "WAVVON_LAN_MDNS",
        "true",
        "Advertise this hub via mDNS/DNS-SD (`_wavvon._tcp.local`) while in LAN mode. \
         Set to `false` to keep LAN mode's guard/trust behavior without the multicast \
         responder (e.g. containers/CI without multicast). Ignored unless WAVVON_LAN_MODE=true",
    ),
];

#[derive(Debug, Deserialize)]
pub struct Settings {
    /// HTTP port the hub listens on. Env: WAVVON_HTTP_PORT
    pub http_port: u16,
    /// UDP port for voice traffic. Env: WAVVON_VOICE_UDP_PORT
    pub voice_udp_port: u16,
    /// Path to TLS certificate PEM. Both cert and key must be set to enable HTTPS.
    /// Env: WAVVON_TLS_CERT
    pub tls_cert: Option<String>,
    /// Path to TLS private key PEM. Env: WAVVON_TLS_KEY
    pub tls_key: Option<String>,
    /// Allowed CORS origins for the main REST API.
    /// Comma-separated list of origins (e.g. "https://app.example.com,https://other.io")
    /// or `*` to allow any origin.  Default is `*`.
    ///
    /// Rationale: the API is authenticated by bearer token, not cookies, so there
    /// is no CSRF surface.  Operators who want to restrict to specific origins can
    /// set this explicitly.
    ///
    /// Env: WAVVON_CORS_ORIGINS
    pub cors_origins: String,
    /// Farm URL when this hub is managed by a farm. Env: WAVVON_FARM_URL
    pub farm_url: Option<String>,
    /// The farm's own row id for this hub, given at spawn. Reported back on
    /// every heartbeat so the farm can bind its row to this hub's pubkey —
    /// without it the farm has a hub it cannot route to.
    /// Env: WAVVON_FARM_HUB_ID
    pub farm_hub_id: Option<String>,
    /// Owner's Ed25519 public key (64 hex chars). Seeded as builtin-owner on first boot.
    /// Env: WAVVON_OWNER_PUBKEY
    pub owner_pubkey: Option<String>,
    /// Discovery service base URL. Env: WAVVON_DISCOVERY_URL
    pub discovery_url: String,
    /// Bootstrap template URL applied on first boot when channels table is empty.
    /// Env: WAVVON_TEMPLATE_URL
    pub template_url: Option<String>,
    /// Path to a local bootstrap template JSON file applied on first boot.
    /// Second in precedence, behind template_url.
    /// Env: WAVVON_TEMPLATE_FILE
    pub template_file: Option<String>,
    /// Built-in bootstrap template preset: "gaming", "community", or "minimal".
    /// Lowest precedence, applied on first boot when no other source resolved.
    /// Env: WAVVON_TEMPLATE
    pub template: Option<String>,
    /// Logging format: "text" (default) or "json". Env: WAVVON_LOG_FORMAT
    pub log_format: String,
    /// OpenTelemetry OTLP collector endpoint. Leave empty to disable.
    /// Env: WAVVON_OTLP_ENDPOINT
    pub otlp_endpoint: Option<String>,
    /// Full-text search backend. None or "tantivy" = Tantivy (default).
    /// Set to "none" to disable search entirely (NullSearch).
    /// Env: WAVVON_SEARCH_BACKEND
    pub search_backend: Option<String>,
    /// PostgreSQL connection URL. Falls back to [`DEFAULT_DATABASE_URL`]
    /// when unset — with a warning, and only until embedded PostgreSQL lands.
    /// Env: WAVVON_DATABASE_URL
    pub database_url: Option<String>,
    /// Read-replica URL. Only used when database_url is PostgreSQL.
    /// If unset, all queries go to the primary.
    pub database_read_url: Option<String>,
    /// PostgreSQL connection-pool size, for the primary and the read replica
    /// alike. Env: WAVVON_DB_MAX_CONNECTIONS
    pub db_max_connections: u32,
    /// Enable trusted-proxy mode for the rate limiter.
    ///
    /// When `true`, the limiter derives the real client IP from the last
    /// `X-Forwarded-For` entry (the hop the proxy observed) instead of
    /// the raw socket address.  Set this only when a single reverse proxy
    /// (Caddy, nginx, …) terminates TLS in front of the hub — never when
    /// the hub is directly internet-facing.
    ///
    /// Env: WAVVON_TRUSTED_PROXY
    pub trusted_proxy: bool,
    /// Path to a directory of pre-built web-client assets.
    ///
    /// When set, the hub serves the browser client from `/` with SPA fallback:
    /// unmatched paths that carry `Accept: text/html` get `index.html`; other
    /// unmatched paths get a plain 404 so API error semantics are preserved.
    /// When unset the hub is API-only and no fallback is registered at all.
    ///
    /// Env: WAVVON_WEB_CLIENT_DIR
    pub web_client_dir: Option<String>,
    /// Allow bot mini-apps that declare `requires_camera: true` to receive
    /// camera access in client webview/iframe sandboxes.
    ///
    /// Env: WAVVON_BOTS_ALLOW_CAMERA
    pub bots_allow_camera: bool,
    /// Operator kill-switch for `can_inject_video` bot video streams.
    /// Env: WAVVON_BOTS_ALLOW_VIDEO
    pub bots_allow_video: bool,
    /// Max concurrent bot-initiated video streams hub-wide.
    /// Env: WAVVON_BOT_VIDEO_STREAM_BUDGET
    pub bot_video_stream_budget: u32,
    /// Public HTTPS URL of this hub. Used to derive the WebAuthn rp_id.
    /// Env: WAVVON_PUBLIC_URL
    pub public_url: Option<String>,
    /// WebAuthn Relying Party ID override. Falls back to public_url hostname.
    /// Env: WAVVON_WEBAUTHN_RP_ID
    pub webauthn_rp_id: Option<String>,
    /// Device token TTL in days. Default: 30.
    /// Env: WAVVON_DEVICE_TOKEN_TTL_DAYS
    pub device_token_ttl_days: u64,
    /// Explicit opt-in for LAN/offline mode. See `crate::lan` and lan-mode.md.
    /// Env: WAVVON_LAN_MODE
    pub lan_mode: bool,
    /// Literal private IP this LAN-mode hub is reached at. Auto-detected when unset.
    /// Env: WAVVON_LAN_ADVERTISE_ADDR
    pub lan_advertise_addr: Option<String>,
    /// LAN-mode trust tier: "self" (self-signed + fingerprint pinning) or "none"
    /// (gated plaintext). Ignored unless `lan_mode` is true and no CA cert is set.
    /// Env: WAVVON_LAN_TLS_MODE
    pub lan_tls_mode: String,
    /// Advertise via mDNS/DNS-SD while in LAN mode. Env: WAVVON_LAN_MDNS
    pub lan_mdns: bool,
}

/// Where this hub is actually reachable from the outside, or `None` when
/// nothing knows.
///
/// Four things need it and all four fail *silently* without it: the voice
/// WebTransport endpoint (`voice_wt_url` stays `None`, so no client can join
/// voice at all), the first-boot owner invite link, the WebAuthn
/// relying-party id, and the canonical URL a client stores for this hub.
///
/// A farm-hosted hub is the case that motivated this. The farm cannot pass the
/// URL at spawn: it contains the hub's pubkey, and that does not exist until
/// the hub's first boot. So the hub derives it — it is the one party holding
/// both halves, its farm's public URL and its own key. Before this, a
/// farm-spawned hub had no public URL and simply had no working voice.
///
/// An explicit `WAVVON_PUBLIC_URL` always wins: an operator fronting the farm
/// with their own domain knows better than we do.
pub fn effective_public_url(
    configured: Option<&str>,
    farm_url: Option<&str>,
    hub_pubkey: Option<&str>,
) -> Option<String> {
    if let Some(url) = configured.map(str::trim).filter(|u| !u.is_empty()) {
        return Some(url.trim_end_matches('/').to_string());
    }
    let farm = farm_url.map(str::trim).filter(|u| !u.is_empty())?;
    let pubkey = hub_pubkey.map(str::trim).filter(|k| !k.is_empty())?;
    // Serial routing: the farm's proxy resolves `/hub/<pubkey>/...`.
    Some(format!("{}/hub/{}", farm.trim_end_matches('/'), pubkey))
}

/// Load hub settings from (in priority order, highest last):
///   1. Built-in defaults
///   2. `hub.toml` in the current working directory (optional — missing file is fine)
///   3. `WAVVON_*` environment variables
pub fn load() -> Result<Settings> {
    let settings = config::Config::builder()
        .set_default("http_port", 3000)?
        .set_default("voice_udp_port", 3001)?
        .set_default("cors_origins", "*")?
        .set_default("log_format", "text")?
        .set_default("discovery_url", "https://discovery.wavvon.io")?
        .set_default("trusted_proxy", false)?
        .set_default("bots_allow_camera", false)?
        .set_default("bots_allow_video", false)?
        .set_default("bot_video_stream_budget", 2u32)?
        .set_default("device_token_ttl_days", 30u64)?
        .set_default("db_max_connections", 5u32)?
        .set_default("lan_mode", false)?
        .set_default("lan_tls_mode", "self")?
        .set_default("lan_mdns", true)?
        .add_source(config::File::with_name("hub").required(false))
        // `ignore_empty` because in a container an empty value is the *only*
        // way to clear a baked-in `ENV`. The hub image sets
        // `WAVVON_WEB_CLIENT_DIR=/web-client` and its own Dockerfile documents
        // `-e WAVVON_WEB_CLIENT_DIR=` as how to run API-only — which failed
        // with `'' does not exist`, because without this an empty variable
        // deserialises as `Some("")` rather than `None`. No setting here wants
        // an empty string to mean something other than "unset".
        .add_source(config::Environment::with_prefix("WAVVON").ignore_empty(true))
        .build()?
        .try_deserialize::<Settings>()?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &str = "abc123";

    #[test]
    fn an_explicit_public_url_always_wins() {
        assert_eq!(
            effective_public_url(
                Some("https://mine.example"),
                Some("https://farm.test"),
                Some(PK)
            ),
            Some("https://mine.example".to_string()),
            "an operator fronting the farm with their own domain knows better"
        );
    }

    /// The case the whole helper exists for: the farm cannot pass this at
    /// spawn because the pubkey in it does not exist yet.
    #[test]
    fn a_farm_hosted_hub_derives_its_serial_routed_url() {
        assert_eq!(
            effective_public_url(None, Some("https://farm.test"), Some(PK)),
            Some("https://farm.test/hub/abc123".to_string())
        );
    }

    #[test]
    fn trailing_slashes_never_double_up() {
        assert_eq!(
            effective_public_url(None, Some("https://farm.test/"), Some(PK)),
            Some("https://farm.test/hub/abc123".to_string())
        );
        assert_eq!(
            effective_public_url(Some("https://mine.example/"), None, None),
            Some("https://mine.example".to_string())
        );
    }

    /// A standalone hub with nothing configured has no public URL, and must
    /// say so rather than invent one — guessing would produce voice endpoints
    /// and invite links pointing at an address nobody can reach.
    #[test]
    fn nothing_configured_means_nothing_known() {
        assert_eq!(effective_public_url(None, None, None), None);
        assert_eq!(
            effective_public_url(None, Some("https://farm.test"), None),
            None
        );
        assert_eq!(effective_public_url(None, None, Some(PK)), None);
    }

    /// Empty strings are what an env var set to "" produces, and they must not
    /// be mistaken for a configured value.
    #[test]
    fn empty_values_are_treated_as_unset() {
        assert_eq!(
            effective_public_url(Some("  "), Some("https://farm.test"), Some(PK)),
            Some("https://farm.test/hub/abc123".to_string())
        );
        assert_eq!(effective_public_url(Some(""), Some(""), Some(PK)), None);
    }

    /// Every key a launcher (farm, agent) may set on a spawned hub must be a
    /// key this hub actually reads.
    ///
    /// This is the assertion that was missing. The farm set
    /// `WAVVON_HUB_HTTP_PORT` and `WAVVON_HUB_DB` for months; the hub reads
    /// `WAVVON_HTTP_PORT` and `WAVVON_DATABASE_URL`. Nothing failed — spawned
    /// hubs quietly ignored their assigned port and bound the default, so the
    /// farm's reverse proxy pointed at nothing and a second hub on the same
    /// box collided.
    #[test]
    fn every_spawnable_key_is_one_the_hub_reads() {
        let declared: Vec<&str> = ENV_VAR_HELP.iter().map(|(name, _, _)| *name).collect();
        for key in wavvon_hub_env::SPAWNABLE {
            assert!(
                declared.contains(key),
                "{key} can be set on a spawned hub but is not in ENV_VAR_HELP — \
                 the hub would ignore it silently"
            );
        }
    }

    /// The test above only proves both sides use the same *symbol*; it would
    /// still pass if that symbol held a name nothing reads, since the table
    /// and the launcher now share it. This one proves the name actually
    /// *configures* the hub, by setting it and watching `load()` react.
    ///
    /// Env is process-global and Rust runs tests in parallel, so every
    /// assertion that touches it lives in this single test rather than one
    /// test per key.
    #[test]
    fn spawnable_keys_actually_reach_settings() {
        // Guard against a stray hub.toml in the crate dir shadowing defaults.
        let baseline = load().expect("settings load with no overrides");
        assert_ne!(baseline.http_port, 41_234, "pick a different probe port");

        std::env::set_var(wavvon_hub_env::HTTP_PORT, "41234");
        std::env::set_var(wavvon_hub_env::VOICE_UDP_PORT, "41235");
        std::env::set_var(wavvon_hub_env::DB_MAX_CONNECTIONS, "37");
        std::env::set_var(wavvon_hub_env::DATABASE_URL, "postgres://probe/db");
        std::env::set_var(wavvon_hub_env::FARM_URL, "https://probe.farm");
        std::env::set_var(wavvon_hub_env::OWNER_PUBKEY, "abc123");
        std::env::set_var(wavvon_hub_env::FARM_HUB_ID, "hub-probe-id");
        std::env::set_var(wavvon_hub_env::PUBLIC_URL, "https://probe.example");

        let s = load().expect("settings load with overrides");

        assert_eq!(
            s.http_port,
            41_234,
            "{} is not read",
            wavvon_hub_env::HTTP_PORT
        );
        assert_eq!(
            s.voice_udp_port,
            41_235,
            "{} is not read",
            wavvon_hub_env::VOICE_UDP_PORT
        );
        assert_eq!(
            s.db_max_connections,
            37,
            "{} is not read",
            wavvon_hub_env::DB_MAX_CONNECTIONS
        );
        assert_eq!(
            s.database_url.as_deref(),
            Some("postgres://probe/db"),
            "{} is not read",
            wavvon_hub_env::DATABASE_URL
        );
        assert_eq!(
            s.farm_url.as_deref(),
            Some("https://probe.farm"),
            "{} is not read",
            wavvon_hub_env::FARM_URL
        );
        assert_eq!(
            s.owner_pubkey.as_deref(),
            Some("abc123"),
            "{} is not read",
            wavvon_hub_env::OWNER_PUBKEY
        );
        assert_eq!(
            s.farm_hub_id.as_deref(),
            Some("hub-probe-id"),
            "{} is not read",
            wavvon_hub_env::FARM_HUB_ID
        );
        assert_eq!(
            s.public_url.as_deref(),
            Some("https://probe.example"),
            "{} is not read",
            wavvon_hub_env::PUBLIC_URL
        );

        for key in wavvon_hub_env::SPAWNABLE {
            std::env::remove_var(key);
        }
    }

    /// An empty variable means "unset", because in a container that is the only
    /// way to clear a baked-in `ENV`. The hub image ships
    /// `WAVVON_WEB_CLIENT_DIR=/web-client` and its Dockerfile documents
    /// `-e WAVVON_WEB_CLIENT_DIR=` as the API-only switch; that exited with
    /// "WAVVON_WEB_CLIENT_DIR '' does not exist" instead, so the documented
    /// escape hatch did not exist.
    #[test]
    fn load_treats_an_empty_env_var_as_unset() {
        std::env::set_var("WAVVON_WEB_CLIENT_DIR", "");
        let s = load().expect("an empty variable must not fail the load");
        assert_eq!(
            s.web_client_dir, None,
            "empty WAVVON_WEB_CLIENT_DIR must mean API-only, not a path called ''"
        );
        std::env::remove_var("WAVVON_WEB_CLIENT_DIR");
    }

    /// `config::Environment::with_prefix("WAVVON")` maps `WAVVON_FOO_BAR` to
    /// the `foo_bar` field, so a row whose name lacks the prefix can never be
    /// read no matter what `load()` does with it.
    #[test]
    fn every_declared_key_uses_the_wavvon_prefix() {
        for (name, _, _) in ENV_VAR_HELP {
            assert!(
                name.starts_with("WAVVON_"),
                "{name} lacks the WAVVON_ prefix and would never be read"
            );
        }
    }
}
