use anyhow::Result;
use serde::Deserialize;

/// Single source of truth for every `WAVVON_*` env var the hub reads.
///
/// This slice is used by both `load()` (for defaults) and `--help` (for the
/// env-var table).  When you add a field to `Settings`, add a row here too.
///
/// Fields: (env-var name without prefix, default value or "" if unset, purpose)
pub const ENV_VAR_HELP: &[(&str, &str, &str)] = &[
    ("WAVVON_HTTP_PORT", "3000", "HTTP / WebSocket port the hub listens on"),
    (
        "WAVVON_VOICE_UDP_PORT",
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
        "WAVVON_FARM_URL",
        "(unset)",
        "URL of the farm this hub is managed by. Enables farm-issued token acceptance",
    ),
    (
        "WAVVON_OWNER_PUBKEY",
        "(unset)",
        "Ed25519 public key (64 hex chars) seeded as builtin-owner on first boot",
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
        "WAVVON_BOOTSTRAP_TOKEN",
        "(unset)",
        "Bootstrap token redeemed from the discovery service to fetch a template",
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
        "WAVVON_DATABASE_URL",
        "sqlite:hub.db",
        "Full database URL. Defaults to SQLite at hub.db. Also accepts postgresql://…",
    ),
    (
        "WAVVON_DATABASE_READ_URL",
        "(unset)",
        "Read-replica URL (PostgreSQL only). All queries go to the primary when unset",
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
        "WAVVON_PUBLIC_URL",
        "(unset)",
        "Public HTTPS URL of this hub (e.g. https://wavvon.example.com). \
         Used to derive the WebAuthn relying-party ID from the hostname. \
         Required for passkey auth on non-localhost deployments",
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
    /// Owner's Ed25519 public key (64 hex chars). Seeded as builtin-owner on first boot.
    /// Env: WAVVON_OWNER_PUBKEY
    pub owner_pubkey: Option<String>,
    /// Discovery service base URL. Env: WAVVON_DISCOVERY_URL
    pub discovery_url: String,
    /// Bootstrap template URL applied on first boot when channels table is empty.
    /// Env: WAVVON_TEMPLATE_URL
    pub template_url: Option<String>,
    /// Bootstrap token redeemed from the discovery service to fetch a template.
    /// Env: WAVVON_BOOTSTRAP_TOKEN
    pub bootstrap_token: Option<String>,
    /// Logging format: "text" (default) or "json". Env: WAVVON_LOG_FORMAT
    pub log_format: String,
    /// OpenTelemetry OTLP collector endpoint. Leave empty to disable.
    /// Env: WAVVON_OTLP_ENDPOINT
    pub otlp_endpoint: Option<String>,
    /// Full-text search backend. None or "tantivy" = Tantivy (default).
    /// Set to "none" to disable search entirely (NullSearch).
    /// Env: WAVVON_SEARCH_BACKEND
    pub search_backend: Option<String>,
    /// Full database URL. Leave unset to use SQLite at hub.db (default).
    /// Examples:
    ///   sqlite://hub.db          (explicit SQLite)
    ///   postgresql://user:pass@host/dbname
    pub database_url: Option<String>,
    /// Read-replica URL. Only used when database_url is PostgreSQL.
    /// If unset, all queries go to the primary.
    pub database_read_url: Option<String>,
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
    /// Public HTTPS URL of this hub. Used to derive the WebAuthn rp_id.
    /// Env: WAVVON_PUBLIC_URL
    pub public_url: Option<String>,
    /// WebAuthn Relying Party ID override. Falls back to public_url hostname.
    /// Env: WAVVON_WEBAUTHN_RP_ID
    pub webauthn_rp_id: Option<String>,
    /// Device token TTL in days. Default: 30.
    /// Env: WAVVON_DEVICE_TOKEN_TTL_DAYS
    pub device_token_ttl_days: u64,
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
        .set_default("device_token_ttl_days", 30u64)?
        .add_source(config::File::with_name("hub").required(false))
        .add_source(config::Environment::with_prefix("WAVVON"))
        .build()?
        .try_deserialize::<Settings>()?;
    Ok(settings)
}
