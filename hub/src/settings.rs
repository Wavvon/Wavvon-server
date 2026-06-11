use anyhow::Result;
use serde::Deserialize;

/// Single source of truth for every `VOXPLY_*` env var the hub reads.
///
/// This slice is used by both `load()` (for defaults) and `--help` (for the
/// env-var table).  When you add a field to `Settings`, add a row here too.
///
/// Fields: (env-var name without prefix, default value or "" if unset, purpose)
pub const ENV_VAR_HELP: &[(&str, &str, &str)] = &[
    ("VOXPLY_HTTP_PORT", "3000", "HTTP / WebSocket port the hub listens on"),
    (
        "VOXPLY_VOICE_UDP_PORT",
        "3001",
        "UDP port for the voice relay",
    ),
    (
        "VOXPLY_TLS_CERT",
        "(unset)",
        "Path to TLS certificate PEM. Both cert and key must be set to enable HTTPS",
    ),
    (
        "VOXPLY_TLS_KEY",
        "(unset)",
        "Path to TLS private key PEM. Required together with VOXPLY_TLS_CERT",
    ),
    (
        "VOXPLY_CORS_ORIGINS",
        "*",
        "Comma-separated allowed CORS origins for the main API, or `*` for any origin. \
         Default is permissive (`*`) because the API is bearer-token authenticated, \
         not cookie-based, so there is no CSRF surface",
    ),
    (
        "VOXPLY_FARM_URL",
        "(unset)",
        "URL of the farm this hub is managed by. Enables farm-issued token acceptance",
    ),
    (
        "VOXPLY_OWNER_PUBKEY",
        "(unset)",
        "Ed25519 public key (64 hex chars) seeded as builtin-owner on first boot",
    ),
    (
        "VOXPLY_DISCOVERY_URL",
        "https://discovery.voxply.io",
        "Discovery service base URL",
    ),
    (
        "VOXPLY_TEMPLATE_URL",
        "(unset)",
        "Bootstrap template URL applied on first boot when the channels table is empty",
    ),
    (
        "VOXPLY_BOOTSTRAP_TOKEN",
        "(unset)",
        "Bootstrap token redeemed from the discovery service to fetch a template",
    ),
    (
        "VOXPLY_LOG_FORMAT",
        "text",
        "Logging format: `text` (default) or `json`",
    ),
    (
        "VOXPLY_OTLP_ENDPOINT",
        "(unset)",
        "OpenTelemetry OTLP collector endpoint (e.g. http://localhost:4318). Leave unset to disable",
    ),
    (
        "VOXPLY_SEARCH_BACKEND",
        "tantivy",
        "Full-text search backend: `tantivy` (default) or `none` to disable search",
    ),
    (
        "VOXPLY_DATABASE_URL",
        "sqlite:hub.db",
        "Full database URL. Defaults to SQLite at hub.db. Also accepts postgresql://…",
    ),
    (
        "VOXPLY_DATABASE_READ_URL",
        "(unset)",
        "Read-replica URL (PostgreSQL only). All queries go to the primary when unset",
    ),
    (
        "VOXPLY_SFU_URL",
        "(unset)",
        "Optional SFU URL for WebRTC video. Advertised in /info; clients connect there directly",
    ),
];

#[derive(Debug, Deserialize)]
pub struct Settings {
    /// HTTP port the hub listens on. Env: VOXPLY_HTTP_PORT
    pub http_port: u16,
    /// UDP port for voice traffic. Env: VOXPLY_VOICE_UDP_PORT
    pub voice_udp_port: u16,
    /// Path to TLS certificate PEM. Both cert and key must be set to enable HTTPS.
    /// Env: VOXPLY_TLS_CERT
    pub tls_cert: Option<String>,
    /// Path to TLS private key PEM. Env: VOXPLY_TLS_KEY
    pub tls_key: Option<String>,
    /// Allowed CORS origins for the main REST API.
    /// Comma-separated list of origins (e.g. "https://app.example.com,https://other.io")
    /// or `*` to allow any origin.  Default is `*`.
    ///
    /// Rationale: the API is authenticated by bearer token, not cookies, so there
    /// is no CSRF surface.  Operators who want to restrict to specific origins can
    /// set this explicitly.
    ///
    /// Env: VOXPLY_CORS_ORIGINS
    pub cors_origins: String,
    /// Farm URL when this hub is managed by a farm. Env: VOXPLY_FARM_URL
    pub farm_url: Option<String>,
    /// Owner's Ed25519 public key (64 hex chars). Seeded as builtin-owner on first boot.
    /// Env: VOXPLY_OWNER_PUBKEY
    pub owner_pubkey: Option<String>,
    /// Discovery service base URL. Env: VOXPLY_DISCOVERY_URL
    pub discovery_url: String,
    /// Bootstrap template URL applied on first boot when channels table is empty.
    /// Env: VOXPLY_TEMPLATE_URL
    pub template_url: Option<String>,
    /// Bootstrap token redeemed from the discovery service to fetch a template.
    /// Env: VOXPLY_BOOTSTRAP_TOKEN
    pub bootstrap_token: Option<String>,
    /// Logging format: "text" (default) or "json". Env: VOXPLY_LOG_FORMAT
    pub log_format: String,
    /// OpenTelemetry OTLP collector endpoint. Leave empty to disable.
    /// Env: VOXPLY_OTLP_ENDPOINT
    pub otlp_endpoint: Option<String>,
    /// Full-text search backend. None or "tantivy" = Tantivy (default).
    /// Set to "none" to disable search entirely (NullSearch).
    /// Env: VOXPLY_SEARCH_BACKEND
    pub search_backend: Option<String>,
    /// Full database URL. Leave unset to use SQLite at hub.db (default).
    /// Examples:
    ///   sqlite://hub.db          (explicit SQLite)
    ///   postgresql://user:pass@host/dbname
    pub database_url: Option<String>,
    /// Read-replica URL. Only used when database_url is PostgreSQL.
    /// If unset, all queries go to the primary.
    pub database_read_url: Option<String>,
}

/// Load hub settings from (in priority order, highest last):
///   1. Built-in defaults
///   2. `hub.toml` in the current working directory (optional — missing file is fine)
///   3. `VOXPLY_*` environment variables
pub fn load() -> Result<Settings> {
    let settings = config::Config::builder()
        .set_default("http_port", 3000)?
        .set_default("voice_udp_port", 3001)?
        .set_default("cors_origins", "*")?
        .set_default("log_format", "text")?
        .set_default("discovery_url", "https://discovery.voxply.io")?
        .add_source(config::File::with_name("hub").required(false))
        .add_source(config::Environment::with_prefix("VOXPLY"))
        .build()?
        .try_deserialize::<Settings>()?;
    Ok(settings)
}
