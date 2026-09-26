use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    /// HTTP port the farm listens on. Env: WAVVON_HTTP_PORT
    pub http_port: u16,
    /// Externally reachable farm URL embedded in issued tokens and hub spawn env.
    /// Defaults to http://127.0.0.1:<http_port> when not set.
    /// Env: WAVVON_FARM_URL
    pub farm_url: Option<String>,
    /// Path to the wavvon-hub binary. Defaults to a sibling of this binary.
    /// Env: WAVVON_HUB_BIN
    pub hub_bin: Option<String>,
    /// Base port for hub child processes. Hub i gets base_port + i.
    /// Env: WAVVON_HUB_BASE_PORT
    pub hub_base_port: u16,
    /// Base port for hub child processes' voice (WebTransport/QUIC over UDP)
    /// port. Defaults to `hub_base_port + 1000` when unset — see `load()`.
    /// Env: WAVVON_VOICE_BASE_PORT
    pub voice_base_port: Option<u16>,
    /// Directory where hub data directories are stored.
    /// Env: WAVVON_HUBS_DIR
    pub hubs_dir: String,
    /// PostgreSQL connection URL. Env: WAVVON_DATABASE_URL
    ///
    /// Note the `WAVVON_` prefix — `load()` reads every field through
    /// `config::Environment::with_prefix("WAVVON")`. This was documented as
    /// plain `DATABASE_URL` while `main.rs` separately read that unprefixed
    /// name, so the farm needed *both* names set to start and neither the
    /// Dockerfile nor docker-compose.farm.yml set either.
    pub database_url: String,
    /// PostgreSQL connection-pool size. Caps concurrent database work, not
    /// concurrent users — a connection is borrowed per query and returned.
    /// Env: WAVVON_DB_MAX_CONNECTIONS
    pub db_max_connections: u32,
    /// Ed25519 pubkey (64 hex) seeded as this farm's admin on first start.
    ///
    /// The farm's counterpart to the hub's `WAVVON_OWNER_PUBKEY`, and the same
    /// necessity: `farms.admin_pubkey` starts NULL, `creation_policy` defaults
    /// to `admin_only`, and nothing else in the codebase ever writes the
    /// column — so a freshly deployed farm refused every hub creation with
    /// `admin_only` and had no way to appoint the admin who could change that.
    /// farm-impl.md always specified this ("set on first start"); it was simply
    /// never built.
    ///
    /// Ignored once an admin exists, so setting it cannot take a farm over.
    /// Env: WAVVON_FARM_ADMIN_PUBKEY
    pub farm_admin_pubkey: Option<String>,
    /// Browser origins allowed to call the farm's own routes. `"*"` (the
    /// default) allows any; anything else is a comma-separated list of exact
    /// origins. Same name and same meaning as the hub's setting, because a
    /// browser talking to a farm-hosted hub talks to *both*: the hub answers
    /// through the proxy, and `/auth/*` is answered by the farm itself
    /// (`/info.farm_url` is what tells the client so).
    /// Env: WAVVON_CORS_ORIGINS
    pub cors_origins: String,
    /// Logging format: "text" (default) or "json". Env: WAVVON_LOG_FORMAT
    pub log_format: String,
    /// OpenTelemetry OTLP collector endpoint. Leave empty to disable.
    /// Env: WAVVON_OTLP_ENDPOINT
    pub otlp_endpoint: Option<String>,
}

impl Settings {
    /// Resolved voice base port: `voice_base_port` if explicitly configured,
    /// else `hub_base_port + 1000`.
    pub fn resolved_voice_base_port(&self) -> u16 {
        self.voice_base_port
            .unwrap_or_else(|| self.hub_base_port.saturating_add(1000))
    }
}

/// Load farm settings from (in priority order, highest last):
///   1. Built-in defaults
///   2. `farm.toml` in the current working directory (optional — missing file is fine)
///   3. `WAVVON_*` environment variables
pub fn load() -> Result<Settings> {
    let settings = config::Config::builder()
        .set_default("http_port", 4000)?
        .set_default("hub_base_port", 9100)?
        .set_default("hubs_dir", "hubs")?
        .set_default("cors_origins", "*")?
        .set_default("log_format", "text")?
        .set_default("db_max_connections", 5u32)?
        .add_source(config::File::with_name("farm").required(false))
        .add_source(config::Environment::with_prefix("WAVVON").ignore_empty(true))
        .build()?
        .try_deserialize::<Settings>()?;
    Ok(settings)
}
