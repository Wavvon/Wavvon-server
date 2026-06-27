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
    /// Directory where per-hub SQLite databases are stored.
    /// Env: WAVVON_HUBS_DIR
    pub hubs_dir: String,
    /// Logging format: "text" (default) or "json". Env: WAVVON_LOG_FORMAT
    pub log_format: String,
    /// OpenTelemetry OTLP collector endpoint. Leave empty to disable.
    /// Env: WAVVON_OTLP_ENDPOINT
    pub otlp_endpoint: Option<String>,
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
        .set_default("log_format", "text")?
        .add_source(config::File::with_name("farm").required(false))
        .add_source(config::Environment::with_prefix("WAVVON"))
        .build()?
        .try_deserialize::<Settings>()?;
    Ok(settings)
}
