use anyhow::Result;
use serde::Deserialize;

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
    /// Token required to access the web admin panel at /admin/panel.
    /// Set once here; the hub writes it to the DB on every boot.
    /// Env: VOXPLY_WEB_ADMIN_TOKEN
    pub web_admin_token: Option<String>,
}

/// Load hub settings from (in priority order, highest last):
///   1. Built-in defaults
///   2. `hub.toml` in the current working directory (optional — missing file is fine)
///   3. `VOXPLY_*` environment variables
pub fn load() -> Result<Settings> {
    let settings = config::Config::builder()
        .set_default("http_port", 3000)?
        .set_default("voice_udp_port", 3001)?
        .set_default("log_format", "text")?
        .set_default("discovery_url", "https://discovery.voxply.io")?
        .add_source(config::File::with_name("hub").required(false))
        .add_source(config::Environment::with_prefix("VOXPLY"))
        .build()?
        .try_deserialize::<Settings>()?;
    Ok(settings)
}
