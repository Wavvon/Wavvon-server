use anyhow::Result;

#[derive(Clone)]
pub struct Settings {
    pub farm_url: String,
    pub server_token: String,
    pub hub_binary: String,
    pub base_port: u16,
    #[allow(dead_code)]
    pub region: Option<String>,
    /// How the farm's proxy reaches the hubs on this node — the address the
    /// agent advertises in its `hello` (farm-model.md, "Multi-node data
    /// plane"). Unset means this node is the farm's own machine, and the
    /// proxy keeps dialing loopback.
    pub node_host: Option<String>,
    /// `ca` (default) or `pin`. With `pin` the farm accepts this node's
    /// certificate by digest and no other.
    pub node_tls: String,
    /// SHA-256 of this node's TLS certificate, for `pin`.
    pub node_cert_sha256: Option<String>,
    /// This node's PostgreSQL, as a template containing `{db}`. When set, the
    /// agent creates each hub's database here and the node's credentials never
    /// leave the node.
    pub db_template: Option<String>,
}

impl Settings {
    pub fn load() -> Result<Self> {
        let farm_url = std::env::var("WAVVON_FARM_URL")
            .unwrap_or_else(|_| "http://localhost:3100".to_string());
        let server_token = std::env::var("WAVVON_SERVER_TOKEN").unwrap_or_else(|_| String::new());
        let hub_binary =
            std::env::var("WAVVON_HUB_BIN").unwrap_or_else(|_| "wavvon-hub".to_string());
        let base_port = std::env::var("WAVVON_BASE_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8100);
        let region = std::env::var("WAVVON_REGION").ok();
        let node_host = std::env::var("WAVVON_NODE_HOST")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty());
        // Anything unrecognised is `ca`: the farm validates the same way it
        // would for any other host, which fails visibly rather than trusting
        // a certificate nobody checked.
        let node_tls = std::env::var("WAVVON_NODE_TLS")
            .ok()
            .filter(|v| v == "pin")
            .unwrap_or_else(|| "ca".to_string());
        let node_cert_sha256 = std::env::var("WAVVON_NODE_CERT_SHA256")
            .ok()
            .map(|d| d.trim().to_lowercase())
            .filter(|d| !d.is_empty());
        let db_template = std::env::var("WAVVON_NODE_DB_TEMPLATE")
            .ok()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty());
        Ok(Self {
            farm_url,
            server_token,
            hub_binary,
            base_port,
            region,
            node_host,
            node_tls,
            node_cert_sha256,
            db_template,
        })
    }
}
