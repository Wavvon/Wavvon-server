use anyhow::Result;

#[derive(Clone)]
pub struct Settings {
    pub farm_url: String,
    pub server_token: String,
    pub hub_binary: String,
    pub base_port: u16,
    #[allow(dead_code)]
    pub region: Option<String>,
}

impl Settings {
    pub fn load() -> Result<Self> {
        let farm_url = std::env::var("VOXPLY_FARM_URL")
            .unwrap_or_else(|_| "http://localhost:3100".to_string());
        let server_token = std::env::var("VOXPLY_SERVER_TOKEN")
            .unwrap_or_else(|_| String::new());
        let hub_binary = std::env::var("VOXPLY_HUB_BIN")
            .unwrap_or_else(|_| "voxply-hub".to_string());
        let base_port = std::env::var("VOXPLY_BASE_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8100);
        let region = std::env::var("VOXPLY_REGION").ok();
        Ok(Self { farm_url, server_token, hub_binary, base_port, region })
    }
}
