use anyhow::{Context, Result};
use std::collections::HashMap;
use tokio::process::Child;
use tokio::sync::RwLock;

struct HubProcess {
    port: u16,
    _child: Child,
}

pub struct HubManager {
    hubs: RwLock<HashMap<String, HubProcess>>,
    hub_bin: String,
    #[allow(dead_code)]
    base_port: u16,
}

impl HubManager {
    pub fn new(hub_bin: String, base_port: u16) -> Self {
        Self {
            hubs: RwLock::new(HashMap::new()),
            hub_bin,
            base_port,
        }
    }

    pub async fn spawn_hub(
        &self,
        hub_id: &str,
        db_path: &str,
        port: u16,
        owner_pubkey: Option<&str>,
        farm_url: Option<&str>,
    ) -> Result<()> {
        let bin = std::env::var("WAVVON_HUB_BIN").unwrap_or_else(|_| self.hub_bin.clone());
        let mut cmd = tokio::process::Command::new(&bin);
        cmd.env("WAVVON_HUB_DB", db_path)
            .env("WAVVON_HUB_HTTP_PORT", port.to_string());
        if let Some(pk) = owner_pubkey {
            cmd.env("WAVVON_OWNER_PUBKEY", pk);
        }
        if let Some(url) = farm_url {
            cmd.env("WAVVON_FARM_URL", url);
        }
        let child = cmd.spawn().with_context(|| format!("spawn hub {hub_id}"))?;
        self.hubs.write().await.insert(
            hub_id.to_string(),
            HubProcess {
                port,
                _child: child,
            },
        );
        tracing::info!(hub_id, port, "Hub spawned");
        Ok(())
    }

    pub async fn stop_hub(&self, hub_id: &str) -> Result<()> {
        let mut hubs = self.hubs.write().await;
        if let Some(mut proc) = hubs.remove(hub_id) {
            proc._child.kill().await.ok();
            tracing::info!(hub_id, "Hub stopped");
        }
        Ok(())
    }

    /// Restart a hub process: stop it if running, then re-spawn it.
    pub async fn restart_hub(
        &self,
        hub_id: &str,
        db_path: &str,
        port: u16,
        owner_pubkey: Option<&str>,
        farm_url: Option<&str>,
    ) -> Result<()> {
        self.stop_hub(hub_id).await?;
        self.spawn_hub(hub_id, db_path, port, owner_pubkey, farm_url)
            .await
    }

    pub async fn list_hubs(&self) -> Vec<serde_json::Value> {
        self.hubs
            .read()
            .await
            .iter()
            .map(|(id, p)| serde_json::json!({"hub_id": id, "port": p.port, "status": "running"}))
            .collect()
    }
}
