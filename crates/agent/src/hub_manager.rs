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
        db_url: &str,
        port: u16,
        voice_port: u16,
        owner_pubkey: Option<&str>,
        farm_url: Option<&str>,
    ) -> Result<()> {
        // See the same block in farm/src/hub_manager.rs: these names used to
        // be literals, and WAVVON_HUB_HTTP_PORT was one the hub never reads,
        // so the assigned port was silently ignored.
        //
        // `db_url` used to be dropped here too, with a warning, so every hub
        // this agent spawned fell back to the hub's own default URL and they
        // all shared one database — reading and writing each other's
        // communities. The caller resolves it now (provision.rs) and refuses
        // the spawn rather than starting a hub with nowhere of its own.
        let bin = std::env::var(wavvon_hub_env::HUB_BIN).unwrap_or_else(|_| self.hub_bin.clone());
        let mut cmd = tokio::process::Command::new(&bin);
        // Tokio does NOT kill a child when its `Child` is dropped — it detaches
        // it. Without this, any path that drops the manager without calling
        // `stop_hub` (a panic, a test ending, the agent exiting) leaves a hub
        // running forever with nothing supervising it, still holding its port
        // and still writing to the shared default database. That is exactly
        // what it did: an orphaned `wavvon-hub` whose parent was gone wedged
        // `cargo test --workspace` for the better part of an hour.
        cmd.kill_on_drop(true)
            .env(wavvon_hub_env::HTTP_PORT, port.to_string())
            .env(wavvon_hub_env::VOICE_UDP_PORT, voice_port.to_string())
            // The farm's row id for this hub, forwarded from the spawn command.
            // The hub reports it back on its heartbeat so the farm can bind the
            // row to the hub's pubkey and route to it.
            .env(wavvon_hub_env::FARM_HUB_ID, hub_id)
            .env(wavvon_hub_env::DATABASE_URL, db_url);
        if let Some(pk) = owner_pubkey {
            cmd.env(wavvon_hub_env::OWNER_PUBKEY, pk);
        }
        if let Some(url) = farm_url {
            cmd.env(wavvon_hub_env::FARM_URL, url);
        }
        let child = cmd.spawn().with_context(|| format!("spawn hub {hub_id}"))?;
        self.hubs.write().await.insert(
            hub_id.to_string(),
            HubProcess {
                port,
                _child: child,
            },
        );
        tracing::info!(hub_id, port, voice_port, "Hub spawned");
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
        db_url: &str,
        port: u16,
        voice_port: u16,
        owner_pubkey: Option<&str>,
        farm_url: Option<&str>,
    ) -> Result<()> {
        self.stop_hub(hub_id).await?;
        self.spawn_hub(hub_id, db_url, port, voice_port, owner_pubkey, farm_url)
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
