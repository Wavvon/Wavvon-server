/// Hub process lifecycle manager.
///
/// Owns the map of running hub child processes and exposes spawn/stop/restart
/// operations. On farm startup `spawn_all_from_db` re-spawns every non-suspended,
/// non-deleted hub found in the `hubs` table.
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::PgPool;
use tokio::process::Child;
use tokio::sync::RwLock;

struct HubProcess {
    port: u16,
    child: Child,
}

pub struct HubManager {
    hubs: RwLock<HashMap<String, HubProcess>>,
    /// Absolute path (or name on PATH) of the `wavvon-hub` binary.
    hub_bin: String,
    /// Externally reachable farm URL — passed to hub processes as `WAVVON_FARM_URL`.
    farm_url: String,
    /// Base port for allocating new hub process ports.
    base_port: u16,
}

impl HubManager {
    pub fn new(hub_bin: String, farm_url: String, base_port: u16) -> Self {
        Self {
            hubs: RwLock::new(HashMap::new()),
            hub_bin,
            farm_url,
            base_port,
        }
    }

    /// Allocate the next free port for a new hub process.
    /// Scans occupied ports and returns `base_port + N` where N is the first gap.
    pub async fn allocate_port(&self) -> u16 {
        let hubs = self.hubs.read().await;
        let mut port = self.base_port;
        let occupied: std::collections::HashSet<u16> = hubs.values().map(|h| h.port).collect();
        while occupied.contains(&port) {
            port += 1;
        }
        port
    }

    /// Spawn a hub child process.
    ///
    /// The hub binary is resolved from `WAVVON_HUB_BIN` env var, falling back to
    /// the path stored in `self.hub_bin`.
    ///
    /// `owner_pubkey` is passed as `WAVVON_OWNER_PUBKEY` so the hub seeds that key
    /// as the builtin-owner role on first boot.
    pub async fn spawn_hub(
        &self,
        hub_id: &str,
        db_path: &str,
        port: u16,
        owner_pubkey: Option<&str>,
    ) -> Result<()> {
        let bin = std::env::var("WAVVON_HUB_BIN").unwrap_or_else(|_| self.hub_bin.clone());

        let mut cmd = tokio::process::Command::new(&bin);
        cmd.env("WAVVON_HUB_DB", db_path)
            .env("WAVVON_HUB_HTTP_PORT", port.to_string())
            .env("WAVVON_FARM_URL", &self.farm_url);
        if let Some(pk) = owner_pubkey {
            cmd.env("WAVVON_OWNER_PUBKEY", pk);
        }
        let child = cmd.spawn().with_context(|| {
            format!("Failed to spawn hub process for {hub_id} (binary: {bin:?})")
        })?;

        let mut hubs = self.hubs.write().await;
        hubs.insert(hub_id.to_string(), HubProcess { port, child });
        tracing::info!(hub_id, port, "Hub process spawned");
        Ok(())
    }

    /// Stop a running hub process (SIGTERM on Unix, TerminateProcess on Windows).
    pub async fn stop_hub(&self, hub_id: &str) -> Result<()> {
        let mut hubs = self.hubs.write().await;
        if let Some(mut proc) = hubs.remove(hub_id) {
            proc.child
                .kill()
                .await
                .with_context(|| format!("Failed to kill hub process {hub_id}"))?;
            tracing::info!(hub_id, "Hub process stopped");
        }
        Ok(())
    }

    /// Restart a hub process: stop it then re-spawn with the same db_path and port.
    pub async fn restart_hub(&self, hub_id: &str, db_path: &str, port: u16) -> Result<()> {
        self.stop_hub(hub_id).await?;
        self.spawn_hub(hub_id, db_path, port, None).await
    }

    /// Whether a hub process is currently tracked as running.
    pub async fn is_running(&self, hub_id: &str) -> bool {
        self.hubs.read().await.contains_key(hub_id)
    }

    /// Return the port the named hub process is listening on, if running.
    pub async fn port_of(&self, hub_id: &str) -> Option<u16> {
        self.hubs.read().await.get(hub_id).map(|h| h.port)
    }

    /// Re-spawn all non-suspended, non-deleted hubs from the DB.
    /// Called once at farm startup.
    pub async fn spawn_all_from_db(&self, db: &PgPool) -> Result<()> {
        let rows: Vec<(String, String, i64, Option<String>)> = sqlx::query_as(
            "SELECT id, db_path, process_port, owner_pubkey FROM hubs
             WHERE suspended_at IS NULL AND deleted_at IS NULL AND process_port IS NOT NULL",
        )
        .fetch_all(db)
        .await
        .context("Failed to query hubs for startup spawn")?;

        for (hub_id, db_path, port, owner_pubkey) in rows {
            let port = port as u16;
            if let Err(e) = self
                .spawn_hub(&hub_id, &db_path, port, owner_pubkey.as_deref())
                .await
            {
                tracing::warn!(hub_id, error = %e, "Failed to spawn hub on startup (skipping)");
            }
        }

        Ok(())
    }

    /// Allocate a port and persist it to the `hubs` row, then spawn.
    /// Returns the allocated port.
    pub async fn allocate_and_spawn(
        self: &Arc<Self>,
        db: &PgPool,
        hub_id: &str,
        db_path: &str,
        owner_pubkey: Option<&str>,
    ) -> Result<u16> {
        let port = self.allocate_port().await;

        // Persist port before spawning so a restart can re-use it.
        sqlx::query("UPDATE hubs SET process_port = ? WHERE id = ?")
            .bind(port as i64)
            .bind(hub_id)
            .execute(db)
            .await
            .context("Failed to persist hub port")?;

        self.spawn_hub(hub_id, db_path, port, owner_pubkey).await?;
        Ok(port)
    }
}
