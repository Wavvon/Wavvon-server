use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::hub_manager::HubManager;

/// Shared state for the farm process.
pub struct FarmState {
    /// PostgreSQL connection pool for the farm database.
    pub db: PgPool,
    /// The farm's Ed25519 signing keypair — private half stays here only.
    pub keypair: Arc<SigningKey>,
    /// Canonical URL for this farm (e.g. `"https://farm.example.com"`).
    /// Embedded in every token as `iss`.
    pub farm_url: String,
    /// Last time (unix secs) we tried to re-fetch the farm pubkey after a
    /// verification failure. Used for rate-limiting the retry logic.
    pub last_pubkey_refresh: RwLock<i64>,
    /// Hub process lifecycle manager. Owns the map of running child processes.
    pub hub_manager: Arc<HubManager>,
    /// Shared HTTP client for outbound requests (proxying, health checks).
    pub http_client: reqwest::Client,
    /// Directory where hub data directories are stored.
    pub hubs_dir: String,
    /// Map server_id → bounded sender for the agent's WebSocket write half.
    /// Only present while the agent is connected.
    pub agent_senders: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<String>>>>,
    /// One HTTP client per remote node, keyed by address and TLS settings.
    /// A pinned node needs a client whose verifier trusts that certificate and
    /// no other, so the shared client above cannot serve them; building one per
    /// request would mean a handshake and a fresh pool on every call.
    pub node_clients: Arc<RwLock<HashMap<String, reqwest::Client>>>,
}

/// The agent that hosts a server could not be handed a command.
///
/// Deliberately empty. It replaced a `Result<(), ()>`, which clippy rightly
/// refuses (`result_unit_err`): a unit error tells a reader nothing about what
/// went wrong, and both callers here only ever ask `is_err()`. A name is the
/// smallest thing that fixes that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentUnreachable;

impl std::fmt::Display for AgentUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the agent hosting that server is not reachable")
    }
}

impl std::error::Error for AgentUnreachable {}

impl FarmState {
    pub fn new(
        db: PgPool,
        keypair: SigningKey,
        farm_url: String,
        hub_manager: Arc<HubManager>,
        hubs_dir: String,
    ) -> Self {
        Self {
            db,
            keypair: Arc::new(keypair),
            farm_url,
            last_pubkey_refresh: RwLock::new(0),
            hub_manager,
            http_client: reqwest::Client::new(),
            hubs_dir,
            agent_senders: Arc::new(RwLock::new(HashMap::new())),
            node_clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Farm public key as a lowercase hex string.
    pub fn public_key_hex(&self) -> String {
        use ed25519_dalek::VerifyingKey;
        hex::encode(VerifyingKey::from(self.keypair.as_ref()).as_bytes())
    }

    /// Send a `restart_hub` command to the agent hosting `server_id`.
    ///
    /// Fails when that agent is not currently connected (no sender in
    /// `agent_senders`) or its send channel is full. Both mean the same thing to
    /// a caller — "agent offline", answered as a 503 — which is why
    /// [`AgentUnreachable`] carries nothing: a richer error here would be
    /// information nobody acts on.
    pub async fn send_restart_to_agent(
        &self,
        server_id: &str,
        hub_id: &str,
        db_url: &str,
        port: u16,
        voice_port: u16,
        owner_pubkey: Option<&str>,
    ) -> Result<(), AgentUnreachable> {
        let sender = {
            let map = self.agent_senders.read().await;
            map.get(server_id).cloned()
        };
        let sender = sender.ok_or(AgentUnreachable)?;
        let cmd = serde_json::json!({
            "type": "restart_hub",
            "hub_id": hub_id,
            "db_url": db_url,
            "port": port,
            "voice_port": voice_port,
            "owner_pubkey": owner_pubkey,
            "farm_url": self.farm_url,
        });
        sender
            .try_send(cmd.to_string())
            .map_err(|_| AgentUnreachable)
    }

    /// Return `existing` if set, else allocate a fresh voice port and persist
    /// it. Backfills hubs created before `voice_port` existed (or agent-hosted
    /// hubs whose `hub_spawned` confirmation predates this field).
    pub async fn resolve_voice_port(&self, hub_id: &str, existing: Option<i32>) -> u16 {
        if let Some(vp) = existing {
            return vp as u16;
        }
        let vp = self.hub_manager.allocate_voice_port(&self.db).await;
        let _ = sqlx::query("UPDATE hubs SET voice_port = $1 WHERE id = $2")
            .bind(vp as i32)
            .bind(hub_id)
            .execute(&self.db)
            .await;
        vp
    }
}
