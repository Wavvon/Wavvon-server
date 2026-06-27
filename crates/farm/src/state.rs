use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::hub_manager::HubManager;

/// Shared state for the farm process.
pub struct FarmState {
    /// SQLite connection pool for farm.db.
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
    /// Directory where per-hub SQLite databases are stored.
    pub hubs_dir: String,
    /// Map server_id → bounded sender for the agent's WebSocket write half.
    /// Only present while the agent is connected.
    pub agent_senders: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<String>>>>,
}

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
        }
    }

    /// Farm public key as a lowercase hex string.
    pub fn public_key_hex(&self) -> String {
        use ed25519_dalek::VerifyingKey;
        hex::encode(VerifyingKey::from(self.keypair.as_ref()).as_bytes())
    }
}
