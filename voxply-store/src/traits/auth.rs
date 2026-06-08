use async_trait::async_trait;
use crate::error::StoreError;
use crate::row_types::SubkeyCertRow;

#[async_trait]
pub trait AuthStore: Send + Sync {
    /// Insert a new session token.
    async fn create_session(
        &self,
        token: &str,
        pubkey: &str,
        expires_at: Option<i64>,
        created_at: i64,
    ) -> Result<(), StoreError>;

    /// Resolve the public_key associated with a session token.
    async fn session_pubkey(&self, token: &str) -> Result<Option<String>, StoreError>;

    /// Delete a session (logout).
    async fn delete_session(&self, token: &str) -> Result<(), StoreError>;

    /// Map (auth_pubkey, optional master) to (canonical_pubkey, master_pubkey).
    /// Implements the legacy-user upgrade path and multi-device resolution.
    async fn resolve_canonical_identity(
        &self,
        auth_pubkey: &str,
        master: Option<&str>,
    ) -> Result<(String, Option<String>), StoreError>;

    /// Upsert a subkey certificate.
    async fn record_subkey_cert(&self, cert: &SubkeyCertRow) -> Result<(), StoreError>;

    /// Check whether a given (master, subkey) pair has been revoked.
    async fn is_subkey_revoked(&self, master: &str, subkey: &str) -> Result<bool, StoreError>;

    /// Store a federated ban entry.
    async fn insert_federated_ban(
        &self,
        source_hub_pubkey: &str,
        target_master_pubkey: &str,
        reason: Option<&str>,
        added_at: i64,
        synced_at: i64,
    ) -> Result<(), StoreError>;

    /// Check if a pubkey is subject to a federated ban.
    async fn is_federated_banned(&self, master_pubkey: &str) -> Result<bool, StoreError>;
}
