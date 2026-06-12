use crate::error::StoreError;
use crate::row_types::{FederatedChannelRow, PeerRow};
use async_trait::async_trait;

#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait FederationStore: Send + Sync {
    // ---- Peers ----

    async fn upsert_peer(&self, p: &PeerRow) -> Result<(), StoreError>;

    async fn get_peer(&self, public_key: &str) -> Result<Option<PeerRow>, StoreError>;

    async fn list_peers(&self) -> Result<Vec<PeerRow>, StoreError>;

    async fn delete_peer(&self, public_key: &str) -> Result<(), StoreError>;

    // ---- Federated channels ----

    async fn upsert_federated_channel(&self, ch: &FederatedChannelRow) -> Result<(), StoreError>;

    async fn list_federated_channels(
        &self,
        peer_pubkey: &str,
    ) -> Result<Vec<FederatedChannelRow>, StoreError>;

    async fn get_federated_channel(
        &self,
        peer_pubkey: &str,
        remote_id: &str,
    ) -> Result<Option<FederatedChannelRow>, StoreError>;

    // ---- Alliances ----

    async fn create_alliance(
        &self,
        id: &str,
        name: &str,
        created_by: &str,
        created_at: i64,
    ) -> Result<(), StoreError>;

    async fn get_alliance(
        &self,
        id: &str,
    ) -> Result<Option<crate::row_types::AllianceRow>, StoreError>;

    async fn list_alliances(&self) -> Result<Vec<crate::row_types::AllianceRow>, StoreError>;

    async fn add_alliance_member(
        &self,
        alliance_id: &str,
        hub_public_key: &str,
        hub_name: &str,
        hub_url: &str,
        joined_at: i64,
    ) -> Result<(), StoreError>;

    async fn remove_alliance_member(
        &self,
        alliance_id: &str,
        hub_public_key: &str,
    ) -> Result<(), StoreError>;

    async fn list_alliance_members(
        &self,
        alliance_id: &str,
    ) -> Result<Vec<(String, String, String)>, StoreError>;

    async fn create_pending_alliance_invite(
        &self,
        id: &str,
        alliance_id: &str,
        alliance_name: &str,
        from_hub_url: &str,
        from_hub_name: &str,
        from_hub_public_key: &str,
        invite_token: &str,
        created_at: i64,
        message: Option<&str>,
    ) -> Result<(), StoreError>;

    async fn list_pending_alliance_invites(
        &self,
    ) -> Result<Vec<crate::row_types::AllianceRow>, StoreError>;

    async fn delete_pending_alliance_invite(&self, id: &str) -> Result<(), StoreError>;

    // ---- Home hub designations ----

    async fn upsert_home_hub(
        &self,
        master_pubkey: &str,
        hubs_json: &str,
        issued_at: i64,
        sequence: i64,
        signature: &str,
        updated_at: i64,
    ) -> Result<(), StoreError>;

    async fn get_home_hub(
        &self,
        master_pubkey: &str,
    ) -> Result<Option<(String, i64, i64, String)>, StoreError>;

    // ---- Public hub profiles ----

    async fn upsert_public_hub_profile(
        &self,
        pubkey: &str,
        profile_json: &str,
        updated_at: i64,
    ) -> Result<(), StoreError>;

    async fn get_public_hub_profile(
        &self,
        pubkey: &str,
    ) -> Result<Option<(String, i64)>, StoreError>;
}
