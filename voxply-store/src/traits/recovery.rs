use async_trait::async_trait;
use crate::error::StoreError;
use crate::row_types::KeyRotationRequestRow;

#[async_trait]
pub trait RecoveryStore: Send + Sync {
    // ---- Recovery settings ----

    async fn upsert_recovery_settings(
        &self,
        owner_pubkey: &str,
        threshold: i64,
        created_at: i64,
    ) -> Result<(), StoreError>;

    async fn get_recovery_settings(
        &self,
        owner_pubkey: &str,
    ) -> Result<Option<(i64, i64)>, StoreError>;

    async fn add_recovery_contact(
        &self,
        owner_pubkey: &str,
        contact_pubkey: &str,
        created_at: i64,
    ) -> Result<(), StoreError>;

    async fn remove_recovery_contact(
        &self,
        owner_pubkey: &str,
        contact_pubkey: &str,
    ) -> Result<(), StoreError>;

    async fn list_recovery_contacts(
        &self,
        owner_pubkey: &str,
    ) -> Result<Vec<String>, StoreError>;

    // ---- Key rotation requests ----

    async fn create_key_rotation_request(
        &self,
        r: &KeyRotationRequestRow,
    ) -> Result<(), StoreError>;

    async fn get_key_rotation_request(
        &self,
        id: &str,
    ) -> Result<Option<KeyRotationRequestRow>, StoreError>;

    async fn update_key_rotation_status(
        &self,
        id: &str,
        status: &str,
        decided_at: i64,
        decided_by: &str,
    ) -> Result<(), StoreError>;

    // ---- Rotation attestations ----

    async fn add_rotation_attestation(
        &self,
        id: &str,
        request_id: &str,
        attester_pubkey: &str,
        signature: &str,
        attested_at: i64,
    ) -> Result<(), StoreError>;

    async fn attestation_count(&self, request_id: &str) -> Result<i64, StoreError>;
}
