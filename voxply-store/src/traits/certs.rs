use async_trait::async_trait;
use crate::error::StoreError;
use crate::row_types::{CertIssuanceRow, UserCertRow};

#[async_trait]
pub trait CertStore: Send + Sync {
    // ---- Hub-issued certs ----

    async fn insert_cert_issuance(&self, c: &CertIssuanceRow) -> Result<(), StoreError>;

    async fn latest_cert_for_subject(
        &self,
        subject_pubkey: &str,
    ) -> Result<Option<CertIssuanceRow>, StoreError>;

    async fn list_certs_for_subject(
        &self,
        subject_pubkey: &str,
    ) -> Result<Vec<CertIssuanceRow>, StoreError>;

    async fn revoke_cert(&self, id: &str, revoked_at: i64) -> Result<(), StoreError>;

    // ---- User-held certs (from external issuers) ----

    async fn insert_user_cert(&self, c: &UserCertRow) -> Result<(), StoreError>;

    async fn list_user_certs(&self, master_pubkey: &str) -> Result<Vec<UserCertRow>, StoreError>;

    async fn delete_expired_user_certs(&self, now: i64) -> Result<u64, StoreError>;

    // ---- Pairing offers ----

    async fn upsert_pairing_offer(&self, p: &crate::row_types::PairingOfferRow) -> Result<(), StoreError>;

    async fn get_pairing_offer(
        &self,
        token: &str,
    ) -> Result<Option<crate::row_types::PairingOfferRow>, StoreError>;

    async fn update_pairing_offer_state(
        &self,
        token: &str,
        state: &str,
        updated_at: i64,
        subkey_pubkey: Option<&str>,
        device_label: Option<&str>,
        claim_proof: Option<&str>,
        cert_json: Option<&str>,
        wrapped_key_hex: Option<&str>,
    ) -> Result<(), StoreError>;

    // ---- Prefs blobs ----

    async fn upsert_prefs_blob(&self, p: &crate::row_types::PrefsBlobRow) -> Result<(), StoreError>;

    async fn get_prefs_blob(
        &self,
        master_pubkey: &str,
    ) -> Result<Option<crate::row_types::PrefsBlobRow>, StoreError>;
}
