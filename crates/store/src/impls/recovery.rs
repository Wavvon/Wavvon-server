use crate::{KeyRotationRequestRow, RecoveryStore, StoreError};
use async_trait::async_trait;
use sqlx::Row;

use crate::error_map::map_err;
use crate::PostgresStore;

#[async_trait]
impl RecoveryStore for PostgresStore {
    async fn upsert_recovery_settings(
        &self,
        owner_pubkey: &str,
        threshold: i64,
        created_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO recovery_settings (owner_pubkey, threshold, created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT(owner_pubkey) DO UPDATE SET threshold = excluded.threshold",
        )
        .bind(owner_pubkey)
        .bind(threshold)
        .bind(created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_recovery_settings(
        &self,
        owner_pubkey: &str,
    ) -> Result<Option<(i64, i64)>, StoreError> {
        let row = sqlx::query(
            "SELECT threshold, created_at FROM recovery_settings WHERE owner_pubkey = $1",
        )
        .bind(owner_pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| (r.get::<i64, _>("threshold"), r.get::<i64, _>("created_at"))))
    }

    async fn add_recovery_contact(
        &self,
        owner_pubkey: &str,
        contact_pubkey: &str,
        created_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO recovery_contacts (owner_pubkey, contact_pubkey, created_at)
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(owner_pubkey)
        .bind(contact_pubkey)
        .bind(created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remove_recovery_contact(
        &self,
        owner_pubkey: &str,
        contact_pubkey: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM recovery_contacts WHERE owner_pubkey = $1 AND contact_pubkey = $2",
        )
        .bind(owner_pubkey)
        .bind(contact_pubkey)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_recovery_contacts(&self, owner_pubkey: &str) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            "SELECT contact_pubkey FROM recovery_contacts WHERE owner_pubkey = $1",
        )
        .bind(owner_pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)
    }

    async fn create_key_rotation_request(
        &self,
        r: &KeyRotationRequestRow,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO key_rotation_requests
             (id, old_pubkey, new_pubkey, reason, status, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&r.id)
        .bind(&r.old_pubkey)
        .bind(&r.new_pubkey)
        .bind(&r.reason)
        .bind(&r.status)
        .bind(r.created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_key_rotation_request(
        &self,
        id: &str,
    ) -> Result<Option<KeyRotationRequestRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, old_pubkey, new_pubkey, reason, status, created_at, decided_at, decided_by
             FROM key_rotation_requests WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| KeyRotationRequestRow {
            id: r.get("id"),
            old_pubkey: r.get("old_pubkey"),
            new_pubkey: r.get("new_pubkey"),
            reason: r.get("reason"),
            status: r.get("status"),
            created_at: r.get("created_at"),
            decided_at: r.get("decided_at"),
            decided_by: r.get("decided_by"),
        }))
    }

    async fn update_key_rotation_status(
        &self,
        id: &str,
        status: &str,
        decided_at: i64,
        decided_by: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE key_rotation_requests
             SET status = $1, decided_at = $2, decided_by = $3
             WHERE id = $4",
        )
        .bind(status)
        .bind(decided_at)
        .bind(decided_by)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn add_rotation_attestation(
        &self,
        id: &str,
        request_id: &str,
        attester_pubkey: &str,
        signature: &str,
        attested_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO rotation_attestations
             (id, request_id, attester_pubkey, signature, attested_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(request_id, attester_pubkey) DO NOTHING",
        )
        .bind(id)
        .bind(request_id)
        .bind(attester_pubkey)
        .bind(signature)
        .bind(attested_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn attestation_count(&self, request_id: &str) -> Result<i64, StoreError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM rotation_attestations WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)
    }
}
