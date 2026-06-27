use crate::{AuthStore, StoreError, SubkeyCertRow};
use async_trait::async_trait;

use crate::error_map::map_err;
use crate::PostgresStore;

#[async_trait]
impl AuthStore for PostgresStore {
    async fn create_session(
        &self,
        token: &str,
        pubkey: &str,
        expires_at: Option<i64>,
        created_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO sessions (token, public_key, created_at, expires_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(token)
        .bind(pubkey)
        .bind(created_at)
        .bind(expires_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn session_pubkey(&self, token: &str) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar::<_, String>("SELECT public_key FROM sessions WHERE token = $1")
            .bind(token)
            .fetch_optional(self.pool())
            .await
            .map_err(map_err)
    }

    async fn delete_session(&self, token: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn resolve_canonical_identity(
        &self,
        auth_pubkey: &str,
        master: Option<&str>,
    ) -> Result<(String, Option<String>), StoreError> {
        let master = match master {
            None => return Ok((auth_pubkey.to_string(), None)),
            Some(m) => m,
        };

        // Existing multi-device user?
        if let Some(canonical) =
            sqlx::query_scalar::<_, String>("SELECT public_key FROM users WHERE master_pubkey = $1")
                .bind(master)
                .fetch_optional(self.pool())
                .await
                .map_err(map_err)?
        {
            return Ok((canonical, Some(master.to_string())));
        }

        // Legacy user upgrading?
        let legacy: Option<String> = sqlx::query_scalar(
            "SELECT public_key FROM users WHERE public_key = $1 AND master_pubkey IS NULL",
        )
        .bind(auth_pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;

        if let Some(canonical) = legacy {
            return Ok((canonical, Some(master.to_string())));
        }

        // Brand-new paired device.
        Ok((master.to_string(), Some(master.to_string())))
    }

    async fn record_subkey_cert(&self, cert: &SubkeyCertRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO subkey_certs
             (master_pubkey, subkey_pubkey, device_label, issued_at, not_after,
              fallback_hubs_json, signature, registered_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT(master_pubkey, subkey_pubkey) DO UPDATE SET
               device_label = excluded.device_label,
               issued_at = excluded.issued_at,
               not_after = excluded.not_after,
               fallback_hubs_json = excluded.fallback_hubs_json,
               signature = excluded.signature,
               registered_at = excluded.registered_at",
        )
        .bind(&cert.master_pubkey)
        .bind(&cert.subkey_pubkey)
        .bind(&cert.device_label)
        .bind(cert.issued_at)
        .bind(cert.not_after)
        .bind(&cert.fallback_hubs_json)
        .bind(&cert.signature)
        .bind(cert.registered_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn is_subkey_revoked(&self, master: &str, subkey: &str) -> Result<bool, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subkey_revocations WHERE master_pubkey = $1 AND subkey_pubkey = $2",
        )
        .bind(master)
        .bind(subkey)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)?;
        Ok(count > 0)
    }

    async fn insert_federated_ban(
        &self,
        source_hub_pubkey: &str,
        target_master_pubkey: &str,
        reason: Option<&str>,
        added_at: i64,
        synced_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO federated_bans
             (source_hub_pubkey, target_master_pubkey, reason, added_at, synced_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(source_hub_pubkey, target_master_pubkey) DO UPDATE SET
               reason = excluded.reason,
               synced_at = excluded.synced_at",
        )
        .bind(source_hub_pubkey)
        .bind(target_master_pubkey)
        .bind(reason)
        .bind(added_at)
        .bind(synced_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn is_federated_banned(&self, master_pubkey: &str) -> Result<bool, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM federated_bans WHERE target_master_pubkey = $1",
        )
        .bind(master_pubkey)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)?;
        Ok(count > 0)
    }
}
