use std::collections::HashMap;

use async_trait::async_trait;
use sqlx::Row;
use wavvon_store::{SettingsStore, StoreError};

use crate::error_map::map_err;
use crate::SqliteStore;

#[async_trait]
impl SettingsStore for SqliteStore {
    async fn get_setting(&self, key: &str) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = ?")
            .bind(key)
            .fetch_optional(self.pool())
            .await
            .map_err(map_err)
    }

    async fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO hub_settings (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn all_settings(&self) -> Result<HashMap<String, String>, StoreError> {
        let rows = sqlx::query("SELECT key, value FROM hub_settings")
            .fetch_all(self.pool())
            .await
            .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get::<String, _>("key"), r.get::<String, _>("value")))
            .collect())
    }

    async fn seed_default(&self, key: &str, value: &str) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO hub_settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING",
        )
        .bind(key)
        .bind(value)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }
}
