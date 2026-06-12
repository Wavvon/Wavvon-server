use crate::error::StoreError;
use async_trait::async_trait;
use std::collections::HashMap;

#[async_trait]
pub trait SettingsStore: Send + Sync {
    /// Fetch a single setting value.
    async fn get_setting(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Insert or update a setting.
    async fn set_setting(&self, key: &str, value: &str) -> Result<(), StoreError>;

    /// Return all settings as a HashMap.
    async fn all_settings(&self) -> Result<HashMap<String, String>, StoreError>;

    /// Insert the default value only when the key does not yet exist.
    async fn seed_default(&self, key: &str, value: &str) -> Result<(), StoreError>;
}
