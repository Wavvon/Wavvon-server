use async_trait::async_trait;
use crate::error::StoreError;
use crate::row_types::{HubGameRow, GameSessionRow};

#[async_trait]
pub trait GameStore: Send + Sync {
    // ---- Hub-installed games ----

    async fn install_game(&self, g: &HubGameRow) -> Result<(), StoreError>;

    async fn get_game(&self, id: &str) -> Result<Option<HubGameRow>, StoreError>;

    async fn list_games(&self) -> Result<Vec<HubGameRow>, StoreError>;

    async fn uninstall_game(&self, id: &str) -> Result<(), StoreError>;

    // ---- Enabled / disabled per-hub ----

    async fn enable_game(&self, game_id: &str, enabled_at: &str, enabled_by: &str) -> Result<(), StoreError>;

    async fn disable_game(&self, game_id: &str) -> Result<(), StoreError>;

    async fn is_game_enabled(&self, game_id: &str) -> Result<bool, StoreError>;

    // ---- Channel-game assignments ----

    async fn assign_game_to_channel(&self, channel_id: &str, game_id: &str) -> Result<(), StoreError>;

    async fn remove_game_from_channel(&self, channel_id: &str, game_id: &str) -> Result<(), StoreError>;

    async fn channel_games(&self, channel_id: &str) -> Result<Vec<String>, StoreError>;

    // ---- Game sessions ----

    async fn create_game_session(&self, s: &GameSessionRow) -> Result<(), StoreError>;

    async fn get_game_session(&self, id: &str) -> Result<Option<GameSessionRow>, StoreError>;

    async fn update_game_session(
        &self,
        id: &str,
        state_json: &str,
        status: &str,
        updated_at: i64,
        snapshot: Option<&[u8]>,
    ) -> Result<(), StoreError>;

    async fn end_game_session(&self, id: &str, ended_at: &str) -> Result<(), StoreError>;

    async fn list_game_sessions(
        &self,
        channel_id: &str,
        limit: i64,
    ) -> Result<Vec<GameSessionRow>, StoreError>;

    // ---- Game shared KV ----

    async fn set_game_kv(
        &self,
        session_id: &str,
        key: &str,
        value: &str,
        updated_at: &str,
    ) -> Result<(), StoreError>;

    async fn get_game_kv(
        &self,
        session_id: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError>;

    async fn delete_game_kv(&self, session_id: &str, key: &str) -> Result<(), StoreError>;

    // ---- Game channel KV ----

    async fn set_game_channel_kv(
        &self,
        game_id: &str,
        channel_id: &str,
        key: &str,
        value: &str,
        updated_at: i64,
    ) -> Result<(), StoreError>;

    async fn get_game_channel_kv(
        &self,
        game_id: &str,
        channel_id: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError>;
}
