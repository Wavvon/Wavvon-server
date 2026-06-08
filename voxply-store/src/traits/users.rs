use std::collections::HashMap;
use async_trait::async_trait;
use crate::error::StoreError;
use crate::row_types::UserRow;

#[async_trait]
pub trait UserStore: Send + Sync {
    /// Insert or update the user's last_seen_at. Creates the row if absent.
    async fn upsert_user(&self, pubkey: &str, now: i64) -> Result<(), StoreError>;

    /// Fetch a user row by public key.
    async fn get_user(&self, pubkey: &str) -> Result<Option<UserRow>, StoreError>;

    /// Update display_name.
    async fn set_display_name(&self, pubkey: &str, name: Option<&str>) -> Result<(), StoreError>;

    /// Update approval_status.
    async fn set_approval_status(&self, pubkey: &str, status: &str) -> Result<(), StoreError>;

    /// List users, newest-first, with pagination.
    async fn list_members(&self, limit: i64, offset: i64) -> Result<Vec<UserRow>, StoreError>;

    /// Count all non-bot members with approval_status = 'approved'.
    async fn member_count(&self) -> Result<i64, StoreError>;

    /// Look up display names for a set of public keys.
    async fn display_names_for(
        &self,
        pubkeys: &[String],
    ) -> Result<HashMap<String, Option<String>>, StoreError>;

    /// Update master_pubkey for a user (legacy → multi-device upgrade).
    async fn set_master_pubkey(&self, pubkey: &str, master: &str) -> Result<(), StoreError>;

    /// Set lobby_status and lobby_entered_at.
    async fn set_lobby_status(
        &self,
        pubkey: &str,
        status: &str,
        entered_at: Option<i64>,
    ) -> Result<(), StoreError>;

    /// Update avatar URL.
    async fn set_avatar(&self, pubkey: &str, avatar: Option<&str>) -> Result<(), StoreError>;

    /// Set is_bot flag.
    async fn set_is_bot(&self, pubkey: &str, is_bot: bool) -> Result<(), StoreError>;

    /// Set bot_invite_token and bot_invite_expires.
    async fn set_bot_invite_token(
        &self,
        pubkey: &str,
        token: Option<&str>,
        expires: Option<i64>,
    ) -> Result<(), StoreError>;

    /// Set pow_level for a user.
    async fn set_pow_level(&self, pubkey: &str, level: i64) -> Result<(), StoreError>;
}
