use crate::error::StoreError;
use crate::row_types::{BanRow, MuteRow, NewReport};
use async_trait::async_trait;

#[async_trait]
pub trait ModerationStore: Send + Sync {
    // ---- Global bans ----

    async fn ban_user(
        &self,
        target: &str,
        by: &str,
        reason: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError>;

    async fn unban_user(&self, target: &str) -> Result<(), StoreError>;

    async fn is_banned(&self, target: &str) -> Result<bool, StoreError>;

    async fn list_bans(&self) -> Result<Vec<BanRow>, StoreError>;

    // ---- Global text mutes ----

    async fn mute_user(
        &self,
        target: &str,
        by: &str,
        reason: Option<&str>,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<(), StoreError>;

    async fn unmute_user(&self, target: &str) -> Result<(), StoreError>;

    async fn is_muted(&self, target: &str) -> Result<bool, StoreError>;

    async fn list_mutes(&self) -> Result<Vec<MuteRow>, StoreError>;

    // ---- Voice mutes ----

    async fn voice_mute(
        &self,
        target: &str,
        by: &str,
        reason: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError>;

    async fn voice_unmute(&self, target: &str) -> Result<(), StoreError>;

    async fn is_voice_muted(&self, target: &str) -> Result<bool, StoreError>;

    // ---- Channel bans ----

    async fn channel_ban(
        &self,
        channel_id: &str,
        target: &str,
        by: &str,
        reason: Option<&str>,
        now: i64,
    ) -> Result<(), StoreError>;

    async fn channel_unban(&self, channel_id: &str, target: &str) -> Result<(), StoreError>;

    async fn is_channel_banned(&self, channel_id: &str, target: &str) -> Result<bool, StoreError>;

    // ---- Reports ----

    async fn create_report(&self, r: &NewReport) -> Result<(), StoreError>;

    async fn list_reports(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::row_types::NewReport>, StoreError>;
}
