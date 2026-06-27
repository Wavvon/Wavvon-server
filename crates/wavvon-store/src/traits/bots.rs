use crate::error::StoreError;
use crate::row_types::{BotCommandRow, BotEventQueueRow, BotProfileRow, BotRow};
use async_trait::async_trait;

#[async_trait]
pub trait BotStore: Send + Sync {
    // ---- Bot profiles (first-party WS bots) ----

    async fn upsert_bot_profile(&self, p: &BotProfileRow) -> Result<(), StoreError>;

    async fn get_bot_profile(&self, pubkey: &str) -> Result<Option<BotProfileRow>, StoreError>;

    async fn list_bot_profiles(&self) -> Result<Vec<BotProfileRow>, StoreError>;

    async fn delete_bot_profile(&self, pubkey: &str) -> Result<(), StoreError>;

    // ---- Bot commands ----

    async fn replace_bot_commands(
        &self,
        pubkey: &str,
        cmds: &[BotCommandRow],
    ) -> Result<(), StoreError>;

    async fn list_bot_commands(&self, pubkey: &str) -> Result<Vec<BotCommandRow>, StoreError>;

    async fn all_bot_commands(&self) -> Result<Vec<BotCommandRow>, StoreError>;

    // ---- Bot subscriptions ----

    async fn set_bot_subscription(
        &self,
        bot_pubkey: &str,
        event_type: &str,
        channel_id: &str,
    ) -> Result<(), StoreError>;

    async fn remove_bot_subscription(
        &self,
        bot_pubkey: &str,
        event_type: &str,
        channel_id: &str,
    ) -> Result<(), StoreError>;

    async fn bot_subscriptions(
        &self,
        bot_pubkey: &str,
    ) -> Result<Vec<(String, String)>, StoreError>;

    async fn bots_subscribed_to(
        &self,
        event_type: &str,
        channel_id: &str,
    ) -> Result<Vec<String>, StoreError>;

    // ---- Bot channel scope ----

    async fn set_bot_channel_scope(
        &self,
        bot_pubkey: &str,
        channel_id: &str,
    ) -> Result<(), StoreError>;

    async fn bot_channel_scope(&self, bot_pubkey: &str) -> Result<Vec<String>, StoreError>;

    // ---- Self-service bots ----

    async fn create_bot(&self, b: &BotRow) -> Result<(), StoreError>;

    async fn get_bot_by_pubkey(&self, pubkey: &str) -> Result<Option<BotRow>, StoreError>;

    async fn list_bots(&self) -> Result<Vec<BotRow>, StoreError>;

    async fn delete_bot(&self, pubkey: &str) -> Result<(), StoreError>;

    // ---- Bot event queue ----

    async fn enqueue_bot_event(&self, e: &BotEventQueueRow) -> Result<(), StoreError>;

    async fn pending_bot_events(
        &self,
        bot_pubkey: &str,
        limit: i64,
    ) -> Result<Vec<BotEventQueueRow>, StoreError>;

    async fn mark_events_delivered(&self, ids: &[String]) -> Result<(), StoreError>;

    // ---- Bot invite tokens ----

    async fn get_user_by_bot_invite_token(
        &self,
        token: &str,
        now: i64,
    ) -> Result<Option<String>, StoreError>;
}
