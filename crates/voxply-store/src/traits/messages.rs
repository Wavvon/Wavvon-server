use crate::error::StoreError;
use crate::row_types::{MessageRow, NewMessage};
use async_trait::async_trait;

#[async_trait]
pub trait MessageStore: Send + Sync {
    /// Insert a new message.
    async fn insert_message(&self, m: &NewMessage) -> Result<(), StoreError>;

    /// Fetch a single message with sender display_name joined.
    async fn get_message(&self, id: &str) -> Result<Option<MessageRow>, StoreError>;

    /// Cursor-paginated message list for a channel.
    /// `before` is a message ID; None = newest page.
    async fn page_messages(
        &self,
        channel_id: &str,
        before: Option<&str>,
        limit: i64,
    ) -> Result<Vec<MessageRow>, StoreError>;

    /// Fetch all replies to a root message (for thread view), oldest-first.
    async fn thread_messages(
        &self,
        channel_id: &str,
        root_id: &str,
        limit: i64,
    ) -> Result<Vec<MessageRow>, StoreError>;

    /// Fetch messages by a list of IDs (used after full-text search).
    async fn messages_by_ids(&self, ids: &[String]) -> Result<Vec<MessageRow>, StoreError>;

    /// Update content and edited_at.
    async fn edit_message(&self, id: &str, content: &str, edited_at: i64)
        -> Result<(), StoreError>;

    /// Delete a message.
    async fn delete_message(&self, id: &str) -> Result<(), StoreError>;

    /// Increment reply_count on a message.
    async fn increment_reply_count(&self, id: &str) -> Result<(), StoreError>;

    /// Decrement reply_count on a message (floor at 0).
    async fn decrement_reply_count(&self, id: &str) -> Result<(), StoreError>;

    // ---- Reactions ----

    /// Add a reaction (INSERT … ON CONFLICT DO NOTHING).
    async fn add_reaction(
        &self,
        message_id: &str,
        emoji: &str,
        user: &str,
        now: i64,
    ) -> Result<(), StoreError>;

    /// Remove a reaction.
    async fn remove_reaction(
        &self,
        message_id: &str,
        emoji: &str,
        user: &str,
    ) -> Result<(), StoreError>;

    /// Aggregated reaction counts for a message, with `me` flag for `viewer`.
    async fn reaction_summary(
        &self,
        message_id: &str,
        viewer: &str,
    ) -> Result<Vec<(String, i64, bool)>, StoreError>;

    /// Aggregated reaction counts without viewer flag.
    async fn reaction_summary_anon(
        &self,
        message_id: &str,
    ) -> Result<Vec<(String, i64)>, StoreError>;

    // ---- Pins ----

    /// Pin a message in a channel.
    async fn pin_message(
        &self,
        channel_id: &str,
        message_id: &str,
        pinned_by: &str,
        pinned_at: i64,
    ) -> Result<(), StoreError>;

    /// Unpin a message.
    async fn unpin_message(&self, channel_id: &str, message_id: &str) -> Result<(), StoreError>;

    /// List all pins for a channel.
    async fn list_pins(
        &self,
        channel_id: &str,
    ) -> Result<Vec<crate::row_types::PinRow>, StoreError>;
}
