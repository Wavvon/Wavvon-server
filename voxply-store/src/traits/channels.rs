use async_trait::async_trait;
use crate::error::StoreError;
use crate::row_types::{ChannelRow, NewChannel, ChannelPatch};

#[async_trait]
pub trait ChannelStore: Send + Sync {
    /// Create a new channel.
    async fn create_channel(&self, ch: &NewChannel) -> Result<(), StoreError>;

    /// Fetch a channel by ID.
    async fn get_channel(&self, id: &str) -> Result<Option<ChannelRow>, StoreError>;

    /// List all channels ordered by display_order, created_at.
    async fn list_channels(&self) -> Result<Vec<ChannelRow>, StoreError>;

    /// Apply a partial update to a channel.
    async fn update_channel(&self, id: &str, patch: &ChannelPatch) -> Result<(), StoreError>;

    /// Delete a channel (caller must verify no children exist).
    async fn delete_channel(&self, id: &str) -> Result<(), StoreError>;

    /// Set display_order for a single channel.
    async fn set_channel_order(&self, id: &str, order: i64) -> Result<(), StoreError>;

    /// Return the largest current display_order value (or -1 if no channels).
    async fn max_channel_order(&self) -> Result<i64, StoreError>;

    /// Count immediate children of a channel.
    async fn child_count(&self, parent_id: &str) -> Result<i64, StoreError>;

    /// Walk up the parent chain; return the depth of parent_id (0 = root).
    async fn parent_id_of(&self, channel_id: &str) -> Result<Option<String>, StoreError>;

    /// List IDs of all non-category channels.
    async fn list_leaf_channel_ids(&self) -> Result<Vec<String>, StoreError>;

    // ---- Unread tracking ----

    /// Upsert last_read_at for a user/channel pair.
    async fn mark_read(&self, pubkey: &str, channel_id: &str, at: i64) -> Result<(), StoreError>;

    /// Get last_read_at for a user/channel pair (None if never read).
    async fn last_read_at(&self, pubkey: &str, channel_id: &str) -> Result<Option<i64>, StoreError>;

    /// Count messages after last_read_at.
    async fn unread_count(&self, channel_id: &str, after: i64) -> Result<i64, StoreError>;
}
