use crate::error::StoreError;
use crate::row_types::{ConversationRow, DhKeyRow, DmMessageRow, FriendRow};
use async_trait::async_trait;

#[async_trait]
#[allow(clippy::too_many_arguments)]
pub trait DmStore: Send + Sync {
    // ---- Conversations ----

    async fn create_conversation(
        &self,
        id: &str,
        conv_type: &str,
        created_at: i64,
    ) -> Result<(), StoreError>;

    async fn get_conversation(&self, id: &str) -> Result<Option<ConversationRow>, StoreError>;

    async fn conversations_for_user(
        &self,
        pubkey: &str,
    ) -> Result<Vec<ConversationRow>, StoreError>;

    async fn find_dm_conversation(
        &self,
        user_a: &str,
        user_b: &str,
    ) -> Result<Option<String>, StoreError>;

    // ---- Conversation members ----

    async fn add_conversation_member(
        &self,
        conv_id: &str,
        pubkey: &str,
        joined_at: i64,
        hub_url: Option<&str>,
    ) -> Result<(), StoreError>;

    async fn remove_conversation_member(
        &self,
        conv_id: &str,
        pubkey: &str,
    ) -> Result<(), StoreError>;

    async fn conversation_members(
        &self,
        conv_id: &str,
    ) -> Result<Vec<(String, Option<String>)>, StoreError>;

    async fn is_conversation_member(&self, conv_id: &str, pubkey: &str)
        -> Result<bool, StoreError>;

    // ---- DM messages ----

    async fn insert_dm_message(&self, m: &DmMessageRow) -> Result<(), StoreError>;

    async fn list_dm_messages(
        &self,
        conv_id: &str,
        before_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DmMessageRow>, StoreError>;

    async fn delete_dm_message(&self, id: &str) -> Result<(), StoreError>;

    // ---- DM blocks ----

    async fn block_user(&self, owner: &str, blocked: &str) -> Result<(), StoreError>;

    async fn unblock_user(&self, owner: &str, blocked: &str) -> Result<(), StoreError>;

    async fn is_blocked(&self, owner: &str, blocked: &str) -> Result<bool, StoreError>;

    // ---- Friends ----

    async fn upsert_friend(&self, f: &FriendRow) -> Result<(), StoreError>;

    async fn get_friend(&self, user_a: &str, user_b: &str)
        -> Result<Option<FriendRow>, StoreError>;

    async fn list_friends(&self, pubkey: &str) -> Result<Vec<FriendRow>, StoreError>;

    async fn delete_friend(&self, user_a: &str, user_b: &str) -> Result<(), StoreError>;

    // ---- DH keys (E2E) ----

    async fn upsert_dh_key(&self, k: &DhKeyRow) -> Result<(), StoreError>;

    async fn get_dh_key(&self, pubkey: &str) -> Result<Option<DhKeyRow>, StoreError>;

    // ---- Group sender-key distributions ----

    async fn insert_sender_key_distribution(
        &self,
        id: &str,
        conv_id: &str,
        sender_pubkey: &str,
        recipient_pubkey: &str,
        sender_key_version: i64,
        iteration: i64,
        wrapped_key_hex: &str,
        wrap_nonce_hex: &str,
        created_at: i64,
    ) -> Result<(), StoreError>;

    async fn list_sender_key_distributions(
        &self,
        conv_id: &str,
        sender_pubkey: &str,
        recipient_pubkey: &str,
    ) -> Result<Vec<(i64, i64, String, String)>, StoreError>;

    // ---- DM outbox ----

    async fn insert_dm_outbox_entry(
        &self,
        message_id: &str,
        recipient_hub_url: &str,
        next_attempt_at: i64,
    ) -> Result<(), StoreError>;

    async fn pending_dm_outbox(
        &self,
        now: i64,
        limit: i64,
    ) -> Result<Vec<(String, String, i64)>, StoreError>;

    async fn mark_dm_outbox_delivered(
        &self,
        message_id: &str,
        hub_url: &str,
    ) -> Result<(), StoreError>;

    async fn record_dm_outbox_failure(
        &self,
        message_id: &str,
        hub_url: &str,
        error: &str,
        next_attempt_at: i64,
    ) -> Result<(), StoreError>;
}
