use crate::error::StoreError;
use crate::row_types::{PollRow, PollVoteRow};
use async_trait::async_trait;

#[async_trait]
pub trait PollStore: Send + Sync {
    async fn create_poll(&self, p: &PollRow) -> Result<(), StoreError>;

    async fn get_poll(&self, id: &str) -> Result<Option<PollRow>, StoreError>;

    async fn list_polls(&self, channel_id: &str) -> Result<Vec<PollRow>, StoreError>;

    async fn delete_poll(&self, id: &str) -> Result<(), StoreError>;

    async fn cast_vote(
        &self,
        poll_id: &str,
        user_pubkey: &str,
        option_ids: &str,
    ) -> Result<(), StoreError>;

    async fn get_vote(
        &self,
        poll_id: &str,
        user_pubkey: &str,
    ) -> Result<Option<PollVoteRow>, StoreError>;

    async fn list_votes(&self, poll_id: &str) -> Result<Vec<PollVoteRow>, StoreError>;

    async fn delete_vote(&self, poll_id: &str, user_pubkey: &str) -> Result<(), StoreError>;
}
