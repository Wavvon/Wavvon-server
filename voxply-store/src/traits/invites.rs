use async_trait::async_trait;
use crate::error::StoreError;
use crate::row_types::InviteRow;

#[async_trait]
pub trait InviteStore: Send + Sync {
    /// Create a new invite code.
    async fn create_invite(
        &self,
        code: &str,
        by: &str,
        max_uses: Option<i64>,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<(), StoreError>;

    /// Fetch an invite by code.
    async fn get_invite(&self, code: &str) -> Result<Option<InviteRow>, StoreError>;

    /// List all invites.
    async fn list_invites(&self) -> Result<Vec<InviteRow>, StoreError>;

    /// Atomically increment uses for an invite.
    async fn consume_invite(&self, code: &str) -> Result<(), StoreError>;

    /// Delete an invite.
    async fn delete_invite(&self, code: &str) -> Result<(), StoreError>;
}
