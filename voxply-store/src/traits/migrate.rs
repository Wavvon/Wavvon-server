use async_trait::async_trait;
use crate::error::StoreError;

/// Each backend implements its own schema setup.
/// The hub calls `store.run_migrations().await?` at startup.
#[async_trait]
pub trait Migrate: Send + Sync {
    async fn run_migrations(&self) -> Result<(), StoreError>;
}
