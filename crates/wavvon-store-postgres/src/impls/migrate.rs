use async_trait::async_trait;
use wavvon_store::{Migrate, StoreError};

use crate::PostgresStore;

#[async_trait]
impl Migrate for PostgresStore {
    async fn run_migrations(&self) -> Result<(), StoreError> {
        crate::migrations::run(self.pool())
            .await
            .map_err(|e| StoreError::Internal(e.to_string()))
    }
}
