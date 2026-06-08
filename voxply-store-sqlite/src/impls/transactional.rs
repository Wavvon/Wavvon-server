use async_trait::async_trait;
use futures::future::BoxFuture;
use voxply_store::{HubStore, StoreError, Transactional};

use crate::SqliteStore;

/// Transaction support for `SqliteStore`.
///
/// The closure-based design from the store-trait-design doc is used here.
/// Because wrapping a `sqlx::Transaction` as a `&dyn HubStore` would require
/// a separate transaction-aware impl of every trait (the exact complexity the
/// design chose to avoid), this implementation runs the closure against the
/// pool-backed store. True ACID isolation for multi-statement flows in a
/// single connection is deferred to a future refinement where a
/// `SqliteTransactionStore` wrapper implements `HubStore` over
/// `&mut sqlx::Transaction`.
///
/// See design doc §6 open question 4.
#[async_trait]
impl Transactional for SqliteStore {
    async fn with_transaction<F, T>(&self, f: F) -> Result<T, StoreError>
    where
        F: for<'tx> FnOnce(
                &'tx dyn HubStore,
            ) -> BoxFuture<'tx, Result<T, StoreError>>
            + Send,
        T: Send + 'static,
    {
        // Run the closure against self. A future iteration will wrap a real
        // transaction handle as the &dyn HubStore.
        f(self).await
    }
}
