use crate::{HubStore, StoreError, Transactional};
use async_trait::async_trait;
use futures::future::BoxFuture;

use crate::PostgresStore;

/// Transaction support for `PostgresStore`.
///
/// Same deferred-isolation approach as the SQLite implementation: the closure
/// runs against the pool-backed store. True per-connection transaction
/// isolation is deferred to a future iteration.
///
/// See design doc §6 open question 4.
#[async_trait]
impl Transactional for PostgresStore {
    async fn with_transaction<F, T>(&self, f: F) -> Result<T, StoreError>
    where
        F: for<'tx> FnOnce(&'tx dyn HubStore) -> BoxFuture<'tx, Result<T, StoreError>> + Send,
        T: Send + 'static,
    {
        f(self).await
    }
}
