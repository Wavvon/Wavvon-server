use async_trait::async_trait;
use futures::future::BoxFuture;
use crate::error::StoreError;

/// A closure-based transaction scope.
///
/// The backend begins a transaction, runs `f` against a transaction-bound
/// store handle, then commits on `Ok` and rolls back on `Err`.
///
/// The `&'tx dyn HubStore` passed into `f` wraps the backend's transaction
/// handle so the transaction lifetime is captured by the closure without
/// leaking backend-specific types.
#[async_trait]
pub trait Transactional: Send + Sync {
    async fn with_transaction<F, T>(&self, f: F) -> Result<T, StoreError>
    where
        F: for<'tx> FnOnce(
                &'tx dyn crate::HubStore,
            ) -> BoxFuture<'tx, Result<T, StoreError>>
            + Send,
        T: Send + 'static;
}
