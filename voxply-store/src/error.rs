/// Canonical error type returned by all `HubStore` trait methods.
///
/// Route handlers map this to HTTP via `From<StoreError> for (StatusCode, String)`.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("permission denied")]
    PermissionDenied,

    #[error("internal: {0}")]
    Internal(String),
}
