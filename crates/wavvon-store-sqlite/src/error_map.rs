use wavvon_store::StoreError;

/// Map a `sqlx::Error` to a `StoreError`.
///
/// - `RowNotFound` → `NotFound`
/// - Database errors with "UNIQUE" in the message → `Conflict`
/// - Everything else → `Internal`
pub(crate) fn map_err(e: sqlx::Error) -> StoreError {
    match e {
        sqlx::Error::RowNotFound => StoreError::NotFound,
        sqlx::Error::Database(ref db_err) => {
            let msg = db_err.message();
            if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("duplicate") {
                StoreError::Conflict(msg.to_string())
            } else {
                StoreError::Internal(e.to_string())
            }
        }
        _ => StoreError::Internal(e.to_string()),
    }
}
