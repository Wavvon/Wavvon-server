use sqlx::PgPool;
use std::ops::Deref;

/// Write pool + optional read replica pool.
/// Derefs to the write pool so existing &state.db usage keeps working.
pub struct DbPool {
    pub write: PgPool,
    pub read: Option<PgPool>,
}

impl DbPool {
    pub fn new(write: PgPool, read: Option<PgPool>) -> Self {
        Self { write, read }
    }

    /// Returns the read pool if configured, otherwise the write pool.
    /// Route handlers that do only reads should use this for potential replica routing.
    pub fn read_pool(&self) -> &PgPool {
        self.read.as_ref().unwrap_or(&self.write)
    }
}

impl Deref for DbPool {
    type Target = PgPool;
    fn deref(&self) -> &PgPool {
        &self.write
    }
}

// Clone is needed because AppState is Arc-wrapped
impl Clone for DbPool {
    fn clone(&self) -> Self {
        Self {
            write: self.write.clone(),
            read: self.read.clone(),
        }
    }
}
