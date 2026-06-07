use sqlx::AnyPool;
use std::ops::Deref;

/// Write pool + optional read replica pool.
/// Derefs to the write pool so existing &state.db usage keeps working.
pub struct DbPool {
    pub write: AnyPool,
    pub read: Option<AnyPool>,
}

impl DbPool {
    pub fn new(write: AnyPool, read: Option<AnyPool>) -> Self {
        Self { write, read }
    }

    /// Returns the read pool if configured, otherwise the write pool.
    /// Route handlers that do only reads should use this for potential replica routing.
    pub fn read_pool(&self) -> &AnyPool {
        self.read.as_ref().unwrap_or(&self.write)
    }
}

impl Deref for DbPool {
    type Target = AnyPool;
    fn deref(&self) -> &AnyPool {
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
