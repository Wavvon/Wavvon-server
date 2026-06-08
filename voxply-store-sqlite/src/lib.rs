mod error_map;
mod impls;
pub mod migrations;

use sqlx::AnyPool;

/// SQLite (or Any-backend) implementation of all `HubStore` traits.
///
/// Wraps an `AnyPool` so the same binary works with both SQLite and
/// PostgreSQL. All `sqlx::query*` calls that previously lived in route
/// handlers are consolidated here.
pub struct SqliteStore(pub AnyPool);

impl SqliteStore {
    pub fn new(pool: AnyPool) -> Self {
        Self(pool)
    }

    pub fn pool(&self) -> &AnyPool {
        &self.0
    }
}
