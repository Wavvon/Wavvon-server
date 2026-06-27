mod error_map;
mod impls;
pub mod migrations;

use sqlx::PgPool;

/// PostgreSQL implementation of all `HubStore` traits.
pub struct PostgresStore(pub PgPool);

impl PostgresStore {
    pub fn new(pool: PgPool) -> Self {
        Self(pool)
    }

    pub fn pool(&self) -> &PgPool {
        &self.0
    }
}
