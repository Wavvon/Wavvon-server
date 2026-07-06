use sqlx::PgPool;

/// Shared state for the discovery seed service.
pub struct SeedState {
    /// PostgreSQL connection pool.
    pub db: PgPool,
    /// Shared HTTP client for outbound farm verification calls.
    pub http_client: reqwest::Client,
}

impl SeedState {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to build reqwest client"),
        }
    }
}
