use anyhow::Result;
use sqlx::PgPool;

pub async fn run(pool: &PgPool) -> Result<()> {
    // Discovery aggregator listing. One row per registered farm.
    // farm_url is the primary key — re-registration is an upsert.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS registered_farms (
            farm_url            TEXT PRIMARY KEY,
            farm_pubkey         TEXT NOT NULL,
            name                TEXT NOT NULL,
            description         TEXT,
            country             TEXT,
            region              TEXT,
            languages           TEXT NOT NULL DEFAULT '[\"en\"]',
            tags                TEXT NOT NULL DEFAULT '[]',
            hub_count           BIGINT NOT NULL DEFAULT 0,
            max_hubs_total      BIGINT,
            capacity_pct        BIGINT,
            geo_unverified      BOOLEAN NOT NULL DEFAULT FALSE,
            last_verified_at    BIGINT NOT NULL,
            registered_at       BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}
