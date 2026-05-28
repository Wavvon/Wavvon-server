use anyhow::Result;
use sqlx::SqlitePool;

pub async fn run(pool: &SqlitePool) -> Result<()> {
    // Farm singleton metadata — always id=1.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farms (
            id                  INTEGER PRIMARY KEY CHECK(id = 1),
            public_key          TEXT NOT NULL,
            name                TEXT NOT NULL DEFAULT 'My Farm',
            description         TEXT,
            directory_public    INTEGER NOT NULL DEFAULT 0,
            created_at          INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Canonical per-farm user identity.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farm_users (
            public_key      TEXT PRIMARY KEY,
            master_pubkey   TEXT,
            first_seen_at   INTEGER NOT NULL,
            last_seen_at    INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Short-lived challenge nonces (60s TTL, swept on read).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_challenges (
            public_key      TEXT PRIMARY KEY,
            challenge_hex   TEXT NOT NULL,
            expires_at      INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Issued session records (the token itself is the signed blob — not stored here).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farm_sessions (
            jti         TEXT PRIMARY KEY,
            public_key  TEXT NOT NULL REFERENCES farm_users(public_key),
            issued_at   INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            revoked_at  INTEGER,
            scope       TEXT NOT NULL DEFAULT 'member'
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}
