use anyhow::Result;
use sqlx::SqlitePool;

pub async fn run(pool: &SqlitePool) -> Result<()> {
    // Farm singleton metadata — always id=1.
    // Includes all additive columns from prior migrations (admin_pubkey,
    // creation policy, quotas, discovery metadata).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farms (
            id                      INTEGER PRIMARY KEY CHECK(id = 1),
            public_key              TEXT NOT NULL,
            name                    TEXT NOT NULL DEFAULT 'My Farm',
            description             TEXT,
            directory_public        INTEGER NOT NULL DEFAULT 0,
            created_at              INTEGER NOT NULL,
            admin_pubkey            TEXT,
            creation_policy         TEXT NOT NULL DEFAULT 'admin_only'
                                        CHECK(creation_policy IN ('open', 'admin_only', 'disabled')),
            max_hubs_per_user       INTEGER NOT NULL DEFAULT 0,
            max_hubs_total          INTEGER NOT NULL DEFAULT 0,
            allow_discovery_listing INTEGER NOT NULL DEFAULT 0,
            languages               TEXT NOT NULL DEFAULT '[\"en\"]',
            tags                    TEXT NOT NULL DEFAULT '[]',
            country                 TEXT,
            region                  TEXT
        )",
    )
    .execute(pool)
    .await?;

    // Canonical per-farm user identity.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farm_users (
            public_key    TEXT PRIMARY KEY,
            master_pubkey TEXT,
            first_seen_at INTEGER NOT NULL,
            last_seen_at  INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Short-lived challenge nonces (60s TTL, swept on read).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_challenges (
            public_key    TEXT PRIMARY KEY,
            challenge_hex TEXT NOT NULL,
            expires_at    INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Issued session records (the token itself is the signed blob — not stored here).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farm_sessions (
            jti              TEXT PRIMARY KEY,
            public_key       TEXT NOT NULL REFERENCES farm_users(public_key),
            issued_at        INTEGER NOT NULL,
            expires_at       INTEGER NOT NULL,
            revoked_at       INTEGER,
            scope            TEXT NOT NULL DEFAULT 'member',
            revoked_manually INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // Per-hub process registry.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hubs (
            id                TEXT PRIMARY KEY,
            owner_pubkey      TEXT NOT NULL,
            name              TEXT NOT NULL,
            description       TEXT,
            visibility        TEXT NOT NULL DEFAULT 'private'
                                  CHECK(visibility IN ('public', 'private')),
            process_port      INTEGER,
            db_path           TEXT NOT NULL,
            created_at        INTEGER NOT NULL,
            suspended_at      INTEGER,
            suspension_reason TEXT,
            deleted_at        INTEGER,
            hub_pubkey        TEXT
        )",
    )
    .execute(pool)
    .await?;

    // Farm-level game catalogue.
    // One row per installed game; the farm admin installs, hubs enable/disable.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS games (
            id               TEXT PRIMARY KEY,
            name             TEXT NOT NULL,
            entry_url        TEXT NOT NULL,
            description      TEXT,
            thumbnail_url    TEXT,
            version          TEXT NOT NULL DEFAULT '1.0.0',
            author           TEXT,
            min_players      INTEGER NOT NULL DEFAULT 1,
            max_players      INTEGER NOT NULL DEFAULT 1,
            permission_grant TEXT NOT NULL DEFAULT '[]',
            installed_by     TEXT,
            installed_at     TEXT
        )",
    )
    .execute(pool)
    .await?;

    // Per-user-per-game key/value store (personal-axis, follows the user).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS game_kv (
            game_id     TEXT NOT NULL,
            user_pubkey TEXT NOT NULL,
            key         TEXT NOT NULL,
            value       TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            PRIMARY KEY (game_id, user_pubkey, key)
        )",
    )
    .execute(pool)
    .await?;

    // Heartbeat: cache of the last stats ping received from each hub.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_heartbeats (
            hub_pubkey     TEXT PRIMARY KEY,
            online_users   INTEGER NOT NULL DEFAULT 0,
            storage_bytes  INTEGER NOT NULL DEFAULT 0,
            uptime_seconds INTEGER NOT NULL DEFAULT 0,
            last_seen_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // TOTP columns on the farms singleton row.
    // SQLite does not support ADD COLUMN IF NOT EXISTS — ignore the "duplicate
    // column name" error (SQLite error code 1) that fires on re-runs.
    let _ = sqlx::query("ALTER TABLE farms ADD COLUMN totp_secret TEXT")
        .execute(pool)
        .await;
    let _ = sqlx::query(
        "ALTER TABLE farms ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0",
    )
    .execute(pool)
    .await;

    // server_id foreign-key column on the hubs table (NULL = local process).
    let _ = sqlx::query("ALTER TABLE hubs ADD COLUMN server_id TEXT REFERENCES servers(id)")
        .execute(pool)
        .await;

    // Registered server agents — one row per remote machine.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS servers (
            id            TEXT PRIMARY KEY,
            token_hash    TEXT NOT NULL,
            name          TEXT NOT NULL,
            region        TEXT,
            registered_at INTEGER NOT NULL,
            last_seen_at  INTEGER,
            deleted_at    INTEGER
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}
