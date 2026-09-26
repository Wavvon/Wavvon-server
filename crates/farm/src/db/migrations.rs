use anyhow::Result;
use sqlx::PgPool;

pub async fn run(pool: &PgPool) -> Result<()> {
    // Farm singleton metadata — always id=1.
    // Includes all columns: admin_pubkey, creation policy, quotas,
    // discovery metadata, and TOTP fields.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farms (
            id                      INTEGER PRIMARY KEY CHECK(id = 1),
            public_key              TEXT NOT NULL,
            name                    TEXT NOT NULL DEFAULT 'My Farm',
            description             TEXT,
            directory_public        BOOLEAN NOT NULL DEFAULT FALSE,
            created_at              BIGINT NOT NULL,
            admin_pubkey            TEXT,
            creation_policy         TEXT NOT NULL DEFAULT 'admin_only'
                                        CHECK(creation_policy IN ('open', 'admin_only', 'disabled')),
            max_hubs_per_user       BIGINT NOT NULL DEFAULT 0,
            max_hubs_total          BIGINT NOT NULL DEFAULT 0,
            languages               TEXT NOT NULL DEFAULT '[\"en\"]',
            tags                    TEXT NOT NULL DEFAULT '[]',
            country                 TEXT,
            region                  TEXT,
            totp_secret             TEXT,
            totp_enabled            BOOLEAN NOT NULL DEFAULT FALSE
        )",
    )
    .execute(pool)
    .await?;

    // Canonical per-farm user identity.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farm_users (
            public_key    TEXT PRIMARY KEY,
            master_pubkey TEXT,
            first_seen_at BIGINT NOT NULL,
            last_seen_at  BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Short-lived challenge nonces (60s TTL, swept on read).
    //
    // Superseded 2026-07-05 by pending_challenges_v2 (below): keying by
    // pubkey meant one slot per key, so two concurrent auth flows for the
    // same key stomped each other's challenge — the same race fixed hub-side.
    // Kept (additive-only rule) but no longer written.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_challenges (
            public_key    TEXT PRIMARY KEY,
            challenge_hex TEXT NOT NULL,
            expires_at    BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // v2: keyed by the nonce itself so any number of challenges can be
    // outstanding per pubkey. Expired rows are pruned lazily on issue.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_challenges_v2 (
            challenge_hex TEXT PRIMARY KEY,
            public_key    TEXT NOT NULL,
            expires_at    BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Issued session records (the token itself is the signed blob — not stored here).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS farm_sessions (
            jti              TEXT PRIMARY KEY,
            public_key       TEXT NOT NULL REFERENCES farm_users(public_key),
            issued_at        BIGINT NOT NULL,
            expires_at       BIGINT NOT NULL,
            revoked_at       BIGINT,
            scope            TEXT NOT NULL DEFAULT 'member',
            revoked_manually BOOLEAN NOT NULL DEFAULT FALSE
        )",
    )
    .execute(pool)
    .await?;

    // Registered server agents — one row per remote machine.
    // Must be created before hubs because hubs references servers(id).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS servers (
            id            TEXT PRIMARY KEY,
            token_hash    TEXT NOT NULL,
            name          TEXT NOT NULL,
            region        TEXT,
            registered_at BIGINT NOT NULL,
            last_seen_at  BIGINT,
            deleted_at    BIGINT
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
            created_at        BIGINT NOT NULL,
            suspended_at      BIGINT,
            suspension_reason TEXT,
            deleted_at        BIGINT,
            hub_pubkey        TEXT,
            server_id         TEXT REFERENCES servers(id)
        )",
    )
    .execute(pool)
    .await?;

    // Serial routing (farm-impl.md "Serial routing — first slice"): the
    // farm's reverse proxy resolves `/hub/<serial>/...` by looking up
    // `hub_pubkey`, so it must be unique. Partial (`WHERE hub_pubkey IS NOT
    // NULL`) because the column is nullable until a hub registers its
    // pubkey — unregistered rows never collide with each other.
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS hubs_hub_pubkey_unique_idx
             ON hubs (hub_pubkey)
             WHERE hub_pubkey IS NOT NULL",
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
            online_users   BIGINT NOT NULL DEFAULT 0,
            storage_bytes  BIGINT NOT NULL DEFAULT 0,
            uptime_seconds BIGINT NOT NULL DEFAULT 0,
            last_seen_at   BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Process supervision (farm-impl.md Phase 2 "process supervision" — see
    // monitor.rs): tracks whether auto-restart is active for a hub, how many
    // consecutive restart attempts have been made, and when the last one ran.
    let _ = sqlx::query(
        "ALTER TABLE hubs ADD COLUMN auto_restart_enabled BOOLEAN NOT NULL DEFAULT TRUE",
    )
    .execute(pool)
    .await;
    let _ = sqlx::query("ALTER TABLE hubs ADD COLUMN restart_attempts INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE hubs ADD COLUMN last_restart_at BIGINT")
        .execute(pool)
        .await;

    // Voice transport v2 (voice-transport-v2.md): per-hub voice
    // (WebTransport/QUIC over UDP) port, allocated alongside process_port so
    // farm-spawned hubs on the same box don't collide on the default 3001.
    let _ = sqlx::query("ALTER TABLE hubs ADD COLUMN voice_port INTEGER")
        .execute(pool)
        .await;

    // Per-hub PostgreSQL connection URL (db/provision.rs).
    //
    // Replaces `db_path`, a SQLite-era file path nothing consumed: the farm
    // passed no database configuration at all, so every hub it spawned fell
    // back to the same default URL and they all shared one database. `db_path`
    // stays (additive-only) but is dead.
    //
    // Nullable because rows created before this exist; a hub with no db_url
    // gets one provisioned on its next spawn.
    let _ = sqlx::query("ALTER TABLE hubs ADD COLUMN db_url TEXT")
        .execute(pool)
        .await;

    // Placement capacity (routes/placement.rs). How many hubs each node may
    // hold: a registered server agent, and the farm's own process.
    //
    // NULL / 0 means unlimited, matching `max_hubs_per_user`. Before this,
    // placement was `map.iter().next()` — the first entry of a HashMap
    // iteration — so "server 1 holds 5 hubs, server 2 holds 3" could not be
    // expressed at all and every hub landed wherever the hash order put it.
    let _ = sqlx::query("ALTER TABLE servers ADD COLUMN max_hubs INTEGER")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE farms ADD COLUMN max_local_hubs BIGINT NOT NULL DEFAULT 0")
        .execute(pool)
        .await;

    // Where a node actually is, and how to trust it (farm-model.md,
    // "Multi-node data plane"). Before these the control plane was multi-node
    // and the data plane was not: the proxy dialed `127.0.0.1:<port>` for
    // every hub, so a hub the farm had spawned on another machine was
    // unreachable through the farm's own domain.
    //
    // All nullable or defaulted: a row with no host is a hub on this machine,
    // which is every row that exists today.
    for sql in [
        "ALTER TABLE servers ADD COLUMN host TEXT",
        // `ca` — ordinary certificate validation, for a node that already
        // terminates TLS. `pin` — the agent advertises its self-signed cert's
        // SHA-256 and the farm refuses anything else, the same primitive voice
        // uses for its relay certificate.
        "ALTER TABLE servers ADD COLUMN tls_mode TEXT NOT NULL DEFAULT 'ca'
             CHECK (tls_mode IN ('ca', 'pin'))",
        "ALTER TABLE servers ADD COLUMN cert_sha256 TEXT",
        // The farm never holds a node's database credentials: it holds a
        // template, and the agent substitutes the per-hub database name where
        // the data actually lives.
        "ALTER TABLE servers ADD COLUMN db_url_template TEXT",
    ] {
        let _ = sqlx::query(sql).execute(pool).await;
    }

    // How hubs' data is separated: `database` (one each, needs CREATEDB) or
    // `schema` (one each inside the farm's own database). See db/provision.rs.
    //
    // Default `database` because it separates more. `schema` exists because a
    // managed PostgreSQL plan routinely gives one database and no CREATEDB —
    // without it the farm cannot create a single hub in those environments.
    let _ = sqlx::query(
        "ALTER TABLE farms ADD COLUMN hub_isolation TEXT NOT NULL DEFAULT 'database'
             CHECK (hub_isolation IN ('database', 'schema'))",
    )
    .execute(pool)
    .await;

    // Orthogonal to the layout above, and for the threat the layout does not
    // address: a database or a schema each stops hubs colliding, not one hub
    // reading another's data, because every hub connects as the farm's own
    // role. `per_hub` gives each hub a login role granted only its own space.
    // Default `shared` — it needs CREATEROLE, which the managed plans `schema`
    // exists for do not hand out, and a farm that cannot start is worse than
    // one whose hubs it already owns.
    let _ = sqlx::query(
        "ALTER TABLE farms ADD COLUMN hub_db_role TEXT NOT NULL DEFAULT 'shared'
             CHECK (hub_db_role IN ('shared', 'per_hub'))",
    )
    .execute(pool)
    .await;

    // Human-readable hub addresses. See `slug.rs` for why a slug is an alias
    // and never the identity.
    //
    // `slug` is the PRIMARY KEY and holds the **lowercase** form, so
    // case-variant impersonation is impossible by construction rather than by
    // remembering to lower() at every call site. `display_slug` keeps the
    // capitalisation the owner typed, for showing back.
    //
    // A row is never deleted. Releasing sets `released_at`: the slug stops
    // resolving and stops counting against the hub's quota, but the row
    // remains, which is what lets the cooling-off window be enforced (only the
    // hub that released it may reclaim it until then) and what makes the
    // history visible to an operator afterwards.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_slugs (
            slug             TEXT PRIMARY KEY,
            display_slug     TEXT NOT NULL,
            hub_id           TEXT NOT NULL REFERENCES hubs(id),
            is_canonical     BOOLEAN NOT NULL DEFAULT FALSE,
            created_at       BIGINT NOT NULL,
            released_at      BIGINT,
            last_resolved_at BIGINT
        )",
    )
    .execute(pool)
    .await?;

    // Resolution reads (slug WHERE released_at IS NULL) on every proxied
    // request, and the quota check counts live slugs per hub.
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS hub_slugs_hub_live_idx
             ON hub_slugs (hub_id) WHERE released_at IS NULL",
    )
    .execute(pool)
    .await?;

    // At most one canonical slug per hub — it is the address the hub publishes
    // and clients store, so "which one" can never be ambiguous.
    sqlx::query(
        "CREATE UNIQUE INDEX IF NOT EXISTS hub_slugs_one_canonical_idx
             ON hub_slugs (hub_id) WHERE is_canonical AND released_at IS NULL",
    )
    .execute(pool)
    .await?;

    // How many live slugs one hub may hold. Farm policy, like
    // max_hubs_per_user — the farm owner sets the ceiling, the hub owner
    // operates inside it and decides which names to keep.
    let _ = sqlx::query("ALTER TABLE farms ADD COLUMN max_slugs_per_hub BIGINT NOT NULL DEFAULT 5")
        .execute(pool)
        .await;

    // Days a released slug stays reserved for the hub that gave it up before
    // returning to the pool. 0 disables the wait entirely.
    let _ =
        sqlx::query("ALTER TABLE farms ADD COLUMN slug_cooloff_days BIGINT NOT NULL DEFAULT 60")
            .execute(pool)
            .await;

    Ok(())
}
