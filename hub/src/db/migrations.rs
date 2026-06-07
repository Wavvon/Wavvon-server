use anyhow::Result;
use sqlx::AnyPool;

pub async fn run(pool: &AnyPool) -> Result<()> {
    // SQLite-only PRAGMAs — skip for PostgreSQL.
    // Detect SQLite by inspecting the pool's connect options URL.
    let connect_str = format!("{:?}", pool.connect_options());
    let is_sqlite = connect_str.to_lowercase().contains("sqlite");
    if is_sqlite {
        sqlx::query("PRAGMA journal_mode=WAL").execute(pool).await?;
        sqlx::query("PRAGMA foreign_keys=ON").execute(pool).await?;
        sqlx::query("PRAGMA synchronous=NORMAL").execute(pool).await?;
    }

    // ---- Core user / session tables ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            public_key        TEXT PRIMARY KEY,
            display_name      TEXT,
            first_seen_at     INTEGER NOT NULL,
            last_seen_at      INTEGER NOT NULL,
            approval_status   TEXT NOT NULL DEFAULT 'approved',
            avatar            TEXT,
            master_pubkey     TEXT,
            is_bot            INTEGER NOT NULL DEFAULT 0,
            is_bot_removed    INTEGER NOT NULL DEFAULT 0,
            bot_invite_token  TEXT,
            bot_invite_expires INTEGER,
            is_webhook        INTEGER NOT NULL DEFAULT 0,
            lobby_status      TEXT NOT NULL DEFAULT 'none',
            lobby_entered_at  INTEGER,
            pow_level         INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_users_master_pubkey ON users(master_pubkey)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            token             TEXT PRIMARY KEY,
            public_key        TEXT NOT NULL REFERENCES users(public_key),
            created_at        INTEGER NOT NULL,
            expires_at        INTEGER,
            expiry_warned_at  INTEGER
        )",
    )
    .execute(pool)
    .await?;

    // ---- Channels ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channels (
            id               TEXT PRIMARY KEY,
            name             TEXT NOT NULL UNIQUE,
            created_by       TEXT NOT NULL REFERENCES users(public_key),
            parent_id        TEXT REFERENCES channels(id),
            is_category      INTEGER NOT NULL DEFAULT 0,
            display_order    INTEGER NOT NULL DEFAULT 0,
            description      TEXT,
            created_at       INTEGER NOT NULL,
            icon             TEXT,
            color            TEXT,
            custom_icon_svg  TEXT,
            min_talk_power   INTEGER NOT NULL DEFAULT 0,
            channel_type     TEXT NOT NULL DEFAULT 'text',
            retention_days   INTEGER
        )",
    )
    .execute(pool)
    .await?;

    // ---- Messages ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS messages (
            id                TEXT PRIMARY KEY,
            channel_id        TEXT NOT NULL REFERENCES channels(id),
            sender            TEXT NOT NULL REFERENCES users(public_key),
            content           TEXT NOT NULL,
            created_at        INTEGER NOT NULL,
            edited_at         INTEGER,
            attachments       TEXT,
            reply_to          TEXT,
            visible_to_pubkey TEXT,
            embeds            TEXT,
            reply_count       INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS message_reactions (
            message_id  TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            emoji       TEXT NOT NULL,
            user_key    TEXT NOT NULL REFERENCES users(public_key),
            created_at  INTEGER NOT NULL,
            PRIMARY KEY (message_id, emoji, user_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_reactions_message ON message_reactions(message_id)",
    )
    .execute(pool)
    .await?;

    // ---- Federation ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS peers (
            public_key TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            url        TEXT NOT NULL,
            added_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS federated_channels (
            id              TEXT PRIMARY KEY,
            peer_public_key TEXT NOT NULL REFERENCES peers(public_key),
            remote_id       TEXT NOT NULL,
            name            TEXT NOT NULL,
            created_at      INTEGER NOT NULL,
            last_synced_at  INTEGER NOT NULL,
            UNIQUE(peer_public_key, remote_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS federated_messages (
            id             TEXT PRIMARY KEY,
            fed_channel_id TEXT NOT NULL REFERENCES federated_channels(id),
            remote_id      TEXT NOT NULL,
            sender         TEXT NOT NULL,
            content        TEXT NOT NULL,
            created_at     INTEGER NOT NULL,
            UNIQUE(fed_channel_id, remote_id)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Roles and permissions ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS roles (
            id                 TEXT PRIMARY KEY,
            name               TEXT NOT NULL UNIQUE,
            priority           INTEGER NOT NULL DEFAULT 0,
            display_separately INTEGER NOT NULL DEFAULT 0,
            created_at         INTEGER NOT NULL,
            talk_power         INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS role_permissions (
            role_id    TEXT NOT NULL REFERENCES roles(id),
            permission TEXT NOT NULL,
            PRIMARY KEY (role_id, permission)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_roles (
            user_public_key TEXT NOT NULL REFERENCES users(public_key),
            role_id         TEXT NOT NULL REFERENCES roles(id),
            assigned_at     INTEGER NOT NULL,
            PRIMARY KEY (user_public_key, role_id)
        )",
    )
    .execute(pool)
    .await?;

    // Seed built-in roles
    sqlx::query(
        "INSERT INTO roles (id, name, priority, created_at) VALUES ('builtin-everyone', '@everyone', 0, 0)
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "INSERT INTO roles (id, name, priority, created_at) VALUES ('builtin-owner', 'Owner', 999999, 0)
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(pool)
    .await?;

    // Seed built-in permissions
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'send_messages') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'read_messages') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'create_posts') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'start_game') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-everyone', 'create_events') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-owner', 'admin') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-owner', 'manage_posts') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-owner', 'manage_games') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-owner', 'manage_voice') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-owner', 'use_video') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO role_permissions (role_id, permission) VALUES ('builtin-owner', 'manage_messages') ON CONFLICT (role_id, permission) DO NOTHING")
        .execute(pool).await?;

    // ---- Moderation ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bans (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            banned_by         TEXT NOT NULL,
            reason            TEXT,
            created_at        INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mutes (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            muted_by          TEXT NOT NULL,
            reason            TEXT,
            expires_at        INTEGER,
            created_at        INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_bans (
            channel_id        TEXT NOT NULL REFERENCES channels(id),
            target_public_key TEXT NOT NULL REFERENCES users(public_key),
            banned_by         TEXT NOT NULL,
            reason            TEXT,
            created_at        INTEGER NOT NULL,
            PRIMARY KEY (channel_id, target_public_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS voice_mutes (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            muted_by          TEXT NOT NULL,
            reason            TEXT,
            created_at        INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_voice_mutes (
            channel_id TEXT NOT NULL,
            pubkey     TEXT NOT NULL,
            muted_by   TEXT NOT NULL,
            muted_at   TEXT NOT NULL,
            PRIMARY KEY (channel_id, pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS raise_hand_requests (
            id           TEXT PRIMARY KEY,
            channel_id   TEXT NOT NULL,
            pubkey       TEXT NOT NULL,
            requested_at TEXT NOT NULL,
            UNIQUE (channel_id, pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS message_reports (
            id              TEXT PRIMARY KEY,
            message_id      TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            reporter_pubkey TEXT NOT NULL REFERENCES users(public_key),
            reason          TEXT NOT NULL DEFAULT '',
            reported_at     INTEGER NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            reviewed_by     TEXT,
            review_note     TEXT,
            UNIQUE(message_id, reporter_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS federated_bans (
            source_hub_pubkey    TEXT NOT NULL,
            target_master_pubkey TEXT NOT NULL,
            reason               TEXT,
            added_at             INTEGER NOT NULL,
            synced_at            INTEGER NOT NULL,
            PRIMARY KEY(source_hub_pubkey, target_master_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Invites ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS invites (
            code       TEXT PRIMARY KEY,
            created_by TEXT NOT NULL,
            max_uses   INTEGER,
            uses       INTEGER NOT NULL DEFAULT 0,
            expires_at INTEGER,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // ---- Hub settings (key-value store for simple config) ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('invite_only', 'false') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('min_security_level', '0') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('require_approval', 'false') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('max_channel_depth', '0') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('lobby_enabled', '1') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('lobby_welcome_md', '') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('challenge_mode', 'off') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('challenge_difficulty', 'easy') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('min_pow_level', '0') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('cert_auto_issue', 'true') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('cert_standing_days', '30') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('cert_validity_days', '90') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('cert_min_pow_level', '0') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('cert_mode', 'none') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('cert_trusted_issuers', '[]') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('cert_require', '{}') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('hub_tags', '[]') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('hub_nsfw', 'false') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('moderation_webhook_url', '') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('moderation_webhook_secret', '') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('banlist_sources', '[]') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;
    sqlx::query("INSERT INTO hub_settings (key, value) VALUES ('bootstrapped_at', '') ON CONFLICT (key) DO NOTHING")
        .execute(pool).await?;

    // ---- Channel settings ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_settings (
            channel_id     TEXT PRIMARY KEY REFERENCES channels(id),
            min_talk_power INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // ---- Games (hub-installed) ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_games (
            id             TEXT PRIMARY KEY,
            name           TEXT NOT NULL,
            description    TEXT,
            version        TEXT NOT NULL,
            entry_url      TEXT NOT NULL,
            thumbnail_url  TEXT,
            author         TEXT,
            min_players    INTEGER NOT NULL DEFAULT 1,
            max_players    INTEGER NOT NULL DEFAULT 1,
            installed_by   TEXT NOT NULL REFERENCES users(public_key),
            installed_at   INTEGER NOT NULL,
            manifest_url   TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Farm-side game enable/disable per hub
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS enabled_games (
            game_id    TEXT PRIMARY KEY,
            enabled_at TEXT NOT NULL,
            enabled_by TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_games (
            channel_id TEXT NOT NULL,
            game_id    TEXT NOT NULL,
            PRIMARY KEY (channel_id, game_id)
        )",
    )
    .execute(pool)
    .await?;

    // Game sessions and shared KV
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS game_sessions (
            id          TEXT PRIMARY KEY,
            channel_id  TEXT NOT NULL,
            game_id     TEXT NOT NULL,
            host_pubkey TEXT NOT NULL,
            state_json  TEXT NOT NULL DEFAULT '{}',
            created_at  TEXT NOT NULL,
            ended_at    TEXT,
            status      TEXT NOT NULL DEFAULT 'lobby',
            snapshot    BLOB,
            updated_at  INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS game_shared_kv (
            session_id TEXT NOT NULL,
            key        TEXT NOT NULL,
            value      TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (session_id, key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS game_channel_kv (
            game_id    TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            key        TEXT NOT NULL,
            value      TEXT NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (game_id, channel_id, key)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Alliances ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliances (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliance_members (
            alliance_id    TEXT NOT NULL REFERENCES alliances(id),
            hub_public_key TEXT NOT NULL,
            hub_name       TEXT NOT NULL,
            hub_url        TEXT NOT NULL,
            joined_at      INTEGER NOT NULL,
            PRIMARY KEY (alliance_id, hub_public_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliance_shared_channels (
            alliance_id TEXT NOT NULL REFERENCES alliances(id),
            channel_id  TEXT NOT NULL REFERENCES channels(id),
            shared_at   INTEGER NOT NULL,
            PRIMARY KEY (alliance_id, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pending_alliance_invites (
            id                   TEXT PRIMARY KEY,
            alliance_id          TEXT NOT NULL,
            alliance_name        TEXT NOT NULL,
            from_hub_url         TEXT NOT NULL,
            from_hub_name        TEXT NOT NULL,
            from_hub_public_key  TEXT NOT NULL,
            invite_token         TEXT NOT NULL,
            created_at           INTEGER NOT NULL,
            message              TEXT
        )",
    )
    .execute(pool)
    .await?;

    // ---- DM / conversations ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conversations (
            id         TEXT PRIMARY KEY,
            conv_type  TEXT NOT NULL DEFAULT 'dm',
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conversation_members (
            conversation_id TEXT NOT NULL REFERENCES conversations(id),
            public_key      TEXT NOT NULL REFERENCES users(public_key),
            joined_at       INTEGER NOT NULL,
            hub_url         TEXT,
            PRIMARY KEY (conversation_id, public_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS friends (
            user_a       TEXT NOT NULL REFERENCES users(public_key),
            user_b       TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            created_at   INTEGER NOT NULL,
            hub_url      TEXT,
            display_name TEXT,
            PRIMARY KEY (user_a, user_b)
        )",
    )
    .execute(pool)
    .await?;

    // content is nullable: encrypted messages store NULL here and use ciphertext_json.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dm_messages (
            id                  TEXT PRIMARY KEY,
            conversation_id     TEXT NOT NULL,
            sender              TEXT NOT NULL,
            content             TEXT,
            signature           TEXT,
            created_at          INTEGER NOT NULL,
            attachments         TEXT,
            is_encrypted        INTEGER NOT NULL DEFAULT 0,
            ciphertext_json     TEXT,
            is_group_encrypted  INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // DM delivery queue
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dm_outbox (
            message_id        TEXT NOT NULL REFERENCES dm_messages(id),
            recipient_hub_url TEXT NOT NULL,
            attempts          INTEGER NOT NULL DEFAULT 0,
            next_attempt_at   INTEGER NOT NULL,
            last_error        TEXT,
            bounced_at        INTEGER,
            PRIMARY KEY (message_id, recipient_hub_url)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dm_blocks (
            owner_pubkey   TEXT NOT NULL,
            blocked_pubkey TEXT NOT NULL,
            PRIMARY KEY (owner_pubkey, blocked_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Multi-device / home-hub state ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS home_hub_designations (
            master_pubkey TEXT PRIMARY KEY,
            hubs_json     TEXT NOT NULL,
            issued_at     INTEGER NOT NULL,
            sequence      INTEGER NOT NULL,
            signature     TEXT NOT NULL,
            updated_at    INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subkey_certs (
            master_pubkey      TEXT NOT NULL,
            subkey_pubkey      TEXT NOT NULL,
            device_label       TEXT NOT NULL,
            issued_at          INTEGER NOT NULL,
            not_after          INTEGER,
            fallback_hubs_json TEXT NOT NULL,
            signature          TEXT NOT NULL,
            registered_at      INTEGER NOT NULL,
            PRIMARY KEY (master_pubkey, subkey_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subkey_revocations (
            master_pubkey TEXT NOT NULL,
            subkey_pubkey TEXT NOT NULL,
            revoked_at    INTEGER NOT NULL,
            signature     TEXT NOT NULL,
            registered_at INTEGER NOT NULL,
            PRIMARY KEY (master_pubkey, subkey_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS prefs_blobs (
            master_pubkey  TEXT PRIMARY KEY,
            blob_version   INTEGER NOT NULL,
            ciphertext_hex TEXT NOT NULL,
            signature      TEXT NOT NULL,
            updated_at     INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pairing_offers (
            pairing_token   TEXT PRIMARY KEY,
            master_pubkey   TEXT NOT NULL,
            home_hubs_json  TEXT NOT NULL,
            issued_at       INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            offer_signature TEXT NOT NULL,
            state           TEXT NOT NULL DEFAULT 'pending',
            subkey_pubkey   TEXT,
            device_label    TEXT,
            claim_proof     TEXT,
            cert_json       TEXT,
            wrapped_key_hex TEXT,
            created_at      INTEGER NOT NULL,
            updated_at      INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS public_hub_profiles (
            pubkey       TEXT PRIMARY KEY,
            profile_json TEXT NOT NULL,
            updated_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // ---- E2E encryption ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dh_keys (
            pubkey        TEXT PRIMARY KEY REFERENCES users(public_key),
            dh_pubkey_hex TEXT NOT NULL,
            signature_hex TEXT NOT NULL,
            published_at  INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS group_sender_key_distributions (
            id                 TEXT PRIMARY KEY,
            conv_id            TEXT NOT NULL,
            sender_pubkey      TEXT NOT NULL,
            recipient_pubkey   TEXT NOT NULL,
            sender_key_version INTEGER NOT NULL,
            iteration          INTEGER NOT NULL,
            wrapped_key_hex    TEXT NOT NULL,
            wrap_nonce_hex     TEXT NOT NULL,
            created_at         INTEGER NOT NULL,
            UNIQUE(conv_id, sender_pubkey, recipient_pubkey, sender_key_version)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Hub icons and emojis ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_icons (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            svg_content TEXT NOT NULL,
            uploaded_by TEXT NOT NULL REFERENCES users(public_key),
            created_at  INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_emojis (
            id         TEXT PRIMARY KEY,
            name       TEXT NOT NULL UNIQUE,
            uploader   TEXT NOT NULL REFERENCES users(public_key),
            mime       TEXT NOT NULL,
            data_b64   TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // ---- Bots ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_tokens (
            token      TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_profiles (
            pubkey       TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            avatar_url   TEXT,
            description  TEXT,
            webhook_url  TEXT,
            homepage_url TEXT,
            capabilities TEXT NOT NULL DEFAULT '[]',
            updated_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_commands (
            pubkey           TEXT NOT NULL,
            name             TEXT NOT NULL,
            description      TEXT NOT NULL,
            args             TEXT,
            scope            TEXT NOT NULL DEFAULT 'channel',
            privileged       INTEGER NOT NULL DEFAULT 0,
            cooldown_seconds INTEGER NOT NULL DEFAULT 3,
            PRIMARY KEY (pubkey, name)
        )",
    )
    .execute(pool)
    .await?;

    // channel_id = '' (empty string) = hub-scope subscription
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_subscriptions (
            bot_pubkey TEXT NOT NULL,
            event_type TEXT NOT NULL,
            channel_id TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (bot_pubkey, event_type, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_channel_scope (
            bot_pubkey TEXT NOT NULL,
            channel_id TEXT NOT NULL,
            PRIMARY KEY (bot_pubkey, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    // Self-service bots (token-authenticated, webhook delivery)
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bots (
            public_key   TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            created_by   TEXT NOT NULL,
            token_hash   TEXT NOT NULL,
            webhook_url  TEXT,
            created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_slash_commands (
            id          TEXT PRIMARY KEY,
            bot_pubkey  TEXT NOT NULL REFERENCES bots(public_key) ON DELETE CASCADE,
            command     TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            UNIQUE(bot_pubkey, command)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_event_queue (
            id         TEXT PRIMARY KEY,
            bot_pubkey TEXT NOT NULL REFERENCES bots(public_key) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            payload    TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            delivered  INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // ---- Bot challenges (anti-spam) ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bot_challenges (
            id              TEXT PRIMARY KEY,
            pubkey          TEXT NOT NULL,
            kind            TEXT NOT NULL,
            expected_answer TEXT,
            created_at      INTEGER NOT NULL,
            expires_at      INTEGER NOT NULL,
            consumed_at     INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_bot_challenges_pubkey ON bot_challenges(pubkey, expires_at)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS challenge_tokens (
            token       TEXT PRIMARY KEY,
            pubkey      TEXT NOT NULL,
            issued_at   INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL,
            consumed_at INTEGER
        )",
    )
    .execute(pool)
    .await?;

    // ---- Message components (interactive bot UI) ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS message_components (
            id            TEXT PRIMARY KEY,
            message_id    TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            row_idx       INTEGER NOT NULL,
            component_idx INTEGER NOT NULL,
            type          TEXT NOT NULL,
            config_json   TEXT NOT NULL,
            expires_at    INTEGER
        )",
    )
    .execute(pool)
    .await?;

    // ---- Audit log ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_audit_seq (
            id  INTEGER PRIMARY KEY,
            seq INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("INSERT INTO hub_audit_seq VALUES(1, 0) ON CONFLICT (id) DO NOTHING")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_audit_log (
            id            TEXT PRIMARY KEY,
            seq           INTEGER NOT NULL,
            event_type    TEXT NOT NULL,
            at            INTEGER NOT NULL,
            actor_pubkey  TEXT,
            target_pubkey TEXT,
            channel_id    TEXT,
            payload_json  TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_audit_seq ON hub_audit_log(seq)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_audit_event_type ON hub_audit_log(event_type)",
    )
    .execute(pool)
    .await?;

    // ---- Incoming webhooks ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS webhooks (
            id                TEXT PRIMARY KEY,
            channel_id        TEXT NOT NULL REFERENCES channels(id),
            secret_token_hash TEXT NOT NULL,
            display_name      TEXT NOT NULL,
            avatar_url        TEXT,
            created_by_pubkey TEXT NOT NULL,
            rate_limit        INTEGER NOT NULL DEFAULT 5,
            active            INTEGER NOT NULL DEFAULT 1,
            created_at        INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // ---- Surveys / onboarding ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS surveys (
            id         TEXT PRIMARY KEY,
            enabled    INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_questions (
            id            TEXT PRIMARY KEY,
            survey_id     TEXT NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
            prompt        TEXT NOT NULL,
            kind          TEXT NOT NULL,
            required      INTEGER NOT NULL DEFAULT 1,
            display_order INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_choices (
            id            TEXT PRIMARY KEY,
            question_id   TEXT NOT NULL REFERENCES survey_questions(id) ON DELETE CASCADE,
            label         TEXT NOT NULL,
            display_order INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_choice_roles (
            choice_id TEXT NOT NULL REFERENCES survey_choices(id) ON DELETE CASCADE,
            role_id   TEXT NOT NULL,
            PRIMARY KEY (choice_id, role_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_responses (
            id           TEXT PRIMARY KEY,
            pubkey       TEXT NOT NULL,
            survey_id    TEXT NOT NULL,
            submitted_at INTEGER NOT NULL,
            UNIQUE(pubkey, survey_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_answers (
            response_id TEXT NOT NULL REFERENCES survey_responses(id) ON DELETE CASCADE,
            question_id TEXT NOT NULL,
            choice_id   TEXT,
            text_answer TEXT,
            PRIMARY KEY (response_id, question_id)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Certifications ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cert_issuances (
            id             TEXT PRIMARY KEY,
            subject_pubkey TEXT NOT NULL,
            pow_level      INTEGER,
            member_since   INTEGER NOT NULL,
            issued_at      INTEGER NOT NULL,
            expires_at     INTEGER NOT NULL,
            revoked_at     INTEGER,
            standing       TEXT NOT NULL DEFAULT 'good',
            payload_json   TEXT NOT NULL,
            signature      TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_cert_issuances_subject
         ON cert_issuances(subject_pubkey, issued_at DESC)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_certs (
            id            TEXT PRIMARY KEY,
            master_pubkey TEXT NOT NULL,
            issuer_pubkey TEXT NOT NULL,
            issuer_url    TEXT NOT NULL,
            payload_json  TEXT NOT NULL,
            signature     TEXT NOT NULL,
            expires_at    INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_user_certs_master ON user_certs(master_pubkey)",
    )
    .execute(pool)
    .await?;

    // ---- Badge federation ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS badge_offers (
            id              TEXT PRIMARY KEY,
            from_hub_pubkey TEXT NOT NULL,
            from_hub_url    TEXT NOT NULL,
            label           TEXT NOT NULL,
            note            TEXT,
            payload         TEXT NOT NULL,
            signature       TEXT NOT NULL,
            created_at      TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_badges (
            id            TEXT PRIMARY KEY,
            issuer_pubkey TEXT NOT NULL,
            issuer_url    TEXT NOT NULL,
            label         TEXT NOT NULL,
            payload       TEXT NOT NULL,
            signature     TEXT NOT NULL,
            accepted_at   TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issued_badges (
            id                   TEXT PRIMARY KEY,
            recipient_hub_url    TEXT NOT NULL,
            recipient_hub_pubkey TEXT NOT NULL,
            label                TEXT NOT NULL,
            payload              TEXT NOT NULL,
            signature            TEXT NOT NULL,
            issued_at            TEXT NOT NULL,
            expires_at           TEXT,
            revoked_at           TEXT
        )",
    )
    .execute(pool)
    .await?;

    // ---- Recovery contacts ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS recovery_settings (
            owner_pubkey TEXT PRIMARY KEY,
            threshold    INTEGER NOT NULL DEFAULT 1,
            created_at   INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS recovery_contacts (
            owner_pubkey   TEXT NOT NULL,
            contact_pubkey TEXT NOT NULL,
            created_at     INTEGER NOT NULL,
            PRIMARY KEY (owner_pubkey, contact_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS key_rotation_requests (
            id         TEXT PRIMARY KEY,
            old_pubkey TEXT NOT NULL,
            new_pubkey TEXT NOT NULL,
            reason     TEXT,
            status     TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            decided_at INTEGER,
            decided_by TEXT
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS rotation_attestations (
            id              TEXT PRIMARY KEY,
            request_id      TEXT NOT NULL,
            attester_pubkey TEXT NOT NULL,
            signature       TEXT NOT NULL,
            attested_at     INTEGER NOT NULL,
            UNIQUE (request_id, attester_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Forum posts ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS posts (
            id               TEXT PRIMARY KEY,
            channel_id       TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            author_pubkey    TEXT NOT NULL,
            title            TEXT NOT NULL,
            body             TEXT NOT NULL,
            created_at       INTEGER NOT NULL,
            edited_at        INTEGER,
            is_pinned        INTEGER NOT NULL DEFAULT 0,
            is_locked        INTEGER NOT NULL DEFAULT 0,
            reply_count      INTEGER NOT NULL DEFAULT 0,
            last_activity_at INTEGER NOT NULL,
            deleted_at       INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_posts_channel_activity
         ON posts (channel_id, is_pinned DESC, last_activity_at DESC)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_posts_author ON posts (author_pubkey)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS post_replies (
            id            TEXT PRIMARY KEY,
            post_id       TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            author_pubkey TEXT NOT NULL,
            body          TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            edited_at     INTEGER,
            reply_to_id   TEXT REFERENCES post_replies(id) ON DELETE SET NULL,
            deleted_at    INTEGER
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_post_replies_post
         ON post_replies (post_id, created_at)",
    )
    .execute(pool)
    .await?;

    // FTS5 virtual tables and triggers are SQLite-only.
    if is_sqlite {
        sqlx::query(
            "CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
                title, body, post_id UNINDEXED, channel_id UNINDEXED
            )",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TRIGGER IF NOT EXISTS posts_fts_ai
             AFTER INSERT ON posts
             WHEN new.deleted_at IS NULL BEGIN
               INSERT INTO posts_fts(post_id, channel_id, title, body)
               VALUES (new.id, new.channel_id, new.title, new.body);
             END",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TRIGGER IF NOT EXISTS posts_fts_au
             AFTER UPDATE ON posts BEGIN
               DELETE FROM posts_fts WHERE post_id = old.id;
               INSERT INTO posts_fts(post_id, channel_id, title, body)
               SELECT new.id, new.channel_id, new.title, new.body
               WHERE new.deleted_at IS NULL;
             END",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TRIGGER IF NOT EXISTS posts_fts_ad
             AFTER DELETE ON posts BEGIN
               DELETE FROM posts_fts WHERE post_id = old.id;
             END",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TRIGGER IF NOT EXISTS post_replies_fts_ai
             AFTER INSERT ON post_replies
             WHEN new.deleted_at IS NULL BEGIN
               INSERT INTO posts_fts(post_id, channel_id, title, body)
               SELECT new.post_id, p.channel_id, '', new.body
               FROM posts p WHERE p.id = new.post_id;
             END",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TRIGGER IF NOT EXISTS post_replies_fts_au
             AFTER UPDATE ON post_replies BEGIN
               DELETE FROM posts_fts WHERE post_id = old.post_id AND body = old.body AND title = '';
               INSERT INTO posts_fts(post_id, channel_id, title, body)
               SELECT new.post_id, p.channel_id, '', new.body
               FROM posts p WHERE p.id = new.post_id AND new.deleted_at IS NULL;
             END",
        )
        .execute(pool)
        .await?;

        sqlx::query(
            "CREATE TRIGGER IF NOT EXISTS post_replies_fts_ad
             AFTER DELETE ON post_replies BEGIN
               DELETE FROM posts_fts WHERE post_id = old.post_id AND body = old.body AND title = '';
             END",
        )
        .execute(pool)
        .await?;
    }

    // ---- Events / calendar ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_events (
            id             TEXT PRIMARY KEY,
            channel_id     TEXT NOT NULL REFERENCES channels(id),
            creator_pubkey TEXT NOT NULL REFERENCES users(public_key),
            title          TEXT NOT NULL,
            description    TEXT NOT NULL DEFAULT '',
            starts_at      INTEGER NOT NULL,
            ends_at        INTEGER,
            location       TEXT,
            created_at     INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS event_rsvps (
            event_id    TEXT NOT NULL REFERENCES hub_events(id) ON DELETE CASCADE,
            user_pubkey TEXT NOT NULL REFERENCES users(public_key),
            status      TEXT NOT NULL CHECK(status IN ('going','maybe','not_going')),
            PRIMARY KEY (event_id, user_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Polls ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS polls (
            id             TEXT PRIMARY KEY,
            channel_id     TEXT NOT NULL REFERENCES channels(id),
            creator_pubkey TEXT NOT NULL,
            question       TEXT NOT NULL,
            options        TEXT NOT NULL,
            ends_at        INTEGER,
            max_choices    INTEGER NOT NULL DEFAULT 1,
            created_at     INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS poll_votes (
            poll_id     TEXT NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
            user_pubkey TEXT NOT NULL REFERENCES users(public_key),
            option_ids  TEXT NOT NULL,
            PRIMARY KEY (poll_id, user_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Unread tracking ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_last_read (
            user_pubkey  TEXT NOT NULL,
            channel_id   TEXT NOT NULL,
            last_read_at INTEGER NOT NULL,
            PRIMARY KEY (user_pubkey, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    // ---- File uploads ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS upload_files (
            id              TEXT PRIMARY KEY,
            filename        TEXT NOT NULL,
            original_name   TEXT NOT NULL,
            mime_type       TEXT NOT NULL,
            size_bytes      INTEGER NOT NULL,
            uploader_pubkey TEXT NOT NULL,
            channel_id      TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            created_at      INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // ---- Message pinning ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_pins (
            channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            pinned_by  TEXT NOT NULL,
            pinned_at  INTEGER NOT NULL,
            PRIMARY KEY (channel_id, message_id)
        )",
    )
    .execute(pool)
    .await?;

    tracing::info!("Database migrations complete");

    Ok(())
}
