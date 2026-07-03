use anyhow::Result;
use sqlx::PgPool;

pub async fn run(pool: &PgPool) -> Result<()> {
    // ---- Core user / session tables ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            public_key        TEXT PRIMARY KEY,
            display_name      TEXT,
            first_seen_at     BIGINT NOT NULL,
            last_seen_at      BIGINT NOT NULL DEFAULT 0,
            approval_status   TEXT NOT NULL DEFAULT 'approved',
            avatar            TEXT,
            master_pubkey     TEXT,
            is_bot            BOOLEAN NOT NULL DEFAULT FALSE,
            is_bot_removed    BOOLEAN NOT NULL DEFAULT FALSE,
            bot_invite_token  TEXT,
            bot_invite_expires BIGINT,
            is_webhook        BOOLEAN NOT NULL DEFAULT FALSE,
            lobby_status      TEXT NOT NULL DEFAULT 'none',
            lobby_entered_at  BIGINT,
            pow_level         BIGINT NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_users_master_pubkey ON users(master_pubkey)")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            token             TEXT PRIMARY KEY,
            public_key        TEXT NOT NULL REFERENCES users(public_key),
            created_at        BIGINT NOT NULL,
            expires_at        BIGINT,
            expiry_warned_at  BIGINT
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
            is_category      BOOLEAN NOT NULL DEFAULT FALSE,
            display_order    BIGINT NOT NULL DEFAULT 0,
            description      TEXT,
            created_at       BIGINT NOT NULL,
            icon             TEXT,
            color            TEXT,
            custom_icon_svg  TEXT,
            min_talk_power   BIGINT NOT NULL DEFAULT 0,
            channel_type     TEXT NOT NULL DEFAULT 'text',
            retention_days   BIGINT,
            banner_url       TEXT,
            banner_file_id   TEXT
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
            created_at        BIGINT NOT NULL,
            edited_at         BIGINT,
            attachments       TEXT,
            reply_to          TEXT,
            visible_to_pubkey TEXT,
            embeds            TEXT,
            reply_count       BIGINT NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_messages_channel_created
         ON messages(channel_id, created_at DESC)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_messages_reply_to
         ON messages(reply_to)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS message_reactions (
            message_id  TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            emoji       TEXT NOT NULL,
            user_key    TEXT NOT NULL REFERENCES users(public_key),
            created_at  BIGINT NOT NULL,
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
            added_at   BIGINT NOT NULL
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
            created_at      BIGINT NOT NULL,
            last_synced_at  BIGINT NOT NULL,
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
            created_at     BIGINT NOT NULL,
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
            priority           BIGINT NOT NULL DEFAULT 0,
            display_separately BOOLEAN NOT NULL DEFAULT FALSE,
            created_at         BIGINT NOT NULL,
            talk_power         BIGINT NOT NULL DEFAULT 0
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
            assigned_at     BIGINT NOT NULL,
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
    for (role, perm) in [
        ("builtin-everyone", "send_messages"),
        ("builtin-everyone", "read_messages"),
        ("builtin-everyone", "create_posts"),
        ("builtin-everyone", "start_game"),
        ("builtin-everyone", "create_events"),
        ("builtin-owner", "admin"),
        ("builtin-owner", "manage_posts"),
        ("builtin-owner", "manage_games"),
        ("builtin-owner", "manage_voice"),
        ("builtin-owner", "use_video"),
        ("builtin-owner", "manage_messages"),
    ] {
        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2) ON CONFLICT (role_id, permission) DO NOTHING",
        )
        .bind(role)
        .bind(perm)
        .execute(pool)
        .await?;
    }

    // ---- Moderation ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bans (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            banned_by         TEXT NOT NULL,
            reason            TEXT,
            created_at        BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS mutes (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            muted_by          TEXT NOT NULL,
            reason            TEXT,
            expires_at        BIGINT,
            created_at        BIGINT NOT NULL
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
            created_at        BIGINT NOT NULL,
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
            created_at        BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_voice_mutes (
            channel_id TEXT   NOT NULL,
            pubkey     TEXT   NOT NULL,
            muted_by   TEXT   NOT NULL,
            muted_at   BIGINT NOT NULL,
            PRIMARY KEY (channel_id, pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS raise_hand_requests (
            id           TEXT   PRIMARY KEY,
            channel_id   TEXT   NOT NULL,
            pubkey       TEXT   NOT NULL,
            requested_at BIGINT NOT NULL,
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
            reported_at     BIGINT NOT NULL,
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
            added_at             BIGINT NOT NULL,
            synced_at            BIGINT NOT NULL,
            PRIMARY KEY(source_hub_pubkey, target_master_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_federated_bans_target
         ON federated_bans(target_master_pubkey)",
    )
    .execute(pool)
    .await?;

    // ---- Invites ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS invites (
            code       TEXT PRIMARY KEY,
            created_by TEXT NOT NULL,
            max_uses   BIGINT,
            uses       BIGINT NOT NULL DEFAULT 0,
            expires_at BIGINT,
            created_at BIGINT NOT NULL
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

    for (key, val) in [
        ("invite_only", "false"),
        ("min_security_level", "0"),
        ("require_approval", "false"),
        ("max_channel_depth", "0"),
        ("lobby_enabled", "1"),
        ("lobby_welcome_md", ""),
        ("challenge_mode", "off"),
        ("challenge_difficulty", "easy"),
        ("min_pow_level", "0"),
        ("cert_auto_issue", "true"),
        ("cert_standing_days", "30"),
        ("cert_validity_days", "90"),
        ("cert_min_pow_level", "0"),
        ("cert_mode", "none"),
        ("cert_trusted_issuers", "[]"),
        ("cert_require", "{}"),
        ("hub_tags", "[]"),
        ("hub_nsfw", "false"),
        ("moderation_webhook_url", ""),
        ("moderation_webhook_secret", ""),
        ("banlist_sources", "[]"),
        ("bootstrapped_at", ""),
    ] {
        sqlx::query(
            "INSERT INTO hub_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
        )
        .bind(key)
        .bind(val)
        .execute(pool)
        .await?;
    }

    // ---- Channel settings ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_settings (
            channel_id     TEXT PRIMARY KEY REFERENCES channels(id),
            min_talk_power BIGINT NOT NULL DEFAULT 0
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
            created_at BIGINT NOT NULL
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
            joined_at      BIGINT NOT NULL,
            PRIMARY KEY (alliance_id, hub_public_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliance_shared_channels (
            alliance_id TEXT NOT NULL REFERENCES alliances(id),
            channel_id  TEXT NOT NULL REFERENCES channels(id),
            shared_at   BIGINT NOT NULL,
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
            created_at           BIGINT NOT NULL,
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
            created_at BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS conversation_members (
            conversation_id TEXT NOT NULL REFERENCES conversations(id),
            public_key      TEXT NOT NULL REFERENCES users(public_key),
            joined_at       BIGINT NOT NULL,
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
            created_at   BIGINT NOT NULL,
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
            created_at          BIGINT NOT NULL,
            attachments         TEXT,
            is_encrypted        BOOLEAN NOT NULL DEFAULT FALSE,
            ciphertext_json     TEXT,
            is_group_encrypted  BOOLEAN NOT NULL DEFAULT FALSE
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_dm_messages_conversation_created
         ON dm_messages(conversation_id, created_at)",
    )
    .execute(pool)
    .await?;

    // DM delivery queue
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dm_outbox (
            message_id        TEXT NOT NULL REFERENCES dm_messages(id),
            recipient_hub_url TEXT NOT NULL,
            attempts          BIGINT NOT NULL DEFAULT 0,
            next_attempt_at   BIGINT NOT NULL,
            last_error        TEXT,
            bounced_at        BIGINT,
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
            issued_at     BIGINT NOT NULL,
            sequence      BIGINT NOT NULL,
            signature     TEXT NOT NULL,
            updated_at    BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subkey_certs (
            master_pubkey      TEXT NOT NULL,
            subkey_pubkey      TEXT NOT NULL,
            device_label       TEXT NOT NULL,
            issued_at          BIGINT NOT NULL,
            not_after          BIGINT,
            fallback_hubs_json TEXT NOT NULL,
            signature          TEXT NOT NULL,
            registered_at      BIGINT NOT NULL,
            PRIMARY KEY (master_pubkey, subkey_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subkey_revocations (
            master_pubkey TEXT NOT NULL,
            subkey_pubkey TEXT NOT NULL,
            revoked_at    BIGINT NOT NULL,
            signature     TEXT NOT NULL,
            registered_at BIGINT NOT NULL,
            PRIMARY KEY (master_pubkey, subkey_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // home_hub_url column — used by the subkey revocation sync worker to discover
    // the issuing hub for each subkey cert.
    let _ =
        sqlx::query("ALTER TABLE subkey_certs ADD COLUMN home_hub_url TEXT NOT NULL DEFAULT ''")
            .execute(pool)
            .await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS subkey_revocation_sync (
            master_pubkey  TEXT NOT NULL,
            home_hub_url   TEXT NOT NULL,
            last_synced_at BIGINT NOT NULL DEFAULT 0,
            PRIMARY KEY (master_pubkey, home_hub_url)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS prefs_blobs (
            master_pubkey  TEXT PRIMARY KEY,
            blob_version   BIGINT NOT NULL,
            ciphertext_hex TEXT NOT NULL,
            signature      TEXT NOT NULL,
            updated_at     BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS pairing_offers (
            pairing_token   TEXT PRIMARY KEY,
            master_pubkey   TEXT NOT NULL,
            home_hubs_json  TEXT NOT NULL,
            issued_at       BIGINT NOT NULL,
            expires_at      BIGINT NOT NULL,
            offer_signature TEXT NOT NULL,
            state           TEXT NOT NULL DEFAULT 'pending',
            subkey_pubkey   TEXT,
            device_label    TEXT,
            claim_proof     TEXT,
            cert_json       TEXT,
            wrapped_key_hex TEXT,
            created_at      BIGINT NOT NULL,
            updated_at      BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS public_hub_profiles (
            pubkey       TEXT PRIMARY KEY,
            profile_json TEXT NOT NULL,
            updated_at   BIGINT NOT NULL
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
            published_at  BIGINT NOT NULL
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
            sender_key_version BIGINT NOT NULL,
            iteration          BIGINT NOT NULL,
            wrapped_key_hex    TEXT NOT NULL,
            wrap_nonce_hex     TEXT NOT NULL,
            created_at         BIGINT NOT NULL,
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
            created_at  BIGINT NOT NULL
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
            created_at BIGINT NOT NULL
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
            created_at BIGINT NOT NULL
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
            updated_at   BIGINT NOT NULL
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
            privileged       BOOLEAN NOT NULL DEFAULT FALSE,
            cooldown_seconds BIGINT NOT NULL DEFAULT 3,
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
            public_key      TEXT PRIMARY KEY,
            display_name    TEXT NOT NULL,
            created_by      TEXT NOT NULL,
            token_hash      TEXT NOT NULL,
            webhook_url     TEXT,
            mini_app_url    TEXT,
            requires_camera BOOLEAN NOT NULL DEFAULT FALSE,
            created_at      BIGINT NOT NULL
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
            created_at  BIGINT NOT NULL,
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
            created_at BIGINT NOT NULL,
            delivered  BOOLEAN NOT NULL DEFAULT FALSE
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
            created_at      BIGINT NOT NULL,
            expires_at      BIGINT NOT NULL,
            consumed_at     BIGINT
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
            issued_at   BIGINT NOT NULL,
            expires_at  BIGINT NOT NULL,
            consumed_at BIGINT
        )",
    )
    .execute(pool)
    .await?;

    // ---- Message components (interactive bot UI) ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS message_components (
            id            TEXT PRIMARY KEY,
            message_id    TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
            row_idx       BIGINT NOT NULL,
            component_idx BIGINT NOT NULL,
            type          TEXT NOT NULL,
            config_json   TEXT NOT NULL,
            expires_at    BIGINT
        )",
    )
    .execute(pool)
    .await?;

    // ---- Audit log ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_audit_seq (
            id  BIGINT PRIMARY KEY,
            seq BIGINT NOT NULL DEFAULT 0
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
            seq           BIGINT NOT NULL,
            event_type    TEXT NOT NULL,
            at            BIGINT NOT NULL,
            actor_pubkey  TEXT,
            target_pubkey TEXT,
            channel_id    TEXT,
            payload_json  TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_seq ON hub_audit_log(seq)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON hub_audit_log(event_type)")
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
            rate_limit        BIGINT NOT NULL DEFAULT 5,
            active            BOOLEAN NOT NULL DEFAULT TRUE,
            created_at        BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // ---- Outgoing webhooks (hub -> external URL push) ----
    // Not to be confused with the incoming `webhooks` table above (external
    // service posting a message into a channel).

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS outgoing_webhooks (
            id                  TEXT    PRIMARY KEY,
            url                 TEXT    NOT NULL,
            display_name        TEXT,
            signing_key         TEXT    NOT NULL,
            created_by_pubkey   TEXT    NOT NULL,
            active              BOOLEAN NOT NULL DEFAULT TRUE,
            failure_count       BIGINT  NOT NULL DEFAULT 0,
            last_delivery_at    BIGINT,
            last_failure_at     BIGINT,
            created_at          BIGINT  NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // channel_id NULL (represented as '' sentinel, matching bot_subscriptions
    // convention) = hub-scope subscription.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS outgoing_webhook_subscriptions (
            webhook_id  TEXT NOT NULL REFERENCES outgoing_webhooks(id) ON DELETE CASCADE,
            event_type  TEXT NOT NULL,
            channel_id  TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (webhook_id, event_type, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS outgoing_webhook_deliveries (
            id              TEXT    PRIMARY KEY,
            webhook_id      TEXT    NOT NULL REFERENCES outgoing_webhooks(id) ON DELETE CASCADE,
            event_type      TEXT    NOT NULL,
            event_seq       BIGINT,
            attempted_at    BIGINT  NOT NULL,
            attempt_number  BIGINT  NOT NULL DEFAULT 1,
            status_code     BIGINT,
            success         BOOLEAN NOT NULL DEFAULT FALSE,
            error_msg       TEXT
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_owd_webhook ON outgoing_webhook_deliveries(webhook_id, attempted_at DESC)",
    )
    .execute(pool)
    .await?;

    // ---- Surveys / onboarding ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS surveys (
            id         TEXT PRIMARY KEY,
            enabled    BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at BIGINT NOT NULL
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
            required      BOOLEAN NOT NULL DEFAULT TRUE,
            display_order BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS survey_choices (
            id            TEXT PRIMARY KEY,
            question_id   TEXT NOT NULL REFERENCES survey_questions(id) ON DELETE CASCADE,
            label         TEXT NOT NULL,
            display_order BIGINT NOT NULL
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
            submitted_at BIGINT NOT NULL,
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
            pow_level      BIGINT,
            member_since   BIGINT NOT NULL,
            issued_at      BIGINT NOT NULL,
            expires_at     BIGINT NOT NULL,
            revoked_at     BIGINT,
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
            expires_at    BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_user_certs_master ON user_certs(master_pubkey)")
        .execute(pool)
        .await?;

    // ---- Badge federation ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS badge_offers (
            id              TEXT   PRIMARY KEY,
            from_hub_pubkey TEXT   NOT NULL,
            from_hub_url    TEXT   NOT NULL,
            label           TEXT   NOT NULL,
            note            TEXT,
            payload         TEXT   NOT NULL,
            signature       TEXT   NOT NULL,
            created_at      BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_badges (
            id            TEXT   PRIMARY KEY,
            issuer_pubkey TEXT   NOT NULL,
            issuer_url    TEXT   NOT NULL,
            label         TEXT   NOT NULL,
            payload       TEXT   NOT NULL,
            signature     TEXT   NOT NULL,
            accepted_at   BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS issued_badges (
            id                   TEXT   PRIMARY KEY,
            recipient_hub_url    TEXT   NOT NULL,
            recipient_hub_pubkey TEXT   NOT NULL,
            label                TEXT   NOT NULL,
            payload              TEXT   NOT NULL,
            signature            TEXT   NOT NULL,
            issued_at            BIGINT NOT NULL,
            expires_at           BIGINT,
            revoked_at           BIGINT
        )",
    )
    .execute(pool)
    .await?;

    // ---- Recovery contacts ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS recovery_settings (
            owner_pubkey TEXT PRIMARY KEY,
            threshold    BIGINT NOT NULL DEFAULT 1,
            created_at   BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS recovery_contacts (
            owner_pubkey   TEXT NOT NULL,
            contact_pubkey TEXT NOT NULL,
            created_at     BIGINT NOT NULL,
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
            created_at BIGINT NOT NULL,
            decided_at BIGINT,
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
            attested_at     BIGINT NOT NULL,
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
            created_at       BIGINT NOT NULL,
            edited_at        BIGINT,
            is_pinned        BOOLEAN NOT NULL DEFAULT FALSE,
            is_locked        BOOLEAN NOT NULL DEFAULT FALSE,
            reply_count      BIGINT NOT NULL DEFAULT 0,
            last_activity_at BIGINT NOT NULL,
            deleted_at       BIGINT,
            search_vector    tsvector GENERATED ALWAYS AS (
                to_tsvector('simple', title || ' ' || body)
            ) STORED
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

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_posts_author ON posts (author_pubkey)")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS post_replies (
            id            TEXT PRIMARY KEY,
            post_id       TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            author_pubkey TEXT NOT NULL,
            body          TEXT NOT NULL,
            created_at    BIGINT NOT NULL,
            edited_at     BIGINT,
            reply_to_id   TEXT REFERENCES post_replies(id) ON DELETE SET NULL,
            deleted_at    BIGINT
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

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_posts_search_vector ON posts USING GIN(search_vector)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS post_reads (
            user_pubkey  TEXT NOT NULL,
            post_id      TEXT NOT NULL,
            read_at      BIGINT NOT NULL,
            PRIMARY KEY (user_pubkey, post_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_post_reads_post ON post_reads(post_id)")
        .execute(pool)
        .await?;

    // ---- Events / calendar ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_events (
            id             TEXT PRIMARY KEY,
            channel_id     TEXT NOT NULL REFERENCES channels(id),
            creator_pubkey TEXT NOT NULL REFERENCES users(public_key),
            title          TEXT NOT NULL,
            description    TEXT NOT NULL DEFAULT '',
            starts_at      BIGINT NOT NULL,
            ends_at        BIGINT,
            location       TEXT,
            created_at     BIGINT NOT NULL
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
            ends_at        BIGINT,
            max_choices    BIGINT NOT NULL DEFAULT 1,
            created_at     BIGINT NOT NULL
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
            last_read_at BIGINT NOT NULL,
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
            size_bytes      BIGINT NOT NULL,
            uploader_pubkey TEXT NOT NULL,
            channel_id      TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            created_at      BIGINT NOT NULL
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
            pinned_at  BIGINT NOT NULL,
            PRIMARY KEY (channel_id, message_id)
        )",
    )
    .execute(pool)
    .await?;

    // ---- Cert revocation relay ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cert_revocation_sync (
            issuer_pubkey  TEXT PRIMARY KEY,
            issuer_url     TEXT NOT NULL,
            last_synced_at BIGINT NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // ---- WebAuthn passkey credentials ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS webauthn_credentials (
            credential_id  TEXT PRIMARY KEY,
            user_pubkey    TEXT NOT NULL,
            passkey_json   TEXT NOT NULL,
            friendly_name  TEXT,
            aaguid         TEXT,
            created_at     BIGINT NOT NULL,
            last_used_at   BIGINT
        )",
    )
    .execute(pool)
    .await?;

    // ---- Device tokens (Trust this device) ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS device_tokens (
            id            TEXT PRIMARY KEY,
            token_hash    TEXT NOT NULL UNIQUE,
            user_pubkey   TEXT NOT NULL,
            device_name   TEXT,
            created_at    BIGINT NOT NULL,
            expires_at    BIGINT NOT NULL,
            last_used_at  BIGINT,
            revoked       BOOLEAN NOT NULL DEFAULT FALSE
        )",
    )
    .execute(pool)
    .await?;

    // ---- Forum post / reply reactions ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS post_reactions (
            post_id    TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            emoji      TEXT NOT NULL,
            user_key   TEXT NOT NULL REFERENCES users(public_key),
            created_at BIGINT NOT NULL,
            PRIMARY KEY (post_id, emoji, user_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_post_reactions_post ON post_reactions(post_id)")
        .execute(pool)
        .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS reply_reactions (
            reply_id   TEXT NOT NULL REFERENCES post_replies(id) ON DELETE CASCADE,
            emoji      TEXT NOT NULL,
            user_key   TEXT NOT NULL REFERENCES users(public_key),
            created_at BIGINT NOT NULL,
            PRIMARY KEY (reply_id, emoji, user_key)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_reply_reactions_reply ON reply_reactions(reply_id)",
    )
    .execute(pool)
    .await?;

    // Attachments columns on posts and post_replies (additive).
    let _ = sqlx::query("ALTER TABLE posts ADD COLUMN attachments TEXT NOT NULL DEFAULT '[]'")
        .execute(pool)
        .await;

    let _ =
        sqlx::query("ALTER TABLE post_replies ADD COLUMN attachments TEXT NOT NULL DEFAULT '[]'")
            .execute(pool)
            .await;

    // ---- ME1: Federated ban list admin tables ----

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS federated_ban_sources (
            url           TEXT PRIMARY KEY,
            policy        TEXT NOT NULL DEFAULT 'hard-reject',
            added_at      BIGINT NOT NULL,
            issuer_pubkey TEXT
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS federated_ban_overrides (
            target_pubkey TEXT PRIMARY KEY,
            override_type TEXT NOT NULL,
            reason        TEXT,
            created_at    BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Toggle: does this hub publish its own /federation/banlist?
    sqlx::query(
        "INSERT INTO hub_settings(key,value) VALUES('publish_banlist','false') ON CONFLICT(key) DO NOTHING",
    )
    .execute(pool)
    .await?;

    // ---- Cleanup phantom zero-sender rows (H1) ----
    let _ = sqlx::query(
        "DELETE FROM users
         WHERE public_key = '00000000000000000000000000000000000000000000000000000000000000000000'
           AND NOT EXISTS (
               SELECT 1 FROM messages
               WHERE sender = '00000000000000000000000000000000000000000000000000000000000000000000'
           )",
    )
    .execute(pool)
    .await;

    // ---- Channel permission overwrites (Nested Channels §3) ----
    // One row per (channel, role, permission). Absence of a row = inherit.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_permission_overwrites (
            channel_id   TEXT    NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            role_id      TEXT    NOT NULL REFERENCES roles(id)     ON DELETE CASCADE,
            permission   TEXT    NOT NULL,
            -- TRUE = allow, FALSE = deny. \"inherit\" is represented by NO ROW.
            allow        BOOLEAN NOT NULL,
            created_at   BIGINT  NOT NULL,
            PRIMARY KEY (channel_id, role_id, permission)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_cpo_channel
         ON channel_permission_overwrites(channel_id)",
    )
    .execute(pool)
    .await?;

    tracing::info!("Database migrations complete");

    Ok(())
}
