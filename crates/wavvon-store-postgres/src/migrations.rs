use sqlx::PgPool;

/// Run the hub migrations against the given PostgreSQL pool.
/// Delegates to the hub crate's migration runner via re-export from main.
/// For standalone use (e.g. tests), delegates to
/// `hub::db::migrations::run` — but since this crate cannot depend on `hub`,
/// we duplicate the call here as a thin wrapper that expects the caller to
/// have already run `hub::db::migrations::run(pool)`.
///
/// In practice `PostgresStore::run_migrations()` is called from `main.rs`,
/// which calls `hub::db::migrations::run(&pool)` before constructing the
/// store. This impl re-runs that call so the trait contract is satisfied.
pub async fn run(pool: &PgPool) -> anyhow::Result<()> {
    // hub migrations are the authoritative DDL source; run them here.
    hub_migrations::run(pool).await
}

/// Thin re-export shim — actual DDL lives in crates/hub/src/db/migrations.rs.
/// We inline the PostgreSQL DDL here so this crate is self-contained for
/// testing without importing `hub`.
mod hub_migrations {
    use anyhow::Result;
    use sqlx::PgPool;

    pub async fn run(pool: &PgPool) -> Result<()> {
        // All tables use IF NOT EXISTS so this is idempotent.
        let stmts: &[&str] = &[
            // -----------------------------------------------------------
            // Core identity / auth
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS users (
                public_key        TEXT PRIMARY KEY,
                display_name      TEXT,
                first_seen_at     BIGINT NOT NULL DEFAULT 0,
                last_seen_at      BIGINT NOT NULL DEFAULT 0,
                approval_status   TEXT NOT NULL DEFAULT 'pending',
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
            )"#,
            r#"CREATE TABLE IF NOT EXISTS sessions (
                token       TEXT PRIMARY KEY,
                public_key  TEXT NOT NULL,
                created_at  BIGINT NOT NULL DEFAULT 0,
                expires_at  BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS subkey_certs (
                master_pubkey       TEXT NOT NULL,
                subkey_pubkey       TEXT NOT NULL,
                device_label        TEXT NOT NULL DEFAULT '',
                issued_at           BIGINT NOT NULL DEFAULT 0,
                not_after           BIGINT,
                fallback_hubs_json  TEXT NOT NULL DEFAULT '[]',
                signature           TEXT NOT NULL DEFAULT '',
                registered_at       BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (master_pubkey, subkey_pubkey)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS subkey_revocations (
                master_pubkey  TEXT NOT NULL,
                subkey_pubkey  TEXT NOT NULL,
                revoked_at     BIGINT NOT NULL DEFAULT 0,
                signature      TEXT NOT NULL DEFAULT '',
                registered_at  BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (master_pubkey, subkey_pubkey)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS federated_bans (
                source_hub_pubkey    TEXT NOT NULL,
                target_master_pubkey TEXT NOT NULL,
                reason               TEXT,
                added_at             BIGINT NOT NULL DEFAULT 0,
                synced_at            BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (source_hub_pubkey, target_master_pubkey)
            )"#,
            // -----------------------------------------------------------
            // Channels & messages
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS channels (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                created_by      TEXT NOT NULL,
                parent_id       TEXT,
                is_category     BOOLEAN NOT NULL DEFAULT FALSE,
                display_order   BIGINT NOT NULL DEFAULT 0,
                description     TEXT,
                icon            TEXT,
                color           TEXT,
                custom_icon_svg TEXT,
                created_at      BIGINT NOT NULL DEFAULT 0,
                channel_type    TEXT NOT NULL DEFAULT 'text',
                banner_url      TEXT,
                banner_file_id  TEXT,
                min_talk_power  BIGINT NOT NULL DEFAULT 0,
                retention_days  BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS messages (
                id                TEXT PRIMARY KEY,
                channel_id        TEXT NOT NULL,
                sender            TEXT NOT NULL,
                content           TEXT NOT NULL DEFAULT '',
                attachments       TEXT,
                reply_to          TEXT,
                created_at        BIGINT NOT NULL DEFAULT 0,
                edited_at         BIGINT,
                reply_count       BIGINT NOT NULL DEFAULT 0,
                visible_to_pubkey TEXT,
                embeds            TEXT
            )"#,
            r#"CREATE INDEX IF NOT EXISTS idx_messages_channel_created
               ON messages (channel_id, created_at DESC)"#,
            r#"CREATE TABLE IF NOT EXISTS message_reactions (
                message_id  TEXT NOT NULL,
                emoji       TEXT NOT NULL,
                user_key    TEXT NOT NULL,
                created_at  BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (message_id, emoji, user_key)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS channel_pins (
                channel_id  TEXT NOT NULL,
                message_id  TEXT NOT NULL,
                pinned_by   TEXT NOT NULL,
                pinned_at   BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (channel_id, message_id)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS channel_last_read (
                user_pubkey  TEXT NOT NULL,
                channel_id   TEXT NOT NULL,
                last_read_at BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (user_pubkey, channel_id)
            )"#,
            // -----------------------------------------------------------
            // Roles
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS roles (
                id                 TEXT PRIMARY KEY,
                name               TEXT NOT NULL,
                priority           BIGINT NOT NULL DEFAULT 0,
                display_separately BOOLEAN NOT NULL DEFAULT FALSE,
                created_at         BIGINT NOT NULL DEFAULT 0,
                talk_power         BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS role_permissions (
                role_id    TEXT NOT NULL,
                permission TEXT NOT NULL,
                PRIMARY KEY (role_id, permission)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS user_roles (
                user_public_key TEXT NOT NULL,
                role_id         TEXT NOT NULL,
                assigned_at     BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (user_public_key, role_id)
            )"#,
            // -----------------------------------------------------------
            // Invites
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS invites (
                code        TEXT PRIMARY KEY,
                created_by  TEXT NOT NULL,
                max_uses    BIGINT,
                uses        BIGINT NOT NULL DEFAULT 0,
                expires_at  BIGINT,
                created_at  BIGINT NOT NULL DEFAULT 0
            )"#,
            // -----------------------------------------------------------
            // Moderation
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS bans (
                target_public_key TEXT PRIMARY KEY,
                banned_by         TEXT NOT NULL,
                reason            TEXT,
                created_at        BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS mutes (
                target_public_key TEXT PRIMARY KEY,
                muted_by          TEXT NOT NULL,
                reason            TEXT,
                expires_at        BIGINT,
                created_at        BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS voice_mutes (
                target_public_key TEXT PRIMARY KEY,
                muted_by          TEXT NOT NULL,
                reason            TEXT,
                created_at        BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS channel_bans (
                channel_id        TEXT NOT NULL,
                target_public_key TEXT NOT NULL,
                banned_by         TEXT NOT NULL,
                reason            TEXT,
                created_at        BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (channel_id, target_public_key)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS message_reports (
                id               TEXT PRIMARY KEY,
                message_id       TEXT NOT NULL,
                reporter_pubkey  TEXT NOT NULL,
                reason           TEXT NOT NULL DEFAULT '',
                reported_at      BIGINT NOT NULL DEFAULT 0,
                status           TEXT NOT NULL DEFAULT 'pending'
            )"#,
            // -----------------------------------------------------------
            // Hub settings & audit
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS hub_settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"#,
            r#"CREATE TABLE IF NOT EXISTS hub_audit_log (
                seq             BIGSERIAL PRIMARY KEY,
                event_type      TEXT NOT NULL,
                at              BIGINT NOT NULL DEFAULT 0,
                actor_pubkey    TEXT,
                target_pubkey   TEXT,
                channel_id      TEXT,
                payload_json    TEXT NOT NULL DEFAULT '{}'
            )"#,
            // -----------------------------------------------------------
            // Bots
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS bots (
                public_key      TEXT PRIMARY KEY,
                display_name    TEXT NOT NULL,
                created_by      TEXT NOT NULL,
                token_hash      TEXT NOT NULL,
                webhook_url     TEXT,
                mini_app_url    TEXT,
                requires_camera BOOLEAN NOT NULL DEFAULT FALSE,
                created_at      BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS bot_slash_commands (
                bot_pubkey  TEXT NOT NULL,
                command     TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (bot_pubkey, command)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS bot_profiles (
                pubkey       TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                avatar_url   TEXT,
                description  TEXT,
                webhook_url  TEXT,
                homepage_url TEXT,
                capabilities TEXT NOT NULL DEFAULT '[]',
                updated_at   BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS bot_commands (
                pubkey           TEXT NOT NULL,
                name             TEXT NOT NULL,
                description      TEXT NOT NULL DEFAULT '',
                args             TEXT,
                scope            TEXT NOT NULL DEFAULT 'all',
                privileged       BIGINT NOT NULL DEFAULT 0,
                cooldown_seconds BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (pubkey, name)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS bot_subscriptions (
                bot_pubkey  TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                channel_id  TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (bot_pubkey, event_type, channel_id)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS bot_channel_scope (
                bot_pubkey TEXT NOT NULL,
                channel_id TEXT NOT NULL,
                PRIMARY KEY (bot_pubkey, channel_id)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS bot_event_queue (
                id         TEXT PRIMARY KEY,
                bot_pubkey TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload    TEXT NOT NULL DEFAULT '',
                created_at BIGINT NOT NULL DEFAULT 0,
                delivered  BOOLEAN NOT NULL DEFAULT FALSE
            )"#,
            // -----------------------------------------------------------
            // DMs / conversations
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS conversations (
                id        TEXT PRIMARY KEY,
                conv_type TEXT NOT NULL DEFAULT 'dm',
                created_at BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS conversation_members (
                conversation_id TEXT NOT NULL,
                public_key      TEXT NOT NULL,
                joined_at       BIGINT NOT NULL DEFAULT 0,
                hub_url         TEXT,
                PRIMARY KEY (conversation_id, public_key)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS dm_messages (
                id                 TEXT PRIMARY KEY,
                conversation_id    TEXT NOT NULL,
                sender             TEXT NOT NULL,
                content            TEXT,
                signature          TEXT,
                created_at         BIGINT NOT NULL DEFAULT 0,
                attachments        TEXT,
                is_encrypted       BOOLEAN NOT NULL DEFAULT FALSE,
                ciphertext_json    TEXT,
                is_group_encrypted BOOLEAN NOT NULL DEFAULT FALSE
            )"#,
            r#"CREATE INDEX IF NOT EXISTS idx_dm_messages_conv_created
               ON dm_messages (conversation_id, created_at DESC)"#,
            r#"CREATE TABLE IF NOT EXISTS dm_blocks (
                owner_pubkey   TEXT NOT NULL,
                blocked_pubkey TEXT NOT NULL,
                PRIMARY KEY (owner_pubkey, blocked_pubkey)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS friends (
                user_a       TEXT NOT NULL,
                user_b       TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'pending',
                created_at   BIGINT NOT NULL DEFAULT 0,
                hub_url      TEXT,
                display_name TEXT,
                PRIMARY KEY (user_a, user_b)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS dh_keys (
                pubkey          TEXT PRIMARY KEY,
                dh_pubkey_hex   TEXT NOT NULL,
                signature_hex   TEXT NOT NULL,
                published_at    BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS group_sender_key_distributions (
                id                  TEXT PRIMARY KEY,
                conv_id             TEXT NOT NULL,
                sender_pubkey       TEXT NOT NULL,
                recipient_pubkey    TEXT NOT NULL,
                sender_key_version  BIGINT NOT NULL DEFAULT 0,
                iteration           BIGINT NOT NULL DEFAULT 0,
                wrapped_key_hex     TEXT NOT NULL,
                wrap_nonce_hex      TEXT NOT NULL,
                created_at          BIGINT NOT NULL DEFAULT 0,
                UNIQUE (conv_id, sender_pubkey, recipient_pubkey, sender_key_version)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS dm_outbox (
                message_id         TEXT NOT NULL,
                recipient_hub_url  TEXT NOT NULL,
                attempts           BIGINT NOT NULL DEFAULT 0,
                last_error         TEXT,
                next_attempt_at    BIGINT NOT NULL DEFAULT 0,
                bounced_at         BIGINT,
                PRIMARY KEY (message_id, recipient_hub_url)
            )"#,
            // -----------------------------------------------------------
            // Federation
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS peers (
                public_key TEXT PRIMARY KEY,
                name       TEXT NOT NULL DEFAULT '',
                url        TEXT NOT NULL,
                added_at   BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS federated_channels (
                id               TEXT PRIMARY KEY,
                peer_public_key  TEXT NOT NULL,
                remote_id        TEXT NOT NULL,
                name             TEXT NOT NULL,
                created_at       BIGINT NOT NULL DEFAULT 0,
                last_synced_at   BIGINT NOT NULL DEFAULT 0,
                UNIQUE (peer_public_key, remote_id)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS alliances (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS alliance_members (
                alliance_id    TEXT NOT NULL,
                hub_public_key TEXT NOT NULL,
                hub_name       TEXT NOT NULL DEFAULT '',
                hub_url        TEXT NOT NULL DEFAULT '',
                joined_at      BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (alliance_id, hub_public_key)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS pending_alliance_invites (
                id                  TEXT PRIMARY KEY,
                alliance_id         TEXT NOT NULL,
                alliance_name       TEXT NOT NULL,
                from_hub_url        TEXT NOT NULL,
                from_hub_name       TEXT NOT NULL DEFAULT '',
                from_hub_public_key TEXT NOT NULL,
                invite_token        TEXT NOT NULL,
                created_at          BIGINT NOT NULL DEFAULT 0,
                message             TEXT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS home_hub_designations (
                master_pubkey TEXT PRIMARY KEY,
                hubs_json     TEXT NOT NULL DEFAULT '[]',
                issued_at     BIGINT NOT NULL DEFAULT 0,
                sequence      BIGINT NOT NULL DEFAULT 0,
                signature     TEXT NOT NULL DEFAULT '',
                updated_at    BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS public_hub_profiles (
                pubkey       TEXT PRIMARY KEY,
                profile_json TEXT NOT NULL DEFAULT '{}',
                updated_at   BIGINT NOT NULL DEFAULT 0
            )"#,
            // -----------------------------------------------------------
            // Polls
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS polls (
                id             TEXT PRIMARY KEY,
                channel_id     TEXT NOT NULL,
                creator_pubkey TEXT NOT NULL,
                question       TEXT NOT NULL,
                options        TEXT NOT NULL DEFAULT '[]',
                ends_at        BIGINT,
                max_choices    BIGINT NOT NULL DEFAULT 1,
                created_at     BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS poll_votes (
                poll_id      TEXT NOT NULL,
                user_pubkey  TEXT NOT NULL,
                option_ids   TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (poll_id, user_pubkey)
            )"#,
            // -----------------------------------------------------------
            // Events / calendar
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS hub_events (
                id             TEXT PRIMARY KEY,
                channel_id     TEXT NOT NULL,
                creator_pubkey TEXT NOT NULL,
                title          TEXT NOT NULL,
                description    TEXT NOT NULL DEFAULT '',
                starts_at      BIGINT NOT NULL DEFAULT 0,
                ends_at        BIGINT,
                location       TEXT,
                created_at     BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS event_rsvps (
                event_id    TEXT NOT NULL,
                user_pubkey TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'yes',
                PRIMARY KEY (event_id, user_pubkey)
            )"#,
            // -----------------------------------------------------------
            // Certifications
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS cert_issuances (
                id             TEXT PRIMARY KEY,
                subject_pubkey TEXT NOT NULL,
                pow_level      BIGINT,
                member_since   BIGINT NOT NULL DEFAULT 0,
                issued_at      BIGINT NOT NULL DEFAULT 0,
                expires_at     BIGINT NOT NULL DEFAULT 0,
                revoked_at     BIGINT,
                standing       TEXT NOT NULL DEFAULT 'active',
                payload_json   TEXT NOT NULL DEFAULT '{}',
                signature      TEXT NOT NULL DEFAULT ''
            )"#,
            r#"CREATE TABLE IF NOT EXISTS user_certs (
                id             TEXT PRIMARY KEY,
                master_pubkey  TEXT NOT NULL,
                issuer_pubkey  TEXT NOT NULL,
                issuer_url     TEXT NOT NULL,
                payload_json   TEXT NOT NULL DEFAULT '{}',
                signature      TEXT NOT NULL DEFAULT '',
                expires_at     BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS pairing_offers (
                pairing_token    TEXT PRIMARY KEY,
                master_pubkey    TEXT NOT NULL,
                home_hubs_json   TEXT NOT NULL DEFAULT '[]',
                issued_at        BIGINT NOT NULL DEFAULT 0,
                expires_at       BIGINT NOT NULL DEFAULT 0,
                offer_signature  TEXT NOT NULL DEFAULT '',
                state            TEXT NOT NULL DEFAULT 'pending',
                subkey_pubkey    TEXT,
                device_label     TEXT,
                claim_proof      TEXT,
                cert_json        TEXT,
                wrapped_key_hex  TEXT,
                created_at       BIGINT NOT NULL DEFAULT 0,
                updated_at       BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS prefs_blobs (
                master_pubkey   TEXT PRIMARY KEY,
                blob_version    BIGINT NOT NULL DEFAULT 0,
                ciphertext_hex  TEXT NOT NULL DEFAULT '',
                signature       TEXT NOT NULL DEFAULT '',
                updated_at      BIGINT NOT NULL DEFAULT 0
            )"#,
            // -----------------------------------------------------------
            // Badge federation
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS badge_offers (
                id               TEXT PRIMARY KEY,
                from_hub_pubkey  TEXT NOT NULL,
                from_hub_url     TEXT NOT NULL,
                label            TEXT NOT NULL,
                note             TEXT,
                payload          TEXT NOT NULL DEFAULT '',
                signature        TEXT NOT NULL DEFAULT '',
                created_at       TEXT NOT NULL DEFAULT ''
            )"#,
            r#"CREATE TABLE IF NOT EXISTS hub_badges (
                id             TEXT PRIMARY KEY,
                issuer_pubkey  TEXT NOT NULL,
                issuer_url     TEXT NOT NULL,
                label          TEXT NOT NULL,
                payload        TEXT NOT NULL DEFAULT '',
                signature      TEXT NOT NULL DEFAULT '',
                accepted_at    TEXT NOT NULL DEFAULT ''
            )"#,
            r#"CREATE TABLE IF NOT EXISTS issued_badges (
                id                    TEXT PRIMARY KEY,
                recipient_hub_url     TEXT NOT NULL,
                recipient_hub_pubkey  TEXT NOT NULL,
                label                 TEXT NOT NULL,
                payload               TEXT NOT NULL DEFAULT '',
                signature             TEXT NOT NULL DEFAULT '',
                issued_at             TEXT NOT NULL DEFAULT '',
                expires_at            TEXT,
                revoked_at            TEXT
            )"#,
            // -----------------------------------------------------------
            // Recovery
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS recovery_settings (
                owner_pubkey TEXT PRIMARY KEY,
                threshold    BIGINT NOT NULL DEFAULT 1,
                created_at   BIGINT NOT NULL DEFAULT 0
            )"#,
            r#"CREATE TABLE IF NOT EXISTS recovery_contacts (
                owner_pubkey   TEXT NOT NULL,
                contact_pubkey TEXT NOT NULL,
                created_at     BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (owner_pubkey, contact_pubkey)
            )"#,
            r#"CREATE TABLE IF NOT EXISTS key_rotation_requests (
                id          TEXT PRIMARY KEY,
                old_pubkey  TEXT NOT NULL,
                new_pubkey  TEXT NOT NULL,
                reason      TEXT,
                status      TEXT NOT NULL DEFAULT 'pending',
                created_at  BIGINT NOT NULL DEFAULT 0,
                decided_at  BIGINT,
                decided_by  TEXT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS rotation_attestations (
                id               TEXT PRIMARY KEY,
                request_id       TEXT NOT NULL,
                attester_pubkey  TEXT NOT NULL,
                signature        TEXT NOT NULL DEFAULT '',
                attested_at      BIGINT NOT NULL DEFAULT 0,
                UNIQUE (request_id, attester_pubkey)
            )"#,
            // -----------------------------------------------------------
            // Uploads
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS upload_files (
                id               TEXT PRIMARY KEY,
                filename         TEXT NOT NULL,
                original_name    TEXT NOT NULL,
                mime_type        TEXT NOT NULL,
                size_bytes       BIGINT NOT NULL DEFAULT 0,
                uploader_pubkey  TEXT NOT NULL,
                channel_id       TEXT NOT NULL,
                created_at       BIGINT NOT NULL DEFAULT 0
            )"#,
            // -----------------------------------------------------------
            // Posts (forum)
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS posts (
                id               TEXT PRIMARY KEY,
                channel_id       TEXT NOT NULL,
                author_pubkey    TEXT NOT NULL,
                title            TEXT NOT NULL DEFAULT '',
                body             TEXT NOT NULL DEFAULT '',
                created_at       BIGINT NOT NULL DEFAULT 0,
                edited_at        BIGINT,
                is_pinned        BOOLEAN NOT NULL DEFAULT FALSE,
                is_locked        BOOLEAN NOT NULL DEFAULT FALSE,
                reply_count      BIGINT NOT NULL DEFAULT 0,
                last_activity_at BIGINT NOT NULL DEFAULT 0,
                deleted_at       BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS post_replies (
                id           TEXT PRIMARY KEY,
                post_id      TEXT NOT NULL,
                author_pubkey TEXT NOT NULL,
                body         TEXT NOT NULL DEFAULT '',
                created_at   BIGINT NOT NULL DEFAULT 0,
                edited_at    BIGINT,
                reply_to_id  TEXT,
                deleted_at   BIGINT
            )"#,
            r#"CREATE TABLE IF NOT EXISTS post_reads (
                user_pubkey TEXT NOT NULL,
                post_id     TEXT NOT NULL,
                last_read_at BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (user_pubkey, post_id)
            )"#,
            // -----------------------------------------------------------
            // Webhooks
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS webhooks (
                id                 TEXT PRIMARY KEY,
                channel_id         TEXT NOT NULL,
                secret_token_hash  TEXT NOT NULL,
                display_name       TEXT NOT NULL DEFAULT '',
                avatar_url         TEXT,
                created_by_pubkey  TEXT NOT NULL,
                rate_limit         BIGINT NOT NULL DEFAULT 10,
                active             BOOLEAN NOT NULL DEFAULT TRUE,
                created_at         BIGINT NOT NULL DEFAULT 0
            )"#,
            // -----------------------------------------------------------
            // Surveys
            // -----------------------------------------------------------
            r#"CREATE TABLE IF NOT EXISTS surveys (
                id         TEXT PRIMARY KEY,
                enabled    BOOLEAN NOT NULL DEFAULT TRUE,
                updated_at BIGINT NOT NULL DEFAULT 0
            )"#,
        ];

        for stmt in stmts {
            sqlx::query(stmt).execute(pool).await?;
        }

        // Seed default hub settings (idempotent via ON CONFLICT DO NOTHING).
        let defaults: &[(&str, &str)] = &[
            ("hub_name", "My Wavvon Hub"),
            ("hub_description", ""),
            ("hub_public", "false"),
            ("require_invite", "true"),
            ("require_approval", "false"),
            ("allow_registration", "true"),
            ("max_message_length", "4000"),
            ("bots_allow_camera", "false"),
        ];
        for (k, v) in defaults {
            sqlx::query(
                "INSERT INTO hub_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
            )
            .bind(k)
            .bind(v)
            .execute(pool)
            .await?;
        }

        Ok(())
    }
}
