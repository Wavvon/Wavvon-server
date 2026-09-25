// Schema baseline reset 2026-08-20 (pre-1.0), following the same reset of
// 2026-07-05.
//
// Every ALTER TABLE ... ADD COLUMN accumulated since the July baseline has
// been folded into its owning CREATE TABLE, and the two forum-tag tables
// have moved up into the forum section they belong to. Columns were
// **appended in the order the ALTERs ran**, so the physical column order is
// unchanged and the resulting schema is byte-identical to the pre-fold one —
// verified by diffing `pg_dump --schema-only` before and after, not by
// reading. No table, column, type, default or REFERENCES clause changed
use crate::permissions::{
    ALL_PERMISSIONS, EVENTS_CREATE, FORUM_POSTS_CREATE, MESSAGES_READ, MESSAGES_SEND, VOICE_JOIN,
};
// meaning.
//
// Exactly one ALTER survives, and it has to: `invites.grant_role_id`
// REFERENCES `roles`, which this file creates *after* `invites`.
//
// This is safe to do only because nothing in production runs this schema
// yet. Folding an ADD COLUMN deletes the statement that would upgrade an
// existing database, and `CREATE TABLE IF NOT EXISTS` then skips the table
// silently — a database created before a folded column would simply lack it,
// with no error until a query touches it. Once there are hub databases in
// the field, a fold needs a schema-version marker and a refuse-to-start
// check first (same shape as `db/version.rs`).
//
// Going forward from this baseline, and **for as long as this is beta**,
// destructive changes are allowed: DROP, ALTER ... TYPE, renames, reshaping a
// table. No database in the field has a promised upgrade path yet, so the
// better schema wins over the additive one.
//
// **The additive-only rule starts at 1.0.0**, and from there it is absolute:
// new columns via `ALTER TABLE ... ADD COLUMN` wrapped in `let _ = ...` so
// "already exists" is ignored, new tables via `CREATE TABLE IF NOT EXISTS`,
// and nothing destructive ever. The paragraph above is why: a fold deletes the
// statement that would upgrade an existing database, and
// `CREATE TABLE IF NOT EXISTS` then skips it silently, so a database created
// before the fold simply lacks the column with no error until a query touches
// it. Before 1.0 that costs a `DROP DATABASE`; after it, it costs somebody
// their hub.

use anyhow::Result;
use sqlx::PgPool;

pub async fn run(pool: &PgPool) -> Result<()> {
    // =======================================================================
    // Identity & sessions
    // =======================================================================

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            public_key        TEXT PRIMARY KEY,
            display_name      TEXT,
            first_seen_at     BIGINT NOT NULL,
            last_seen_at      BIGINT NOT NULL DEFAULT 0,
            approval_status   TEXT NOT NULL DEFAULT 'approved',
            avatar             TEXT,
            master_pubkey     TEXT,
            is_webhook        BOOLEAN NOT NULL DEFAULT FALSE,
            lobby_status      TEXT NOT NULL DEFAULT 'none',
            lobby_entered_at  BIGINT,
            pow_level         BIGINT NOT NULL DEFAULT 0,
            presence_status    TEXT, -- away/dnd, NULL = plain online; survives reconnects
            presence_custom    TEXT,
            bio                TEXT, -- profile fields below: PATCH /me, empty string clears
            pronouns           TEXT,
            interests          TEXT, -- dormant: superseded by status_message + activities
            status_message     TEXT,
            activities         TEXT,
            accent_color       TEXT, -- #rrggbb, drives the profile banner with cover
            cover              TEXT,
            favorite_hubs      TEXT, -- JSON [{url,name,icon}]; show_hubs gates visibility
            show_hubs          BOOLEAN, -- NULL = false
            birthday           TEXT, -- MM-DD, never a year; validated in routes/me.rs
            name_color         TEXT -- per-user override; hub name_color_mode picks the winner
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
            scope              TEXT NOT NULL DEFAULT 'member', -- 'member' | 'lobby' | 'mini_app'
            mini_app_channel_id TEXT, -- set only for scope='mini_app': bound channel + host
            mini_app_host    TEXT
        )",
    )
    .execute(pool)
    .await?;

    // WebAuthn passkey credentials.
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

    // Device tokens ("Trust this device").
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

    // =======================================================================
    // Hub configuration
    // =======================================================================

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    for (key, val) in [
        // Invite-first default (task #31): fresh hubs start invite_only so an
        // operator has to deliberately open the door. Templates that intend a
        // public/discovery-listed community opt OUT by setting
        // `"invite_only": "false"` explicitly in their `settings` block (see
        // bootstrap::apply_template) — this row only seeds the value when it
        // isn't already present (ON CONFLICT DO NOTHING below), so existing
        // hubs are never flipped retroactively.
        ("invite_only", "true"),
        // Code of the one-time, owner-granting invite minted on first boot
        // when the hub has no users yet (see routes::invites::
        // maybe_mint_first_boot_owner_invite). Empty until minted.
        ("first_boot_owner_invite_code", ""),
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
        ("cert_issuer_urls", "{}"),
        ("cert_require", "{}"),
        ("hub_tags", "[]"),
        ("hub_nsfw", "false"),
        ("moderation_webhook_url", ""),
        ("moderation_webhook_secret", ""),
        ("banlist_sources", "[]"),
        ("bootstrapped_at", ""),
        // Does this hub publish its own /federation/banlist?
        ("publish_banlist", "false"),
    ] {
        sqlx::query(
            "INSERT INTO hub_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO NOTHING",
        )
        .bind(key)
        .bind(val)
        .execute(pool)
        .await?;
    }

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

    // =======================================================================
    // Channels & messages
    // =======================================================================

    // is_temporary/owner_pubkey/spawner_name_template/empty_since support
    // join-to-create temporary voice channels (docs/docs/temp-voice-channels.md):
    // is_temporary + owner_pubkey mark a normal channel as a personal room
    // spawned by joining a channel_type='spawner' channel. spawner_name_template
    // lives on the spawner itself. empty_since is GC bookkeeping: stamped when a
    // temp room's voice roster drains to zero, cleared on rejoin, and swept by
    // temp_channel_worker once past the grace period.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channels (
            id                    TEXT PRIMARY KEY,
            name                  TEXT NOT NULL UNIQUE,
            created_by            TEXT NOT NULL REFERENCES users(public_key),
            parent_id             TEXT REFERENCES channels(id),
            is_category           BOOLEAN NOT NULL DEFAULT FALSE,
            display_order         BIGINT NOT NULL DEFAULT 0,
            description           TEXT,
            created_at            BIGINT NOT NULL,
            icon                  TEXT,
            color                 TEXT,
            custom_icon_svg       TEXT,
            min_talk_power        BIGINT NOT NULL DEFAULT 0,
            channel_type          TEXT NOT NULL DEFAULT 'text',
            retention_days        BIGINT,
            banner_url            TEXT,
            banner_file_id        TEXT,
            is_temporary          BOOLEAN NOT NULL DEFAULT FALSE,
            owner_pubkey          TEXT,
            spawner_name_template TEXT,
            empty_since           BIGINT,
            event_id           TEXT, -- squad room's originating event; nullable, no FK on purpose
            forum_require_tag  BOOLEAN NOT NULL DEFAULT FALSE, -- forum leaves only (forum.md 10.1)
            nsfw               BOOLEAN NOT NULL DEFAULT FALSE -- per-channel, distinct from the hub-wide flag
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS channel_settings (
            channel_id     TEXT PRIMARY KEY REFERENCES channels(id),
            min_talk_power BIGINT NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

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
            reply_count       BIGINT NOT NULL DEFAULT 0,
            game               TEXT -- launch card {entry_url,name,...}; needs apps.register
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

    // Interactive UI components attached to a message.
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

    // Unread tracking.
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

    // File uploads.
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

    // =======================================================================
    // Roles & permissions
    // =======================================================================

    // role_categories must exist before roles.category_id references it.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS role_categories (
            id         TEXT   PRIMARY KEY,
            name       TEXT   NOT NULL,
            color      TEXT,
            icon       TEXT,
            position   BIGINT NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // color/icon/category_id are role appearance + grouping — see
    // docs/docs/role-categories.md §2.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS roles (
            id                 TEXT PRIMARY KEY,
            name               TEXT NOT NULL UNIQUE,
            priority           BIGINT NOT NULL DEFAULT 0,
            display_separately BOOLEAN NOT NULL DEFAULT FALSE,
            created_at         BIGINT NOT NULL,
            talk_power         BIGINT NOT NULL DEFAULT 0,
            color              TEXT,
            icon               TEXT,
            category_id        TEXT REFERENCES role_categories(id) ON DELETE SET NULL
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
        "INSERT INTO roles (id, name, priority, created_at) VALUES ('builtin-everyone', 'everyone', 0, 0)
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

    // Seed built-in permissions, in the rebuilt catalogue's ids.
    //
    // `builtin-owner` loses its `admin` row and gains nothing in its place
    // (permissions.md §6): its power comes from `is_owner`, which is
    // membership of the role itself. The rows it used to carry beside `admin`
    // were redundant with the wildcard and are gone with it.
    //
    // `builtin-everyone` keeps the baseline every member needs, including
    // `voice.join` — that one row is the whole "nothing changes until someone
    // denies it" property of an independent voice gate.
    for (role, perm) in [
        ("builtin-everyone", MESSAGES_SEND),
        ("builtin-everyone", MESSAGES_READ),
        ("builtin-everyone", FORUM_POSTS_CREATE),
        ("builtin-everyone", EVENTS_CREATE),
        ("builtin-everyone", VOICE_JOIN),
    ] {
        sqlx::query(
            "INSERT INTO role_permissions (role_id, permission) VALUES ($1, $2) ON CONFLICT (role_id, permission) DO NOTHING",
        )
        .bind(role)
        .bind(perm)
        .execute(pool)
        .await?;
    }

    // Role-based channel permission overwrites (Nested Channels §3). One row
    // per (channel, role, permission). Absence of a row = inherit. Depends on
    // both channels and roles, so it lives here rather than in the
    // channels/messages section above.
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

    // Backfill: wherever a channel denies `read_messages`, deny `voice.join`
    // the same way.
    //
    // Before voice admission was its own question, hiding a channel *was*
    // closing it to voice — one deny did both. Splitting them without this
    // would quietly reopen every already-hidden channel on the first boot
    // after the upgrade: the deny row survives, `voice.join` is newly seeded
    // as allowed hub-wide, and the channel comes back listed and joinable.
    // permissions.md §6 argues the split is safe because the rebuild drops and
    // reseeds this table, but the rebuild is a later change than this one, so
    // that argument does not cover the gap between them.
    //
    // ON CONFLICT DO NOTHING makes re-running harmless in the case that
    // matters (an operator who has since set `voice.join` to allow keeps
    // their allow). It does not cover an operator who sets it back to
    // *inherit* on a channel that still denies read — the row is gone, so a
    // later migrate re-adds the deny. Narrow, and it needs a schema-version
    // marker to fix properly (the `db/version.rs` shape this file's header
    // already names); not worth one before 1.0.
    sqlx::query(
        "INSERT INTO channel_permission_overwrites (channel_id, role_id, permission, allow, created_at)
         SELECT channel_id, role_id, 'voice.join', FALSE, created_at
         FROM channel_permission_overwrites
         WHERE permission = 'messages.read' AND allow = FALSE
         ON CONFLICT DO NOTHING",
    )
    .execute(pool)
    .await?;

    // ── the catalogue rebuild ───────────────────────────────────────────
    //
    // The catalogue is rebuilt rather than mapped (permissions.md §6): there is
    // no old-to-new table and no dual-reading period, so every row written in
    // the previous spelling has to go. Anything left behind would be a
    // permission that renders in the roles UI, matches no check, and cannot be
    // removed by anyone who does not already know it is there.
    //
    // Alpha, and no promised upgrade path yet, which is what makes a delete
    // acceptable here rather than a migration: an operator's role *structure*
    // survives, its permission rows do not, and the hub says so on first boot.
    // The built-ins above are re-seeded on the same pass, so a hub is never
    // left with nobody able to read a channel.
    //
    // Idempotent by construction: after the first run there is nothing left
    // that is not in the catalogue, so it matches no rows.
    let ids: Vec<String> = ALL_PERMISSIONS.iter().map(|s| (*s).to_string()).collect();
    let dropped_roles = sqlx::query("DELETE FROM role_permissions WHERE permission <> ALL($1)")
        .bind(&ids)
        .execute(pool)
        .await?
        .rows_affected();
    let dropped_overwrites =
        sqlx::query("DELETE FROM channel_permission_overwrites WHERE permission <> ALL($1)")
            .bind(&ids)
            .execute(pool)
            .await?
            .rows_affected();
    if dropped_roles > 0 || dropped_overwrites > 0 {
        tracing::warn!(
            "permission catalogue rebuilt: dropped {dropped_roles} role and \
             {dropped_overwrites} channel-overwrite rows written in the old \
             spelling. Roles and channels are untouched; re-grant what your \
             custom roles carried from the new catalogue."
        );
    }

    // =======================================================================
    // Moderation
    // =======================================================================

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS bans (
            target_public_key TEXT PRIMARY KEY REFERENCES users(public_key),
            banned_by         TEXT NOT NULL,
            reason            TEXT,
            -- NULL is a permanent ban, the same shape `mutes` already uses to
            -- tell a timeout from a permanent mute. Every read of this table
            -- has to carry the filter; a reader that forgets it enforces a ban
            -- that expired, which is worse than one that never applied.
            expires_at        BIGINT,
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

    // Federated ban list admin tables (ME1).
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

    // =======================================================================
    // Federation & alliances
    // =======================================================================

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

    // include_descendants: sharing a container channel (category) can include
    // its whole subtree with live semantics — descendants added later still
    // show up, because membership is computed at read time via a recursive
    // query rather than snapshotted into rows.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliance_shared_channels (
            alliance_id         TEXT NOT NULL REFERENCES alliances(id),
            channel_id          TEXT NOT NULL REFERENCES channels(id),
            shared_at           BIGINT NOT NULL,
            include_descendants BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (alliance_id, channel_id),
            forum_remote_write TEXT NOT NULL DEFAULT 'replies_only' -- 'none' | 'replies_only' | 'posts_and_replies' (forum.md 9)
        )",
    )
    .execute(pool)
    .await?;

    // Who, besides `alliances.manage`, may act on one alliance: inviting
    // another hub into it, sharing and unsharing a channel, the per-share
    // policies (decisions.md, "Alliance permissions: one hub permission plus a
    // per-alliance grant list"). A plain list rather than an allow/deny/inherit
    // axis: alliances are a handful and flat, so there is nothing for a cascade
    // to cascade through and "deny" has no baseline to subtract from. Local
    // roles only — nothing here crosses a hub boundary.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliance_managers (
            alliance_id TEXT   NOT NULL REFERENCES alliances(id) ON DELETE CASCADE,
            role_id     TEXT   NOT NULL REFERENCES roles(id)     ON DELETE CASCADE,
            granted_by  TEXT   NOT NULL,
            granted_at  BIGINT NOT NULL,
            PRIMARY KEY (alliance_id, role_id)
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

    // =======================================================================
    // Client apps
    // =======================================================================

    // Baseline reset, not an additive migration: the bot subsystem is gone
    // (decisions.md, "A bot is a client like any other"), and with it every
    // table that existed to tell one kind of client from another. What
    // survives is keyed on `users` and reachable by any identity holding
    // `apps.register`: a profile, its slash commands, its event
    // subscriptions, and the queue behind the polling transport.
    //
    // `bot_capability_grants` and `bot_channel_scope` do not survive.
    // Authority is the permission catalogue now — a second grant system
    // keyed on a pubkey was the bot distinction wearing a different name.
    //
    // Authorised explicitly for beta, which is the general rule here rather
    // than an exception carved out for this one statement (see the file
    // header). If you are reading it after 1.0, it should be gone, and
    // nothing new like it may be added. CASCADE because an already-migrated
    // database has foreign keys pointing at these from each other.
    for table in [
        "bot_event_queue",
        "bot_subscriptions",
        "bot_channel_scope",
        "bot_capability_grants",
        "bot_challenges",
        "bot_commands",
        "bot_profiles",
        "bot_slash_commands",
        "bots",
        "bot_tokens",
    ] {
        sqlx::query(&format!("DROP TABLE IF EXISTS {table} CASCADE"))
            .execute(pool)
            .await?;
    }

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS app_profiles (
            pubkey       TEXT PRIMARY KEY REFERENCES users(public_key) ON DELETE CASCADE,
            name         TEXT NOT NULL,
            avatar_url   TEXT,
            description  TEXT,
            webhook_url  TEXT,
            homepage_url TEXT,
            updated_at   BIGINT NOT NULL,
            mini_app_url       TEXT, -- self-declared via AppMeta or PUT /me/app/profile
            requires_camera    BOOLEAN NOT NULL DEFAULT FALSE,
            game               TEXT -- same GameLaunchCard shape as messages.game
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS app_commands (
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
        "CREATE TABLE IF NOT EXISTS app_subscriptions (
            app_pubkey TEXT NOT NULL,
            event_type TEXT NOT NULL,
            channel_id TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (app_pubkey, event_type, channel_id)
        )",
    )
    .execute(pool)
    .await?;

    // Event queue behind the HTTP polling transport (`GET /me/events`), for
    // a client that holds no persistent WebSocket.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS app_event_queue (
            id         TEXT PRIMARY KEY,
            app_pubkey TEXT NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            payload    TEXT NOT NULL,
            created_at BIGINT NOT NULL,
            delivered  BOOLEAN NOT NULL DEFAULT FALSE
        )",
    )
    .execute(pool)
    .await?;

    // Admission challenges (anti-spam, `challenge_mode`). It was called
    // `bot_challenges` and never had anything to do with bots: it is the
    // puzzle a stranger answers on the way in.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS admission_challenges (
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
        "CREATE INDEX IF NOT EXISTS idx_admission_challenges_pubkey
         ON admission_challenges(pubkey, expires_at)",
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

    // =======================================================================
    // Webhooks
    // =======================================================================

    // Incoming webhooks (external service posting a message into a channel).
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

    // Outgoing webhooks (hub -> external URL push). Not to be confused with
    // the incoming `webhooks` table above.
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

    // channel_id NULL (represented as '' sentinel, matching app_subscriptions
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

    // =======================================================================
    // DMs & E2E encryption
    // =======================================================================

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

    // =======================================================================
    // Multi-device, recovery & certifications (identity infrastructure)
    // =======================================================================

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

    // home_hub_url is used by the subkey revocation sync worker to discover
    // the issuing hub for each subkey cert.
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
            home_hub_url       TEXT NOT NULL DEFAULT '',
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
            updated_at      BIGINT NOT NULL,
            wrapped_dh_seed_hex TEXT -- ECIES-wrapped canonical DH scalar (Mechanism A)
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
            decided_by TEXT,
            nonce              TEXT -- binds a contact attestation to one request
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

    // Cert revocation relay sync bookkeeping (per issuer).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS cert_revocation_sync (
            issuer_pubkey  TEXT PRIMARY KEY,
            issuer_url     TEXT NOT NULL,
            last_synced_at BIGINT NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // Badge federation.
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

    // =======================================================================
    // Misc content features
    // =======================================================================

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
            attachments      TEXT NOT NULL DEFAULT '[]',
            search_vector    tsvector GENERATED ALWAYS AS (
                to_tsvector('simple', title || ' ' || body)
            ) STORED,
            author_hub         TEXT -- origin hub pubkey for proxied writes; hub-asserted only
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
        "CREATE INDEX IF NOT EXISTS idx_posts_search_vector ON posts USING GIN(search_vector)",
    )
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
            deleted_at    BIGINT,
            attachments   TEXT NOT NULL DEFAULT '[]',
            author_hub         TEXT -- origin hub pubkey for proxied writes; hub-asserted only
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

    // Post tags (forum.md §10): admin-curated, channel-scoped labels for
    // filtering the forum post list. A definitions table plus a join table,
    // not a JSON column on `posts` -- tag CRUD must work independently of any
    // one post, and the join gives an indexed EXISTS filter plus FK cascade
    // (delete a tag -> assignments vanish, no app-side sweep) for free.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS forum_tags (
            id         TEXT PRIMARY KEY,
            channel_id TEXT NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
            label      TEXT NOT NULL,
            color      TEXT,
            position   BIGINT NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_forum_tags_channel ON forum_tags(channel_id, position)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS post_tags (
            post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
            tag_id  TEXT NOT NULL REFERENCES forum_tags(id) ON DELETE CASCADE,
            PRIMARY KEY (post_id, tag_id)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_post_tags_tag ON post_tags(tag_id)")
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

    // ---- Events / calendar ----

    // reminder_minutes: NULL = no reminder configured. reminder_sent_at: NULL
    // = not yet sent (set once by the reminder worker). See docs/docs/events.md §3.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS hub_events (
            id               TEXT PRIMARY KEY,
            channel_id       TEXT NOT NULL REFERENCES channels(id),
            creator_pubkey   TEXT NOT NULL REFERENCES users(public_key),
            title            TEXT NOT NULL,
            description      TEXT NOT NULL DEFAULT '',
            starts_at        BIGINT NOT NULL,
            ends_at          BIGINT,
            location         TEXT,
            created_at       BIGINT NOT NULL,
            reminder_minutes BIGINT,
            reminder_sent_at BIGINT,
            hub_wide           BOOLEAN NOT NULL DEFAULT FALSE, -- community-wide: bypasses the anchor's read gate
            propagate_to_children BOOLEAN NOT NULL DEFAULT FALSE -- fans cards out to descendants; one event row
        )",
    )
    .execute(pool)
    .await?;

    // Event role-slot sign-ups (events.md §2). Created before event_rsvps
    // since event_rsvps.slot_id references it.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS event_slots (
            id         TEXT   PRIMARY KEY,
            event_id   TEXT   NOT NULL REFERENCES hub_events(id) ON DELETE CASCADE,
            name       TEXT   NOT NULL,
            capacity   BIGINT,
            position   BIGINT NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_event_slots_event ON event_slots(event_id)")
        .execute(pool)
        .await?;

    // slot_id: optional role-slot claim on this RSVP (events.md §2).
    // `ON DELETE SET NULL` demotes claimants to a plain "going" RSVP instead
    // of losing their row when the slot itself is deleted.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS event_rsvps (
            event_id    TEXT NOT NULL REFERENCES hub_events(id) ON DELETE CASCADE,
            user_pubkey TEXT NOT NULL REFERENCES users(public_key),
            status      TEXT NOT NULL CHECK(status IN ('going','maybe','not_going')),
            slot_id     TEXT REFERENCES event_slots(id) ON DELETE SET NULL,
            PRIMARY KEY (event_id, user_pubkey)
        )",
    )
    .execute(pool)
    .await?;

    // Queued voice-move assignments (events.md §7.3): a `voice_move` issued
    // to a member not currently in voice is persisted here and auto-applied
    // when they next join any voice channel while the event is active. The
    // (event_id, user_pubkey) PK makes re-issuing an UPSERT -- latest
    // assignment wins. Rows are pruned at event end by the reminder worker's
    // sweep (reminder_worker.rs); an event with no `ends_at` keeps its
    // assignments until the event row itself is deleted (ON DELETE CASCADE).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS event_move_assignments (
            event_id           TEXT   NOT NULL REFERENCES hub_events(id) ON DELETE CASCADE,
            user_pubkey        TEXT   NOT NULL,
            target_channel_id  TEXT   NOT NULL REFERENCES channels(id)   ON DELETE CASCADE,
            assigned_by        TEXT   NOT NULL,
            created_at         BIGINT NOT NULL,
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

    // ---- Soundboard (soundboard.md §1) ----
    // Audio bytes live on disk under WAVVON_UPLOADS_DIR (same storage as
    // uploads.rs); this table is metadata only.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS soundboard_clips (
            id          TEXT   PRIMARY KEY,
            name        TEXT   NOT NULL,
            emoji       TEXT,
            uploader    TEXT   NOT NULL REFERENCES users(public_key),
            size_bytes  BIGINT NOT NULL,
            duration_ms BIGINT NOT NULL,
            created_at  BIGINT NOT NULL
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

    // =======================================================================
    // Additive migrations after the 2026-08-20 baseline
    // =======================================================================
    // The additive-only rule (see the file header): ALTER TABLE ADD COLUMN,
    // wrapped in `let _ =` so "already exists" errors are ignored.

    // Role-granting invites (task #34). NULL = a plain invite. When set, the
    // role is assigned to the joining user in addition to builtin-everyone --
    // see routes::invites::create_invite for the priority/admin guards and
    // auth::handlers::verify for the grant.
    //
    // This one cannot be folded into `CREATE TABLE invites`: it REFERENCES
    // `roles`, which this file creates *after* `invites`. Folding it would
    // make the create fail on a fresh database. Left as an ALTER on purpose.
    let _ = sqlx::query("ALTER TABLE bans ADD COLUMN expires_at BIGINT")
        .execute(pool)
        .await;

    let _ = sqlx::query("ALTER TABLE invites ADD COLUMN grant_role_id TEXT REFERENCES roles(id)")
        .execute(pool)
        .await;

    // Queued voice-move assignments fire when the event starts (events.md
    // §7.3), and this column is what makes that happen once: NULL = the
    // start-time sweep hasn't run for this event, set by the reminder worker
    // in the same pass that pushes the moves. Without it a worker that ticks
    // every 60s would re-push the same move for the whole event.
    let _ = sqlx::query("ALTER TABLE hub_events ADD COLUMN moves_applied_at BIGINT")
        .execute(pool)
        .await;

    // Mirror-forward between a recipient's home hubs (home-hub.md "DM
    // delivery", step 2). A queued copy has to be *remembered* as a copy: the
    // retry worker rebuilds the envelope from dm_messages, and rebuilding it
    // as an original would have the receiving hub fan out to its own peers.
    let _ = sqlx::query("ALTER TABLE dm_outbox ADD COLUMN mirror BOOLEAN NOT NULL DEFAULT FALSE")
        .execute(pool)
        .await;

    // Voice in alliance channels (alliances.md). Who is currently admitted to
    // one of this hub's shared voice rooms as a *visitor* — a member of an
    // allied hub, holding an `alliance_voice`-scoped session and no `users`
    // row at all. Deliberately not a user: no roles, no approval queue, no
    // presence in `/users`, nothing that could be mistaken for membership.
    //
    // `channel_id` is what makes a grant a ticket to one room rather than to
    // the hub: `voice_join` checks against it, so a visitor admitted for one
    // shared channel cannot walk into another.
    // The visit *is* the session, and that is not a shortcut — `sessions` has
    // `public_key REFERENCES users(public_key)`, so a row there for someone with
    // no `users` row is impossible, and the additive-only rule rightly forbids
    // dropping the constraint. Keeping visitor tokens here instead leaves
    // `sessions` meaning exactly what it has always meant (a member's session)
    // and makes "a visitor is not a member" structural rather than something a
    // loosened join has to remember.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alliance_voice_visitors (
            subject_pubkey    TEXT PRIMARY KEY,
            token             TEXT NOT NULL UNIQUE,
            origin_hub_pubkey TEXT NOT NULL,
            origin_hub_url    TEXT NOT NULL,
            display_name      TEXT,
            channel_id        TEXT NOT NULL,
            admitted_at       BIGINT NOT NULL,
            expires_at        BIGINT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Per-share moderation policy, mirroring `forum_remote_write`: whether
    // members of allied hubs may join voice in this shared channel at all.
    // 'allowed' | 'none'. The owning hub stays sovereign over its own rooms
    // without having to leave the alliance or unshare the channel.
    let _ = sqlx::query(
        "ALTER TABLE alliance_shared_channels
         ADD COLUMN voice_remote_join TEXT NOT NULL DEFAULT 'allowed'",
    )
    .execute(pool)
    .await;

    // =======================================================================
    // One-time data cleanup
    // =======================================================================

    // Cleanup phantom zero-sender rows (H1). Runs last since it touches both
    // `users` and `messages`, which are defined far above; kept as a
    // best-effort statement (errors ignored) since it's not schema DDL.
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

    // Two capability backfills used to follow, seeding the grant tables that
    // gated what a bot could do. Both tables are gone: a client's authority
    // is its roles, resolved through the permission catalogue like everyone
    // else's, so there is no per-pubkey grant left to seed.

    tracing::info!("Database migrations complete");

    Ok(())
}
