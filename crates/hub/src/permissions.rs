use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use sqlx::PgPool;

pub const SEND_MESSAGES: &str = "send_messages";
pub const READ_MESSAGES: &str = "read_messages";
pub const MANAGE_CHANNELS: &str = "manage_channels";
pub const MANAGE_MESSAGES: &str = "manage_messages";
pub const MANAGE_ROLES: &str = "manage_roles";
pub const KICK_MEMBERS: &str = "kick_members";
pub const BAN_MEMBERS: &str = "ban_members";
pub const MUTE_MEMBERS: &str = "mute_members";
pub const TIMEOUT_MEMBERS: &str = "timeout_members";
pub const MANAGE_GAMES: &str = "manage_games";
pub const MANAGE_HUB_ICONS: &str = "manage_hub_icons";
pub const MANAGE_CHANNEL_ICONS: &str = "manage_channel_icons";
pub const ADMIN: &str = "admin";
pub const CREATE_POSTS: &str = "create_posts";
pub const MANAGE_POSTS: &str = "manage_posts";
pub const START_GAME: &str = "start_game";
pub const CREATE_EVENTS: &str = "create_events";
pub const USE_SOUNDBOARD: &str = "use_soundboard";
pub const MANAGE_SOUNDBOARD: &str = "manage_soundboard";
/// Move a voice participant into another channel (events.md §7.1). Resolved
/// channel-scoped against the *destination* channel via `channel_permissions`.
pub const MOVE_MEMBERS: &str = "move_members";

/// Every permission string recognized by the server. Used to validate
/// admin-supplied permission strings for channel overwrites (see
/// `hub/src/routes/channel_permissions.rs`).
pub const ALL_PERMISSIONS: &[&str] = &[
    SEND_MESSAGES,
    READ_MESSAGES,
    MANAGE_CHANNELS,
    MANAGE_MESSAGES,
    MANAGE_ROLES,
    KICK_MEMBERS,
    BAN_MEMBERS,
    MUTE_MEMBERS,
    TIMEOUT_MEMBERS,
    MANAGE_GAMES,
    MANAGE_HUB_ICONS,
    MANAGE_CHANNEL_ICONS,
    ADMIN,
    CREATE_POSTS,
    MANAGE_POSTS,
    START_GAME,
    CREATE_EVENTS,
    USE_SOUNDBOARD,
    MANAGE_SOUNDBOARD,
    MOVE_MEMBERS,
];

#[derive(sqlx::FromRow)]
pub struct RoleRow {
    pub id: String,
    pub name: String,
    pub priority: i64,
    pub created_at: i64,
}

pub struct UserPermissions {
    pub roles: Vec<RoleRow>,
    pub effective: HashSet<String>,
    pub max_priority: i64,
}

impl UserPermissions {
    pub fn has(&self, permission: &str) -> bool {
        self.effective.contains(ADMIN) || self.effective.contains(permission)
    }

    pub fn require(&self, permission: &str) -> Result<(), (StatusCode, String)> {
        if self.has(permission) {
            Ok(())
        } else {
            Err((
                StatusCode::FORBIDDEN,
                format!("Missing permission: {permission}"),
            ))
        }
    }
}

pub async fn user_permissions(
    db: &PgPool,
    public_key: &str,
) -> Result<UserPermissions, (StatusCode, String)> {
    let roles = sqlx::query_as::<_, RoleRow>(
        "SELECT r.id, r.name, r.priority, r.created_at
         FROM roles r
         INNER JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_public_key = $1",
    )
    .bind(public_key)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let role_ids: Vec<&str> = roles.iter().map(|r| r.id.as_str()).collect();
    let effective = fetch_permissions(db, &role_ids).await?;
    let max_priority = roles.iter().map(|r| r.priority).max().unwrap_or(0);

    Ok(UserPermissions {
        roles,
        effective,
        max_priority,
    })
}

async fn fetch_permissions(
    db: &PgPool,
    role_ids: &[&str],
) -> Result<HashSet<String>, (StatusCode, String)> {
    if role_ids.is_empty() {
        return Ok(HashSet::new());
    }

    // Build a query with placeholders for each role_id
    let placeholders: Vec<String> = role_ids
        .iter()
        .enumerate()
        .map(|(i, _)| format!("${}", i + 1))
        .collect();
    let query = format!(
        "SELECT DISTINCT permission FROM role_permissions WHERE role_id IN ({})",
        placeholders.join(",")
    );

    let mut q = sqlx::query_scalar::<_, String>(&query);
    for id in role_ids {
        q = q.bind(id);
    }

    let permissions: Vec<String> = q
        .fetch_all(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(permissions.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Channel permission overwrites (Nested Channels §3)
// ---------------------------------------------------------------------------
//
// An overwrite targets a role on a channel and sets, per permission, one of
// allow / deny / inherit (absence of a row = inherit). Effective permission
// on a channel = hub-wide baseline, then fold in the ancestor chain
// root -> target, applying each level's rows for the roles the user holds.
// Within one level, allow wins over deny; deeper levels win over shallower
// ones; `admin` is never removed by a deny. See docs/docs/nested-channels-ux.md §3.

#[derive(sqlx::FromRow, Clone)]
pub struct OverwriteRow {
    pub channel_id: String,
    pub role_id: String,
    pub permission: String,
    /// TRUE = allow, FALSE = deny.
    pub allow: bool,
}

/// Walks `channels.parent_id` from `channel_id` up to the root and returns
/// the chain in root -> target order (target included last). If
/// `channel_id` doesn't exist, returns the single-element chain
/// `[channel_id]` — no overwrite rows will match a nonexistent channel, so
/// the fold is a no-op.
pub async fn ancestor_chain(
    db: &PgPool,
    channel_id: &str,
) -> Result<Vec<String>, (StatusCode, String)> {
    let mut chain = vec![channel_id.to_string()];
    let mut current = channel_id.to_string();
    // Safety cap mirrors the existing depth-walk convention in routes/channels.rs.
    for _ in 0..64 {
        let parent: Option<String> =
            sqlx::query_scalar("SELECT parent_id FROM channels WHERE id = $1")
                .bind(&current)
                .fetch_optional(db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
                .flatten();
        match parent {
            None => break,
            Some(p) => {
                chain.push(p.clone());
                current = p;
            }
        }
    }
    chain.reverse();
    Ok(chain)
}

/// Same as `ancestor_chain`, but walks an already-loaded `id -> parent_id`
/// map instead of issuing a query per hop. Used to batch-filter a channel
/// list without one ancestor-chain round trip per channel (§3.5).
pub fn ancestor_chain_from_map(
    parent_of: &HashMap<String, Option<String>>,
    channel_id: &str,
) -> Vec<String> {
    let mut chain = vec![channel_id.to_string()];
    let mut current = channel_id.to_string();
    for _ in 0..64 {
        match parent_of.get(&current).cloned().flatten() {
            None => break,
            Some(p) => {
                chain.push(p.clone());
                current = p;
            }
        }
    }
    chain.reverse();
    chain
}

/// Batch-loads overwrite rows for a set of channels restricted to a set of
/// roles, in one query.
pub async fn fetch_overwrites(
    db: &PgPool,
    channel_ids: &[String],
    role_ids: &[String],
) -> Result<Vec<OverwriteRow>, (StatusCode, String)> {
    if channel_ids.is_empty() || role_ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, OverwriteRow>(
        "SELECT channel_id, role_id, permission, allow
         FROM channel_permission_overwrites
         WHERE channel_id = ANY($1) AND role_id = ANY($2)",
    )
    .bind(channel_ids)
    .bind(role_ids)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}

/// Folds `rows` into `baseline` in `chain` order (root -> target), applying
/// the §3.2 rules:
/// - within one channel level, allow wins over deny for the same permission
///   (across whichever roles hold a row at that level);
/// - a deeper (later-in-`chain`) level's decision overrides a shallower one;
/// - `admin` is never removed by a deny.
pub fn fold_overwrites(
    baseline: &HashSet<String>,
    chain: &[String],
    rows: &[OverwriteRow],
) -> HashSet<String> {
    let mut effective = baseline.clone();
    for channel_id in chain {
        let mut allow: HashSet<&str> = HashSet::new();
        let mut deny: HashSet<&str> = HashSet::new();
        for row in rows.iter().filter(|r| &r.channel_id == channel_id) {
            if row.allow {
                allow.insert(row.permission.as_str());
            } else {
                deny.insert(row.permission.as_str());
            }
        }
        for perm in &deny {
            if allow.contains(perm) {
                continue; // allow wins within the same level
            }
            if *perm == ADMIN {
                continue; // admin is immune to channel deny
            }
            effective.remove(*perm);
        }
        for perm in &allow {
            effective.insert((*perm).to_string());
        }
    }
    effective
}

/// Channel-aware resolver: hub-wide baseline permissions, adjusted by the
/// channel's ancestor-chain overwrite cascade for the roles the caller
/// holds. `has` / `require` on the returned `UserPermissions` are unchanged
/// -- call sites switch by one argument, not by shape.
pub async fn channel_permissions(
    db: &PgPool,
    public_key: &str,
    channel_id: &str,
) -> Result<UserPermissions, (StatusCode, String)> {
    let baseline = user_permissions(db, public_key).await?;
    if baseline.roles.is_empty() {
        // Overwrites are role-scoped; a user with no roles can't match any.
        return Ok(baseline);
    }

    let chain = ancestor_chain(db, channel_id).await?;
    let role_ids: Vec<String> = baseline.roles.iter().map(|r| r.id.clone()).collect();
    let rows = fetch_overwrites(db, &chain, &role_ids).await?;
    let effective = fold_overwrites(&baseline.effective, &chain, &rows);

    Ok(UserPermissions {
        roles: baseline.roles,
        effective,
        max_priority: baseline.max_priority,
    })
}

/// Returns the set of channel ids (of every channel currently in the
/// `channels` table, categories included) for which `public_key`'s
/// effective permissions include `permission`, after folding in the
/// ancestor-chain cascade. Used to batch-filter a channel list or a
/// WS auto-subscribe set in two queries total (§3.5) rather than one
/// ancestor-chain round trip per channel.
pub async fn channels_with_permission(
    db: &PgPool,
    public_key: &str,
    permission: &str,
) -> Result<HashSet<String>, (StatusCode, String)> {
    let baseline = user_permissions(db, public_key).await?;

    let all: Vec<(String, Option<String>)> = sqlx::query_as("SELECT id, parent_id FROM channels")
        .fetch_all(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Admin immunity: an admin's baseline already grants every permission,
    // and no channel deny can strip `admin` from effective, so skip the
    // per-channel fold entirely.
    if baseline.has(ADMIN) {
        return Ok(all.into_iter().map(|(id, _)| id).collect());
    }

    if baseline.roles.is_empty() {
        return Ok(all
            .into_iter()
            .filter(|_| baseline.effective.contains(permission))
            .map(|(id, _)| id)
            .collect());
    }

    let parent_of: HashMap<String, Option<String>> = all.iter().cloned().collect();
    let all_ids: Vec<String> = all.into_iter().map(|(id, _)| id).collect();
    let role_ids: Vec<String> = baseline.roles.iter().map(|r| r.id.clone()).collect();
    let overwrite_rows = fetch_overwrites(db, &all_ids, &role_ids).await?;

    Ok(all_ids
        .into_iter()
        .filter(|id| {
            let chain = ancestor_chain_from_map(&parent_of, id);
            let effective = fold_overwrites(&baseline.effective, &chain, &overwrite_rows);
            effective.contains(ADMIN) || effective.contains(permission)
        })
        .collect())
}
