use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::routes::me::{parse_favorite_hubs, FavoriteHub};
use crate::state::AppState;

/// Row shape for the profile fields SELECT in `get_user_profile`:
/// display_name, avatar, first_seen_at, bio, pronouns, status_message,
/// activities, accent_color, cover, favorite_hubs, show_hubs, birthday,
/// name_color.
#[allow(clippy::type_complexity)]
type UserProfileRow = (
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<String>,
    Option<String>,
);

/// Allowed values for the hub-wide `name_color_mode` setting (member name
/// colors feature). Default when unset is `role_over_user`.
pub const NAME_COLOR_MODES: &[&str] = &[
    "user_over_role",
    "role_over_user",
    "role_only",
    "user_only",
    "none",
];

/// Reads the hub-wide `name_color_mode` setting, falling back to
/// `role_over_user` when unset or set to an unrecognized value. Callers
/// resolving a roster/list of users should call this once per request, not
/// once per row.
pub async fn name_color_mode(db: &sqlx::PgPool) -> String {
    crate::routes::hub::read_setting(db, "name_color_mode")
        .await
        .filter(|v| NAME_COLOR_MODES.contains(&v.as_str()))
        .unwrap_or_else(|| "role_over_user".to_string())
}

/// Resolves the color shown for a member's name from the hub-wide mode, the
/// color of their highest-priority role that has one, and their own
/// `name_color` profile field. `role_color`/`user_color` should both already
/// be `None` when absent (no further filtering needed here).
pub fn resolve_name_color(
    mode: &str,
    role_color: Option<&str>,
    user_color: Option<&str>,
) -> Option<String> {
    match mode {
        "none" => None,
        "role_only" => role_color.map(str::to_string),
        "user_only" => user_color.map(str::to_string),
        "user_over_role" => user_color.or(role_color).map(str::to_string),
        // "role_over_user" and any unrecognized value (name_color_mode
        // already validates against NAME_COLOR_MODES at the write path).
        _ => role_color.or(user_color).map(str::to_string),
    }
}

/// Default page size for `GET /users` when the caller passes no `limit`.
/// Large enough that a typical hub's whole roster arrives in one request
/// (the member sidebar wants everyone), small enough to bound the response.
const USERS_DEFAULT_LIMIT: i64 = 200;
const USERS_MAX_LIMIT: i64 = 500;

#[derive(Deserialize)]
pub struct UserSearchParams {
    pub q: Option<String>,
    /// Page size, clamped to `1..=USERS_MAX_LIMIT`.
    pub limit: Option<i64>,
    /// Keyset cursor: the `public_key` of the last row of the previous page.
    /// Rows are ordered by `(display_name, public_key)`, so the cursor row's
    /// display_name is looked up to resume from exactly where it left off.
    pub cursor: Option<String>,
}

/// Whether a user's presence should be *reported* to other members as
/// online, given whether they have a live connection and their stored
/// `presence_status`. A user with `presence_status == "invisible"` always
/// reports as offline here, regardless of `is_connected` — they remain
/// fully connected for delivery purposes (DMs, messages, voice); only what
/// other members are told about their presence changes.
pub(crate) fn reported_online(is_connected: bool, presence_status: Option<&str>) -> bool {
    is_connected && presence_status != Some("invisible")
}

/// Fetch a user's stored `presence_status` column. Used by the WS presence
/// paths (connect/disconnect/set_status) to decide whether the invisible
/// gate applies, independent of the roster read path above.
pub(crate) async fn fetch_presence_status(db: &sqlx::PgPool, public_key: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT presence_status FROM users WHERE public_key = $1",
    )
    .bind(public_key)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .flatten()
}

/// Convenience single-user form of the invisible check used by the voice
/// participant surfaces (see `invisible_subset`).
pub(crate) async fn is_invisible(db: &sqlx::PgPool, public_key: &str) -> bool {
    fetch_presence_status(db, public_key).await.as_deref() == Some("invisible")
}

/// Subset of `keys` whose stored `presence_status` is "invisible". The voice
/// participant surfaces (lists, rosters, populations) use this to hide
/// invisible users from *other* members the same way `reported_online` hides
/// them from the member roster — decisions.md 2026-07-12 specifies invisible
/// as "shown offline to everyone else", and the voice participant list was
/// the flagged known gap. Delivery/voice/relay paths are never filtered:
/// only what other members are shown changes.
pub(crate) async fn invisible_subset(
    db: &sqlx::PgPool,
    keys: &[String],
) -> std::collections::HashSet<String> {
    if keys.is_empty() {
        return std::collections::HashSet::new();
    }
    sqlx::query_scalar::<_, String>(
        "SELECT public_key FROM users WHERE public_key = ANY($1) AND presence_status = 'invisible'",
    )
    .bind(keys)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .collect()
}

#[derive(Serialize)]
pub struct UserInfo {
    pub public_key: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    pub online: bool,
    /// Presence status for online users: None = plain online, "away", "dnd".
    /// Always None while offline (the stored value is not surfaced).
    /// Also always None for a connected user whose stored status is
    /// "invisible" — see `reported_online`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Optional short custom status text; only surfaced while online.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_custom: Option<String>,
    /// Name of the highest-priority role with display_separately=true assigned
    /// to this user. Used by the client to group members in the sidebar.
    #[serde(default)]
    pub group_role: Option<String>,
    /// "MM-DD", never a year. `null` when unset or when `birthdays_enabled`
    /// is false hub-wide.
    #[serde(default)]
    pub birthday: Option<String>,
    /// Server-resolved nickname color ("#rrggbb"), or `null`. Resolved from
    /// the hub-wide `name_color_mode` setting, this user's highest-priority
    /// role color, and their own `name_color` profile field — see
    /// `resolve_name_color`.
    #[serde(default)]
    pub name_color: Option<String>,
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(params): Query<UserSearchParams>,
) -> Result<Json<Vec<UserInfo>>, (StatusCode, String)> {
    let online = state.online_users.read().await;

    // Cap search queries to prevent unbounded LIKE pattern scans. Truncating
    // by *character* rather than by byte: `&s[..64]` panics outright when
    // byte 64 lands mid-codepoint, so any search of 22+ three-byte characters
    // (`€`, most CJK, …) took the handler down. The hub ships in four locales.
    let q = params
        .q
        .as_deref()
        .map(|s| s.chars().take(64).collect::<String>());

    let limit = params
        .limit
        .unwrap_or(USERS_DEFAULT_LIMIT)
        .clamp(1, USERS_MAX_LIMIT);

    // One query with the search and cursor predicates switched on by binds
    // rather than by building two near-identical SQL strings. `$1` NULL means
    // "no search"; `$2` NULL means "first page". The cursor is a keyset on
    // (display_name, public_key) — the same order the rows come back in — so
    // paging stays correct as members are added or renamed mid-scroll.
    //
    // The two correlated subqueries pick up the highest-priority
    // display_separately role and role color in one round-trip instead of N+1.
    let search = q.map(|q| format!("%{q}%"));

    let rows: Vec<UserRowWithRole> = sqlx::query_as::<_, UserRowWithRole>(
        "SELECT u.public_key, u.display_name, u.avatar,
                u.presence_status, u.presence_custom, u.birthday, u.name_color,
                (SELECT r.name FROM roles r
                 INNER JOIN user_roles ur ON r.id = ur.role_id
                 WHERE ur.user_public_key = u.public_key AND r.display_separately = TRUE
                 ORDER BY r.priority DESC LIMIT 1) AS group_role,
                (SELECT r.color FROM roles r
                 INNER JOIN user_roles ur ON r.id = ur.role_id
                 WHERE ur.user_public_key = u.public_key AND r.color IS NOT NULL
                 ORDER BY r.priority DESC LIMIT 1) AS role_color
         FROM users u
         WHERE ($1::text IS NULL OR u.display_name LIKE $1 OR u.public_key LIKE $1)
           AND ($2::text IS NULL OR
                (COALESCE(u.display_name, ''), u.public_key) >
                ((SELECT COALESCE(display_name, '') FROM users WHERE public_key = $2), $2))
           AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.target_public_key = u.public_key)
           AND EXISTS
                (SELECT 1 FROM user_roles ur2 WHERE ur2.user_public_key = u.public_key)
         ORDER BY COALESCE(u.display_name, ''), u.public_key
         LIMIT $3",
    )
    .bind(search.as_deref())
    .bind(params.cursor.as_deref())
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Checked once per request, not per row.
    let show_birthdays = crate::routes::hub::birthdays_enabled(&state.db).await;
    let color_mode = name_color_mode(&state.db).await;

    let result: Vec<UserInfo> = rows
        .into_iter()
        .map(|r| {
            let is_connected = online.contains_key(&r.public_key);
            let is_online = reported_online(is_connected, r.presence_status.as_deref());
            let name_color = resolve_name_color(
                &color_mode,
                r.role_color.as_deref(),
                r.name_color.as_deref(),
            );
            UserInfo {
                online: is_online,
                status: r.presence_status.filter(|_| is_online),
                status_custom: r.presence_custom.filter(|_| is_online),
                public_key: r.public_key,
                display_name: r.display_name,
                avatar: r.avatar,
                group_role: r.group_role,
                birthday: if show_birthdays { r.birthday } else { None },
                name_color,
            }
        })
        .collect();

    Ok(Json(result))
}

/// Row shape for `list_users`, including the pre-joined group_role column.
#[derive(sqlx::FromRow)]
struct UserRowWithRole {
    public_key: String,
    display_name: Option<String>,
    avatar: Option<String>,
    presence_status: Option<String>,
    presence_custom: Option<String>,
    birthday: Option<String>,
    name_color: Option<String>,
    group_role: Option<String>,
    role_color: Option<String>,
}

// ---------------------------------------------------------------------------
// User profile endpoint
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RoleSummary {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
    pub icon: Option<String>,
    pub category_id: Option<String>,
}

#[derive(Serialize)]
pub struct BadgeSummary {
    pub id: String,
    pub label: String,
}

#[derive(Serialize)]
pub struct UserProfileResponse {
    pub public_key: String,
    pub display_name: Option<String>,
    pub avatar: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub pronouns: Option<String>,
    #[serde(default)]
    pub status_message: Option<String>,
    #[serde(default)]
    pub activities: Option<String>,
    #[serde(default)]
    pub accent_color: Option<String>,
    #[serde(default)]
    pub cover: Option<String>,
    #[serde(default)]
    pub show_hubs: bool,
    #[serde(default)]
    pub favorite_hubs: Vec<FavoriteHub>,
    pub joined_at: i64,
    pub roles: Vec<RoleSummary>,
    pub badges: Vec<BadgeSummary>,
    /// "MM-DD", never a year. `null` when unset or when `birthdays_enabled`
    /// is false hub-wide (unless viewing your own profile).
    #[serde(default)]
    pub birthday: Option<String>,
    /// Server-resolved nickname color ("#rrggbb"), or `null`. See
    /// `resolve_name_color`.
    #[serde(default)]
    pub name_color: Option<String>,
}

/// GET /users/:pubkey/profile
pub async fn get_user_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<Json<UserProfileResponse>, (StatusCode, String)> {
    let row: Option<UserProfileRow> = sqlx::query_as(
        "SELECT display_name, avatar, first_seen_at, bio, pronouns, status_message, activities, accent_color, cover, favorite_hubs, show_hubs, birthday, name_color FROM users WHERE public_key = $1",
    )
    .bind(&pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (
        display_name,
        avatar,
        joined_at,
        bio,
        pronouns,
        status_message,
        activities,
        accent_color,
        cover,
        favorite_hubs_raw,
        show_hubs_raw,
        birthday_raw,
        name_color_raw,
    ) = row.ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    // Gate: hide birthday from other members when disabled hub-wide; the
    // profile owner viewing their own profile always sees their real value.
    let birthday =
        if user.public_key == pubkey || crate::routes::hub::birthdays_enabled(&state.db).await {
            birthday_raw
        } else {
            None
        };

    let show_hubs = show_hubs_raw.unwrap_or(false);
    // Privacy gate: a hidden favorite-hubs list is never exposed to other
    // members, but the profile owner viewing their own profile always sees
    // their real stored list regardless of show_hubs (the web editor reads
    // its own profile through this endpoint).
    let favorite_hubs = if show_hubs || user.public_key == pubkey {
        parse_favorite_hubs(&favorite_hubs_raw)
    } else {
        Vec::new()
    };

    // Fetch roles assigned to this user (reuse the RoleResponse pattern from me.rs).
    #[derive(sqlx::FromRow)]
    struct RoleRow {
        id: String,
        name: String,
        color: Option<String>,
        icon: Option<String>,
        category_id: Option<String>,
    }

    let roles: Vec<RoleRow> = sqlx::query_as(
        "SELECT r.id, r.name, r.color, r.icon, r.category_id
         FROM roles r
         INNER JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_public_key = $1
         ORDER BY r.priority DESC",
    )
    .bind(&pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Roles above are already ordered by priority DESC, so the first one
    // carrying a color is the highest-priority role color.
    let role_color = roles.iter().find_map(|r| r.color.clone());
    let color_mode = name_color_mode(&state.db).await;
    let name_color = resolve_name_color(
        &color_mode,
        role_color.as_deref(),
        name_color_raw.as_deref(),
    );

    let role_summaries: Vec<RoleSummary> = roles
        .into_iter()
        .map(|r| RoleSummary {
            id: r.id,
            name: r.name,
            color: r.color,
            icon: r.icon,
            category_id: r.category_id,
        })
        .collect();

    // Fetch badges held by this user (from hub_badges table, linked via subject_pubkey
    // stored inside the JSON payload).
    #[derive(sqlx::FromRow)]
    struct BadgeRow {
        id: String,
        label: String,
    }

    let badges: Vec<BadgeRow> = sqlx::query_as(
        "SELECT id, label FROM issued_badges WHERE recipient_hub_pubkey = $1 AND revoked_at IS NULL",
    )
    .bind(&pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let badge_summaries: Vec<BadgeSummary> = badges
        .into_iter()
        .map(|b| BadgeSummary {
            id: b.id,
            label: b.label,
        })
        .collect();

    Ok(Json(UserProfileResponse {
        public_key: pubkey,
        display_name,
        avatar,
        bio,
        pronouns,
        status_message,
        activities,
        accent_color,
        cover,
        show_hubs,
        favorite_hubs,
        joined_at,
        roles: role_summaries,
        badges: badge_summaries,
        birthday,
        name_color,
    }))
}

#[cfg(test)]
mod tests {
    use super::reported_online;

    #[test]
    fn connected_plain_online_reports_online() {
        assert!(reported_online(true, None));
    }

    #[test]
    fn connected_away_or_dnd_reports_online_with_status_intact() {
        assert!(reported_online(true, Some("away")));
        assert!(reported_online(true, Some("dnd")));
    }

    #[test]
    fn connected_invisible_reports_offline() {
        assert!(!reported_online(true, Some("invisible")));
    }

    #[test]
    fn disconnected_never_reports_online_regardless_of_status() {
        assert!(!reported_online(false, None));
        assert!(!reported_online(false, Some("away")));
        assert!(!reported_online(false, Some("invisible")));
    }
}
