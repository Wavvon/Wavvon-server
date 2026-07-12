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
/// activities, accent_color, cover, favorite_hubs, show_hubs.
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
);

#[derive(Deserialize)]
pub struct UserSearchParams {
    pub q: Option<String>,
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
    #[serde(default)]
    pub is_bot: bool,
}

pub async fn list_users(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(params): Query<UserSearchParams>,
) -> Result<Json<Vec<UserInfo>>, (StatusCode, String)> {
    let online = state.online_users.read().await;

    // Cap search queries to prevent unbounded LIKE pattern scans.
    let q = params
        .q
        .as_deref()
        .map(|s| if s.len() > 64 { &s[..64] } else { s });

    // Single query with a LEFT JOIN to pick up the highest-priority
    // display_separately role in one round-trip instead of N+1 queries.
    let rows: Vec<UserRowWithRole> = if let Some(q) = q {
        let search = format!("%{q}%");
        sqlx::query_as::<_, UserRowWithRole>(
            "SELECT u.public_key, u.display_name, u.avatar, u.is_bot,
                    u.presence_status, u.presence_custom,
                    (SELECT r.name FROM roles r
                     INNER JOIN user_roles ur ON r.id = ur.role_id
                     WHERE ur.user_public_key = u.public_key AND r.display_separately = TRUE
                     ORDER BY r.priority DESC LIMIT 1) AS group_role
             FROM users u
             WHERE (u.display_name LIKE $1 OR u.public_key LIKE $2)
               AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.target_public_key = u.public_key)
               AND (u.is_bot = TRUE OR EXISTS
                    (SELECT 1 FROM user_roles ur2 WHERE ur2.user_public_key = u.public_key))
             ORDER BY u.display_name, u.public_key LIMIT 50",
        )
        .bind(&search)
        .bind(&search)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as::<_, UserRowWithRole>(
            "SELECT u.public_key, u.display_name, u.avatar, u.is_bot,
                    u.presence_status, u.presence_custom,
                    (SELECT r.name FROM roles r
                     INNER JOIN user_roles ur ON r.id = ur.role_id
                     WHERE ur.user_public_key = u.public_key AND r.display_separately = TRUE
                     ORDER BY r.priority DESC LIMIT 1) AS group_role
             FROM users u
             WHERE NOT EXISTS (SELECT 1 FROM bans b WHERE b.target_public_key = u.public_key)
               AND (u.is_bot = TRUE OR EXISTS
                    (SELECT 1 FROM user_roles ur2 WHERE ur2.user_public_key = u.public_key))
             ORDER BY u.display_name, u.public_key LIMIT 50",
        )
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let result: Vec<UserInfo> = rows
        .into_iter()
        .map(|r| {
            let is_connected = online.contains_key(&r.public_key);
            let is_online = reported_online(is_connected, r.presence_status.as_deref());
            UserInfo {
                online: is_online,
                status: r.presence_status.filter(|_| is_online),
                status_custom: r.presence_custom.filter(|_| is_online),
                public_key: r.public_key,
                display_name: r.display_name,
                avatar: r.avatar,
                group_role: r.group_role,
                is_bot: r.is_bot,
            }
        })
        .collect();

    Ok(Json(result))
}

pub async fn channel_members(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<UserInfo>>, (StatusCode, String)> {
    // For now, all hub users can see all channels (no per-channel access control yet).
    // Return all users, marking who's online.
    // When channel bans exist, we filter out banned users.
    let online = state.online_users.read().await;

    let rows = sqlx::query_as::<_, UserRow>(
        "SELECT u.public_key, u.display_name, u.avatar, u.is_bot,
                u.presence_status, u.presence_custom
         FROM users u
         WHERE u.public_key NOT IN (
             SELECT target_public_key FROM channel_bans WHERE channel_id = $1
         )
           AND NOT EXISTS (SELECT 1 FROM bans b WHERE b.target_public_key = u.public_key)
           AND (u.is_bot = TRUE OR EXISTS
                (SELECT 1 FROM user_roles ur2 WHERE ur2.user_public_key = u.public_key))
         ORDER BY u.display_name, u.public_key",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| {
                let is_connected = online.contains_key(&r.public_key);
                let is_online = reported_online(is_connected, r.presence_status.as_deref());
                UserInfo {
                    online: is_online,
                    status: r.presence_status.filter(|_| is_online),
                    status_custom: r.presence_custom.filter(|_| is_online),
                    public_key: r.public_key,
                    display_name: r.display_name,
                    avatar: r.avatar,
                    group_role: None,
                    is_bot: r.is_bot,
                }
            })
            .collect(),
    ))
}

#[derive(sqlx::FromRow)]
struct UserRow {
    public_key: String,
    display_name: Option<String>,
    avatar: Option<String>,
    is_bot: bool,
    presence_status: Option<String>,
    presence_custom: Option<String>,
}

/// Like UserRow but includes the pre-joined group_role column.
#[derive(sqlx::FromRow)]
struct UserRowWithRole {
    public_key: String,
    display_name: Option<String>,
    avatar: Option<String>,
    is_bot: bool,
    presence_status: Option<String>,
    presence_custom: Option<String>,
    group_role: Option<String>,
}

// ---------------------------------------------------------------------------
// User profile endpoint
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct RoleSummary {
    pub id: String,
    pub name: String,
    pub color: Option<String>,
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
}

/// GET /users/:pubkey/profile
pub async fn get_user_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<Json<UserProfileResponse>, (StatusCode, String)> {
    let row: Option<UserProfileRow> = sqlx::query_as(
        "SELECT display_name, avatar, first_seen_at, bio, pronouns, status_message, activities, accent_color, cover, favorite_hubs, show_hubs FROM users WHERE public_key = $1",
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
    ) = row.ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

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
    }

    let roles: Vec<RoleRow> = sqlx::query_as(
        "SELECT r.id, r.name, NULL as color
         FROM roles r
         INNER JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_public_key = $1
         ORDER BY r.priority DESC",
    )
    .bind(&pubkey)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let role_summaries: Vec<RoleSummary> = roles
        .into_iter()
        .map(|r| RoleSummary {
            id: r.id,
            name: r.name,
            color: r.color,
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
