use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::routes::role_models::RoleResponse;
use crate::state::AppState;

/// Row shape shared by the GET and PATCH `/me` handlers: display_name,
/// approval_status, avatar, bio, pronouns, interests (raw JSON text),
/// accent_color, cover.
type MeProfileRow = (
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

pub async fn me(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let row: Option<MeProfileRow> = sqlx::query_as(
        "SELECT display_name, approval_status, avatar, bio, pronouns, interests, accent_color, cover FROM users WHERE public_key = $1",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (display_name, approval_status, avatar, bio, pronouns, interests, accent_color, cover) =
        row.unwrap_or((
            None,
            "approved".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        ));

    let roles = fetch_user_roles(&state.db, &user.public_key).await?;

    Ok(Json(MeResponse {
        public_key: user.public_key,
        display_name,
        avatar,
        bio,
        pronouns,
        interests: parse_interests(interests.as_deref()),
        accent_color,
        cover,
        approval_status,
        roles,
    }))
}

pub async fn update_me(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateMeRequest>,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    if let Some(ref name) = req.display_name {
        sqlx::query("UPDATE users SET display_name = $1 WHERE public_key = $2")
            .bind(name)
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ref avatar) = req.avatar {
        // Empty string clears the avatar.
        let stored = if avatar.is_empty() {
            None
        } else {
            Some(avatar.as_str())
        };
        sqlx::query("UPDATE users SET avatar = $1 WHERE public_key = $2")
            .bind(stored)
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ref bio) = req.bio {
        if bio.chars().count() > 500 {
            return Err((
                StatusCode::BAD_REQUEST,
                "bio must be 500 characters or fewer".to_string(),
            ));
        }
        // Empty string clears the bio.
        let stored = if bio.is_empty() {
            None
        } else {
            Some(bio.as_str())
        };
        sqlx::query("UPDATE users SET bio = $1 WHERE public_key = $2")
            .bind(stored)
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ref pronouns) = req.pronouns {
        if pronouns.chars().count() > 40 {
            return Err((
                StatusCode::BAD_REQUEST,
                "pronouns must be 40 characters or fewer".to_string(),
            ));
        }
        // Empty string clears the pronouns.
        let stored = if pronouns.is_empty() {
            None
        } else {
            Some(pronouns.as_str())
        };
        sqlx::query("UPDATE users SET pronouns = $1 WHERE public_key = $2")
            .bind(stored)
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ref entries) = req.interests {
        if entries.len() > 6 {
            return Err((
                StatusCode::BAD_REQUEST,
                "interests must have 6 entries or fewer".to_string(),
            ));
        }
        const ALLOWED_KINDS: [&str; 4] = ["playing", "want", "lfg", "into"];
        let mut trimmed = Vec::with_capacity(entries.len());
        for entry in entries {
            if !ALLOWED_KINDS.contains(&entry.kind.as_str()) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("invalid interest kind: {}", entry.kind),
                ));
            }
            let text = entry.text.trim();
            if text.is_empty() || text.chars().count() > 80 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "interest text must be 1-80 characters after trimming".to_string(),
                ));
            }
            trimmed.push(InterestEntry {
                kind: entry.kind.clone(),
                text: text.to_string(),
            });
        }
        // Empty array clears the interests list.
        let stored = if trimmed.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&trimmed).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to serialize interests: {e}"),
                )
            })?)
        };
        sqlx::query("UPDATE users SET interests = $1 WHERE public_key = $2")
            .bind(stored)
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ref accent_color) = req.accent_color {
        // Empty string clears the accent color.
        let stored = if accent_color.is_empty() {
            None
        } else {
            if !is_valid_hex_color(accent_color) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "accent_color must match #rrggbb".to_string(),
                ));
            }
            Some(accent_color.as_str())
        };
        sqlx::query("UPDATE users SET accent_color = $1 WHERE public_key = $2")
            .bind(stored)
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ref cover) = req.cover {
        if cover.chars().count() > 400_000 {
            return Err((
                StatusCode::BAD_REQUEST,
                "cover must be 400000 characters or fewer".to_string(),
            ));
        }
        // Empty string clears the cover.
        let stored = if cover.is_empty() {
            None
        } else {
            Some(cover.as_str())
        };
        sqlx::query("UPDATE users SET cover = $1 WHERE public_key = $2")
            .bind(stored)
            .bind(&user.public_key)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    // Return fresh me
    let row: Option<MeProfileRow> = sqlx::query_as(
        "SELECT display_name, approval_status, avatar, bio, pronouns, interests, accent_color, cover FROM users WHERE public_key = $1",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (display_name, approval_status, avatar, bio, pronouns, interests, accent_color, cover) =
        row.unwrap_or((
            None,
            "approved".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
        ));

    let roles = fetch_user_roles(&state.db, &user.public_key).await?;

    // Push the change hub-wide so other clients refresh this user's name/avatar
    // in the member list and on message authors without reconnecting.
    let json: std::sync::Arc<str> = std::sync::Arc::from(
        serde_json::to_string(
            &crate::routes::chat_models::WsServerMessage::MemberUpdated {
                public_key: user.public_key.clone(),
                display_name: display_name.clone(),
                avatar: avatar.clone(),
            },
        )
        .unwrap_or_default()
        .as_str(),
    );
    let _ = state.chat_tx.send((
        crate::routes::chat_models::ChatEvent::MemberUpdated {
            public_key: user.public_key.clone(),
        },
        json,
    ));

    Ok(Json(MeResponse {
        public_key: user.public_key,
        display_name,
        avatar,
        bio,
        pronouns,
        interests: parse_interests(interests.as_deref()),
        accent_color,
        cover,
        approval_status,
        roles,
    }))
}

/// Parse the stored `interests` JSON column into the wire representation,
/// defaulting to an empty list when NULL or on any (should-never-happen)
/// deserialization failure.
pub(crate) fn parse_interests(raw: Option<&str>) -> Vec<InterestEntry> {
    raw.and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Matches `#` followed by exactly 6 hex digits (e.g. `#7c5cff`).
fn is_valid_hex_color(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 7 && bytes[0] == b'#' && bytes[1..].iter().all(|b| b.is_ascii_hexdigit())
}

async fn fetch_user_roles(
    db: &sqlx::PgPool,
    public_key: &str,
) -> Result<Vec<RoleResponse>, (StatusCode, String)> {
    let roles = sqlx::query_as::<_, RoleRow>(
        "SELECT r.id, r.name, r.priority, r.display_separately, r.created_at,
                r.color, r.icon, r.category_id
         FROM roles r
         INNER JOIN user_roles ur ON r.id = ur.role_id
         WHERE ur.user_public_key = $1
         ORDER BY r.priority DESC",
    )
    .bind(public_key)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::new();
    for role in roles {
        let perms: Vec<String> =
            sqlx::query_scalar("SELECT permission FROM role_permissions WHERE role_id = $1")
                .bind(&role.id)
                .fetch_all(db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        result.push(RoleResponse {
            id: role.id,
            name: role.name,
            permissions: perms,
            priority: role.priority,
            display_separately: role.display_separately,
            created_at: role.created_at,
            color: role.color,
            icon: role.icon,
            category_id: role.category_id,
        });
    }
    Ok(result)
}

#[derive(Serialize, Deserialize)]
pub struct MeResponse {
    pub public_key: String,
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub pronouns: Option<String>,
    #[serde(default)]
    pub interests: Vec<InterestEntry>,
    #[serde(default)]
    pub accent_color: Option<String>,
    #[serde(default)]
    pub cover: Option<String>,
    #[serde(default = "default_approval_status")]
    pub approval_status: String,
    #[serde(default)]
    pub roles: Vec<RoleResponse>,
}

fn default_approval_status() -> String {
    "approved".to_string()
}

#[derive(Deserialize)]
pub struct UpdateMeRequest {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub bio: Option<String>,
    #[serde(default)]
    pub pronouns: Option<String>,
    #[serde(default)]
    pub interests: Option<Vec<InterestEntry>>,
    #[serde(default)]
    pub accent_color: Option<String>,
    #[serde(default)]
    pub cover: Option<String>,
}

/// A single self-authored interest entry on a member profile.
/// `kind` is validated against a fixed allowed set at the handler level
/// (see `update_me`); `text` is trimmed and length-capped there too.
#[derive(Serialize, Deserialize, Clone)]
pub struct InterestEntry {
    pub kind: String,
    pub text: String,
}

#[derive(sqlx::FromRow)]
struct RoleRow {
    id: String,
    name: String,
    priority: i64,
    display_separately: bool,
    created_at: i64,
    color: Option<String>,
    icon: Option<String>,
    category_id: Option<String>,
}
