use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::routes::role_models::RoleResponse;
use crate::state::AppState;

// Per-hub member profile field limits.
const BIO_MAX: usize = 500;
const PRONOUNS_MAX: usize = 40;
const STATUS_MESSAGE_MAX: usize = 140;
const ACTIVITIES_MAX: usize = 1000;
const COVER_MAX: usize = 400_000;

/// Row shape shared by the GET and PATCH `/me` handlers: display_name,
/// approval_status, avatar, bio, pronouns, status_message, activities,
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
    Option<String>,
);

const ME_SELECT: &str = "SELECT display_name, approval_status, avatar, bio, pronouns, status_message, activities, accent_color, cover FROM users WHERE public_key = $1";

fn empty_row() -> MeProfileRow {
    (
        None,
        "approved".to_string(),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

pub async fn me(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let row: Option<MeProfileRow> = sqlx::query_as(ME_SELECT)
        .bind(&user.public_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (
        display_name,
        approval_status,
        avatar,
        bio,
        pronouns,
        status_message,
        activities,
        accent_color,
        cover,
    ) = row.unwrap_or_else(empty_row);

    let roles = fetch_user_roles(&state.db, &user.public_key).await?;

    Ok(Json(MeResponse {
        public_key: user.public_key,
        display_name,
        avatar,
        bio,
        pronouns,
        status_message,
        activities,
        accent_color,
        cover,
        approval_status,
        roles,
    }))
}

/// Update a single nullable text profile column with the shared "absent =
/// unchanged, empty string = clear to NULL" semantics, after an optional
/// length check (chars, not bytes).
async fn update_text_field(
    db: &sqlx::PgPool,
    public_key: &str,
    column: &str,
    value: &str,
    max: usize,
    label: &str,
) -> Result<(), (StatusCode, String)> {
    if value.chars().count() > max {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{label} must be {max} characters or fewer"),
        ));
    }
    let stored = if value.is_empty() { None } else { Some(value) };
    // `column` is never user-supplied — it's a hardcoded literal from the
    // handler below — so this format! is not an injection vector.
    sqlx::query(&format!(
        "UPDATE users SET {column} = $1 WHERE public_key = $2"
    ))
    .bind(stored)
    .bind(public_key)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(())
}

pub async fn update_me(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateMeRequest>,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let pk = &user.public_key;
    if let Some(ref name) = req.display_name {
        sqlx::query("UPDATE users SET display_name = $1 WHERE public_key = $2")
            .bind(name)
            .bind(pk)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ref avatar) = req.avatar {
        update_text_field(&state.db, pk, "avatar", avatar, usize::MAX, "avatar").await?;
    }
    if let Some(ref bio) = req.bio {
        update_text_field(&state.db, pk, "bio", bio, BIO_MAX, "bio").await?;
    }
    if let Some(ref pronouns) = req.pronouns {
        update_text_field(
            &state.db,
            pk,
            "pronouns",
            pronouns,
            PRONOUNS_MAX,
            "pronouns",
        )
        .await?;
    }
    if let Some(ref status) = req.status_message {
        update_text_field(
            &state.db,
            pk,
            "status_message",
            status,
            STATUS_MESSAGE_MAX,
            "status_message",
        )
        .await?;
    }
    if let Some(ref activities) = req.activities {
        update_text_field(
            &state.db,
            pk,
            "activities",
            activities,
            ACTIVITIES_MAX,
            "activities",
        )
        .await?;
    }
    if let Some(ref accent_color) = req.accent_color {
        if !accent_color.is_empty() && !is_valid_hex_color(accent_color) {
            return Err((
                StatusCode::BAD_REQUEST,
                "accent_color must match #rrggbb".to_string(),
            ));
        }
        update_text_field(
            &state.db,
            pk,
            "accent_color",
            accent_color,
            usize::MAX,
            "accent_color",
        )
        .await?;
    }
    if let Some(ref cover) = req.cover {
        update_text_field(&state.db, pk, "cover", cover, COVER_MAX, "cover").await?;
    }

    // Return fresh me
    let row: Option<MeProfileRow> = sqlx::query_as(ME_SELECT)
        .bind(pk)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (
        display_name,
        approval_status,
        avatar,
        bio,
        pronouns,
        status_message,
        activities,
        accent_color,
        cover,
    ) = row.unwrap_or_else(empty_row);

    let roles = fetch_user_roles(&state.db, &user.public_key).await?;

    // Push the change hub-wide so other clients refresh this user's name/avatar
    // in the member list and on message authors without reconnecting. Only
    // name/avatar are mirrored elsewhere; the richer profile fields are
    // fetched live when a card opens, so they are deliberately not broadcast.
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
        status_message,
        activities,
        accent_color,
        cover,
        approval_status,
        roles,
    }))
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
    pub status_message: Option<String>,
    #[serde(default)]
    pub activities: Option<String>,
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
    pub status_message: Option<String>,
    #[serde(default)]
    pub activities: Option<String>,
    #[serde(default)]
    pub accent_color: Option<String>,
    #[serde(default)]
    pub cover: Option<String>,
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
