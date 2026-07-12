use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::routes::role_models::RoleResponse;
use crate::state::AppState;

pub async fn me(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<MeResponse>, (StatusCode, String)> {
    let row: Option<(Option<String>, String, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT display_name, approval_status, avatar, bio, pronouns FROM users WHERE public_key = $1",
        )
        .bind(&user.public_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (display_name, approval_status, avatar, bio, pronouns) =
        row.unwrap_or((None, "approved".to_string(), None, None, None));

    let roles = fetch_user_roles(&state.db, &user.public_key).await?;

    Ok(Json(MeResponse {
        public_key: user.public_key,
        display_name,
        avatar,
        bio,
        pronouns,
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

    // Return fresh me
    let row: Option<(Option<String>, String, Option<String>, Option<String>, Option<String>)> =
        sqlx::query_as(
            "SELECT display_name, approval_status, avatar, bio, pronouns FROM users WHERE public_key = $1",
        )
        .bind(&user.public_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (display_name, approval_status, avatar, bio, pronouns) =
        row.unwrap_or((None, "approved".to_string(), None, None, None));

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
        approval_status,
        roles,
    }))
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
