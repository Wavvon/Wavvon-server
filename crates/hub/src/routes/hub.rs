use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::routes::role_models::RoleResponse;
use crate::state::AppState;

/// Update the hub's branding: name, description, icon (all optional).
/// Requires the caller to have the admin permission.
pub async fn update_hub(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateHubRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    if let Some(name) = req.name.as_deref() {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "Name cannot be empty".to_string()));
        }
        upsert_setting(&state.db, "hub_name", trimmed).await?;
    }
    if let Some(description) = req.description.as_deref() {
        upsert_setting(&state.db, "hub_description", description).await?;
    }
    if let Some(icon) = req.icon.as_deref() {
        // Accept any string here — caller sends a base64 data URL or empty to clear.
        upsert_setting(&state.db, "hub_icon", icon).await?;
    }
    if let Some(flag) = req.require_approval {
        upsert_setting(
            &state.db,
            "require_approval",
            if flag { "true" } else { "false" },
        )
        .await?;
    }
    if let Some(level) = req.min_security_level {
        upsert_setting(&state.db, "min_security_level", &level.to_string()).await?;
    }
    if let Some(d) = req.max_channel_depth {
        upsert_setting(&state.db, "max_channel_depth", &d.to_string()).await?;
    }
    if let Some(label) = req.welcome_label.as_deref() {
        if label.chars().count() > 100 {
            return Err((
                StatusCode::BAD_REQUEST,
                "welcome_label must be at most 100 characters".to_string(),
            ));
        }
        upsert_setting(&state.db, "welcome_label", label).await?;
    }
    if let Some(invite_url) = req.welcome_invite_url.as_deref() {
        if !invite_url.is_empty() {
            validate_welcome_invite_url(invite_url)?;
        }
        upsert_setting(&state.db, "welcome_invite_url", invite_url).await?;
    }

    Ok(StatusCode::OK)
}

/// Validates the operator-supplied welcome invite link (Feature: welcome
/// invite banner). Must parse as a URL and use either `https://` (a
/// federation-style invite to another hub) or `wavvon://` (an in-app deep
/// link). Callers should skip this check for an empty string, which clears
/// the setting.
fn validate_welcome_invite_url(raw: &str) -> Result<(), (StatusCode, String)> {
    let parsed = url::Url::parse(raw).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            "welcome_invite_url is not a valid URL".to_string(),
        )
    })?;

    if parsed.scheme() != "https" && parsed.scheme() != "wavvon" {
        return Err((
            StatusCode::BAD_REQUEST,
            "welcome_invite_url must use https:// or wavvon://".to_string(),
        ));
    }

    Ok(())
}

/// List all users awaiting admin approval.
pub async fn list_pending(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<PendingUser>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let rows = sqlx::query_as::<_, PendingUserRow>(
        "SELECT public_key, display_name, first_seen_at
         FROM users WHERE approval_status = 'pending'
         ORDER BY first_seen_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| PendingUser {
                public_key: r.public_key,
                display_name: r.display_name,
                first_seen_at: r.first_seen_at,
            })
            .collect(),
    ))
}

/// Approve a pending user so they can start using the hub.
pub async fn approve_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    axum::extract::Path(target_key): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    sqlx::query("UPDATE users SET approval_status = 'approved' WHERE public_key = $1")
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

/// GET /admin/settings/pow — returns the current min_pow_level setting.
pub async fn get_pow_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<PowSettingsResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let min_pow_level: u8 = read_setting(&state.db, "min_pow_level")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    Ok(Json(PowSettingsResponse { min_pow_level }))
}

/// PATCH /admin/settings/pow — updates the min_pow_level setting.
pub async fn patch_pow_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<PowSettingsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    upsert_setting(&state.db, "min_pow_level", &req.min_pow_level.to_string()).await?;
    Ok(StatusCode::OK)
}

#[derive(Serialize, Deserialize)]
pub struct PowSettingsResponse {
    pub min_pow_level: u8,
}

#[derive(Deserialize)]
pub struct PowSettingsRequest {
    pub min_pow_level: u8,
}

/// GET /admin/settings/channel-depth — returns the current max_channel_depth setting.
pub async fn get_channel_depth(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<ChannelDepthResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let max_channel_depth: u32 = read_setting(&state.db, "max_channel_depth")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    Ok(Json(ChannelDepthResponse { max_channel_depth }))
}

/// PATCH /admin/settings/channel-depth — updates the max_channel_depth setting.
pub async fn patch_channel_depth(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<ChannelDepthRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    upsert_setting(
        &state.db,
        "max_channel_depth",
        &req.max_channel_depth.to_string(),
    )
    .await?;
    Ok(StatusCode::OK)
}

#[derive(Serialize)]
pub struct ChannelDepthResponse {
    pub max_channel_depth: u32,
}

#[derive(Deserialize)]
pub struct ChannelDepthRequest {
    pub max_channel_depth: u32,
}

/// Read-only admin view of hub-wide settings for the Overview tab.
pub async fn get_hub_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<HubSettings>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let require_approval: bool = read_setting(&state.db, "require_approval")
        .await
        .map(|v| v == "true")
        .unwrap_or(false);
    let invite_only: bool = read_setting(&state.db, "invite_only")
        .await
        .map(|v| v == "true")
        .unwrap_or(false);

    let min_security_level: u32 = read_setting(&state.db, "min_security_level")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let max_channel_depth: u32 = read_setting(&state.db, "max_channel_depth")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    Ok(Json(HubSettings {
        require_approval,
        invite_only,
        min_security_level,
        max_channel_depth,
    }))
}

#[derive(Serialize)]
pub struct HubSettings {
    pub require_approval: bool,
    pub invite_only: bool,
    pub min_security_level: u32,
    pub max_channel_depth: u32,
}

#[derive(Serialize)]
pub struct PendingUser {
    pub public_key: String,
    pub display_name: Option<String>,
    pub first_seen_at: i64,
}

#[derive(sqlx::FromRow)]
struct PendingUserRow {
    public_key: String,
    display_name: Option<String>,
    first_seen_at: i64,
}

pub async fn upsert_setting(
    db: &sqlx::PgPool,
    key: &str,
    value: &str,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO hub_settings (key, value) VALUES ($1, $2)
         ON CONFLICT(key) DO UPDATE SET value = $3",
    )
    .bind(key)
    .bind(value)
    .bind(value)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(())
}

#[derive(Deserialize)]
pub struct UpdateHubRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub require_approval: Option<bool>,
    #[serde(default)]
    pub min_security_level: Option<u32>,
    #[serde(default)]
    pub max_channel_depth: Option<u32>,
    /// Label for the welcome invite banner, e.g. "a server by Acme Co."
    /// Max 100 chars. Empty string clears the setting.
    #[serde(default)]
    pub welcome_label: Option<String>,
    /// Invite link shown alongside `welcome_label`. Must be `https://` or
    /// `wavvon://`. Empty string clears the setting.
    #[serde(default)]
    pub welcome_invite_url: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct HubBranding {
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
}

/// GET /admin/settings/moderation — returns moderation settings and circuit-breaker state.
///
/// Never returns the webhook secret; only a boolean indicating whether one is set.
pub async fn get_moderation_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<ModerationSettingsResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let webhook_url = read_setting(&state.db, "moderation_webhook_url").await;
    let webhook_secret_set = read_setting(&state.db, "moderation_webhook_secret")
        .await
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    let (circuit_open, circuit_open_until) = {
        let circuit = state.webhook_circuit.lock().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        match circuit.open_until {
            Some(until) if now < until => (true, Some(until)),
            _ => (false, None),
        }
    };

    Ok(Json(ModerationSettingsResponse {
        webhook_url: webhook_url.filter(|s| !s.is_empty()),
        webhook_secret_set,
        circuit_open,
        circuit_open_until,
    }))
}

#[derive(Serialize, Deserialize)]
pub struct ModerationSettingsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    pub webhook_secret_set: bool,
    pub circuit_open: bool,
    pub circuit_open_until: Option<i64>,
}

/// PATCH /admin/settings/moderation — sets the auto-mod webhook URL and HMAC secret.
pub async fn patch_moderation_settings(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<ModerationSettingsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    if let Some(url) = req.webhook_url.as_deref() {
        upsert_setting(&state.db, "moderation_webhook_url", url).await?;
    }
    if let Some(secret) = req.webhook_secret.as_deref() {
        upsert_setting(&state.db, "moderation_webhook_secret", secret).await?;
    }

    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
pub struct ModerationSettingsRequest {
    #[serde(default)]
    pub webhook_url: Option<String>,
    #[serde(default)]
    pub webhook_secret: Option<String>,
}

/// Read all three branding fields with fallback to the value seeded in AppState.
pub async fn read_branding(state: &AppState) -> HubBranding {
    let name = current_hub_name(state).await;
    let description = read_setting(&state.db, "hub_description").await;
    let icon = read_setting(&state.db, "hub_icon").await;
    HubBranding {
        name,
        description,
        icon,
    }
}

/// Live hub name. The startup-time AppState.hub_name is only the fallback —
/// callers that want what an admin renamed the hub to (alliance member rows,
/// federated DM prefixes, etc.) should use this instead of state.hub_name.
pub async fn current_hub_name(state: &AppState) -> String {
    read_setting(&state.db, "hub_name")
        .await
        .unwrap_or_else(|| state.hub_name.clone())
}

async fn read_setting(db: &sqlx::PgPool, key: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = $1")
        .bind(key)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// Admin-facing member listing with joined / last-seen / online + role summaries.
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<MemberAdminInfo>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    let users = sqlx::query_as::<_, UserAdminRow>(
        "SELECT public_key, display_name, first_seen_at, last_seen_at, is_bot
         FROM users ORDER BY first_seen_at LIMIT 1000",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if users.is_empty() {
        return Ok(Json(vec![]));
    }

    let user_keys: Vec<String> = users.iter().map(|u| u.public_key.clone()).collect();

    // One query for all user-role associations + role metadata.
    #[allow(clippy::type_complexity)]
    let user_role_rows: Vec<(
        String,
        String,
        String,
        i64,
        bool,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT ur.user_public_key, r.id, r.name, r.priority, r.display_separately, r.created_at,
                r.color, r.icon, r.category_id
         FROM user_roles ur
         INNER JOIN roles r ON r.id = ur.role_id
         WHERE ur.user_public_key = ANY($1)
         ORDER BY ur.user_public_key, r.priority DESC",
    )
    .bind(&user_keys[..])
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // One query for all permissions across all roles seen above.
    let distinct_role_ids: Vec<String> = user_role_rows
        .iter()
        .map(|(_, id, ..)| id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();

    let perm_rows: Vec<(String, String)> = if distinct_role_ids.is_empty() {
        vec![]
    } else {
        sqlx::query_as("SELECT role_id, permission FROM role_permissions WHERE role_id = ANY($1)")
            .bind(&distinct_role_ids[..])
            .fetch_all(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    };

    let mut perms_by_role: HashMap<String, Vec<String>> = HashMap::new();
    for (role_id, perm) in perm_rows {
        perms_by_role.entry(role_id).or_default().push(perm);
    }

    let mut roles_by_user: HashMap<String, Vec<RoleResponse>> = HashMap::new();
    for (
        user_key,
        role_id,
        role_name,
        priority,
        display_separately,
        created_at,
        color,
        icon,
        category_id,
    ) in user_role_rows
    {
        let permissions = perms_by_role.get(&role_id).cloned().unwrap_or_default();
        roles_by_user
            .entry(user_key)
            .or_default()
            .push(RoleResponse {
                id: role_id,
                name: role_name,
                priority,
                display_separately,
                created_at,
                permissions,
                color,
                icon,
                category_id,
            });
    }

    let online = state.online_users.read().await;
    let result: Vec<MemberAdminInfo> = users
        .into_iter()
        .map(|u| {
            let roles = roles_by_user.remove(&u.public_key).unwrap_or_default();
            MemberAdminInfo {
                online: online.contains_key(&u.public_key),
                public_key: u.public_key,
                display_name: u.display_name,
                first_seen_at: u.first_seen_at,
                last_seen_at: u.last_seen_at,
                roles,
                is_bot: u.is_bot,
            }
        })
        .collect();

    Ok(Json(result))
}

#[derive(Serialize)]
pub struct MemberAdminInfo {
    pub public_key: String,
    pub display_name: Option<String>,
    pub online: bool,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub roles: Vec<RoleResponse>,
    #[serde(default)]
    pub is_bot: bool,
}

#[derive(sqlx::FromRow)]
struct UserAdminRow {
    public_key: String,
    display_name: Option<String>,
    first_seen_at: i64,
    last_seen_at: i64,
    is_bot: bool,
}
