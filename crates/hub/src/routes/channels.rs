use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{
    ChannelResponse, ChatEvent, CreateChannelRequest, UpdateChannelRequest, WsServerMessage,
};
use crate::state::AppState;

/// Returns a per-channel voice population snapshot. Channels with zero
/// participants are omitted -- callers can treat "missing key" as zero.
pub async fn voice_populations(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Json<HashMap<String, usize>> {
    let voice = state.voice_channels.read().await;
    let mut out: HashMap<String, usize> = HashMap::with_capacity(voice.len());
    for (channel_id, members) in voice.iter() {
        if !members.is_empty() {
            out.insert(channel_id.clone(), members.len());
        }
    }
    Json(out)
}

/// Returns voice participants grouped by channel, enriched with each
/// member's display_name from the local users table. Lets the sidebar
/// show participant names nested under each voice-active channel rather
/// than just a count.
///
/// Shape: { channel_id: [{ public_key, display_name }] }. Channels with
/// zero participants are omitted.
pub async fn voice_channel_participants(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<HashMap<String, Vec<VoiceParticipantInfo>>>, (StatusCode, String)> {
    let voice = state.voice_channels.read().await;

    // Collect every distinct pubkey first so we can look up display names
    // in one query. Avoids N round-trips for a hub with many in-voice users.
    let mut all_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for members in voice.values() {
        for pk in members.keys() {
            all_keys.insert(pk.clone());
        }
    }

    let mut name_by_key: HashMap<String, Option<String>> = HashMap::new();
    if !all_keys.is_empty() {
        // sqlx doesn't have great IN-clause helpers; this loop is cheap and
        // bounded by hub size. The lookup itself is one indexed PK fetch.
        for key in &all_keys {
            let name: Option<String> =
                sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = ?")
                    .bind(key)
                    .fetch_optional(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
                    .flatten();
            name_by_key.insert(key.clone(), name);
        }
    }

    let mut out: HashMap<String, Vec<VoiceParticipantInfo>> = HashMap::new();
    for (channel_id, members) in voice.iter() {
        if members.is_empty() {
            continue;
        }
        let participants = members
            .keys()
            .map(|pk| VoiceParticipantInfo {
                public_key: pk.clone(),
                display_name: name_by_key.get(pk).cloned().flatten(),
            })
            .collect();
        out.insert(channel_id.clone(), participants);
    }
    Ok(Json(out))
}

#[derive(serde::Serialize)]
pub struct VoiceParticipantInfo {
    pub public_key: String,
    pub display_name: Option<String>,
}

/// Returns the set of public keys currently in any voice channel on this
/// hub. Used by the client to show a 🎙️ next to in-voice users in the
/// member list.
pub async fn voice_active_users(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Json<Vec<String>> {
    let voice = state.voice_channels.read().await;
    let mut out: std::collections::HashSet<String> = std::collections::HashSet::new();
    for members in voice.values() {
        for pk in members.keys() {
            out.insert(pk.clone());
        }
    }
    Json(out.into_iter().collect())
}

pub async fn create_channel(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateChannelRequest>,
) -> Result<(StatusCode, Json<ChannelResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_CHANNELS)?;

    // Validate parent if specified
    if let Some(parent_id) = &req.parent_id {
        let parent_is_category: Option<i64> =
            sqlx::query_scalar("SELECT is_category FROM channels WHERE id = ?")
                .bind(parent_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        match parent_is_category {
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    "Parent channel not found".to_string(),
                ))
            }
            Some(0) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Parent must be a category".to_string(),
                ))
            }
            _ => {}
        }
    }

    // Enforce max_channel_depth
    let max_depth = read_max_depth(&state.db).await;
    if max_depth > 0 {
        let new_depth = node_depth(&state.db, req.parent_id.as_deref()).await?;
        let max_code_depth = max_depth - 1;
        if new_depth > max_code_depth {
            return Err((StatusCode::BAD_REQUEST, "depth_exceeded".to_string()));
        }
        if req.is_category && new_depth >= max_code_depth {
            return Err((StatusCode::BAD_REQUEST, "category_at_max_depth".to_string()));
        }
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let is_category_int = if req.is_category { 1i64 } else { 0 };

    // Validate channel_type: "text", "forum", or "banner" on leaf channels.
    let channel_type = if req.is_category {
        "text".to_string()
    } else {
        match req.channel_type.as_deref() {
            None | Some("text") => "text".to_string(),
            Some("forum") => "forum".to_string(),
            Some("banner") => "banner".to_string(),
            Some(other) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("unknown channel_type: {other}"),
                ))
            }
        }
    };

    if channel_type == "banner" {
        if req.banner_url.is_some() && req.banner_file_id.is_some() {
            return Err((
                StatusCode::BAD_REQUEST,
                "banner_url and banner_file_id are mutually exclusive".to_string(),
            ));
        }
        if let Some(ref url) = req.banner_url {
            if !url.starts_with("https://") {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "banner_url must be an https:// URL".to_string(),
                ));
            }
        }
    } else {
        if req.banner_url.is_some() || req.banner_file_id.is_some() {
            return Err((
                StatusCode::BAD_REQUEST,
                "banner_url and banner_file_id are only valid for banner channels".to_string(),
            ));
        }
    }

    // Append at the end of the current order
    let next_order: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(display_order), -1) + 1 FROM channels")
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query(
        "INSERT INTO channels (id, name, created_by, parent_id, is_category, display_order, description, channel_type, created_at, banner_url, banner_file_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&user.public_key)
    .bind(&req.parent_id)
    .bind(is_category_int)
    .bind(next_order)
    .bind(&req.description)
    .bind(&channel_type)
    .bind(now)
    .bind(&req.banner_url)
    .bind(&req.banner_file_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            (StatusCode::CONFLICT, format!("Channel '{}' already exists", req.name))
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
        }
    })?;

    let resp = ChannelResponse {
        id: id.clone(),
        name: req.name.clone(),
        created_by: user.public_key.clone(),
        parent_id: req.parent_id.clone(),
        is_category: req.is_category,
        display_order: next_order,
        description: req.description.clone(),
        icon: None,
        color: None,
        custom_icon_svg: None,
        created_at: now,
        channel_type,
        banner_url: req.banner_url.clone(),
        banner_file_id: req.banner_file_id.clone(),
    };

    // Publish channel.created audit event.
    {
        let state_c = state.clone();
        let ch_id = id.clone();
        let ch_name = req.name.clone();
        let creator = user.public_key.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "channel.created",
                Some(&creator),
                None,
                Some(&ch_id),
                serde_json::json!({ "channel_id": ch_id, "name": ch_name }),
            )
            .await;
        });
    }

    let json: std::sync::Arc<str> = std::sync::Arc::from(
        serde_json::to_string(&WsServerMessage::ChannelsUpdated)
            .unwrap()
            .as_str(),
    );
    let _ = state.chat_tx.send((ChatEvent::ChannelsUpdated, json));

    Ok((StatusCode::CREATED, Json(resp)))
}

pub async fn update_channel(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<UpdateChannelRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;

    let existing_type: Option<String> =
        sqlx::query_scalar("SELECT channel_type FROM channels WHERE id = ?")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let existing_type =
        existing_type.ok_or_else(|| (StatusCode::NOT_FOUND, "Channel not found".to_string()))?;

    let changing_structure = req.name.is_some()
        || req.description.is_some()
        || req.parent_id.is_some()
        || req.banner_url.is_some()
        || req.banner_file_id.is_some();
    let changing_appearance =
        req.icon.is_some() || req.color.is_some() || req.custom_icon_svg.is_some();
    let changing_talk_power = req.min_talk_power.is_some();
    let changing_retention = req.retention_days.is_some();

    if changing_structure {
        perms.require(permissions::MANAGE_CHANNELS)?;
    }
    if changing_appearance {
        perms.require(permissions::MANAGE_CHANNEL_ICONS)?;
    }
    if changing_talk_power || changing_retention {
        perms.require(permissions::ADMIN)?;
    }

    if let Some(Some(parent_id)) = &req.parent_id {
        if parent_id == &channel_id {
            return Err((
                StatusCode::BAD_REQUEST,
                "A channel can't be its own parent".to_string(),
            ));
        }
        let parent_is_category: Option<i64> =
            sqlx::query_scalar("SELECT is_category FROM channels WHERE id = ?")
                .bind(parent_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        match parent_is_category {
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    "Parent channel not found".to_string(),
                ))
            }
            Some(0) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Parent must be a category".to_string(),
                ))
            }
            _ => {}
        }

        // Server-side cycle detection
        if is_ancestor(&state.db, &channel_id, parent_id).await? {
            return Err((
                StatusCode::BAD_REQUEST,
                "Cannot move a channel into its own descendant".to_string(),
            ));
        }
        // Depth enforcement
        let max_depth = read_max_depth(&state.db).await;
        if max_depth > 0 {
            let parent_depth = node_depth(&state.db, Some(parent_id)).await?;
            let moved_depth = parent_depth + 1;
            let max_code_depth = max_depth - 1;
            if moved_depth > max_code_depth {
                return Err((StatusCode::BAD_REQUEST, "depth_exceeded".to_string()));
            }
            let is_cat: i64 = sqlx::query_scalar("SELECT is_category FROM channels WHERE id = ?")
                .bind(&channel_id)
                .fetch_one(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
            if is_cat == 1 && moved_depth >= max_code_depth {
                return Err((StatusCode::BAD_REQUEST, "category_at_max_depth".to_string()));
            }
        }
    }

    // Banner field validation
    if req.banner_url.is_some() || req.banner_file_id.is_some() {
        if existing_type != "banner" {
            return Err((
                StatusCode::BAD_REQUEST,
                "banner_url and banner_file_id are only valid for banner channels".to_string(),
            ));
        }
        if let Some(ref url) = req.banner_url {
            if !url.starts_with("https://") {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "banner_url must be an https:// URL".to_string(),
                ));
            }
        }
        if let Some(ref fid) = req.banner_file_id {
            let valid: Option<String> = sqlx::query_scalar(
                "SELECT id FROM upload_files WHERE id = ? AND channel_id = ? AND mime_type IN ('image/png','image/jpeg','image/gif','image/webp')",
            )
            .bind(fid)
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
            if valid.is_none() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "banner_file_id must reference an image uploaded to this channel".to_string(),
                ));
            }
        }
        if req.banner_url.is_some() && req.banner_file_id.is_some() {
            return Err((
                StatusCode::BAD_REQUEST,
                "banner_url and banner_file_id are mutually exclusive".to_string(),
            ));
        }
    }

    let needs_update = req.description.is_some()
        || req.icon.is_some()
        || req.color.is_some()
        || req.custom_icon_svg.is_some()
        || req.parent_id.is_some()
        || req.min_talk_power.is_some()
        || req.retention_days.is_some()
        || req.banner_url.is_some()
        || req.banner_file_id.is_some();

    if needs_update {
        let mut qb = sqlx::QueryBuilder::new("UPDATE channels SET ");
        let mut sep = qb.separated(", ");
        if req.description.is_some() {
            sep.push("description = ");
            sep.push_bind_unseparated(req.description.as_deref());
        }
        if let Some(icon_opt) = &req.icon {
            sep.push("icon = ");
            sep.push_bind_unseparated(icon_opt.as_deref());
        }
        if let Some(color_opt) = &req.color {
            sep.push("color = ");
            sep.push_bind_unseparated(color_opt.as_deref());
        }
        if let Some(svg_opt) = &req.custom_icon_svg {
            sep.push("custom_icon_svg = ");
            sep.push_bind_unseparated(svg_opt.as_deref());
        }
        if let Some(parent_option) = &req.parent_id {
            sep.push("parent_id = ");
            sep.push_bind_unseparated(parent_option.as_deref());
        }
        if let Some(mtp) = req.min_talk_power {
            sep.push("min_talk_power = ");
            sep.push_bind_unseparated(mtp);
        }
        if let Some(rd_opt) = &req.retention_days {
            sep.push("retention_days = ");
            sep.push_bind_unseparated(*rd_opt);
        }
        if req.banner_url.is_some() {
            sep.push("banner_url = ");
            sep.push_bind_unseparated(req.banner_url.as_deref());
        }
        if req.banner_file_id.is_some() {
            sep.push("banner_file_id = ");
            sep.push_bind_unseparated(req.banner_file_id.as_deref());
        }
        qb.push(" WHERE id = ");
        qb.push_bind(&channel_id);
        qb.build()
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    if let Some(name) = &req.name {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "Channel name cannot be empty".to_string(),
            ));
        }
        // The channels.name column has a UNIQUE constraint, so collisions
        // surface as a constraint error -- map to 409 for a clearer
        // client-side message than "DB error: ...".
        match sqlx::query("UPDATE channels SET name = ? WHERE id = ?")
            .bind(trimmed)
            .bind(&channel_id)
            .execute(&state.db)
            .await
        {
            Ok(_) => {}
            Err(sqlx::Error::Database(e)) if e.message().contains("UNIQUE") => {
                return Err((
                    StatusCode::CONFLICT,
                    "A channel with that name already exists".to_string(),
                ))
            }
            Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))),
        }
    }

    let json: std::sync::Arc<str> = std::sync::Arc::from(
        serde_json::to_string(&WsServerMessage::ChannelsUpdated)
            .unwrap()
            .as_str(),
    );
    let _ = state.chat_tx.send((ChatEvent::ChannelsUpdated, json));

    Ok(StatusCode::OK)
}

pub async fn list_channels(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<ChannelResponse>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, ChannelRow>(
        "SELECT id, name, created_by, parent_id, is_category, display_order, description, icon, color, custom_icon_svg, created_at, channel_type, banner_url, banner_file_id
         FROM channels
         ORDER BY display_order, created_at",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let channels = rows
        .into_iter()
        .map(|r| ChannelResponse {
            id: r.id,
            name: r.name,
            created_by: r.created_by,
            parent_id: r.parent_id,
            is_category: r.is_category != 0,
            display_order: r.display_order,
            description: r.description,
            icon: r.icon,
            color: r.color,
            custom_icon_svg: r.custom_icon_svg,
            created_at: r.created_at,
            channel_type: r.channel_type,
            banner_url: r.banner_url,
            banner_file_id: r.banner_file_id,
        })
        .collect();

    Ok(Json(channels))
}

#[derive(serde::Deserialize)]
pub struct ReorderRequest {
    /// Ordered list of channel IDs as they should appear
    pub channel_ids: Vec<String>,
}

pub async fn reorder_channels(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<ReorderRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_CHANNELS)?;

    // Assign sequential display_order values
    for (index, channel_id) in req.channel_ids.iter().enumerate() {
        sqlx::query("UPDATE channels SET display_order = ? WHERE id = ?")
            .bind(index as i64)
            .bind(channel_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let json: std::sync::Arc<str> = std::sync::Arc::from(
        serde_json::to_string(&WsServerMessage::ChannelsUpdated)
            .unwrap()
            .as_str(),
    );
    let _ = state.chat_tx.send((ChatEvent::ChannelsUpdated, json));

    Ok(StatusCode::OK)
}

pub async fn delete_channel(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::MANAGE_CHANNELS)?;

    // Check if channel exists
    let exists: Option<i64> = sqlx::query_scalar("SELECT is_category FROM channels WHERE id = ?")
        .bind(&channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    // Check for children (prevent deleting non-empty categories)
    let child_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE parent_id = ?")
        .bind(&channel_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if child_count > 0 {
        return Err((
            StatusCode::CONFLICT,
            "Cannot delete: category still has channels".to_string(),
        ));
    }

    // Clean up related data
    sqlx::query("DELETE FROM messages WHERE channel_id = ?")
        .bind(&channel_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM channel_bans WHERE channel_id = ?")
        .bind(&channel_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM channel_settings WHERE channel_id = ?")
        .bind(&channel_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM alliance_shared_channels WHERE channel_id = ?")
        .bind(&channel_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query("DELETE FROM channels WHERE id = ?")
        .bind(&channel_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Publish channel.deleted audit event.
    {
        let state_c = state.clone();
        let ch_id = channel_id.clone();
        let actor = user.public_key.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "channel.deleted",
                Some(&actor),
                None,
                Some(&ch_id),
                serde_json::json!({ "channel_id": ch_id }),
            )
            .await;
        });
    }

    let json: std::sync::Arc<str> = std::sync::Arc::from(
        serde_json::to_string(&WsServerMessage::ChannelsUpdated)
            .unwrap()
            .as_str(),
    );
    let _ = state.chat_tx.send((ChatEvent::ChannelsUpdated, json));

    Ok(StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow)]
struct ChannelRow {
    id: String,
    name: String,
    created_by: String,
    parent_id: Option<String>,
    is_category: i64,
    display_order: i64,
    description: Option<String>,
    icon: Option<String>,
    color: Option<String>,
    custom_icon_svg: Option<String>,
    created_at: i64,
    channel_type: String,
    banner_url: Option<String>,
    banner_file_id: Option<String>,
}

/// Returns the code-depth a new item would sit at if placed under `parent_id`
/// (0 = root-level, 1 = one level down, etc.).
async fn node_depth(
    db: &sqlx::AnyPool,
    parent_id: Option<&str>,
) -> Result<u32, (StatusCode, String)> {
    let Some(pid) = parent_id else { return Ok(0) };
    let mut depth = 1u32;
    let mut current = pid.to_string();
    loop {
        let parent: Option<String> =
            sqlx::query_scalar("SELECT parent_id FROM channels WHERE id = ?")
                .bind(&current)
                .fetch_optional(db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
                .flatten();
        match parent {
            None => break,
            Some(p) => {
                depth += 1;
                current = p;
                if depth > 50 {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "Channel nesting depth exceeds safety limit".to_string(),
                    ));
                }
            }
        }
    }
    Ok(depth)
}

/// Returns true if `candidate` is an ancestor of `start`
/// (i.e. walking up from `start` eventually reaches `candidate`).
/// Used for server-side cycle detection.
async fn is_ancestor(
    db: &sqlx::AnyPool,
    candidate: &str,
    start: &str,
) -> Result<bool, (StatusCode, String)> {
    let mut current = start.to_string();
    for _ in 0..50 {
        let parent: Option<String> =
            sqlx::query_scalar("SELECT parent_id FROM channels WHERE id = ?")
                .bind(&current)
                .fetch_optional(db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
                .flatten();
        match parent {
            None => return Ok(false),
            Some(p) if p == candidate => return Ok(true),
            Some(p) => current = p,
        }
    }
    Ok(false)
}

async fn read_max_depth(db: &sqlx::AnyPool) -> u32 {
    sqlx::query_scalar::<_, String>(
        "SELECT value FROM hub_settings WHERE key = 'max_channel_depth'",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .and_then(|v| v.parse().ok())
    .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Unread counts (Feature 2)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
pub struct UnreadCount {
    pub channel_id: String,
    pub unread_count: i64,
}

/// GET /channels/unread — returns [{channel_id, unread_count}] for every
/// non-category channel the authenticated user can see.
pub async fn get_unread_counts(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<UnreadCount>>, (StatusCode, String)> {
    // All non-category channels (no per-channel ACL in the base model)
    let channel_ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM channels WHERE is_category = 0")
            .fetch_all(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::with_capacity(channel_ids.len());
    for channel_id in channel_ids {
        // Look up last_read_at for this user/channel; default to 0 (never read).
        let last_read_at: i64 = sqlx::query_scalar(
            "SELECT last_read_at FROM channel_last_read WHERE user_pubkey = ? AND channel_id = ?",
        )
        .bind(&user.public_key)
        .bind(&channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .unwrap_or(0);

        let unread_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM messages WHERE channel_id = ? AND created_at > ?",
        )
        .bind(&channel_id)
        .bind(last_read_at)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        result.push(UnreadCount {
            channel_id,
            unread_count,
        });
    }

    Ok(Json(result))
}

/// POST /channels/:id/read — upsert last_read_at for the authenticated user.
pub async fn mark_channel_read(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Verify the channel exists
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
        .bind(&channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO channel_last_read (user_pubkey, channel_id, last_read_at)
         VALUES (?, ?, ?)
         ON CONFLICT(user_pubkey, channel_id) DO UPDATE SET last_read_at = excluded.last_read_at",
    )
    .bind(&user.public_key)
    .bind(&channel_id)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}
