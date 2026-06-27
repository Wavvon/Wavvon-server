use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN, BAN_MEMBERS, MUTE_MEMBERS};
use crate::routes::moderation_models::*;
use crate::state::AppState;

use super::models::{require_can_moderate, ChannelBanRow, VoiceMuteRow};

// --- Channel Ban ---

pub async fn channel_ban(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<ChannelBanRequest>,
) -> Result<(StatusCode, Json<ChannelBanResponse>), (StatusCode, String)> {
    require_can_moderate(
        &state,
        &user.public_key,
        &req.target_public_key,
        MUTE_MEMBERS,
    )
    .await?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO channel_bans (channel_id, target_public_key, banned_by, reason, created_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (channel_id, target_public_key) DO UPDATE SET banned_by = excluded.banned_by, reason = excluded.reason, created_at = excluded.created_at",
    )
    .bind(&channel_id)
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(ChannelBanResponse {
            channel_id,
            target_public_key: req.target_public_key,
            banned_by: user.public_key,
            reason: req.reason,
            created_at: now,
        }),
    ))
}

pub async fn list_channel_bans(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<ChannelBanResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    let rows = sqlx::query_as::<_, ChannelBanRow>(
        "SELECT channel_id, target_public_key, banned_by, reason, created_at
         FROM channel_bans WHERE channel_id = $1 ORDER BY created_at DESC",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ChannelBanResponse {
                channel_id: r.channel_id,
                target_public_key: r.target_public_key,
                banned_by: r.banned_by,
                reason: r.reason,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

pub async fn channel_unban(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, target_key)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    sqlx::query("DELETE FROM channel_bans WHERE channel_id = $1 AND target_public_key = $2")
        .bind(&channel_id)
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// --- Voice Mute ---

pub async fn voice_mute(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<VoiceMuteRequest>,
) -> Result<(StatusCode, Json<VoiceMuteResponse>), (StatusCode, String)> {
    require_can_moderate(
        &state,
        &user.public_key,
        &req.target_public_key,
        MUTE_MEMBERS,
    )
    .await?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO voice_mutes (target_public_key, muted_by, reason, created_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT (target_public_key) DO UPDATE SET muted_by = excluded.muted_by, reason = excluded.reason, created_at = excluded.created_at",
    )
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(VoiceMuteResponse {
            target_public_key: req.target_public_key,
            muted_by: user.public_key,
            reason: req.reason,
            created_at: now,
        }),
    ))
}

pub async fn voice_unmute(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(target_key): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    sqlx::query("DELETE FROM voice_mutes WHERE target_public_key = $1")
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_voice_mutes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<VoiceMuteResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    let rows = sqlx::query_as::<_, VoiceMuteRow>(
        "SELECT target_public_key, muted_by, reason, created_at FROM voice_mutes ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| VoiceMuteResponse {
                target_public_key: r.target_public_key,
                muted_by: r.muted_by,
                reason: r.reason,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

// --- Talk Power ---

pub async fn set_talk_power(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<SetTalkPowerRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    sqlx::query(
        "INSERT INTO channel_settings (channel_id, min_talk_power) VALUES ($1, $2)
         ON CONFLICT(channel_id) DO UPDATE SET min_talk_power = $3",
    )
    .bind(&channel_id)
    .bind(req.min_talk_power)
    .bind(req.min_talk_power)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::OK)
}

pub async fn get_talk_power(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<TalkPowerResponse>, (StatusCode, String)> {
    let min_talk_power: i64 =
        sqlx::query_scalar("SELECT min_talk_power FROM channel_settings WHERE channel_id = $1")
            .bind(&channel_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .unwrap_or(0);

    Ok(Json(TalkPowerResponse {
        channel_id,
        min_talk_power,
    }))
}

// --- Channel-scoped bans (routes under /channels/:id/bans, pubkey field) ---

pub async fn channel_ban_v2(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<ChannelBanByPubkeyRequest>,
) -> Result<(StatusCode, Json<ChannelBanByPubkeyResponse>), (StatusCode, String)> {
    require_can_moderate(&state, &user.public_key, &req.pubkey, BAN_MEMBERS).await?;

    let now = crate::auth::handlers::unix_timestamp().to_string();

    sqlx::query(
        "INSERT INTO channel_bans (channel_id, target_public_key, banned_by, reason, created_at) VALUES ($1, $2, $3, NULL, $4)
         ON CONFLICT (channel_id, target_public_key) DO UPDATE SET banned_by = excluded.banned_by, reason = excluded.reason, created_at = excluded.created_at",
    )
    .bind(&channel_id)
    .bind(&req.pubkey)
    .bind(&user.public_key)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(ChannelBanByPubkeyResponse {
            channel_id,
            pubkey: req.pubkey,
            banned_by: user.public_key,
            banned_at: now,
        }),
    ))
}

pub async fn channel_unban_v2(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, pubkey)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(BAN_MEMBERS)?;

    sqlx::query("DELETE FROM channel_bans WHERE channel_id = $1 AND target_public_key = $2")
        .bind(&channel_id)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_channel_bans_v2(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<ChannelBanByPubkeyResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(BAN_MEMBERS)?;

    let rows = sqlx::query_as::<_, ChannelBanRow>(
        "SELECT channel_id, target_public_key, banned_by, reason, created_at
         FROM channel_bans WHERE channel_id = $1 ORDER BY created_at DESC",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ChannelBanByPubkeyResponse {
                channel_id: r.channel_id,
                pubkey: r.target_public_key,
                banned_by: r.banned_by,
                banned_at: r.created_at.to_string(),
            })
            .collect(),
    ))
}

// --- Per-channel voice mutes ---

pub async fn channel_voice_mute(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<ChannelVoiceMuteRequest>,
) -> Result<(StatusCode, Json<ChannelVoiceMuteResponse>), (StatusCode, String)> {
    require_can_moderate(&state, &user.public_key, &req.pubkey, MUTE_MEMBERS).await?;

    let now = crate::auth::handlers::unix_timestamp().to_string();

    sqlx::query(
        "INSERT INTO channel_voice_mutes (channel_id, pubkey, muted_by, muted_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT (channel_id, pubkey) DO UPDATE SET muted_by = excluded.muted_by, muted_at = excluded.muted_at",
    )
    .bind(&channel_id)
    .bind(&req.pubkey)
    .bind(&user.public_key)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(ChannelVoiceMuteResponse {
            channel_id,
            pubkey: req.pubkey,
            muted_by: user.public_key,
            muted_at: now,
        }),
    ))
}

pub async fn channel_voice_unmute(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, pubkey)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    sqlx::query("DELETE FROM channel_voice_mutes WHERE channel_id = $1 AND pubkey = $2")
        .bind(&channel_id)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_channel_voice_mutes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<ChannelVoiceMuteResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    #[derive(sqlx::FromRow)]
    struct Row {
        channel_id: String,
        pubkey: String,
        muted_by: String,
        muted_at: String,
    }

    let rows = sqlx::query_as::<_, Row>(
        "SELECT channel_id, pubkey, muted_by, muted_at FROM channel_voice_mutes WHERE channel_id = $1 ORDER BY muted_at DESC",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| ChannelVoiceMuteResponse {
                channel_id: r.channel_id,
                pubkey: r.pubkey,
                muted_by: r.muted_by,
                muted_at: r.muted_at,
            })
            .collect(),
    ))
}

// --- Raise-hand ---

pub async fn raise_hand(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<(StatusCode, Json<RaiseHandResponse>), (StatusCode, String)> {
    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp().to_string();

    sqlx::query(
        "INSERT INTO raise_hand_requests (id, channel_id, pubkey, requested_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT (channel_id, pubkey) DO UPDATE SET id = excluded.id, requested_at = excluded.requested_at",
    )
    .bind(&id)
    .bind(&channel_id)
    .bind(&user.public_key)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(RaiseHandResponse {
            id,
            channel_id,
            pubkey: user.public_key,
            requested_at: now,
        }),
    ))
}

pub async fn lower_hand(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, pubkey)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    // User can lower their own hand; admin can lower anyone's
    if pubkey != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(MUTE_MEMBERS)?;
    }

    sqlx::query("DELETE FROM raise_hand_requests WHERE channel_id = $1 AND pubkey = $2")
        .bind(&channel_id)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_raise_hands(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<RaiseHandResponse>>, (StatusCode, String)> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: String,
        channel_id: String,
        pubkey: String,
        requested_at: String,
    }

    let rows = sqlx::query_as::<_, Row>(
        "SELECT id, channel_id, pubkey, requested_at FROM raise_hand_requests WHERE channel_id = $1 ORDER BY requested_at ASC",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| RaiseHandResponse {
                id: r.id,
                channel_id: r.channel_id,
                pubkey: r.pubkey,
                requested_at: r.requested_at,
            })
            .collect(),
    ))
}
