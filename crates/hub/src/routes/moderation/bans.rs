use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, BAN_MEMBERS, KICK_MEMBERS, MUTE_MEMBERS, TIMEOUT_MEMBERS};
use crate::routes::moderation_models::*;
use crate::state::AppState;

use super::models::{require_can_moderate, BanRow, MuteRow};

/// Membership ends on kick/ban: strip the target's roles (member = has
/// roles; /users hides role-less non-bots) and tell connected clients to
/// refresh their member list. The users row is deliberately kept so old
/// messages stay attributed.
async fn end_membership(state: &AppState, target: &str) -> Result<(), (StatusCode, String)> {
    sqlx::query("DELETE FROM user_roles WHERE user_public_key = $1")
        .bind(target)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // MemberOffline prompts clients to drop/grey the row now; the next
    // /users refetch removes them entirely.
    let ws_msg = crate::routes::chat_models::WsServerMessage::MemberOffline {
        public_key: target.to_string(),
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
    let _ = state.chat_tx.send((
        crate::routes::chat_models::ChatEvent::MemberOffline {
            public_key: target.to_string(),
        },
        json,
    ));
    Ok(())
}

// --- Ban ---

pub async fn ban_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<BanRequest>,
) -> Result<(StatusCode, Json<BanResponse>), (StatusCode, String)> {
    require_can_moderate(
        &state,
        &user.public_key,
        &req.target_public_key,
        BAN_MEMBERS,
    )
    .await?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO bans (target_public_key, banned_by, reason, created_at) VALUES ($1, $2, $3, $4)
         ON CONFLICT (target_public_key) DO UPDATE SET banned_by = excluded.banned_by, reason = excluded.reason, created_at = excluded.created_at",
    )
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Delete their sessions so they're immediately logged out
    sqlx::query("DELETE FROM sessions WHERE public_key = $1")
        .bind(&req.target_public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    end_membership(&state, &req.target_public_key).await?;

    tracing::info!("Banned user: {}", &req.target_public_key[..16]);

    // Publish member.banned audit event.
    {
        let state_c = state.clone();
        let actor = user.public_key.clone();
        let target = req.target_public_key.clone();
        let reason = req.reason.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "member.banned",
                Some(&actor),
                Some(&target),
                None,
                serde_json::json!({ "reason": reason }),
            )
            .await;
        });
    }

    Ok((
        StatusCode::CREATED,
        Json(BanResponse {
            target_public_key: req.target_public_key,
            banned_by: user.public_key,
            reason: req.reason,
            created_at: now,
        }),
    ))
}

pub async fn unban_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(target_key): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(BAN_MEMBERS)?;

    sqlx::query("DELETE FROM bans WHERE target_public_key = $1")
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_bans(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<BanResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(BAN_MEMBERS)?;

    let rows = sqlx::query_as::<_, BanRow>(
        "SELECT target_public_key, banned_by, reason, created_at FROM bans ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| BanResponse {
                target_public_key: r.target_public_key,
                banned_by: r.banned_by,
                reason: r.reason,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

// --- Mute ---

pub async fn mute_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<MuteRequest>,
) -> Result<(StatusCode, Json<MuteResponse>), (StatusCode, String)> {
    require_can_moderate(
        &state,
        &user.public_key,
        &req.target_public_key,
        MUTE_MEMBERS,
    )
    .await?;

    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO mutes (target_public_key, muted_by, reason, expires_at, created_at) VALUES ($1, $2, $3, NULL, $4)
         ON CONFLICT (target_public_key) DO UPDATE SET muted_by = excluded.muted_by, reason = excluded.reason, expires_at = excluded.expires_at, created_at = excluded.created_at",
    )
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!("Muted user: {}", &req.target_public_key[..16]);

    Ok((
        StatusCode::CREATED,
        Json(MuteResponse {
            target_public_key: req.target_public_key,
            muted_by: user.public_key,
            reason: req.reason,
            expires_at: None,
            created_at: now,
        }),
    ))
}

pub async fn unmute_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(target_key): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    sqlx::query("DELETE FROM mutes WHERE target_public_key = $1")
        .bind(&target_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_mutes(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<MuteResponse>>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(MUTE_MEMBERS)?;

    let rows = sqlx::query_as::<_, MuteRow>(
        "SELECT target_public_key, muted_by, reason, expires_at, created_at FROM mutes ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(
        rows.into_iter()
            .map(|r| MuteResponse {
                target_public_key: r.target_public_key,
                muted_by: r.muted_by,
                reason: r.reason,
                expires_at: r.expires_at,
                created_at: r.created_at,
            })
            .collect(),
    ))
}

// --- Timeout ---

pub async fn timeout_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<TimeoutRequest>,
) -> Result<(StatusCode, Json<MuteResponse>), (StatusCode, String)> {
    require_can_moderate(
        &state,
        &user.public_key,
        &req.target_public_key,
        TIMEOUT_MEMBERS,
    )
    .await?;

    let now = crate::auth::handlers::unix_timestamp();
    let expires_at = now + req.duration_seconds as i64;

    sqlx::query(
        "INSERT INTO mutes (target_public_key, muted_by, reason, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (target_public_key) DO UPDATE SET muted_by = excluded.muted_by, reason = excluded.reason, expires_at = excluded.expires_at, created_at = excluded.created_at",
    )
    .bind(&req.target_public_key)
    .bind(&user.public_key)
    .bind(&req.reason)
    .bind(expires_at)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tracing::info!(
        "Timed out user: {} for {}s",
        &req.target_public_key[..16],
        req.duration_seconds
    );

    Ok((
        StatusCode::CREATED,
        Json(MuteResponse {
            target_public_key: req.target_public_key,
            muted_by: user.public_key,
            reason: req.reason,
            expires_at: Some(expires_at),
            created_at: now,
        }),
    ))
}

// --- Kick ---

pub async fn kick_user(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<KickRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_can_moderate(
        &state,
        &user.public_key,
        &req.target_public_key,
        KICK_MEMBERS,
    )
    .await?;

    // Delete their sessions to force re-auth
    sqlx::query("DELETE FROM sessions WHERE public_key = $1")
        .bind(&req.target_public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Strip membership. On re-auth the target is treated as a brand-new
    // joiner (initial roles reassigned; invite required on invite-only
    // hubs) — exactly what "kick" should mean.
    end_membership(&state, &req.target_public_key).await?;

    tracing::info!("Kicked user: {}", &req.target_public_key[..16]);

    // Publish member.kicked audit event.
    {
        let state_c = state.clone();
        let actor = user.public_key.clone();
        let target = req.target_public_key.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "member.kicked",
                Some(&actor),
                Some(&target),
                None,
                serde_json::json!({}),
            )
            .await;
        });
    }

    Ok(StatusCode::OK)
}
