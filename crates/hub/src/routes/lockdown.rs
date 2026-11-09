//! Raid response (Wavvon-server#316): one switch that stops new members
//! joining, optionally holds back the ones who joined just before it, and a
//! join-rate alert that can throw the switch by itself.
//!
//! Settings live in `hub_settings`: `lockdown`, `lockdown_freeze_minutes`,
//! `raid_join_threshold` (joins per minute, 0 = no alert) and
//! `raid_auto_lockdown`. Every change and every alert is a hub event, so it
//! lands in the audit log and reaches subscribed apps and webhooks.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, MODERATION_SETTINGS};
use crate::routes::hub::{read_setting, upsert_setting};
use crate::state::AppState;

#[derive(Serialize, Deserialize, Default)]
pub struct LockdownSettings {
    pub enabled: bool,
    /// While enabled, members who joined within this many minutes cannot
    /// post. 0 = nobody is held back.
    pub freeze_minutes: i64,
    /// Joins in one minute that raise a raid alert. 0 = no alert.
    pub raid_join_threshold: i64,
    /// Turn lockdown on when the alert fires.
    pub auto_lockdown: bool,
}

async fn num(db: &sqlx::PgPool, key: &str) -> i64 {
    read_setting(db, key)
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

pub async fn load(db: &sqlx::PgPool) -> LockdownSettings {
    LockdownSettings {
        enabled: read_setting(db, "lockdown").await.as_deref() == Some("true"),
        freeze_minutes: num(db, "lockdown_freeze_minutes").await,
        raid_join_threshold: num(db, "raid_join_threshold").await,
        auto_lockdown: read_setting(db, "raid_auto_lockdown").await.as_deref() == Some("true"),
    }
}

/// GET /admin/settings/lockdown
pub async fn get_lockdown(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<LockdownSettings>, (StatusCode, String)> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(MODERATION_SETTINGS)?;
    Ok(Json(load(&state.db).await))
}

/// PUT /admin/settings/lockdown — replaces all four settings.
pub async fn put_lockdown(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<LockdownSettings>,
) -> Result<Json<LockdownSettings>, (StatusCode, String)> {
    permissions::user_permissions(&state.db, &user.public_key)
        .await?
        .require(MODERATION_SETTINGS)?;
    if !(0..=1440).contains(&req.freeze_minutes) || !(0..=10_000).contains(&req.raid_join_threshold)
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "freeze_minutes must be 0-1440 and raid_join_threshold 0-10000".to_string(),
        ));
    }
    let was = load(&state.db).await;
    upsert_setting(
        &state.db,
        "lockdown",
        if req.enabled { "true" } else { "false" },
    )
    .await?;
    upsert_setting(
        &state.db,
        "lockdown_freeze_minutes",
        &req.freeze_minutes.to_string(),
    )
    .await?;
    upsert_setting(
        &state.db,
        "raid_join_threshold",
        &req.raid_join_threshold.to_string(),
    )
    .await?;
    upsert_setting(
        &state.db,
        "raid_auto_lockdown",
        if req.auto_lockdown { "true" } else { "false" },
    )
    .await?;
    if was.enabled != req.enabled {
        crate::apps::events::publish_hub_event(
            &state,
            "hub.lockdown",
            Some(&user.public_key),
            None,
            None,
            serde_json::json!({ "enabled": req.enabled, "automatic": false }),
        )
        .await;
    }
    Ok(Json(req))
}

/// Refuse to admit a new member while the hub is locked down. An identity
/// that is already a member passes: the switch is about arrivals.
pub async fn refuse_if_locked(
    db: &sqlx::PgPool,
    public_key: &str,
) -> Result<(), (StatusCode, String)> {
    if read_setting(db, "lockdown").await.as_deref() != Some("true") {
        return Ok(());
    }
    let member: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT is_member FROM users WHERE public_key = $1), FALSE)",
    )
    .bind(public_key)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if member {
        return Ok(());
    }
    Err((
        StatusCode::FORBIDDEN,
        "This hub is not admitting new members right now".to_string(),
    ))
}

/// During lockdown, hold back members who joined within the freeze window,
/// moderators excepted.
pub async fn refuse_if_frozen(
    db: &sqlx::PgPool,
    public_key: &str,
) -> Result<(), (StatusCode, String)> {
    let settings = load(db).await;
    if !settings.enabled || settings.freeze_minutes <= 0 {
        return Ok(());
    }
    let since = crate::auth::handlers::unix_timestamp() - settings.freeze_minutes * 60;
    let recent: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT first_seen_at > $2 FROM users WHERE public_key = $1), FALSE)",
    )
    .bind(public_key)
    .bind(since)
    .fetch_one(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    // Moderators answering the raid are exempt, however new.
    let moderator = permissions::user_permissions(db, public_key)
        .await
        .is_ok_and(|p| p.has(permissions::MODERATION_MUTE));
    if recent && !moderator {
        return Err((
            StatusCode::FORBIDDEN,
            "New members cannot post while the hub is locked down".to_string(),
        ));
    }
    Ok(())
}

/// When the last raid alert fired, so a raid raises one alert, not one per
/// joiner.
static LAST_ALERT: AtomicI64 = AtomicI64::new(0);
const ALERT_COOLDOWN_SECS: i64 = 600;

/// After a join: count the last minute's joins and raise the alert (and,
/// when configured, the lockdown) once the threshold is met.
pub async fn after_join(state: &Arc<AppState>) {
    let settings = load(&state.db).await;
    if settings.raid_join_threshold <= 0 {
        return;
    }
    let now = crate::auth::handlers::unix_timestamp();
    let joins: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_member AND first_seen_at > $1")
            .bind(now - 60)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
    if joins < settings.raid_join_threshold {
        return;
    }
    let last = LAST_ALERT.load(Ordering::Relaxed);
    if now - last < ALERT_COOLDOWN_SECS
        || LAST_ALERT
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    tracing::warn!(joins, "Raid alert: {joins} joins in the last minute");
    crate::apps::events::publish_hub_event(
        state,
        "raid.suspected",
        None,
        None,
        None,
        serde_json::json!({ "joins_last_minute": joins, "threshold": settings.raid_join_threshold }),
    )
    .await;
    if settings.auto_lockdown && !settings.enabled {
        let _ = upsert_setting(&state.db, "lockdown", "true").await;
        crate::apps::events::publish_hub_event(
            state,
            "hub.lockdown",
            None,
            None,
            None,
            serde_json::json!({ "enabled": true, "automatic": true }),
        )
        .await;
    }
}
