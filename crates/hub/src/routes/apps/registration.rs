//! App registration: what a member running a program tells the hub about it.
//!
//! There is no bot account and no bot admission path. A program authenticates
//! on the ordinary session flow with an ordinary invite, and these routes let
//! the identity behind it declare a profile, the slash commands it answers,
//! and the events it wants pushed. Every one of them is self-service and
//! self-scoped — the caller writes its own rows, never another identity's —
//! and gated on `apps.register`, because an embed or a launch card nobody
//! vouched for is a forgery with a nice border.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::app_models::{AppCommandDef, GameLaunchCard};
use crate::state::AppState;

use super::models::{
    AppCommandOwnerRow, AppCommandRow, AppCommandSummary, AppDirectoryRow, AppListEntry,
    AppMeResponse, AppProfileRow, SetSubscriptionsResponse, UpdateCommandsRequest,
    UpdateSubscriptionsRequest,
};

/// `apps.register` or nothing. Resolved once per call rather than cached on
/// the session: a role can be taken away between two requests, and the next
/// write must feel it.
async fn require_app_registrar(
    state: &AppState,
    user: &AuthUser,
) -> Result<(), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::APPS_REGISTER)
}

/// GET /apps — the apps registered on this hub, for any member.
///
/// A client needs this for the slash-command list it offers while typing:
/// the commands live in `app_commands`, and without a way to read them the
/// autocomplete has nothing to autocomplete. Readable by any session, since
/// what it returns is what an app already says about itself in public —
/// registering one is the gated act, listing them is not.
pub async fn list_apps(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<AppListEntry>>, (StatusCode, String)> {
    let profiles = sqlx::query_as::<_, AppDirectoryRow>(
        "SELECT pubkey, name, avatar_url, description, game
         FROM app_profiles ORDER BY name, pubkey",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let commands = sqlx::query_as::<_, AppCommandOwnerRow>(
        "SELECT pubkey, name, description FROM app_commands ORDER BY pubkey, name",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut by_pubkey: HashMap<String, Vec<AppCommandSummary>> = HashMap::new();
    for c in commands {
        by_pubkey
            .entry(c.pubkey)
            .or_default()
            .push(AppCommandSummary {
                name: c.name,
                description: c.description,
            });
    }

    Ok(Json(
        profiles
            .into_iter()
            .map(|p| AppListEntry {
                commands: by_pubkey.remove(&p.pubkey).unwrap_or_default(),
                game: parse_game(p.game),
                pubkey: p.pubkey,
                name: p.name,
                avatar_url: p.avatar_url,
                description: p.description,
            })
            .collect(),
    ))
}

/// Decode an `app_profiles.game` JSON column. A malformed value reads back as
/// no launch card rather than failing the listing — same "best-effort
/// optional column" behaviour as `parse_game` in routes/messages.rs.
fn parse_game(json: Option<String>) -> Option<GameLaunchCard> {
    json.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
}

/// GET /me/app — the caller's own app registration.
pub async fn get_my_app(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<AppMeResponse>, (StatusCode, String)> {
    require_app_registrar(&state, &user).await?;

    let profile = sqlx::query_as::<_, AppProfileRow>(
        "SELECT pubkey, name, avatar_url, description, webhook_url, homepage_url
         FROM app_profiles WHERE pubkey = $1",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((
        StatusCode::NOT_FOUND,
        "No app registered for this identity".to_string(),
    ))?;

    let cmds = sqlx::query_as::<_, AppCommandRow>(
        "SELECT name, description, args, scope, privileged, cooldown_seconds
         FROM app_commands WHERE pubkey = $1 ORDER BY name",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(AppMeResponse {
        pubkey: profile.pubkey,
        name: profile.name,
        avatar_url: profile.avatar_url,
        description: profile.description,
        webhook_url: profile.webhook_url,
        homepage_url: profile.homepage_url,
        commands: cmds
            .into_iter()
            .map(|c| AppCommandDef {
                name: c.name,
                description: c.description,
                args: c.args,
                scope: Some(c.scope),
                privileged: Some(c.privileged),
                cooldown_seconds: Some(c.cooldown_seconds),
            })
            .collect(),
    }))
}

/// PUT /me/app/profile — register or replace the caller's own app profile.
pub async fn put_my_app_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(meta): Json<crate::routes::app_models::AppMeta>,
) -> Result<Json<AppMeResponse>, (StatusCode, String)> {
    require_app_registrar(&state, &user).await?;

    let now = crate::auth::handlers::unix_timestamp();
    let game_json = meta
        .game
        .as_ref()
        .map(|g| serde_json::to_string(g).unwrap_or_default());
    sqlx::query(
        "INSERT INTO app_profiles(pubkey, name, avatar_url, description, webhook_url, homepage_url, mini_app_url, requires_camera, game, updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT(pubkey) DO UPDATE SET
           name=excluded.name, avatar_url=excluded.avatar_url,
           description=excluded.description, webhook_url=excluded.webhook_url,
           homepage_url=excluded.homepage_url,
           mini_app_url=excluded.mini_app_url, requires_camera=excluded.requires_camera,
           game=excluded.game,
           updated_at=excluded.updated_at",
    )
    .bind(&user.public_key)
    .bind(&meta.name)
    .bind(&meta.avatar_url)
    .bind(&meta.description)
    .bind(&meta.webhook_url)
    .bind(&meta.homepage_url)
    .bind(&meta.mini_app_url)
    .bind(meta.requires_camera.unwrap_or(false))
    .bind(&game_json)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    get_my_app(State(state), user).await
}

/// PUT /me/app/commands — replace the caller's slash command list.
pub async fn put_my_app_commands(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateCommandsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_app_registrar(&state, &user).await?;

    sqlx::query("DELETE FROM app_commands WHERE pubkey = $1")
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for cmd in &req.commands {
        sqlx::query(
            "INSERT INTO app_commands(pubkey,name,description,args,scope,privileged,cooldown_seconds)
             VALUES($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(&user.public_key)
        .bind(&cmd.name)
        .bind(&cmd.description)
        .bind(&cmd.args)
        .bind(cmd.scope.as_deref().unwrap_or("channel"))
        .bind(cmd.privileged.unwrap_or(false))
        .bind(cmd.cooldown_seconds.unwrap_or(3))
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    Ok(StatusCode::OK)
}

/// PUT /me/app/subscriptions — replace the caller's event subscriptions.
pub async fn put_my_app_subscriptions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateSubscriptionsRequest>,
) -> Result<Json<SetSubscriptionsResponse>, (StatusCode, String)> {
    require_app_registrar(&state, &user).await?;

    // `message.*` fans out content, so it is per channel by construction: a
    // hub-wide subscription to it would be a firehose of every conversation.
    for sub in &req.subscriptions {
        let is_message_event = sub.event.starts_with("message.") && sub.event != "message.mention";
        if is_message_event && sub.channels.as_ref().is_none_or(|v| v.is_empty()) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Subscription '{}' requires an explicit channels list",
                    sub.event
                ),
            ));
        }
    }

    // Replace atomically: delete all, insert new.
    sqlx::query("DELETE FROM app_subscriptions WHERE app_pubkey = $1")
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut count = 0usize;
    for sub in &req.subscriptions {
        match &sub.channels {
            Some(channels) if !channels.is_empty() => {
                for channel_id in channels {
                    sqlx::query(
                        "INSERT INTO app_subscriptions(app_pubkey, event_type, channel_id)
                         VALUES($1,$2,$3) ON CONFLICT (app_pubkey, event_type, channel_id) DO NOTHING",
                    )
                    .bind(&user.public_key)
                    .bind(&sub.event)
                    .bind(channel_id)
                    .execute(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                    count += 1;
                }
            }
            _ => {
                // Hub-scoped subscription: '' is the "no channel filter" sentinel.
                sqlx::query(
                    "INSERT INTO app_subscriptions(app_pubkey, event_type, channel_id)
                     VALUES($1,$2,'') ON CONFLICT (app_pubkey, event_type, channel_id) DO NOTHING",
                )
                .bind(&user.public_key)
                .bind(&sub.event)
                .execute(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
                count += 1;
            }
        }
    }

    Ok(Json(SetSubscriptionsResponse { count }))
}
