use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::bot_models::{BotCommandDef, GameLaunchCard};
use crate::state::AppState;

use super::models::{
    AcceptInviteRequest, AcceptInviteResponse, BotCommandRow, BotCommandSummary, BotListEntry,
    BotMeResponse, BotProfileRow, InviteBotRequest, InviteBotResponse, SetSubscriptionsResponse,
    UpdateCommandsRequest, UpdateSubscriptionsRequest,
};

/// Decode a `bot_profiles.game` JSON column into a `GameLaunchCard`.
/// Absent/invalid JSON reads back as `None` -- same "best-effort optional
/// column" behavior as `parse_game` in routes/messages.rs.
fn parse_game(json: Option<String>) -> Option<GameLaunchCard> {
    json.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
}

// ---- Handler: POST /bots — admin invites external bot by pubkey ----

pub async fn ext_invite_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<InviteBotRequest>,
) -> Result<Json<InviteBotResponse>, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    if !perms.has(permissions::MANAGE_ROLES) && !perms.has(permissions::ADMIN) {
        return Err((
            StatusCode::FORBIDDEN,
            "Missing permission: manage_roles".to_string(),
        ));
    }

    // Validate the pubkey looks like a 64-hex-char Ed25519 pubkey.
    if req.pubkey.len() != 64 || !req.pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "pubkey must be 64 hex characters".to_string(),
        ));
    }

    let now = crate::auth::handlers::unix_timestamp();

    // Create the pending users row (idempotent so re-inviting is safe).
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at, approval_status, is_bot)
         VALUES ($1, $2, $3, 'bot_pending', TRUE) ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(&req.pubkey)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Generate a 32-byte random invite token.
    let token = {
        use rand::RngCore;
        let mut bytes = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let expires = now + 86400; // 24 hours

    sqlx::query(
        "UPDATE users SET bot_invite_token = $1, bot_invite_expires = $2 WHERE public_key = $3",
    )
    .bind(&token)
    .bind(expires)
    .bind(&req.pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(InviteBotResponse {
        invite_token: token,
    }))
}

// ---- Handler: POST /bots/accept-invite — bot accepts an invite ----

pub async fn ext_accept_invite(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AcceptInviteRequest>,
) -> Result<Json<AcceptInviteResponse>, (StatusCode, String)> {
    let row: Option<(Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT bot_invite_token, bot_invite_expires FROM users WHERE public_key = $1 AND is_bot = TRUE",
    )
    .bind(&req.pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (stored_token, expires) = row.ok_or((
        StatusCode::NOT_FOUND,
        "Bot not found or not invited".to_string(),
    ))?;

    let stored_token = stored_token.ok_or((
        StatusCode::NOT_FOUND,
        "No pending invite for this bot".to_string(),
    ))?;

    let now = crate::auth::handlers::unix_timestamp();
    if let Some(exp) = expires {
        if now > exp {
            return Err((StatusCode::GONE, "Invite token has expired".to_string()));
        }
    }

    // Verify the bot signed the raw token bytes with its Ed25519 private key.
    let token_bytes = stored_token.as_bytes();
    let sig_bytes = hex::decode(&req.signature_over_token)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature hex".to_string()))?;
    wavvon_identity::verify_signature(&req.pubkey, token_bytes, &sig_bytes).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid signature over invite token".to_string(),
        )
    })?;

    // Approve and clear the invite token.
    sqlx::query(
        "UPDATE users SET approval_status = 'approved', bot_invite_token = NULL, bot_invite_expires = NULL
         WHERE public_key = $1",
    )
    .bind(&req.pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Upsert bot_profiles.
    let meta = &req.bot_meta;
    let game_json = meta
        .game
        .as_ref()
        .map(|g| serde_json::to_string(g).unwrap_or_default());
    sqlx::query(
        "INSERT INTO bot_profiles(pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities, mini_app_url, requires_camera, game, updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT(pubkey) DO UPDATE SET
           name=excluded.name, avatar_url=excluded.avatar_url,
           description=excluded.description, webhook_url=excluded.webhook_url,
           homepage_url=excluded.homepage_url, capabilities=excluded.capabilities,
           mini_app_url=excluded.mini_app_url, requires_camera=excluded.requires_camera,
           game=excluded.game,
           updated_at=excluded.updated_at",
    )
    .bind(&req.pubkey)
    .bind(&meta.name)
    .bind(&meta.avatar_url)
    .bind(&meta.description)
    .bind(&meta.webhook_url)
    .bind(&meta.homepage_url)
    .bind(serde_json::to_string(&meta.capabilities.as_deref().unwrap_or(&[])).unwrap())
    .bind(&meta.mini_app_url)
    .bind(meta.requires_camera.unwrap_or(false))
    .bind(&game_json)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Replace commands if provided.
    if let Some(cmds) = &meta.commands {
        sqlx::query("DELETE FROM bot_commands WHERE pubkey = $1")
            .bind(&req.pubkey)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        for cmd in cmds {
            sqlx::query(
                "INSERT INTO bot_commands(pubkey,name,description,args,scope,privileged,cooldown_seconds)
                 VALUES($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(&req.pubkey)
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
    }

    Ok(Json(AcceptInviteResponse {
        status: "accepted".to_string(),
    }))
}

// ---- Handler: DELETE /bots/:pubkey — admin removes a bot ----

pub async fn ext_remove_bot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(pubkey): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::ADMIN)?;

    sqlx::query("UPDATE users SET is_bot_removed = TRUE WHERE public_key = $1 AND is_bot = TRUE")
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ---- Handler: GET /bots — list bots (any member) ----

pub async fn ext_list_bots(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
) -> Result<Json<Vec<BotListEntry>>, (StatusCode, String)> {
    #[derive(sqlx::FromRow)]
    struct BotListRow {
        pubkey: String,
        name: String,
        avatar_url: Option<String>,
        description: Option<String>,
        last_seen_at: Option<i64>,
        webhook_url: Option<String>,
        game: Option<String>,
    }

    let rows = sqlx::query_as::<_, BotListRow>(
        "SELECT u.public_key as pubkey, bp.name, bp.avatar_url, bp.description,
                u.last_seen_at, bp.webhook_url, bp.game
         FROM users u
         JOIN bot_profiles bp ON bp.pubkey = u.public_key
         WHERE u.is_bot = TRUE AND u.is_bot_removed = FALSE",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let cmds = sqlx::query_as::<_, (String, String)>(
            "SELECT name, description FROM bot_commands WHERE pubkey = $1 ORDER BY name",
        )
        .bind(&row.pubkey)
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

        entries.push(BotListEntry {
            pubkey: row.pubkey,
            name: row.name,
            avatar_url: row.avatar_url,
            description: row.description,
            last_seen_at: row.last_seen_at,
            webhook_url: row.webhook_url,
            game: parse_game(row.game),
            commands: cmds
                .into_iter()
                .map(|(name, description)| BotCommandSummary { name, description })
                .collect(),
        });
    }

    Ok(Json(entries))
}

// ---- Handler: GET /bots/me — bot fetches its own profile ----

pub async fn ext_bot_me(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<BotMeResponse>, (StatusCode, String)> {
    // Verify caller is a bot.
    let is_bot: Option<bool> = sqlx::query_scalar("SELECT is_bot FROM users WHERE public_key = $1")
        .bind(&user.public_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .flatten();

    if is_bot != Some(true) {
        return Err((StatusCode::FORBIDDEN, "Not a bot identity".to_string()));
    }

    let profile = sqlx::query_as::<_, BotProfileRow>(
        "SELECT pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities
         FROM bot_profiles WHERE pubkey = $1",
    )
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Bot profile not found".to_string()))?;

    let cmds = sqlx::query_as::<_, BotCommandRow>(
        "SELECT name, description, args, scope, privileged, cooldown_seconds
         FROM bot_commands WHERE pubkey = $1 ORDER BY name",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let capabilities: Vec<String> = serde_json::from_str(&profile.capabilities).unwrap_or_default();

    Ok(Json(BotMeResponse {
        pubkey: profile.pubkey,
        name: profile.name,
        avatar_url: profile.avatar_url,
        description: profile.description,
        webhook_url: profile.webhook_url,
        homepage_url: profile.homepage_url,
        capabilities,
        commands: cmds
            .into_iter()
            .map(|c| BotCommandDef {
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

// ---- Handler: PUT /bots/me/profile — bot updates its own profile ----

pub async fn ext_update_bot_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(meta): Json<crate::routes::bot_models::BotMeta>,
) -> Result<Json<BotMeResponse>, (StatusCode, String)> {
    let is_bot: Option<bool> = sqlx::query_scalar("SELECT is_bot FROM users WHERE public_key = $1")
        .bind(&user.public_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .flatten();

    if is_bot != Some(true) {
        return Err((StatusCode::FORBIDDEN, "Not a bot identity".to_string()));
    }

    let now = crate::auth::handlers::unix_timestamp();
    let game_json = meta
        .game
        .as_ref()
        .map(|g| serde_json::to_string(g).unwrap_or_default());
    sqlx::query(
        "INSERT INTO bot_profiles(pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities, mini_app_url, requires_camera, game, updated_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
         ON CONFLICT(pubkey) DO UPDATE SET
           name=excluded.name, avatar_url=excluded.avatar_url,
           description=excluded.description, webhook_url=excluded.webhook_url,
           homepage_url=excluded.homepage_url, capabilities=excluded.capabilities,
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
    .bind(serde_json::to_string(&meta.capabilities.as_deref().unwrap_or(&[])).unwrap())
    .bind(&meta.mini_app_url)
    .bind(meta.requires_camera.unwrap_or(false))
    .bind(&game_json)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Reload and return.
    ext_bot_me(State(state), user).await
}

// ---- Handler: PUT /bots/me/commands — bot replaces its command list ----

pub async fn ext_update_bot_commands(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateCommandsRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let is_bot: Option<bool> = sqlx::query_scalar("SELECT is_bot FROM users WHERE public_key = $1")
        .bind(&user.public_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .flatten();

    if is_bot != Some(true) {
        return Err((StatusCode::FORBIDDEN, "Not a bot identity".to_string()));
    }

    sqlx::query("DELETE FROM bot_commands WHERE pubkey = $1")
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for cmd in &req.commands {
        sqlx::query(
            "INSERT INTO bot_commands(pubkey,name,description,args,scope,privileged,cooldown_seconds)
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

// ---- Handler: PUT /bots/me/subscriptions — bot replaces its event subscriptions ----

pub async fn ext_update_bot_subscriptions(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<UpdateSubscriptionsRequest>,
) -> Result<Json<SetSubscriptionsResponse>, (StatusCode, String)> {
    let is_bot: Option<bool> = sqlx::query_scalar("SELECT is_bot FROM users WHERE public_key = $1")
        .bind(&user.public_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .flatten();

    if is_bot != Some(true) {
        return Err((StatusCode::FORBIDDEN, "Not a bot identity".to_string()));
    }

    // Validate: message.* events require an explicit channels list.
    for sub in &req.subscriptions {
        let is_message_event =
            sub.event.starts_with("message.") && sub.event != "message.mention_bot"; // mention_bot is hub-scoped, no channels needed
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
    sqlx::query("DELETE FROM bot_subscriptions WHERE bot_pubkey = $1")
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
                        "INSERT INTO bot_subscriptions(bot_pubkey, event_type, channel_id)
                         VALUES($1,$2,$3) ON CONFLICT (bot_pubkey, event_type, channel_id) DO NOTHING",
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
                // Hub-scoped subscription: use '' as sentinel for "no channel filter".
                sqlx::query(
                    "INSERT INTO bot_subscriptions(bot_pubkey, event_type, channel_id)
                     VALUES($1,$2,'') ON CONFLICT (bot_pubkey, event_type, channel_id) DO NOTHING",
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
