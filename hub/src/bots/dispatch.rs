use std::sync::Arc;

use axum::http::StatusCode;
use uuid::Uuid;

use crate::routes::bot_models::{AuthorInfo, BotResponse, SlashInvocation};
use crate::routes::chat_models::{ChatEvent, MessageResponse};
use crate::state::AppState;

/// Hub URL placeholder — in production this comes from hub config. We read it
/// from a hub_settings key 'hub_url' if present, else fall back to a placeholder.
/// This is a design note: a proper hub_url config key should be set by the
/// operator; for v1 we read it from settings gracefully.
async fn hub_url(state: &AppState) -> String {
    sqlx::query_scalar::<_, String>("SELECT value FROM hub_settings WHERE key = 'hub_url'")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| "https://unknown-hub".to_string())
}

/// Detect a slash command in the message content and, if a registered bot
/// handles it, dispatch the invocation to the bot's webhook.
///
/// Returns:
/// - `None`  — no bot command matched; caller stores the message normally.
/// - `Some(ephemeral_error)` — a command matched but an error occurred; the
///   caller should store an ephemeral error message and return early without
///   storing the original message.
///
/// When the bot responds with a reply, that reply is inserted into the DB
/// here and broadcast via `state.chat_tx` so WS clients receive it.
pub async fn dispatch_slash(
    state: &Arc<AppState>,
    channel_id: &str,
    invoker_pubkey: &str,
    content: &str,
) -> Option<String> {
    if !content.starts_with('/') {
        return None;
    }

    // Parse command name and args.
    let rest = &content[1..];
    let mut parts = rest.splitn(2, ' ');
    let command_name = parts.next().unwrap_or("").to_lowercase();
    let args_raw = parts.next().unwrap_or("").to_string();

    if command_name.is_empty() {
        return None;
    }

    // Look up a matching command. If bot_channel_scope has any rows for this
    // bot, the channel must be listed there. We join bot_profiles to get the
    // webhook URL and bot name.
    #[derive(sqlx::FromRow)]
    struct MatchedCommand {
        bot_pubkey: String,
        bot_name: String,
        webhook_url: Option<String>,
        privileged: i64,
        // Reserved for per-user cooldown enforcement (spec §6). Not yet
        // wired into the in-memory cooldown store.
        #[allow(dead_code)]
        cooldown_seconds: i64,
    }

    let matched = sqlx::query_as::<_, MatchedCommand>(
        "SELECT bc.pubkey as bot_pubkey, bp.name as bot_name, bp.webhook_url,
                bc.privileged, bc.cooldown_seconds
         FROM bot_commands bc
         JOIN bot_profiles bp ON bp.pubkey = bc.pubkey
         JOIN users u ON u.public_key = bc.pubkey
         WHERE bc.name = ?
           AND u.is_bot = 1
           AND u.is_bot_removed = 0
           AND (
             -- Either no channel scope restriction for this bot...
             NOT EXISTS (
               SELECT 1 FROM bot_channel_scope WHERE bot_pubkey = bc.pubkey
             )
             -- ...or this channel is in the bot's scope.
             OR EXISTS (
               SELECT 1 FROM bot_channel_scope
               WHERE bot_pubkey = bc.pubkey AND channel_id = ?
             )
           )
         LIMIT 1",
    )
    .bind(&command_name)
    .bind(channel_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()?; // None = no bot matched, fall through to normal message storage

    // Privileged command: check invoker's permissions.
    if matched.privileged != 0 {
        let perms = crate::permissions::user_permissions(&state.db, invoker_pubkey)
            .await
            .ok()?;
        if !perms.has(crate::permissions::MANAGE_MESSAGES) {
            return Some("You don't have permission to use this command.".to_string());
        }
    }

    let webhook_url = match matched.webhook_url {
        Some(ref url) if !url.is_empty() => url.clone(),
        _ => {
            // No webhook configured; silently store as normal message.
            return None;
        }
    };

    let message_id_hint = Uuid::new_v4().to_string();

    // Look up invoker display name.
    let invoker_name: Option<String> = sqlx::query_scalar(
        "SELECT display_name FROM users WHERE public_key = ?",
    )
    .bind(invoker_pubkey)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let hub_url = hub_url(state).await;

    let args_tokens: Vec<String> = if args_raw.is_empty() {
        Vec::new()
    } else {
        args_raw.split_whitespace().map(|s| s.to_string()).collect()
    };

    let invocation = SlashInvocation {
        kind: "slash_command".to_string(),
        hub_url: hub_url.clone(),
        channel_id: channel_id.to_string(),
        message_id_hint: message_id_hint.clone(),
        author: AuthorInfo {
            pubkey: invoker_pubkey.to_string(),
            display_name: invoker_name,
        },
        command: command_name.clone(),
        args_raw: args_raw.clone(),
        args_tokens,
    };

    let body_json = match serde_json::to_string(&invocation) {
        Ok(j) => j,
        Err(_) => return Some(format!("Bot @{} failed to respond.", matched.bot_name)),
    };

    // Sign the body with the hub's federation keypair.
    let hub_pubkey = state.hub_identity.public_key_hex();
    let body_bytes = body_json.as_bytes();
    let signature = state.hub_identity.sign(body_bytes);
    let sig_hex = hex::encode(signature.to_bytes());
    let timestamp = crate::auth::handlers::unix_timestamp();

    // POST to bot webhook with 5s timeout.
    let resp = state
        .http_client
        .post(&webhook_url)
        .header("Content-Type", "application/json")
        .header("X-Voxply-Hub-Pubkey", &hub_pubkey)
        .header("X-Voxply-Signature", &sig_hex)
        .header("X-Voxply-Timestamp", timestamp.to_string())
        .body(body_json)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await;

    let resp = match resp {
        Ok(r) => r,
        Err(_) => {
            return Some(format!("Bot @{} failed to respond.", matched.bot_name));
        }
    };

    if !resp.status().is_success() {
        return Some(format!("Bot @{} failed to respond.", matched.bot_name));
    }

    let bot_response: BotResponse = match resp.json().await {
        Ok(r) => r,
        Err(_) => {
            return Some(format!("Bot @{} failed to respond.", matched.bot_name));
        }
    };

    // Process bot reply.
    if let Some(reply) = bot_response.reply {
        let ephemeral = bot_response.ephemeral.unwrap_or(false);
        let msg_id = Uuid::new_v4().to_string();
        let now = crate::auth::handlers::unix_timestamp();

        let visible_to: Option<&str> = if ephemeral {
            Some(invoker_pubkey)
        } else {
            None
        };

        let embeds_json = reply.embeds.as_ref().and_then(|e| {
            if e.is_empty() {
                None
            } else {
                serde_json::to_string(e).ok()
            }
        });

        sqlx::query(
            "INSERT INTO messages(id, channel_id, sender, content, created_at, visible_to_pubkey, embeds)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(&msg_id)
        .bind(channel_id)
        .bind(&matched.bot_pubkey)
        .bind(&reply.body)
        .bind(now)
        .bind(visible_to)
        .bind(&embeds_json)
        .execute(&state.db)
        .await
        .ok();

        // Look up bot display name.
        let bot_name: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM users WHERE public_key = ?",
        )
        .bind(&matched.bot_pubkey)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        let message = MessageResponse {
            id: msg_id,
            channel_id: channel_id.to_string(),
            sender: matched.bot_pubkey,
            sender_name: bot_name.or(Some(matched.bot_name)),
            content: reply.body,
            created_at: now,
            edited_at: None,
            attachments: Vec::new(),
            reactions: Vec::new(),
            reply_to: None,
            visible_to_pubkey: visible_to.map(|s| s.to_string()),
        };

        let _ = state.chat_tx.send(ChatEvent::New {
            channel_id: channel_id.to_string(),
            message,
        });
    }

    // Slash command was handled (or deferred) — signal to caller not to store.
    // Return None means "no error, command was dispatched successfully".
    None
}

/// Build and return an ephemeral error message row, inserting it into the DB
/// and broadcasting it. The broadcast carries `visible_to_pubkey` so WS
/// filtering in `ws.rs` ensures only the invoker sees it.
pub async fn insert_ephemeral_error(
    state: &Arc<AppState>,
    channel_id: &str,
    invoker_pubkey: &str,
    error_text: &str,
) -> Result<(), (StatusCode, String)> {
    let err_id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO messages(id, channel_id, sender, content, created_at, visible_to_pubkey)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(&err_id)
    .bind(channel_id)
    .bind(invoker_pubkey)
    .bind(error_text)
    .bind(now)
    .bind(invoker_pubkey)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let message = MessageResponse {
        id: err_id,
        channel_id: channel_id.to_string(),
        sender: invoker_pubkey.to_string(),
        sender_name: None,
        content: error_text.to_string(),
        created_at: now,
        edited_at: None,
        attachments: Vec::new(),
        reactions: Vec::new(),
        reply_to: None,
        visible_to_pubkey: Some(invoker_pubkey.to_string()),
    };

    let _ = state.chat_tx.send(ChatEvent::New {
        channel_id: channel_id.to_string(),
        message,
    });

    Ok(())
}
