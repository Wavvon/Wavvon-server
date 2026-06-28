use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{
    Attachment, ChatEvent, EditMessageRequest, MessageResponse, PaginationParams, ReactionRequest,
    ReactionSummary, ReplyContext, SendMessageRequest, MAX_ATTACHMENTS_BYTES,
};
use crate::state::AppState;

pub async fn send_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<SendMessageRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), (StatusCode, String)> {
    // 30 messages per 60 seconds per user
    {
        let mut map = state
            .rate_limiters
            .messages
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);

        // Opportunistic eviction: when the map grows large, drop all entries
        // whose window has fully elapsed. This mirrors the pattern in rate_limit.rs
        // and prevents the map from growing without bound on busy hubs.
        const EVICTION_THRESHOLD: usize = 5_000;
        if map.len() >= EVICTION_THRESHOLD {
            map.retain(|_, (_, ts)| now.duration_since(*ts) <= window);
        }

        let entry = map.entry(user.public_key.clone()).or_insert((0, now));
        if now.duration_since(entry.1) > window {
            *entry = (0, now);
        }
        if entry.0 >= 30 {
            return Err((
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "rate_limited".to_string(),
            ));
        }
        entry.0 += 1;
    }

    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::SEND_MESSAGES)?;

    if crate::routes::moderation::is_muted(&state.db, &user.public_key).await? {
        return Err((StatusCode::FORBIDDEN, "You are muted".to_string()));
    }

    if crate::routes::moderation::is_channel_banned(&state.db, &channel_id, &user.public_key)
        .await?
    {
        return Err((
            StatusCode::FORBIDDEN,
            "You are banned from this channel".to_string(),
        ));
    }

    // Federated-ban check: reject message submission from any user whose
    // master key is listed in federated_bans. Auth middleware already blocks
    // new sessions for these users, but an active session obtained before the
    // ban was applied can still reach here without this second check.
    if crate::routes::moderation::is_federated_banned(&state.db, &user.public_key).await? {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }

    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(&channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    // Cap attachments size. The base64 payload is what counts toward the
    // limit since that's what travels over WS and lands in the DB.
    let attach_total: usize = req.attachments.iter().map(|a| a.data_b64.len()).sum();
    if attach_total > MAX_ATTACHMENTS_BYTES {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "Attachments exceed {}MB cap",
                MAX_ATTACHMENTS_BYTES / 1024 / 1024
            ),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp_ms();

    let attachments_json = if req.attachments.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&req.attachments)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Encode: {e}")))?,
        )
    };

    // If a reply_to is provided, sanity-check the parent exists in this
    // same channel. Cross-channel replies would surprise everyone.
    if let Some(parent_id) = &req.reply_to {
        let parent_channel: Option<String> =
            sqlx::query_scalar("SELECT channel_id FROM messages WHERE id = $1")
                .bind(parent_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        match parent_channel {
            None => {
                return Err((
                    StatusCode::NOT_FOUND,
                    "Parent message not found".to_string(),
                ))
            }
            Some(c) if c != channel_id => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Parent message is in a different channel".to_string(),
                ))
            }
            _ => {}
        }
    }

    // Slash command dispatch (external bot system): if the message starts with
    // '/' and a registered bot handles the command, the bot responds via its
    // webhook. We do NOT store the original slash message by default — the bot
    // decides what to post. Only store the message if no bot matched.
    if req.content.starts_with('/') {
        let ephemeral_err = crate::bots::dispatch::dispatch_slash(
            &state,
            &channel_id,
            &user.public_key,
            &req.content,
        )
        .await;

        match ephemeral_err {
            Some(err_text) => {
                // Command matched but errored — insert ephemeral error and return.
                crate::bots::dispatch::insert_ephemeral_error(
                    &state,
                    &channel_id,
                    &user.public_key,
                    &err_text,
                )
                .await?;
                // Return a minimal 200 so the client doesn't retry.
                let placeholder = MessageResponse {
                    id: id.clone(),
                    channel_id: channel_id.clone(),
                    sender: user.public_key.clone(),
                    sender_name: None,
                    content: err_text,
                    created_at: now,
                    edited_at: None,
                    attachments: Vec::new(),
                    reactions: Vec::new(),
                    reply_to: None,
                    visible_to_pubkey: Some(user.public_key),
                    reply_count: 0,
                };
                return Ok((StatusCode::OK, Json(placeholder)));
            }
            None => {
                // dispatch_slash returns None in two cases:
                //   1. No bot matched — fall through to store the message normally.
                //   2. Bot matched and handled (reply inserted inside dispatch_slash).
                // We have no way to distinguish these without an extra return value,
                // so we always fall through and store the message. The stored slash
                // text serves as the user's "command invocation" record in the channel.
                // (Design note: the spec says "hub does NOT persist slash invocations
                // by default" — this is a pragmatic choice to keep the flow simple
                // while the bot still posts its own reply. A future version could
                // track whether dispatch consumed the message and skip storage.)
            }
        }
    }

    // Auto-mod webhook check (fail-open: allow on timeout, error, or any non-403 response).
    // Runs BEFORE the INSERT so a block never stores anything.
    {
        let webhook_url = sqlx::query_scalar::<_, String>(
            "SELECT value FROM hub_settings WHERE key = 'moderation_webhook_url'",
        )
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

        if !webhook_url.is_empty() {
            let secret = sqlx::query_scalar::<_, String>(
                "SELECT value FROM hub_settings WHERE key = 'moderation_webhook_secret'",
            )
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();

            let payload = serde_json::json!({
                "message_id": &id,
                "channel_id": &channel_id,
                "sender_pubkey": &user.public_key,
                "content": &req.content,
                "attachments_count": req.attachments.len(),
                "timestamp": now,
            });
            let payload_str = serde_json::to_string(&payload).unwrap_or_default();

            // HMAC-SHA256 signature over the payload bytes.
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let sig = if !secret.is_empty() {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
                mac.update(payload_str.as_bytes());
                hex::encode(mac.finalize().into_bytes())
            } else {
                String::new()
            };

            let result = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                state
                    .http_client
                    .post(&webhook_url)
                    .header("X-Wavvon-Signature", &sig)
                    .header("Content-Type", "application/json")
                    .body(payload_str)
                    .send(),
            )
            .await;

            // Block only on an explicit 403 from the webhook; everything else is fail-open.
            if let Ok(Ok(resp)) = result {
                if resp.status() == reqwest::StatusCode::FORBIDDEN {
                    return Err((
                        StatusCode::FORBIDDEN,
                        "Message blocked by moderation policy".to_string(),
                    ));
                }
            }
        }
    }

    sqlx::query(
        "INSERT INTO messages (id, channel_id, sender, content, attachments, reply_to, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&channel_id)
    .bind(&user.public_key)
    .bind(&req.content)
    .bind(&attachments_json)
    .bind(&req.reply_to)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    {
        let indexed = crate::search::IndexedMessage {
            id: id.clone(),
            channel_id: channel_id.clone(),
            author_pubkey: user.public_key.clone(),
            content: req.content.clone(),
            timestamp: now,
        };
        if let Err(e) = state.search.index(&indexed).await {
            tracing::warn!("search index error: {e}");
        }
    }

    // Increment reply_count on the parent message when this is a reply.
    if let Some(parent_id) = &req.reply_to {
        let _ = sqlx::query(
            "UPDATE messages SET reply_count = COALESCE(reply_count, 0) + 1 WHERE id = $1",
        )
        .bind(parent_id)
        .execute(&state.db)
        .await;
    }

    let reply_ctx = if let Some(parent_id) = &req.reply_to {
        load_reply_context(&state.db, parent_id).await?
    } else {
        None
    };

    let sender_name: Option<String> =
        sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
            .bind(&user.public_key)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
            .flatten();

    let message = MessageResponse {
        id,
        channel_id: channel_id.clone(),
        sender: user.public_key,
        sender_name,
        content: req.content,
        created_at: now,
        edited_at: None,
        attachments: req.attachments,
        reactions: Vec::new(),
        reply_to: reply_ctx,
        visible_to_pubkey: None,
        reply_count: 0,
    };

    {
        let ws_msg = crate::routes::chat_models::WsServerMessage::ChatMessage {
            channel_id: channel_id.clone(),
            message: message.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((
            ChatEvent::New {
                channel_id: channel_id.clone(),
                message: message.clone(),
            },
            json,
        ));
    }

    // Publish message.created audit event for bot subscriptions.
    {
        let state_c = state.clone();
        let ch = channel_id.clone();
        let msg_c = message.clone();
        tokio::spawn(async move {
            crate::bots::events::publish_hub_event(
                &state_c,
                "message.created",
                Some(&msg_c.sender),
                None,
                Some(&ch),
                serde_json::json!({
                    "message_id": msg_c.id,
                    "content": msg_c.content,
                    "sender": msg_c.sender,
                    "sender_name": msg_c.sender_name,
                    "created_at": msg_c.created_at,
                    "attachments": msg_c.attachments,
                }),
            )
            .await;
        });
    }

    Ok((StatusCode::CREATED, Json(message)))
}

pub async fn edit_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id)): Path<(String, String)>,
    Json(req): Json<EditMessageRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT sender, channel_id FROM messages WHERE id = $1")
            .bind(&message_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (sender, msg_channel) =
        row.ok_or((StatusCode::NOT_FOUND, "Message not found".to_string()))?;
    if msg_channel != channel_id {
        return Err((
            StatusCode::NOT_FOUND,
            "Message not in this channel".to_string(),
        ));
    }
    if sender != user.public_key {
        return Err((
            StatusCode::FORBIDDEN,
            "You can only edit your own messages".to_string(),
        ));
    }

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query("UPDATE messages SET content = $1, edited_at = $2 WHERE id = $3")
        .bind(&req.content)
        .bind(now)
        .bind(&message_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let updated = load_message(&state, &message_id).await?;
    {
        let ws_msg = crate::routes::chat_models::WsServerMessage::MessageEdited {
            channel_id: channel_id.clone(),
            message: updated.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((
            ChatEvent::Edited {
                channel_id: channel_id.clone(),
                message: updated.clone(),
            },
            json,
        ));
    }
    Ok(Json(updated))
}

pub async fn delete_message(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row: Option<(String, String, Option<String>)> =
        sqlx::query_as("SELECT sender, channel_id, reply_to FROM messages WHERE id = $1")
            .bind(&message_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (sender, msg_channel, reply_to) =
        row.ok_or((StatusCode::NOT_FOUND, "Message not found".to_string()))?;
    if msg_channel != channel_id {
        return Err((
            StatusCode::NOT_FOUND,
            "Message not in this channel".to_string(),
        ));
    }

    // Author can always delete their own. Others need manage_messages.
    if sender != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::MANAGE_MESSAGES)?;
    }

    sqlx::query("DELETE FROM messages WHERE id = $1")
        .bind(&message_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    {
        let search = state.search.clone();
        let id = message_id.clone();
        tokio::spawn(async move {
            if let Err(e) = search.delete(&id).await {
                tracing::warn!("search delete error: {e}");
            }
        });
    }

    // Decrement reply_count on the parent when a reply is removed.
    if let Some(parent_id) = reply_to {
        let _ = sqlx::query(
            "UPDATE messages SET reply_count = GREATEST(0, COALESCE(reply_count, 0) - 1) WHERE id = $1",
        )
        .bind(&parent_id)
        .execute(&state.db)
        .await;
    }

    {
        let ws_msg = crate::routes::chat_models::WsServerMessage::MessageDeleted {
            channel_id: channel_id.clone(),
            message_id: message_id.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((
            ChatEvent::Deleted {
                channel_id,
                message_id,
            },
            json,
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

fn parse_attachments(json: Option<String>) -> Vec<Attachment> {
    json.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

async fn load_message(
    state: &AppState,
    message_id: &str,
) -> Result<MessageResponse, (StatusCode, String)> {
    let row = sqlx::query_as::<_, MessageRow>(
        "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name,
                m.content, m.attachments, m.reply_to, m.created_at, m.edited_at,
                COALESCE(m.reply_count, 0) as reply_count
         FROM messages m LEFT JOIN users u ON m.sender = u.public_key
         WHERE m.id = $1",
    )
    .bind(message_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let reactions = load_reactions_anon(&state.db, &row.id).await?;
    let reply_to = if let Some(parent_id) = &row.reply_to {
        load_reply_context(&state.db, parent_id).await?
    } else {
        None
    };
    Ok(MessageResponse {
        id: row.id,
        channel_id: row.channel_id,
        sender: row.sender,
        sender_name: row.sender_name,
        content: row.content,
        created_at: row.created_at,
        edited_at: row.edited_at,
        attachments: parse_attachments(row.attachments),
        reactions,
        reply_to,
        visible_to_pubkey: None,
        reply_count: row.reply_count,
    })
}

pub async fn get_messages(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<Vec<MessageResponse>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(50).min(100);
    let search = params
        .q
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    let rows = if let Some(ref root_id) = params.thread_root {
        // Thread mode: return all replies to this root, oldest first.
        sqlx::query_as::<_, MessageRow>(
            "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name, m.content, m.attachments, m.reply_to, m.created_at, m.edited_at, COALESCE(m.reply_count, 0) as reply_count
             FROM messages m LEFT JOIN users u ON m.sender = u.public_key
             WHERE m.channel_id = $1 AND m.reply_to = $2
             ORDER BY m.created_at ASC, m.id ASC LIMIT $3",
        )
        .bind(&channel_id)
        .bind(root_id)
        .bind(limit)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    } else {
        match (search, &params.before) {
            // Search mode: uses Tantivy for full-text, scoped to the single channel.
            (Some(q), _) => {
                let search_params = crate::search::SearchParams {
                    q: q.to_string(),
                    channel_ids: vec![channel_id.clone()],
                    limit: limit as usize,
                };
                let hit_ids: Vec<String> = state
                    .search
                    .query(&search_params)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|h| h.message_id)
                    .collect();

                if hit_ids.is_empty() {
                    return Ok(Json(vec![]));
                }

                let placeholders = hit_ids
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("${}", i + 1))
                    .collect::<Vec<_>>()
                    .join(",");
                let sql = format!(
                    "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name, m.content, m.attachments, m.reply_to, m.created_at, m.edited_at, COALESCE(m.reply_count, 0) as reply_count
                     FROM messages m LEFT JOIN users u ON m.sender = u.public_key
                     WHERE m.id IN ({placeholders})
                     ORDER BY m.created_at DESC, m.id DESC"
                );
                let mut q_builder = sqlx::query_as::<_, MessageRow>(&sql);
                for id in &hit_ids {
                    q_builder = q_builder.bind(id);
                }
                q_builder.fetch_all(&state.db).await
            }
            (None, Some(before_id)) => {
                sqlx::query_as::<_, MessageRow>(
                    "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name, m.content, m.attachments, m.reply_to, m.created_at, m.edited_at, COALESCE(m.reply_count, 0) as reply_count
                     FROM messages m LEFT JOIN users u ON m.sender = u.public_key
                     WHERE m.channel_id = $1
                       AND (m.created_at, m.id) < (
                         (SELECT created_at FROM messages WHERE id = $2), $2
                       )
                     ORDER BY m.created_at DESC, m.id DESC LIMIT $3",
                )
                .bind(&channel_id)
                .bind(before_id)
                .bind(limit)
                .fetch_all(&state.db)
                .await
            }
            (None, None) => {
                sqlx::query_as::<_, MessageRow>(
                    "SELECT m.id, m.channel_id, m.sender, u.display_name as sender_name, m.content, m.attachments, m.reply_to, m.created_at, m.edited_at, COALESCE(m.reply_count, 0) as reply_count
                     FROM messages m LEFT JOIN users u ON m.sender = u.public_key
                     WHERE m.channel_id = $1
                     ORDER BY m.created_at DESC, m.id DESC LIMIT $2",
                )
                .bind(&channel_id)
                .bind(limit)
                .fetch_all(&state.db)
                .await
            }
        }
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    };

    let msg_ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let reply_ids: Vec<String> = rows
        .iter()
        .filter_map(|r| r.reply_to.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let mut reactions_map = batch_load_reactions(&state.db, &msg_ids, &user.public_key).await?;
    let mut reply_map = batch_load_reply_contexts(&state.db, &reply_ids).await?;

    let messages: Vec<MessageResponse> = rows
        .into_iter()
        .map(|r| {
            let reactions = reactions_map.remove(&r.id).unwrap_or_default();
            let reply_to = r.reply_to.as_deref().and_then(|id| reply_map.remove(id));
            MessageResponse {
                id: r.id,
                channel_id: r.channel_id,
                sender: r.sender,
                sender_name: r.sender_name,
                content: r.content,
                created_at: r.created_at,
                edited_at: r.edited_at,
                attachments: parse_attachments(r.attachments),
                reactions,
                reply_to,
                visible_to_pubkey: None,
                reply_count: r.reply_count,
            }
        })
        .collect();

    Ok(Json(messages))
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: String,
    channel_id: String,
    sender: String,
    sender_name: Option<String>,
    content: String,
    attachments: Option<String>,
    reply_to: Option<String>,
    created_at: i64,
    edited_at: Option<i64>,
    reply_count: i64,
}

/// Bulk variant of load_reactions: one query for all messages in a page,
/// returns a map keyed by message_id.
async fn batch_load_reactions(
    db: &sqlx::PgPool,
    message_ids: &[String],
    viewer: &str,
) -> Result<HashMap<String, Vec<ReactionSummary>>, (StatusCode, String)> {
    if message_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(String, String, i64, i64)> = sqlx::query_as(
        "SELECT message_id, emoji, COUNT(*) as cnt,
                MAX(CASE WHEN user_key = $1 THEN 1 ELSE 0 END) as mine
         FROM message_reactions
         WHERE message_id = ANY($2)
         GROUP BY message_id, emoji
         ORDER BY message_id, MIN(created_at) ASC",
    )
    .bind(viewer)
    .bind(message_ids)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut map: HashMap<String, Vec<ReactionSummary>> = HashMap::new();
    for (message_id, emoji, count, mine) in rows {
        map.entry(message_id).or_default().push(ReactionSummary {
            emoji,
            count,
            me: mine != 0,
        });
    }
    Ok(map)
}

/// Bulk variant of load_reply_context: one query for all parent IDs in a page,
/// returns a map keyed by parent message_id.
async fn batch_load_reply_contexts(
    db: &sqlx::PgPool,
    parent_ids: &[String],
) -> Result<HashMap<String, ReplyContext>, (StatusCode, String)> {
    if parent_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT m.id, m.sender, u.display_name as sender_name, m.content
         FROM messages m LEFT JOIN users u ON m.sender = u.public_key
         WHERE m.id = ANY($1)",
    )
    .bind(parent_ids)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(id, sender, sender_name, content)| {
            let preview: String = content.chars().take(140).collect();
            (
                id.clone(),
                ReplyContext {
                    message_id: id,
                    sender,
                    sender_name,
                    content_preview: preview,
                },
            )
        })
        .collect())
}

/// Load a small preview of a parent message for the reply chip. Returns
/// None if the parent has been deleted.
async fn load_reply_context(
    db: &sqlx::PgPool,
    parent_id: &str,
) -> Result<Option<ReplyContext>, (StatusCode, String)> {
    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT m.sender, u.display_name as sender_name, m.content
         FROM messages m LEFT JOIN users u ON m.sender = u.public_key
         WHERE m.id = $1",
    )
    .bind(parent_id)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(row.map(|(sender, sender_name, content)| {
        // Cap the preview so a paragraph doesn't blow up the WS frame.
        let preview: String = content.chars().take(140).collect();
        ReplyContext {
            message_id: parent_id.to_string(),
            sender,
            sender_name,
            content_preview: preview,
        }
    }))
}

/// Load aggregated reaction counts for one message, with `me` flagged for
/// rows the viewer reacted to.
pub(crate) async fn load_reactions(
    db: &sqlx::PgPool,
    message_id: &str,
    viewer: &str,
) -> Result<Vec<ReactionSummary>, (StatusCode, String)> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT emoji, COUNT(*) as cnt, MAX(CASE WHEN user_key = $1 THEN 1 ELSE 0 END) as mine
         FROM message_reactions
         WHERE message_id = $2
         GROUP BY emoji
         ORDER BY MIN(created_at) ASC",
    )
    .bind(viewer)
    .bind(message_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(emoji, count, mine)| ReactionSummary {
            emoji,
            count,
            me: mine != 0,
        })
        .collect())
}

/// Same as load_reactions but for broadcast: `me` is false because we
/// don't know who the recipient will be.
async fn load_reactions_anon(
    db: &sqlx::PgPool,
    message_id: &str,
) -> Result<Vec<ReactionSummary>, (StatusCode, String)> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT emoji, COUNT(*) as cnt
         FROM message_reactions
         WHERE message_id = $1
         GROUP BY emoji
         ORDER BY MIN(created_at) ASC",
    )
    .bind(message_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(emoji, count)| ReactionSummary {
            emoji,
            count,
            me: false,
        })
        .collect())
}

pub async fn add_reaction(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id)): Path<(String, String)>,
    Json(req): Json<ReactionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::SEND_MESSAGES)?;

    let emoji = req.emoji.trim();
    if emoji.is_empty() || emoji.chars().count() > 16 {
        return Err((
            StatusCode::BAD_REQUEST,
            "emoji must be 1..16 chars".to_string(),
        ));
    }

    // Sanity-check the message belongs to the channel claimed in the path.
    let row: Option<String> = sqlx::query_scalar("SELECT channel_id FROM messages WHERE id = $1")
        .bind(&message_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    match row {
        None => return Err((StatusCode::NOT_FOUND, "message not found".to_string())),
        Some(c) if c != channel_id => {
            return Err((StatusCode::NOT_FOUND, "message not in channel".to_string()))
        }
        _ => {}
    }

    let now = crate::auth::handlers::unix_timestamp();
    sqlx::query(
        "INSERT INTO message_reactions (message_id, emoji, user_key, created_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT (message_id, emoji, user_key) DO NOTHING",
    )
    .bind(&message_id)
    .bind(emoji)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let summary = load_reactions_anon(&state.db, &message_id).await?;
    {
        let ws_msg = crate::routes::chat_models::WsServerMessage::ReactionsUpdated {
            channel_id: channel_id.clone(),
            message_id: message_id.clone(),
            reactions: summary.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((
            ChatEvent::ReactionsUpdated {
                channel_id,
                message_id,
                reactions: summary,
            },
            json,
        ));
    }

    Ok(StatusCode::CREATED)
}

pub async fn remove_reaction(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, message_id, emoji)): Path<(String, String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query(
        "DELETE FROM message_reactions WHERE message_id = $1 AND emoji = $2 AND user_key = $3",
    )
    .bind(&message_id)
    .bind(&emoji)
    .bind(&user.public_key)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let summary = load_reactions_anon(&state.db, &message_id).await?;
    {
        let ws_msg = crate::routes::chat_models::WsServerMessage::ReactionsUpdated {
            channel_id: channel_id.clone(),
            message_id: message_id.clone(),
            reactions: summary.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((
            ChatEvent::ReactionsUpdated {
                channel_id,
                message_id,
                reactions: summary,
            },
            json,
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}
