use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::auth::middleware::{AuthUser, PeerHub};
use crate::permissions;
use crate::routes::chat_models::ChatEvent;
use crate::routes::post_models::{
    post_to_summary, reply_to_view, Attachment, CreatePostRequest, CreateReplyRequest,
    EditPostRequest, EditReplyRequest, FederatedCreatePostRequest, FederatedCreateReplyRequest,
    FederatedReactionRequest, PostDetail, PostListParams, PostListResponse, PostRow, PostSearchHit,
    PostSearchResponse, ReactionCount, ReplyListParams, ReplyRow, ReplyView, SearchParams,
};
use crate::state::AppState;

// ── Guard helper ─────────────────────────────────────────────────────────────

/// Load a channel row and verify it is a forum channel.
async fn require_forum_channel(
    db: &sqlx::PgPool,
    channel_id: &str,
) -> Result<(), (StatusCode, String)> {
    let row: Option<(bool, String)> =
        sqlx::query_as("SELECT is_category, channel_type FROM channels WHERE id = $1")
            .bind(channel_id)
            .fetch_optional(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    match row {
        None => Err((StatusCode::NOT_FOUND, "channel_not_found".to_string())),
        Some((true, _)) => Err((StatusCode::NOT_FOUND, "not_a_forum".to_string())),
        Some((_, t)) if t != "forum" => Err((StatusCode::CONFLICT, "not_a_forum".to_string())),
        _ => Ok(()),
    }
}

/// Load a post by id, verifying it belongs to the given channel.
async fn require_post(
    db: &sqlx::PgPool,
    channel_id: &str,
    post_id: &str,
) -> Result<PostRow, (StatusCode, String)> {
    let row = sqlx::query_as::<_, PostRow>(
        "SELECT id, channel_id, author_pubkey, title, body,
                created_at, edited_at, is_pinned, is_locked,
                reply_count, last_activity_at, deleted_at,
                COALESCE(attachments, '[]') AS attachments, author_hub
         FROM posts WHERE id = $1",
    )
    .bind(post_id)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "post_not_found".to_string()))?;

    if row.channel_id != channel_id {
        return Err((StatusCode::NOT_FOUND, "post_not_found".to_string()));
    }
    Ok(row)
}

/// Load a reply by id, verifying it belongs to the given post.
async fn require_reply(
    db: &sqlx::PgPool,
    post_id: &str,
    reply_id: &str,
) -> Result<ReplyRow, (StatusCode, String)> {
    let row = sqlx::query_as::<_, ReplyRow>(
        "SELECT id, post_id, author_pubkey, body,
                created_at, edited_at, reply_to_id, deleted_at,
                COALESCE(attachments, '[]') AS attachments, author_hub
         FROM post_replies WHERE id = $1",
    )
    .bind(reply_id)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "reply_not_found".to_string()))?;

    if row.post_id != post_id {
        return Err((StatusCode::NOT_FOUND, "reply_not_found".to_string()));
    }
    Ok(row)
}

fn unix_now() -> i64 {
    crate::auth::handlers::unix_timestamp()
}

/// Broadcast a forum event over the chat channel so WS subscribers receive it.
fn broadcast_forum_event(state: &AppState, channel_id: &str, event: serde_json::Value) {
    use crate::routes::chat_models::WsServerMessage;
    let ws_msg = WsServerMessage::ForumEvent {
        channel_id: channel_id.to_string(),
        event,
    };
    if let Ok(json) = serde_json::to_string(&ws_msg) {
        let json: Arc<str> = Arc::from(json.as_str());
        let _ = state.chat_tx.send((
            ChatEvent::Forum {
                channel_id: channel_id.to_string(),
            },
            json,
        ));
    }
}

// ── Reaction helpers ─────────────────────────────────────────────────────────

/// Load aggregated reaction counts for a post, with `me` set for the viewer.
async fn load_post_reactions(db: &sqlx::PgPool, post_id: &str, viewer: &str) -> Vec<ReactionCount> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT emoji, COUNT(*) as cnt,
                MAX(CASE WHEN user_key = $1 THEN 1 ELSE 0 END)::BIGINT as mine
         FROM post_reactions
         WHERE post_id = $2
         GROUP BY emoji
         ORDER BY MIN(created_at) ASC",
    )
    .bind(viewer)
    .bind(post_id)
    .fetch_all(db)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("load_post_reactions failed for {post_id}: {e}");
        Vec::new()
    });

    rows.into_iter()
        .map(|(emoji, count, mine)| ReactionCount {
            emoji,
            count,
            me: mine != 0,
        })
        .collect()
}

/// Load aggregated reaction counts for a reply, with `me` set for the viewer.
async fn load_reply_reactions(
    db: &sqlx::PgPool,
    reply_id: &str,
    viewer: &str,
) -> Vec<ReactionCount> {
    let rows: Vec<(String, i64, i64)> = sqlx::query_as(
        "SELECT emoji, COUNT(*) as cnt,
                MAX(CASE WHEN user_key = $1 THEN 1 ELSE 0 END)::BIGINT as mine
         FROM reply_reactions
         WHERE reply_id = $2
         GROUP BY emoji
         ORDER BY MIN(created_at) ASC",
    )
    .bind(viewer)
    .bind(reply_id)
    .fetch_all(db)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!("load_reply_reactions failed for {reply_id}: {e}");
        Vec::new()
    });

    rows.into_iter()
        .map(|(emoji, count, mine)| ReactionCount {
            emoji,
            count,
            me: mine != 0,
        })
        .collect()
}

fn encode_attachments(attachments: &Option<Vec<Attachment>>) -> String {
    attachments
        .as_deref()
        .filter(|a| !a.is_empty())
        .map(|a| serde_json::to_string(a).unwrap_or_else(|_| "[]".to_string()))
        .unwrap_or_else(|| "[]".to_string())
}

// ── GET /channels/:cid/posts ─────────────────────────────────────────────────

pub async fn list_posts(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Query(params): Query<PostListParams>,
) -> Result<Json<PostListResponse>, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let can_moderate = {
        let p = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
        p.has(permissions::MANAGE_POSTS)
    };

    let limit = params.limit.unwrap_or(50).min(100);

    // Parse cursor: "last_activity_at:id"
    let rows: Vec<PostRow> = if let Some(cursor) = &params.cursor {
        let parts: Vec<&str> = cursor.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err((StatusCode::BAD_REQUEST, "invalid_cursor".to_string()));
        }
        let cursor_ts: i64 = parts[0]
            .parse()
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid_cursor".to_string()))?;
        let cursor_id = parts[1];

        sqlx::query_as::<_, PostRow>(
            "SELECT id, channel_id, author_pubkey, title, body,
                    created_at, edited_at, is_pinned, is_locked,
                    reply_count, last_activity_at, deleted_at,
                    COALESCE(attachments, '[]') AS attachments, author_hub
             FROM posts
             WHERE channel_id = $1
               AND (last_activity_at < $2 OR (last_activity_at = $3 AND id < $4))
               AND deleted_at IS NULL
             ORDER BY is_pinned DESC, last_activity_at DESC, id DESC
             LIMIT $5",
        )
        .bind(&channel_id)
        .bind(cursor_ts)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    } else {
        sqlx::query_as::<_, PostRow>(
            "SELECT id, channel_id, author_pubkey, title, body,
                    created_at, edited_at, is_pinned, is_locked,
                    reply_count, last_activity_at, deleted_at,
                    COALESCE(attachments, '[]') AS attachments, author_hub
             FROM posts
             WHERE channel_id = $1 AND deleted_at IS NULL
             ORDER BY is_pinned DESC, last_activity_at DESC, id DESC
             LIMIT $2",
        )
        .bind(&channel_id)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    };

    let has_more = rows.len() as i64 > limit;
    let rows: Vec<PostRow> = rows.into_iter().take(limit as usize).collect();

    let cursor = if has_more {
        rows.last()
            .map(|r| format!("{}:{}", r.last_activity_at, r.id))
    } else {
        None
    };

    // Populate unread_reply_count and reactions for each post.
    let mut posts: Vec<_> = Vec::with_capacity(rows.len());
    for row in &rows {
        let reactions = load_post_reactions(&state.db, &row.id, &user.public_key).await;
        let mut summary = post_to_summary(row, can_moderate, reactions);

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM post_replies
             WHERE post_id = $1 AND created_at > COALESCE(
                 (SELECT read_at FROM post_reads WHERE user_pubkey = $2 AND post_id = $3),
                 0
             )",
        )
        .bind(&row.id)
        .bind(&user.public_key)
        .bind(&row.id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
        summary.unread_reply_count = Some(count);

        posts.push(summary);
    }

    Ok(Json(PostListResponse { posts, cursor }))
}

// ── POST /channels/:cid/posts ────────────────────────────────────────────────

pub async fn create_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<CreatePostRequest>,
) -> Result<(StatusCode, Json<PostDetail>), (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::CREATE_POSTS)?;

    let title = req.title.trim().to_string();
    let body = req.body.trim().to_string();
    if title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title_required".to_string()));
    }
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "body_required".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let now = unix_now();
    let attachments_json = encode_attachments(&req.attachments);

    sqlx::query(
        "INSERT INTO posts (id, channel_id, author_pubkey, title, body, attachments, created_at, last_activity_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&channel_id)
    .bind(&user.public_key)
    .bind(&title)
    .bind(&body)
    .bind(&attachments_json)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let row = require_post(&state.db, &channel_id, &id).await?;
    let can_moderate = perms.has(permissions::MANAGE_POSTS);
    let reactions = load_post_reactions(&state.db, &id, &user.public_key).await;
    let summary = post_to_summary(&row, can_moderate, reactions);
    let detail = PostDetail {
        body: Some(row.body.clone()),
        replies: Vec::new(),
        reply_cursor: None,
        summary,
    };

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_created",
            "channel_id": channel_id,
            "post_id": id,
        }),
    );

    Ok((StatusCode::CREATED, Json(detail)))
}

// ── GET /channels/:cid/posts/:pid ───────────────────────────────────────────

pub async fn get_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
    Query(params): Query<ReplyListParams>,
) -> Result<Json<PostDetail>, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    let can_moderate = perms.has(permissions::MANAGE_POSTS);

    let row = require_post(&state.db, &channel_id, &post_id).await?;
    let reactions = load_post_reactions(&state.db, &post_id, &user.public_key).await;
    let mut summary = post_to_summary(&row, can_moderate, reactions);

    // Populate unread_reply_count using the caller's read cursor.
    let unread: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM post_replies
         WHERE post_id = $1 AND created_at > COALESCE(
             (SELECT read_at FROM post_reads WHERE user_pubkey = $2 AND post_id = $3),
             0
         )",
    )
    .bind(&post_id)
    .bind(&user.public_key)
    .bind(&post_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    summary.unread_reply_count = Some(unread);

    let limit = params.limit.unwrap_or(50).min(100);

    let reply_rows: Vec<ReplyRow> = if let Some(after_id) = &params.after {
        sqlx::query_as::<_, ReplyRow>(
            "SELECT id, post_id, author_pubkey, body, created_at, edited_at, reply_to_id, deleted_at,
                    COALESCE(attachments, '[]') AS attachments, author_hub
             FROM post_replies
             WHERE post_id = $1
               AND created_at > (SELECT created_at FROM post_replies WHERE id = $2)
             ORDER BY created_at ASC, id ASC
             LIMIT $3",
        )
        .bind(&post_id)
        .bind(after_id)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    } else {
        sqlx::query_as::<_, ReplyRow>(
            "SELECT id, post_id, author_pubkey, body, created_at, edited_at, reply_to_id, deleted_at,
                    COALESCE(attachments, '[]') AS attachments, author_hub
             FROM post_replies
             WHERE post_id = $1
             ORDER BY created_at ASC, id ASC
             LIMIT $2",
        )
        .bind(&post_id)
        .bind(limit + 1)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    };

    let has_more = reply_rows.len() as i64 > limit;
    let reply_rows: Vec<ReplyRow> = reply_rows.into_iter().take(limit as usize).collect();
    let reply_cursor = if has_more {
        reply_rows.last().map(|r| r.id.clone())
    } else {
        None
    };

    let mut replies = Vec::with_capacity(reply_rows.len());
    for r in &reply_rows {
        let r_reactions = load_reply_reactions(&state.db, &r.id, &user.public_key).await;
        replies.push(reply_to_view(r, can_moderate, r_reactions));
    }

    Ok(Json(PostDetail {
        body: if row.deleted_at.is_some() {
            None
        } else {
            Some(row.body)
        },
        replies,
        reply_cursor,
        summary,
    }))
}

// ── PATCH /channels/:cid/posts/:pid ─────────────────────────────────────────

pub async fn edit_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
    Json(req): Json<EditPostRequest>,
) -> Result<Json<PostDetail>, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let row = require_post(&state.db, &channel_id, &post_id).await?;
    if row.deleted_at.is_some() {
        return Err((StatusCode::GONE, "post_deleted".to_string()));
    }

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    let can_moderate = perms.has(permissions::MANAGE_POSTS);
    if row.author_pubkey != user.public_key && !can_moderate {
        return Err((StatusCode::FORBIDDEN, "forbidden".to_string()));
    }

    let new_title = req
        .title
        .as_deref()
        .unwrap_or(&row.title)
        .trim()
        .to_string();
    let new_body = req.body.as_deref().unwrap_or(&row.body).trim().to_string();
    if new_title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title_required".to_string()));
    }

    let now = unix_now();
    sqlx::query("UPDATE posts SET title = $1, body = $2, edited_at = $3 WHERE id = $4")
        .bind(&new_title)
        .bind(&new_body)
        .bind(now)
        .bind(&post_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let updated_row = require_post(&state.db, &channel_id, &post_id).await?;
    let reactions = load_post_reactions(&state.db, &post_id, &user.public_key).await;
    let summary = post_to_summary(&updated_row, can_moderate, reactions);
    let detail = PostDetail {
        body: Some(updated_row.body.clone()),
        replies: Vec::new(),
        reply_cursor: None,
        summary,
    };

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_updated",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(Json(detail))
}

// ── DELETE /channels/:cid/posts/:pid ────────────────────────────────────────

pub async fn delete_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let row = require_post(&state.db, &channel_id, &post_id).await?;
    if row.deleted_at.is_some() {
        return Ok(StatusCode::NO_CONTENT);
    }

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    if row.author_pubkey != user.public_key && !perms.has(permissions::MANAGE_POSTS) {
        return Err((StatusCode::FORBIDDEN, "forbidden".to_string()));
    }

    let now = unix_now();
    sqlx::query("UPDATE posts SET deleted_at = $1 WHERE id = $2")
        .bind(now)
        .bind(&post_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_deleted",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /channels/:cid/posts/:pid/replies ───────────────────────────────────

pub async fn create_reply(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
    Json(req): Json<CreateReplyRequest>,
) -> Result<(StatusCode, Json<crate::routes::post_models::ReplyView>), (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    // Channel-scoped: this same `perms` also gates the MANAGE_POSTS lock
    // check below, and MANAGE_POSTS must be channel-scoped, so resolve
    // once through channel_permissions rather than splitting the two
    // checks across two resolvers.
    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::SEND_MESSAGES)?;

    let row = require_post(&state.db, &channel_id, &post_id).await?;
    if row.deleted_at.is_some() {
        return Err((StatusCode::GONE, "post_deleted".to_string()));
    }
    if row.is_locked && !perms.has(permissions::MANAGE_POSTS) {
        return Err((StatusCode::FORBIDDEN, "post_locked".to_string()));
    }

    let body = req.body.trim().to_string();
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "body_required".to_string()));
    }

    // Validate reply_to_id belongs to this post.
    if let Some(ref rto) = req.reply_to_id {
        let belongs: Option<String> =
            sqlx::query_scalar("SELECT id FROM post_replies WHERE id = $1 AND post_id = $2")
                .bind(rto)
                .bind(&post_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        if belongs.is_none() {
            return Err((StatusCode::NOT_FOUND, "reply_to_not_found".to_string()));
        }
    }

    let id = Uuid::new_v4().to_string();
    let now = unix_now();
    let attachments_json = encode_attachments(&req.attachments);

    sqlx::query(
        "INSERT INTO post_replies (id, post_id, author_pubkey, body, attachments, created_at, reply_to_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&post_id)
    .bind(&user.public_key)
    .bind(&body)
    .bind(&attachments_json)
    .bind(now)
    .bind(&req.reply_to_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Update denormalized counters on the parent post.
    sqlx::query(
        "UPDATE posts SET reply_count = reply_count + 1, last_activity_at = $1 WHERE id = $2",
    )
    .bind(now)
    .bind(&post_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let reply_row = require_reply(&state.db, &post_id, &id).await?;
    let can_moderate = perms.has(permissions::MANAGE_POSTS);
    let reactions = load_reply_reactions(&state.db, &id, &user.public_key).await;
    let view = reply_to_view(&reply_row, can_moderate, reactions);

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "reply_created",
            "channel_id": channel_id,
            "post_id": post_id,
            "reply_id": id,
        }),
    );

    Ok((StatusCode::CREATED, Json(view)))
}

// ── PATCH /channels/:cid/posts/:pid/replies/:rid ─────────────────────────────

pub async fn edit_reply(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id, reply_id)): Path<(String, String, String)>,
    Json(req): Json<EditReplyRequest>,
) -> Result<Json<crate::routes::post_models::ReplyView>, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let _post = require_post(&state.db, &channel_id, &post_id).await?;
    let reply = require_reply(&state.db, &post_id, &reply_id).await?;
    if reply.deleted_at.is_some() {
        return Err((StatusCode::GONE, "reply_deleted".to_string()));
    }

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    let can_moderate = perms.has(permissions::MANAGE_POSTS);
    if reply.author_pubkey != user.public_key && !can_moderate {
        return Err((StatusCode::FORBIDDEN, "forbidden".to_string()));
    }

    let body = req.body.trim().to_string();
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "body_required".to_string()));
    }

    let now = unix_now();
    sqlx::query("UPDATE post_replies SET body = $1, edited_at = $2 WHERE id = $3")
        .bind(&body)
        .bind(now)
        .bind(&reply_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let updated = require_reply(&state.db, &post_id, &reply_id).await?;
    let reactions = load_reply_reactions(&state.db, &reply_id, &user.public_key).await;
    let view = reply_to_view(&updated, can_moderate, reactions);

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "reply_updated",
            "channel_id": channel_id,
            "post_id": post_id,
            "reply_id": reply_id,
        }),
    );

    Ok(Json(view))
}

// ── DELETE /channels/:cid/posts/:pid/replies/:rid ────────────────────────────

pub async fn delete_reply(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id, reply_id)): Path<(String, String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let _post = require_post(&state.db, &channel_id, &post_id).await?;
    let reply = require_reply(&state.db, &post_id, &reply_id).await?;
    if reply.deleted_at.is_some() {
        return Ok(StatusCode::NO_CONTENT);
    }

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    if reply.author_pubkey != user.public_key && !perms.has(permissions::MANAGE_POSTS) {
        return Err((StatusCode::FORBIDDEN, "forbidden".to_string()));
    }

    let now = unix_now();
    sqlx::query("UPDATE post_replies SET deleted_at = $1 WHERE id = $2")
        .bind(now)
        .bind(&reply_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Decrement reply_count (don't go below 0).
    sqlx::query("UPDATE posts SET reply_count = GREATEST(0, reply_count - 1) WHERE id = $1")
        .bind(&post_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "reply_deleted",
            "channel_id": channel_id,
            "post_id": post_id,
            "reply_id": reply_id,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /channels/:cid/posts/:pid/pin ──────────────────────────────────────

pub async fn pin_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::MANAGE_POSTS)?;

    let row = require_post(&state.db, &channel_id, &post_id).await?;
    if row.deleted_at.is_some() {
        return Err((StatusCode::GONE, "post_deleted".to_string()));
    }

    sqlx::query("UPDATE posts SET is_pinned = TRUE WHERE id = $1")
        .bind(&post_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_updated",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /channels/:cid/posts/:pid/pin ────────────────────────────────────

pub async fn unpin_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::MANAGE_POSTS)?;

    let row = require_post(&state.db, &channel_id, &post_id).await?;
    if row.deleted_at.is_some() {
        return Err((StatusCode::GONE, "post_deleted".to_string()));
    }

    sqlx::query("UPDATE posts SET is_pinned = FALSE WHERE id = $1")
        .bind(&post_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_updated",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /channels/:cid/posts/:pid/lock ─────────────────────────────────────

pub async fn lock_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::MANAGE_POSTS)?;

    let row = require_post(&state.db, &channel_id, &post_id).await?;
    if row.deleted_at.is_some() {
        return Err((StatusCode::GONE, "post_deleted".to_string()));
    }

    sqlx::query("UPDATE posts SET is_locked = TRUE WHERE id = $1")
        .bind(&post_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_updated",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── DELETE /channels/:cid/posts/:pid/lock ───────────────────────────────────

pub async fn unlock_post(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::MANAGE_POSTS)?;

    let row = require_post(&state.db, &channel_id, &post_id).await?;
    if row.deleted_at.is_some() {
        return Err((StatusCode::GONE, "post_deleted".to_string()));
    }

    sqlx::query("UPDATE posts SET is_locked = FALSE WHERE id = $1")
        .bind(&post_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_updated",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /channels/:cid/posts/:pid/read ─────────────────────────────────────

pub async fn mark_post_read(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;
    // Ensure the post exists and belongs to this channel.
    let _ = require_post(&state.db, &channel_id, &post_id).await?;

    let now = unix_now();
    sqlx::query(
        "INSERT INTO post_reads (user_pubkey, post_id, read_at) VALUES ($1, $2, $3)
         ON CONFLICT (user_pubkey, post_id) DO UPDATE SET read_at = EXCLUDED.read_at",
    )
    .bind(&user.public_key)
    .bind(&post_id)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /channels/:cid/posts/:pid/reactions ─────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ReactionRequest {
    pub emoji: String,
}

pub async fn add_post_reaction(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id)): Path<(String, String)>,
    Json(req): Json<ReactionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;
    let _ = require_post(&state.db, &channel_id, &post_id).await?;

    let emoji = req.emoji.trim();
    if emoji.is_empty() || emoji.chars().count() > 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "emoji must be 1..8 chars".to_string(),
        ));
    }

    let now = unix_now();
    sqlx::query(
        "INSERT INTO post_reactions (post_id, emoji, user_key, created_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT (post_id, emoji, user_key) DO NOTHING",
    )
    .bind(&post_id)
    .bind(emoji)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_updated",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(StatusCode::CREATED)
}

// ── DELETE /channels/:cid/posts/:pid/reactions/:emoji ─────────────────────────

pub async fn remove_post_reaction(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id, emoji)): Path<(String, String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;
    let _ = require_post(&state.db, &channel_id, &post_id).await?;

    sqlx::query("DELETE FROM post_reactions WHERE post_id = $1 AND emoji = $2 AND user_key = $3")
        .bind(&post_id)
        .bind(&emoji)
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_updated",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── POST /posts/:rid/reactions ────────────────────────────────────────────────
// Note: these routes are registered at /channels/:cid/posts/:pid/replies/:rid/reactions

pub async fn add_reply_reaction(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id, reply_id)): Path<(String, String, String)>,
    Json(req): Json<ReactionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;
    let _ = require_post(&state.db, &channel_id, &post_id).await?;
    let _ = require_reply(&state.db, &post_id, &reply_id).await?;

    let emoji = req.emoji.trim();
    if emoji.is_empty() || emoji.chars().count() > 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "emoji must be 1..8 chars".to_string(),
        ));
    }

    let now = unix_now();
    sqlx::query(
        "INSERT INTO reply_reactions (reply_id, emoji, user_key, created_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT (reply_id, emoji, user_key) DO NOTHING",
    )
    .bind(&reply_id)
    .bind(emoji)
    .bind(&user.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "reply_updated",
            "channel_id": channel_id,
            "post_id": post_id,
            "reply_id": reply_id,
        }),
    );

    Ok(StatusCode::CREATED)
}

// ── DELETE /posts/:pid/replies/:rid/reactions/:emoji ──────────────────────────

pub async fn remove_reply_reaction(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((channel_id, post_id, reply_id, emoji)): Path<(String, String, String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;
    let _ = require_post(&state.db, &channel_id, &post_id).await?;
    let _ = require_reply(&state.db, &post_id, &reply_id).await?;

    sqlx::query("DELETE FROM reply_reactions WHERE reply_id = $1 AND emoji = $2 AND user_key = $3")
        .bind(&reply_id)
        .bind(&emoji)
        .bind(&user.public_key)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "reply_updated",
            "channel_id": channel_id,
            "post_id": post_id,
            "reply_id": reply_id,
        }),
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── GET /channels/:cid/posts/search?q= ──────────────────────────────────────

pub async fn search_posts(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(channel_id): Path<String>,
    Query(params): Query<SearchParams>,
) -> Result<Json<PostSearchResponse>, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let q = params
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "q_required".to_string()))?;

    #[derive(sqlx::FromRow)]
    struct SearchRow {
        post_id: String,
        title_snippet: String,
        body_snippet: String,
    }

    let rows: Vec<SearchRow> = sqlx::query_as::<_, SearchRow>(
        "SELECT p.id AS post_id,
                COALESCE(ts_headline('simple', p.title, plainto_tsquery('simple', $1),
                    'StartSel=<b>,StopSel=</b>,MaxWords=10,MinWords=5,MaxFragments=1'), '') AS title_snippet,
                COALESCE(ts_headline('simple', p.body, plainto_tsquery('simple', $1),
                    'StartSel=<b>,StopSel=</b>,MaxWords=20,MinWords=10,MaxFragments=2'), '') AS body_snippet
         FROM posts p
         WHERE p.search_vector @@ plainto_tsquery('simple', $1)
           AND p.channel_id = $2
           AND p.deleted_at IS NULL
         LIMIT 50",
    )
    .bind(q)
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let results = rows
        .into_iter()
        .map(|r| PostSearchHit {
            post_id: r.post_id,
            title_snippet: r.title_snippet,
            body_snippet: r.body_snippet,
            is_reply: false,
            reply_id: None,
        })
        .collect();

    Ok(Json(PostSearchResponse {
        results,
        cursor: None,
    }))
}

// ── Federation: proxied writes (forum.md §9 phase 2) ────────────────────────
//
// Hit only by an allied hub over `/federation/forum/...`, never by an end
// user directly. `PeerHub` (not `AuthUser`) gates entry, mirroring
// `receive_federated_dm`. Crucially, the CALLER's own local
// `create_posts`/`send_messages`/`manage_posts` permissions do NOT apply
// here -- the caller authenticates as itself (its hub identity), which
// doesn't map to a member of this hub, so the only gate that matters is
// alliance membership (does the channel's alliance share include this peer?)
// plus the per-channel `forum_remote_write` policy. Content is attributed to
// the asserted `author_pubkey` with `author_hub` set to the caller's own
// public key -- never a client-supplied value, so a peer cannot claim to be
// forwarding on behalf of a different hub.

/// Resolve the federated-write policy for `channel_id` as seen from
/// `origin_hub_pubkey`: is this channel shared into an alliance that hub is
/// a member of, and if so under what policy? `None` means "not shared with
/// this caller at all" (reject as not-found, not forbidden, to avoid leaking
/// which channels exist). When a channel is shared into more than one
/// alliance the caller belongs to with different policies, the most
/// permissive one wins.
///
/// ponytail: only the *direct* `alliance_shared_channels` row is consulted --
/// a channel shared solely via an `include_descendants` category share has
/// no policy of its own yet. Add descendant-policy inheritance if a forum
/// under a shared category needs federated writes.
async fn forum_write_policy(
    db: &sqlx::PgPool,
    channel_id: &str,
    origin_hub_pubkey: &str,
) -> Result<Option<String>, (StatusCode, String)> {
    sqlx::query_scalar::<_, String>(
        "SELECT asc_.forum_remote_write
         FROM alliance_shared_channels asc_
         JOIN alliance_members am ON am.alliance_id = asc_.alliance_id
         WHERE asc_.channel_id = $1 AND am.hub_public_key = $2
         ORDER BY CASE asc_.forum_remote_write
             WHEN 'posts_and_replies' THEN 3
             WHEN 'replies_only' THEN 2
             ELSE 1
         END DESC
         LIMIT 1",
    )
    .bind(channel_id)
    .bind(origin_hub_pubkey)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}

/// Enforce the per-origin-hub federated forum write limiter. Mirrors the
/// `badge_offer` limiter in `federation/handlers.rs` (fixed window, same
/// eviction policy) — see `RateLimiters::forum_federated_write`.
fn check_forum_federated_rate_limit(
    state: &AppState,
    origin_hub_pubkey: &str,
) -> Result<(), (StatusCode, String)> {
    const LIMIT: u32 = 30;
    const WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
    const EVICTION_THRESHOLD: usize = 2_000;

    let mut map = state
        .rate_limiters
        .forum_federated_write
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    if map.len() >= EVICTION_THRESHOLD {
        map.retain(|_, (_, ts)| now.duration_since(*ts) <= WINDOW);
    }
    let entry = map.entry(origin_hub_pubkey.to_string()).or_insert((0, now));
    if now.duration_since(entry.1) > WINDOW {
        *entry = (0, now);
    }
    if entry.0 >= LIMIT {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate_limited".to_string()));
    }
    entry.0 += 1;
    Ok(())
}

/// Not-shared-with-this-caller vs. shared-but-policy-forbids: both surface
/// as 403 so an ally can't distinguish "you're not allied here" from
/// "you're allied but this forum doesn't take your posts" via status code
/// alone -- the JSON error body still names the reason.
fn require_write_policy(
    policy: Option<String>,
    allow_posts: bool,
) -> Result<(), (StatusCode, String)> {
    match policy.as_deref() {
        None => Err((
            StatusCode::FORBIDDEN,
            "channel_not_shared_with_caller".to_string(),
        )),
        Some("none") => Err((
            StatusCode::FORBIDDEN,
            "forum_remote_write_disabled".to_string(),
        )),
        Some("posts_and_replies") => Ok(()),
        Some("replies_only") if !allow_posts => Ok(()),
        Some("replies_only") => Err((
            StatusCode::FORBIDDEN,
            "forum_remote_write_posts_disabled".to_string(),
        )),
        Some(_) => Err((
            StatusCode::FORBIDDEN,
            "forum_remote_write_disabled".to_string(),
        )),
    }
}

// ── POST /federation/forum/channels/:cid/posts ──────────────────────────────

pub async fn federated_create_post(
    State(state): State<Arc<AppState>>,
    peer: PeerHub,
    Path(channel_id): Path<String>,
    Json(req): Json<FederatedCreatePostRequest>,
) -> Result<(StatusCode, Json<PostDetail>), (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let policy = forum_write_policy(&state.db, &channel_id, &peer.public_key).await?;
    require_write_policy(policy, true)?;
    check_forum_federated_rate_limit(&state, &peer.public_key)?;

    let author_pubkey = req.author_pubkey.trim().to_string();
    let title = req.title.trim().to_string();
    let body = req.body.trim().to_string();
    if author_pubkey.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "author_pubkey_required".to_string(),
        ));
    }
    if title.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title_required".to_string()));
    }
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "body_required".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let now = unix_now();

    sqlx::query(
        "INSERT INTO posts (id, channel_id, author_pubkey, author_hub, title, body, created_at, last_activity_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&channel_id)
    .bind(&author_pubkey)
    .bind(&peer.public_key)
    .bind(&title)
    .bind(&body)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let row = require_post(&state.db, &channel_id, &id).await?;
    // A freshly-created post is never a moderation-hidden tombstone, so the
    // viewer_can_moderate flag has no effect here.
    let summary = post_to_summary(&row, false, Vec::new());
    let detail = PostDetail {
        body: Some(row.body.clone()),
        replies: Vec::new(),
        reply_cursor: None,
        summary,
    };

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_created",
            "channel_id": channel_id,
            "post_id": id,
        }),
    );

    Ok((StatusCode::CREATED, Json(detail)))
}

// ── POST /federation/forum/channels/:cid/posts/:pid/replies ─────────────────

pub async fn federated_create_reply(
    State(state): State<Arc<AppState>>,
    peer: PeerHub,
    Path((channel_id, post_id)): Path<(String, String)>,
    Json(req): Json<FederatedCreateReplyRequest>,
) -> Result<(StatusCode, Json<ReplyView>), (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let policy = forum_write_policy(&state.db, &channel_id, &peer.public_key).await?;
    require_write_policy(policy, false)?;
    check_forum_federated_rate_limit(&state, &peer.public_key)?;

    let post_row = require_post(&state.db, &channel_id, &post_id).await?;
    if post_row.deleted_at.is_some() {
        return Err((StatusCode::GONE, "post_deleted".to_string()));
    }
    if post_row.is_locked {
        return Err((StatusCode::FORBIDDEN, "post_locked".to_string()));
    }

    let author_pubkey = req.author_pubkey.trim().to_string();
    let body = req.body.trim().to_string();
    if author_pubkey.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "author_pubkey_required".to_string(),
        ));
    }
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "body_required".to_string()));
    }

    if let Some(ref rto) = req.reply_to_id {
        let belongs: Option<String> =
            sqlx::query_scalar("SELECT id FROM post_replies WHERE id = $1 AND post_id = $2")
                .bind(rto)
                .bind(&post_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        if belongs.is_none() {
            return Err((StatusCode::NOT_FOUND, "reply_to_not_found".to_string()));
        }
    }

    let id = Uuid::new_v4().to_string();
    let now = unix_now();

    sqlx::query(
        "INSERT INTO post_replies (id, post_id, author_pubkey, author_hub, body, created_at, reply_to_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(&post_id)
    .bind(&author_pubkey)
    .bind(&peer.public_key)
    .bind(&body)
    .bind(now)
    .bind(&req.reply_to_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query(
        "UPDATE posts SET reply_count = reply_count + 1, last_activity_at = $1 WHERE id = $2",
    )
    .bind(now)
    .bind(&post_id)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let reply_row = require_reply(&state.db, &post_id, &id).await?;
    let view = reply_to_view(&reply_row, false, Vec::new());

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "reply_created",
            "channel_id": channel_id,
            "post_id": post_id,
            "reply_id": id,
        }),
    );

    Ok((StatusCode::CREATED, Json(view)))
}

// ── POST /federation/forum/channels/:cid/posts/:pid/reactions ───────────────

pub async fn federated_add_post_reaction(
    State(state): State<Arc<AppState>>,
    peer: PeerHub,
    Path((channel_id, post_id)): Path<(String, String)>,
    Json(req): Json<FederatedReactionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_forum_channel(&state.db, &channel_id).await?;

    let policy = forum_write_policy(&state.db, &channel_id, &peer.public_key).await?;
    require_write_policy(policy, false)?;
    check_forum_federated_rate_limit(&state, &peer.public_key)?;

    let _ = require_post(&state.db, &channel_id, &post_id).await?;

    let author_pubkey = req.author_pubkey.trim().to_string();
    if author_pubkey.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "author_pubkey_required".to_string(),
        ));
    }
    let emoji = req.emoji.trim();
    if emoji.is_empty() || emoji.chars().count() > 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "emoji must be 1..8 chars".to_string(),
        ));
    }

    let now = unix_now();
    sqlx::query(
        "INSERT INTO post_reactions (post_id, emoji, user_key, created_at)
         VALUES ($1, $2, $3, $4) ON CONFLICT (post_id, emoji, user_key) DO NOTHING",
    )
    .bind(&post_id)
    .bind(emoji)
    .bind(&author_pubkey)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    broadcast_forum_event(
        &state,
        &channel_id,
        serde_json::json!({
            "type": "post_updated",
            "channel_id": channel_id,
            "post_id": post_id,
        }),
    );

    Ok(StatusCode::CREATED)
}
