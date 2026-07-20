use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{ChatEvent, MessageResponse, WsServerMessage};
use crate::state::AppState;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PollOption {
    pub id: String,
    pub text: String,
}

#[derive(Deserialize)]
pub struct CreatePollRequest {
    pub question: String,
    pub options: Vec<PollOption>,
    #[serde(default)]
    pub ends_at: Option<i64>,
    #[serde(default)]
    pub max_choices: Option<i64>,
}

#[derive(Deserialize)]
pub struct VoteRequest {
    pub option_ids: Vec<String>,
}

#[derive(Serialize, Clone, sqlx::FromRow)]
pub struct PollResponse {
    pub id: String,
    pub channel_id: String,
    pub creator_pubkey: String,
    pub question: String,
    /// JSON-encoded Vec<PollOption> as stored.
    pub options: String,
    pub ends_at: Option<i64>,
    pub max_choices: i64,
    pub created_at: i64,
}

#[derive(Serialize)]
pub struct PollWithTotals {
    #[serde(flatten)]
    pub poll: PollResponse,
    /// option_id → vote count
    pub totals: HashMap<String, i64>,
    /// The calling user's current vote (option_ids), if any.
    pub your_vote: Option<Vec<String>>,
}

/// Poll option shape used by the channel poll listing, matching the web
/// client's `Poll`/`PollOption` types (`clients/apps/web/src/types.ts`)
/// byte-for-byte so `getPolls()` can cast the response directly.
#[derive(Serialize)]
pub struct PollOptionOut {
    pub id: String,
    pub text: String,
    pub vote_count: i64,
    pub voted: bool,
}

/// Poll shape returned by `GET /channels/:channel_id/polls`. Unlike
/// `PollWithTotals` (used by `GET /polls/:poll_id`), this flattens vote
/// totals and the caller's own vote directly into each option, matching
/// the client's `Poll` interface exactly.
#[derive(Serialize)]
pub struct PollListItem {
    pub id: String,
    pub channel_id: String,
    pub question: String,
    pub options: Vec<PollOptionOut>,
    pub total_votes: i64,
    pub created_by: String,
    pub created_at: i64,
    pub ends_at: Option<i64>,
    pub is_deleted: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Aggregate vote counts across all voters for a poll.
async fn load_poll_totals(
    db: &sqlx::PgPool,
    poll_id: &str,
) -> Result<HashMap<String, i64>, (StatusCode, String)> {
    let rows: Vec<String> =
        sqlx::query_scalar("SELECT option_ids FROM poll_votes WHERE poll_id = $1")
            .bind(poll_id)
            .fetch_all(db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut totals: HashMap<String, i64> = HashMap::new();
    for row in rows {
        let ids: Vec<String> = serde_json::from_str(&row).unwrap_or_default();
        for id in ids {
            *totals.entry(id).or_insert(0) += 1;
        }
    }
    Ok(totals)
}

/// Insert a card message for the poll into the channel and broadcast via WS.
/// The creator's users row is guaranteed to exist (they just authenticated).
async fn post_poll_card(
    state: &AppState,
    channel_id: &str,
    poll: &PollResponse,
) -> Result<(), (StatusCode, String)> {
    let content = format!("**Poll:** {}", poll.question);
    let msg_id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let sender = &poll.creator_pubkey;

    sqlx::query(
        "INSERT INTO messages (id, channel_id, sender, content, created_at) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&msg_id)
    .bind(channel_id)
    .bind(sender)
    .bind(&content)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let message = MessageResponse {
        id: msg_id,
        channel_id: channel_id.to_string(),
        sender: sender.to_string(),
        sender_name: None,
        content,
        created_at: now,
        edited_at: None,
        attachments: Vec::new(),
        reactions: Vec::new(),
        reply_to: None,
        visible_to_pubkey: None,
        reply_count: 0,
        embeds: None,
        game: None,
    };

    let ws_msg = WsServerMessage::ChatMessage {
        channel_id: channel_id.to_string(),
        message: message.clone(),
    };
    let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
    let _ = state.chat_tx.send((
        ChatEvent::New {
            channel_id: channel_id.to_string(),
            message,
        },
        json,
    ));

    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /channels/:channel_id/polls
pub async fn create_poll(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
    Json(req): Json<CreatePollRequest>,
) -> Result<(StatusCode, Json<PollResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::SEND_MESSAGES)?;

    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(&channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    if req.question.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "question is required".to_string()));
    }
    if req.options.len() < 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least 2 options required".to_string(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let max_choices = req.max_choices.unwrap_or(1).max(1);
    let options_json = serde_json::to_string(
        &req.options
            .iter()
            .map(|o| serde_json::json!({ "id": o.id, "text": o.text }))
            .collect::<Vec<_>>(),
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Encode error: {e}"),
        )
    })?;

    sqlx::query(
        "INSERT INTO polls (id, channel_id, creator_pubkey, question, options, ends_at, max_choices, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(&id)
    .bind(&channel_id)
    .bind(&user.public_key)
    .bind(&req.question)
    .bind(&options_json)
    .bind(req.ends_at)
    .bind(max_choices)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let poll = PollResponse {
        id,
        channel_id: channel_id.clone(),
        creator_pubkey: user.public_key,
        question: req.question,
        options: options_json,
        ends_at: req.ends_at,
        max_choices,
        created_at: now,
    };

    post_poll_card(&state, &channel_id, &poll).await?;

    Ok((StatusCode::CREATED, Json(poll)))
}

/// GET /channels/:channel_id/polls
///
/// Returns every poll on the channel, newest first, in the flattened shape
/// the web client's `getPolls()` expects (vote totals and the caller's own
/// vote already merged into each option). Gated behind the same effective
/// READ_MESSAGES permission as message history and pinned messages (§3.5).
pub async fn list_polls(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(channel_id): Path<String>,
) -> Result<Json<Vec<PollListItem>>, (StatusCode, String)> {
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(&channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::READ_MESSAGES)?;

    let polls: Vec<PollResponse> = sqlx::query_as(
        "SELECT id, channel_id, creator_pubkey, question, options, ends_at, max_choices, created_at
         FROM polls WHERE channel_id = $1
         ORDER BY created_at DESC, id DESC",
    )
    .bind(&channel_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut out = Vec::with_capacity(polls.len());
    for poll in polls {
        let totals = load_poll_totals(&state.db, &poll.id).await?;

        let your_vote_raw: Option<String> = sqlx::query_scalar(
            "SELECT option_ids FROM poll_votes WHERE poll_id = $1 AND user_pubkey = $2",
        )
        .bind(&poll.id)
        .bind(&user.public_key)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        let your_vote: Vec<String> = your_vote_raw
            .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
            .unwrap_or_default();

        let options: Vec<PollOption> = serde_json::from_str(&poll.options).unwrap_or_default();
        let total_votes: i64 = totals.values().sum();
        let options_out = options
            .into_iter()
            .map(|o| PollOptionOut {
                vote_count: totals.get(&o.id).copied().unwrap_or(0),
                voted: your_vote.contains(&o.id),
                id: o.id,
                text: o.text,
            })
            .collect();

        out.push(PollListItem {
            id: poll.id,
            channel_id: poll.channel_id,
            question: poll.question,
            options: options_out,
            total_votes,
            created_by: poll.creator_pubkey,
            created_at: poll.created_at,
            ends_at: poll.ends_at,
            is_deleted: false,
        });
    }

    Ok(Json(out))
}

/// GET /polls/:poll_id
pub async fn get_poll(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(poll_id): Path<String>,
) -> Result<Json<PollWithTotals>, (StatusCode, String)> {
    let poll: Option<PollResponse> = sqlx::query_as(
        "SELECT id, channel_id, creator_pubkey, question, options, ends_at, max_choices, created_at
         FROM polls WHERE id = $1",
    )
    .bind(&poll_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let poll = poll.ok_or((StatusCode::NOT_FOUND, "Poll not found".to_string()))?;

    let totals = load_poll_totals(&state.db, &poll_id).await?;

    let your_vote_raw: Option<String> = sqlx::query_scalar(
        "SELECT option_ids FROM poll_votes WHERE poll_id = $1 AND user_pubkey = $2",
    )
    .bind(&poll_id)
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let your_vote = your_vote_raw.and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok());

    Ok(Json(PollWithTotals {
        poll,
        totals,
        your_vote,
    }))
}

/// POST /polls/:poll_id/vote
pub async fn vote_poll(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(poll_id): Path<String>,
    Json(req): Json<VoteRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let poll: Option<(String, i64, Option<i64>)> =
        sqlx::query_as("SELECT channel_id, max_choices, ends_at FROM polls WHERE id = $1")
            .bind(&poll_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (channel_id, max_choices, ends_at) =
        poll.ok_or((StatusCode::NOT_FOUND, "Poll not found".to_string()))?;

    // Closed poll check.
    if let Some(end) = ends_at {
        if crate::auth::handlers::unix_timestamp() > end {
            return Err((StatusCode::GONE, "Poll has ended".to_string()));
        }
    }

    if req.option_ids.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "option_ids must not be empty".to_string(),
        ));
    }
    if req.option_ids.len() as i64 > max_choices {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("too many choices; max is {max_choices}"),
        ));
    }

    let option_ids_json = serde_json::to_string(&req.option_ids).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Encode error: {e}"),
        )
    })?;

    sqlx::query(
        "INSERT INTO poll_votes (poll_id, user_pubkey, option_ids)
         VALUES ($1, $2, $3)
         ON CONFLICT(poll_id, user_pubkey) DO UPDATE SET option_ids = excluded.option_ids",
    )
    .bind(&poll_id)
    .bind(&user.public_key)
    .bind(&option_ids_json)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Broadcast updated totals over WS.
    let totals = load_poll_totals(&state.db, &poll_id).await?;
    {
        let ws_msg = WsServerMessage::PollVoteUpdated {
            channel_id: channel_id.clone(),
            poll_id: poll_id.clone(),
            totals: totals.clone(),
        };
        let json: Arc<str> = Arc::from(serde_json::to_string(&ws_msg).unwrap().as_str());
        let _ = state.chat_tx.send((ChatEvent::Poll { channel_id }, json));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /polls/:poll_id
pub async fn delete_poll(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(poll_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row: Option<(String,)> = sqlx::query_as("SELECT creator_pubkey FROM polls WHERE id = $1")
        .bind(&poll_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (creator,) = row.ok_or((StatusCode::NOT_FOUND, "Poll not found".to_string()))?;

    if creator != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    sqlx::query("DELETE FROM polls WHERE id = $1")
        .bind(&poll_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}
