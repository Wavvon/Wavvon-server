use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::routes::dm_models::*;
use crate::state::AppState;

use super::models::{ensure_user_stub, find_existing_dm, load_members, ConvRow};

pub async fn create_conversation(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateConversationRequest>,
) -> Result<(StatusCode, Json<ConversationResponse>), (StatusCode, String)> {
    if req.members.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Need at least one other member".to_string(),
        ));
    }

    let conv_type = if req.members.len() == 1 {
        "dm"
    } else {
        "group"
    };

    // For DMs (1-on-1), check if a conversation already exists between these two users
    if conv_type == "dm" {
        let existing = find_existing_dm(&state, &user.public_key, &req.members[0]).await?;
        if let Some(conv) = existing {
            return Ok((StatusCode::OK, Json(conv)));
        }
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query("INSERT INTO conversations (id, conv_type, created_at) VALUES ($1, $2, $3)")
        .bind(&id)
        .bind(conv_type)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Add the creator (always local)
    sqlx::query("INSERT INTO conversation_members (conversation_id, public_key, joined_at, hub_url) VALUES ($1, $2, $3, NULL)")
        .bind(&id)
        .bind(&user.public_key)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Add other members with their (optional) delivery hub URL.
    // Remote members may not yet exist in our users table — insert a stub so
    // the FK holds. We only track public_key for these; they never sign in here.
    for member_key in &req.members {
        let hub_url = req.member_hubs.get(member_key).cloned();
        ensure_user_stub(&state.db, member_key, now).await?;
        sqlx::query("INSERT INTO conversation_members (conversation_id, public_key, joined_at, hub_url) VALUES ($1, $2, $3, $4)")
            .bind(&id)
            .bind(member_key)
            .bind(now)
            .bind(&hub_url)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let mut all_members = req.members.clone();
    all_members.push(user.public_key);

    Ok((
        StatusCode::CREATED,
        Json(ConversationResponse {
            id,
            conv_type: conv_type.to_string(),
            members: all_members,
            created_at: now,
            last_activity_at: now,
        }),
    ))
}

pub async fn list_conversations(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<Json<Vec<ConversationResponse>>, (StatusCode, String)> {
    let rows = sqlx::query_as::<_, ConvRow>(
        "SELECT c.id, c.conv_type, c.created_at
         FROM conversations c
         INNER JOIN conversation_members cm ON c.id = cm.conversation_id
         WHERE cm.public_key = $1
         ORDER BY c.created_at DESC",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::new();
    for row in rows {
        let members: Vec<String> = sqlx::query_scalar(
            "SELECT public_key FROM conversation_members WHERE conversation_id = $1",
        )
        .bind(&row.id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        // Last activity = most recent dm_message in this conversation, or
        // the conversation creation time if there are no messages yet.
        let last_msg: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(created_at) FROM dm_messages WHERE conversation_id = $1",
        )
        .bind(&row.id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        result.push(ConversationResponse {
            id: row.id,
            conv_type: row.conv_type,
            members,
            created_at: row.created_at,
            last_activity_at: last_msg.unwrap_or(row.created_at),
        });
    }

    Ok(Json(result))
}

// GET /conversations/:id — a single conversation the requester is a member
// of. Membership is enforced by the JOIN, so a non-member gets the same 404
// as a nonexistent id (no existence leak). The web client depends on this
// route in its DM send path (member lookup for E2E) and its
// dm_members_changed WS handler.
pub async fn get_conversation(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
) -> Result<Json<ConversationResponse>, (StatusCode, String)> {
    let row = sqlx::query_as::<_, ConvRow>(
        "SELECT c.id, c.conv_type, c.created_at
         FROM conversations c
         INNER JOIN conversation_members cm ON c.id = cm.conversation_id
         WHERE c.id = $1 AND cm.public_key = $2",
    )
    .bind(&conversation_id)
    .bind(&user.public_key)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
    .ok_or((StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;

    let members: Vec<String> = sqlx::query_scalar(
        "SELECT public_key FROM conversation_members WHERE conversation_id = $1",
    )
    .bind(&row.id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let last_msg: Option<i64> =
        sqlx::query_scalar("SELECT MAX(created_at) FROM dm_messages WHERE conversation_id = $1")
            .bind(&row.id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    Ok(Json(ConversationResponse {
        id: row.id,
        conv_type: row.conv_type,
        members,
        created_at: row.created_at,
        last_activity_at: last_msg.unwrap_or(row.created_at),
    }))
}

// ---------------------------------------------------------------------------
// POST /conversations/:id/members  { "public_key": "..." }
// Adds a member to a group conversation. Caller must already be a member.
// Not permitted on 1-on-1 DMs (conv_type = 'dm').
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub public_key: String,
}

pub async fn add_conversation_member(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(conversation_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let members = load_members(&state, &conversation_id).await?;
    if !members.iter().any(|m| m.public_key == user.public_key) {
        return Err((
            StatusCode::FORBIDDEN,
            "Not a member of this conversation".to_string(),
        ));
    }

    // Only group conversations allow member management.
    let conv_type: String = sqlx::query_scalar("SELECT conv_type FROM conversations WHERE id = $1")
        .bind(&conversation_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .ok_or((StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;
    if conv_type != "group" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Cannot add members to a 1-on-1 DM".to_string(),
        ));
    }

    // No-op if already a member.
    if members.iter().any(|m| m.public_key == req.public_key) {
        return Ok(StatusCode::NO_CONTENT);
    }

    let now = crate::auth::handlers::unix_timestamp();
    ensure_user_stub(&state.db, &req.public_key, now).await?;
    sqlx::query(
        "INSERT INTO conversation_members (conversation_id, public_key, joined_at, hub_url)
         VALUES ($1, $2, $3, NULL)
         ON CONFLICT DO NOTHING",
    )
    .bind(&conversation_id)
    .bind(&req.public_key)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let _ = state.dm_tx.send(crate::state::DmEvent::MemberChanged {
        conversation_id,
        actor: user.public_key,
        added: vec![req.public_key],
        removed: vec![],
    });

    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// DELETE /conversations/:id/members/:pubkey
// Removes a member from a group conversation. Callers may only remove themselves.
// ---------------------------------------------------------------------------

pub async fn remove_conversation_member(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((conversation_id, pubkey)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    if pubkey != user.public_key {
        return Err((
            StatusCode::FORBIDDEN,
            "You can only remove yourself from a conversation".to_string(),
        ));
    }

    let members = load_members(&state, &conversation_id).await?;
    if !members.iter().any(|m| m.public_key == user.public_key) {
        return Err((
            StatusCode::NOT_FOUND,
            "Not a member of this conversation".to_string(),
        ));
    }

    let conv_type: String = sqlx::query_scalar("SELECT conv_type FROM conversations WHERE id = $1")
        .bind(&conversation_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?
        .ok_or((StatusCode::NOT_FOUND, "Conversation not found".to_string()))?;
    if conv_type != "group" {
        return Err((
            StatusCode::BAD_REQUEST,
            "Cannot leave a 1-on-1 DM".to_string(),
        ));
    }

    sqlx::query("DELETE FROM conversation_members WHERE conversation_id = $1 AND public_key = $2")
        .bind(&conversation_id)
        .bind(&pubkey)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let _ = state.dm_tx.send(crate::state::DmEvent::MemberChanged {
        conversation_id,
        actor: user.public_key,
        added: vec![],
        removed: vec![pubkey],
    });

    Ok(StatusCode::NO_CONTENT)
}
