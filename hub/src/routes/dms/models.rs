use axum::http::StatusCode;

use crate::routes::chat_models::Attachment;
use crate::state::AppState;

// ---------------------------------------------------------------------------
// DB row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
pub(super) struct ConvRow {
    pub id: String,
    pub conv_type: String,
    pub created_at: i64,
}

#[derive(sqlx::FromRow)]
pub(super) struct DmMessageRow {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content: Option<String>,
    pub attachments: Option<String>,
    pub created_at: i64,
    pub is_encrypted: i64,
    pub ciphertext_json: Option<String>,
    pub is_group_encrypted: i64,
    /// 0 or 1 from SQLite EXISTS — there's no native bool, so we cast at
    /// the boundary in list_dm_messages.
    pub delivery_failed: i64,
}

pub(super) struct ConvMember {
    pub public_key: String,
    pub hub_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub fn parse_dm_attachments(json: Option<String>) -> Vec<Attachment> {
    json.as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

/// Ensure a user row exists for `public_key` so FKs into the users table hold.
/// For remote users we only know their key; the stub is created with no display name.
pub async fn ensure_user_stub(
    db: &sqlx::AnyPool,
    public_key: &str,
    now: i64,
) -> Result<(), (StatusCode, String)> {
    sqlx::query(
        "INSERT INTO users (public_key, display_name, first_seen_at, last_seen_at)
         VALUES (?, NULL, ?, ?) ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(public_key)
    .bind(now)
    .bind(now)
    .execute(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    Ok(())
}

pub async fn load_members(
    state: &AppState,
    conversation_id: &str,
) -> Result<Vec<ConvMember>, (StatusCode, String)> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT public_key, hub_url FROM conversation_members WHERE conversation_id = ?",
    )
    .bind(conversation_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(rows
        .into_iter()
        .map(|(pk, url)| ConvMember {
            public_key: pk,
            hub_url: url,
        })
        .collect())
}

use crate::routes::dm_models::ConversationResponse;

pub async fn find_existing_dm(
    state: &AppState,
    user_a: &str,
    user_b: &str,
) -> Result<Option<ConversationResponse>, (StatusCode, String)> {
    let convs: Vec<String> = sqlx::query_scalar(
        "SELECT cm1.conversation_id FROM conversation_members cm1
         INNER JOIN conversation_members cm2 ON cm1.conversation_id = cm2.conversation_id
         INNER JOIN conversations c ON c.id = cm1.conversation_id
         WHERE cm1.public_key = ? AND cm2.public_key = ? AND c.conv_type = 'dm'",
    )
    .bind(user_a)
    .bind(user_b)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for conv_id in convs {
        let member_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM conversation_members WHERE conversation_id = ?",
        )
        .bind(&conv_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        if member_count == 2 {
            let conv = sqlx::query_as::<_, ConvRow>(
                "SELECT id, conv_type, created_at FROM conversations WHERE id = ?",
            )
            .bind(&conv_id)
            .fetch_one(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            return Ok(Some(ConversationResponse {
                id: conv.id,
                conv_type: conv.conv_type,
                members: vec![user_a.to_string(), user_b.to_string()],
                created_at: conv.created_at,
                last_activity_at: conv.created_at,
            }));
        }
    }

    Ok(None)
}
