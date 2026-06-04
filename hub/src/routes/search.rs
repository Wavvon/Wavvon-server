use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SearchQuery {
    pub q: String,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    20
}

#[derive(Serialize, Deserialize)]
pub struct SearchResult {
    pub message_id: String,
    pub channel_id: String,
    pub channel_name: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content_preview: String,
    pub created_at: i64,
}

pub async fn search_messages(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<SearchResult>>, (StatusCode, String)> {
    if params.q.trim().len() < 2 {
        return Ok(Json(vec![]));
    }

    let limit = params.limit.min(100);

    // Channels the user is not banned from (text channels only).
    let visible_channels: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM channels
         WHERE is_category = 0
           AND channel_type = 'text'
           AND id NOT IN (
               SELECT channel_id FROM channel_bans WHERE target_public_key = ?
           )",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    if visible_channels.is_empty() {
        return Ok(Json(vec![]));
    }

    // Build the IN-clause placeholder list. sqlx does not support dynamic IN
    // binding, so we build the SQL string manually and bind positionally.
    let placeholders = visible_channels
        .iter()
        .map(|_| "?")
        .collect::<Vec<_>>()
        .join(",");

    let sql = format!(
        "SELECT m.id, m.channel_id, c.name, m.sender, u.display_name, m.content, m.created_at
         FROM messages_fts fts
         JOIN messages m ON fts.rowid = m.rowid
         JOIN channels c ON c.id = m.channel_id
         LEFT JOIN users u ON u.public_key = m.sender
         WHERE messages_fts MATCH ?
           AND m.channel_id IN ({placeholders})
         ORDER BY m.created_at DESC
         LIMIT ?"
    );

    let mut query =
        sqlx::query_as::<_, (String, String, String, String, Option<String>, String, i64)>(&sql);
    query = query.bind(&params.q);
    for ch in &visible_channels {
        query = query.bind(ch);
    }
    query = query.bind(limit);

    let rows = query.fetch_all(&state.db).await.unwrap_or_default();

    let results = rows
        .into_iter()
        .map(
            |(id, channel_id, channel_name, sender, sender_name, content, created_at)| {
                // Truncate at a char boundary to avoid panics on multi-byte text.
                let preview = if content.len() > 200 {
                    let boundary = content
                        .char_indices()
                        .map(|(i, _)| i)
                        .take_while(|&i| i <= 197)
                        .last()
                        .unwrap_or(0);
                    format!("{}\u{2026}", &content[..boundary])
                } else {
                    content
                };
                SearchResult {
                    message_id: id,
                    channel_id,
                    channel_name,
                    sender,
                    sender_name,
                    content_preview: preview,
                    created_at,
                }
            },
        )
        .collect();

    Ok(Json(results))
}
