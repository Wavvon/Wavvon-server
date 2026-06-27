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
               SELECT channel_id FROM channel_bans WHERE target_public_key = $1
           )",
    )
    .bind(&user.public_key)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    if visible_channels.is_empty() {
        return Ok(Json(vec![]));
    }

    // Query Tantivy with visibility filter.
    let search_params = crate::search::SearchParams {
        q: params.q.trim().to_string(),
        channel_ids: visible_channels,
        limit: limit as usize,
    };
    let hits = state.search.query(&search_params).await.unwrap_or_default();

    if hits.is_empty() {
        return Ok(Json(vec![]));
    }

    // Fetch channel name and sender display name for each hit from the DB.
    let ids: Vec<String> = hits.iter().map(|h| h.message_id.clone()).collect();
    let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let sql = format!(
        "SELECT m.id, c.name, u.display_name
         FROM messages m
         JOIN channels c ON c.id = m.channel_id
         LEFT JOIN users u ON u.public_key = m.sender
         WHERE m.id IN ({placeholders})"
    );

    let mut q_builder = sqlx::query_as::<_, (String, String, Option<String>)>(&sql);
    for id in &ids {
        q_builder = q_builder.bind(id);
    }
    let meta_rows = q_builder.fetch_all(&state.db).await.unwrap_or_default();

    // Build a lookup map id -> (channel_name, sender_name)
    let meta_map: std::collections::HashMap<String, (String, Option<String>)> = meta_rows
        .into_iter()
        .map(|(id, channel_name, sender_name)| (id, (channel_name, sender_name)))
        .collect();

    let results: Vec<SearchResult> = hits
        .into_iter()
        .filter_map(|hit| {
            let (channel_name, sender_name) = meta_map.get(&hit.message_id)?.clone();
            Some(SearchResult {
                message_id: hit.message_id,
                channel_id: hit.channel_id,
                channel_name,
                sender: hit.author_pubkey,
                sender_name,
                content_preview: hit.content_preview,
                created_at: hit.timestamp,
            })
        })
        .collect();

    Ok(Json(results))
}
