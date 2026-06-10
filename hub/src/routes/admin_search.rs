use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Serialize;

use crate::auth::middleware::AuthUser;
use crate::permissions::{self, ADMIN};
use crate::search::IndexedMessage;
use crate::state::AppState;

#[derive(Serialize)]
pub struct ReindexResponse {
    pub status: &'static str,
}

/// POST /admin/search/reindex
///
/// Rebuilds the full-text search index from the messages table. Admin-only.
/// Long-running: the work is spawned in the background and this handler
/// returns immediately with 202 Accepted.
///
/// If a reindex is already in progress, returns 202 with
/// `{"status":"already_running"}` instead of starting a second job.
pub async fn admin_reindex(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<(StatusCode, Json<ReindexResponse>), (StatusCode, String)> {
    // ADMIN permission required — mirrors every other /admin/* endpoint.
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(ADMIN)?;

    // Guard against concurrent reindex runs with a compare-exchange.
    if state
        .reindex_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(ReindexResponse {
                status: "already_running",
            }),
        ));
    }

    // Fetch all messages from the DB before spawning so the spawn doesn't
    // need access to the pool inside a blocking context.
    let rows: Vec<(String, String, String, String, i64)> = sqlx::query_as(
        "SELECT id, channel_id, sender, content, created_at FROM messages ORDER BY created_at ASC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        // Release the flag on DB error so future calls aren't stuck.
        state.reindex_running.store(false, Ordering::SeqCst);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}"))
    })?;

    let messages: Vec<IndexedMessage> = rows
        .into_iter()
        .map(
            |(id, channel_id, author_pubkey, content, timestamp)| IndexedMessage {
                id,
                channel_id,
                author_pubkey,
                content,
                timestamp,
            },
        )
        .collect();

    let search = state.search.clone();
    let flag = state.reindex_running.clone();

    tokio::spawn(async move {
        match search.reindex_all(messages).await {
            Ok(()) => tracing::info!("Search reindex completed successfully"),
            Err(e) => tracing::error!("Search reindex failed: {e}"),
        }
        flag.store(false, Ordering::SeqCst);
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(ReindexResponse { status: "started" }),
    ))
}
