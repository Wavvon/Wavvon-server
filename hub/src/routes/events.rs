use std::sync::Arc;

use axum::extract::{Path, Query, State};
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
pub struct CreateEventRequest {
    pub channel_id: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    pub starts_at: i64,
    #[serde(default)]
    pub ends_at: Option<i64>,
    #[serde(default)]
    pub location: Option<String>,
}

#[derive(Deserialize, Default)]
pub struct UpdateEventRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub starts_at: Option<i64>,
    #[serde(default)]
    pub ends_at: Option<i64>,
    #[serde(default)]
    pub location: Option<String>,
}

#[derive(Deserialize)]
pub struct RsvpRequest {
    pub status: String,
}

#[derive(Serialize, Clone, sqlx::FromRow)]
pub struct EventResponse {
    pub id: String,
    pub channel_id: String,
    pub creator_pubkey: String,
    pub title: String,
    pub description: String,
    pub starts_at: i64,
    pub ends_at: Option<i64>,
    pub location: Option<String>,
    pub created_at: i64,
}

#[derive(Serialize, Clone)]
pub struct EventWithRsvps {
    #[serde(flatten)]
    pub event: EventResponse,
    pub rsvp_counts: RsvpCounts,
}

#[derive(Serialize, Clone, Default)]
pub struct RsvpCounts {
    pub going: i64,
    pub maybe: i64,
    pub not_going: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct RsvpEntry {
    pub user_pubkey: String,
    pub status: String,
}

#[derive(Deserialize)]
pub struct ListEventsParams {
    pub upcoming: Option<bool>,
    pub limit: Option<i64>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a Unix timestamp as "YYYY-MM-DD HH:MM UTC" without external dependencies.
fn format_unix_utc(ts: i64) -> String {
    // Days since epoch arithmetic (Gregorian proleptic calendar).
    const SECS_PER_MIN: i64 = 60;
    const SECS_PER_HOUR: i64 = 3600;
    const SECS_PER_DAY: i64 = 86400;

    let ts = ts.max(0);
    let time_of_day = ts % SECS_PER_DAY;
    let days = ts / SECS_PER_DAY;

    let h = time_of_day / SECS_PER_HOUR;
    let m = (time_of_day % SECS_PER_HOUR) / SECS_PER_MIN;

    // Civil date from days-since-1970-01-01 (algorithm from Howard Hinnant).
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = y + if mth <= 2 { 1 } else { 0 };

    format!("{yr:04}-{mth:02}-{d:02} {h:02}:{m:02} UTC")
}

fn system_message_sender() -> &'static str {
    "00000000000000000000000000000000000000000000000000000000000000000000"
}

async fn load_rsvp_counts(
    db: &sqlx::AnyPool,
    event_id: &str,
) -> Result<RsvpCounts, (StatusCode, String)> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) as cnt FROM event_rsvps WHERE event_id = ? GROUP BY status",
    )
    .bind(event_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut counts = RsvpCounts::default();
    for (status, cnt) in rows {
        match status.as_str() {
            "going" => counts.going = cnt,
            "maybe" => counts.maybe = cnt,
            "not_going" => counts.not_going = cnt,
            _ => {}
        }
    }
    Ok(counts)
}

/// Insert a system card message into the channel and broadcast it over WS.
async fn post_event_card(
    state: &AppState,
    channel_id: &str,
    event: &EventResponse,
) -> Result<(), (StatusCode, String)> {
    // Format starts_at as a simple UTC string for the card content.
    // We avoid pulling in chrono — a direct conversion is fine for display.
    let dt = format_unix_utc(event.starts_at);

    let content = format!("**{}** — {}", event.title, dt);
    let msg_id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let sender = system_message_sender();

    // Ensure the system-message sender exists so the FK is satisfied.
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at) VALUES (?, ?, ?)
         ON CONFLICT (public_key) DO NOTHING",
    )
    .bind(sender)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    sqlx::query(
        "INSERT INTO messages (id, channel_id, sender, content, created_at) VALUES (?, ?, ?, ?, ?)",
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

/// POST /events
pub async fn create_event(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(req): Json<CreateEventRequest>,
) -> Result<(StatusCode, Json<EventResponse>), (StatusCode, String)> {
    let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
    perms.require(permissions::CREATE_EVENTS)?;

    // Verify channel exists.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = ?")
        .bind(&req.channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    if req.title.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title is required".to_string()));
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let description = req.description.unwrap_or_default();

    sqlx::query(
        "INSERT INTO hub_events (id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.channel_id)
    .bind(&user.public_key)
    .bind(&req.title)
    .bind(&description)
    .bind(req.starts_at)
    .bind(req.ends_at)
    .bind(&req.location)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let event = EventResponse {
        id,
        channel_id: req.channel_id,
        creator_pubkey: user.public_key,
        title: req.title,
        description,
        starts_at: req.starts_at,
        ends_at: req.ends_at,
        location: req.location,
        created_at: now,
    };

    post_event_card(&state, &event.channel_id, &event).await?;

    Ok((StatusCode::CREATED, Json(event)))
}

/// GET /events
pub async fn list_events(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Query(params): Query<ListEventsParams>,
) -> Result<Json<Vec<EventWithRsvps>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(20).min(100);
    let upcoming = params.upcoming.unwrap_or(false);
    let now = crate::auth::handlers::unix_timestamp();

    let rows: Vec<EventResponse> = if upcoming {
        sqlx::query_as(
            "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at
             FROM hub_events WHERE starts_at >= ? ORDER BY starts_at ASC LIMIT ?",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as(
            "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at
             FROM hub_events ORDER BY starts_at ASC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let mut result = Vec::with_capacity(rows.len());
    for event in rows {
        let rsvp_counts = load_rsvp_counts(&state.db, &event.id).await?;
        result.push(EventWithRsvps { event, rsvp_counts });
    }
    Ok(Json(result))
}

/// GET /events/:id
pub async fn get_event(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(event_id): Path<String>,
) -> Result<Json<EventWithRsvps>, (StatusCode, String)> {
    let event: Option<EventResponse> = sqlx::query_as(
        "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at
         FROM hub_events WHERE id = ?",
    )
    .bind(&event_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let event = event.ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;
    let rsvp_counts = load_rsvp_counts(&state.db, &event_id).await?;
    Ok(Json(EventWithRsvps { event, rsvp_counts }))
}

/// PUT /events/:id
pub async fn update_event(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(event_id): Path<String>,
    Json(req): Json<UpdateEventRequest>,
) -> Result<Json<EventResponse>, (StatusCode, String)> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT creator_pubkey FROM hub_events WHERE id = ?")
            .bind(&event_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (creator,) = row.ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    if creator != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    if let Some(title) = &req.title {
        sqlx::query("UPDATE hub_events SET title = ? WHERE id = ?")
            .bind(title)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(desc) = &req.description {
        sqlx::query("UPDATE hub_events SET description = ? WHERE id = ?")
            .bind(desc)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(starts) = req.starts_at {
        sqlx::query("UPDATE hub_events SET starts_at = ? WHERE id = ?")
            .bind(starts)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ends) = req.ends_at {
        sqlx::query("UPDATE hub_events SET ends_at = ? WHERE id = ?")
            .bind(ends)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(loc) = &req.location {
        sqlx::query("UPDATE hub_events SET location = ? WHERE id = ?")
            .bind(loc)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let updated: EventResponse = sqlx::query_as(
        "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at
         FROM hub_events WHERE id = ?",
    )
    .bind(&event_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(updated))
}

/// DELETE /events/:id
pub async fn delete_event(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(event_id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT creator_pubkey FROM hub_events WHERE id = ?")
            .bind(&event_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (creator,) = row.ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    if creator != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    sqlx::query("DELETE FROM hub_events WHERE id = ?")
        .bind(&event_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// POST /events/:id/rsvp
pub async fn rsvp_event(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(event_id): Path<String>,
    Json(req): Json<RsvpRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Validate status value.
    match req.status.as_str() {
        "going" | "maybe" | "not_going" => {}
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                "status must be going, maybe, or not_going".to_string(),
            ))
        }
    }

    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM hub_events WHERE id = ?")
        .bind(&event_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Event not found".to_string()));
    }

    sqlx::query(
        "INSERT INTO event_rsvps (event_id, user_pubkey, status)
         VALUES (?, ?, ?)
         ON CONFLICT(event_id, user_pubkey) DO UPDATE SET status = excluded.status",
    )
    .bind(&event_id)
    .bind(&user.public_key)
    .bind(&req.status)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// GET /events/:id/rsvps
pub async fn list_rsvps(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(event_id): Path<String>,
) -> Result<Json<Vec<RsvpEntry>>, (StatusCode, String)> {
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM hub_events WHERE id = ?")
        .bind(&event_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Event not found".to_string()));
    }

    let entries: Vec<RsvpEntry> =
        sqlx::query_as("SELECT user_pubkey, status FROM event_rsvps WHERE event_id = ?")
            .bind(&event_id)
            .fetch_all(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(entries))
}
