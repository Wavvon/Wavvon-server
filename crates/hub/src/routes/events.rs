use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::permissions;
use crate::routes::chat_models::{ChannelResponse, ChatEvent, MessageResponse, WsServerMessage};
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
    /// Minutes before `starts_at` to post a reminder card. NULL/absent = no
    /// reminder (events.md §3).
    #[serde(default)]
    pub reminder_minutes: Option<i64>,
    /// Role-slot sign-up buckets (events.md §2), created in array order —
    /// `position` is assigned sequentially starting at 0.
    #[serde(default)]
    pub slots: Vec<CreateSlotRequest>,
    /// Hub-level event (events.md §5): visible to every member regardless of
    /// whether they can read the anchor `channel_id`. Create-time only --
    /// requires hub-level `CREATE_EVENTS` in addition to the channel-scoped
    /// gate on the anchor (see `create_event`).
    #[serde(default)]
    pub hub_wide: bool,
    /// Fan the announcement/reminder cards out to every descendant of the
    /// anchor channel (events.md §6). Same permission as the base event --
    /// no extra grant needed.
    #[serde(default)]
    pub propagate_to_children: bool,
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
    /// Tri-state: absent = don't touch, `Some(Some(n))` = set the reminder
    /// offset (minutes before start), `Some(None)` = clear it. Either way,
    /// providing this field resets `reminder_sent_at` to NULL so a
    /// newly-picked (or re-picked) offset can fire again -- see
    /// `update_event` below.
    #[serde(default, deserialize_with = "deserialize_some")]
    pub reminder_minutes: Option<Option<i64>>,
    /// `hub_wide` is create-time only (events.md §5): present here purely so
    /// `update_event` can detect and reject an attempted flip with a clear
    /// 400 rather than silently ignoring it or erroring on an unknown field.
    /// Absent = don't touch (the common case: no attempted flip at all).
    #[serde(default)]
    pub hub_wide: Option<bool>,
}

/// Lets us distinguish "field missing" from "field explicitly null" in JSON
/// (see `UpdateEventRequest::reminder_minutes` and `UpdateSlotRequest::capacity`).
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    T: serde::Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
pub struct RsvpRequest {
    pub status: String,
    /// Slot claim (events.md §2). Only meaningful when `status == "going"`;
    /// ignored (treated as no slot) otherwise.
    #[serde(default)]
    pub slot_id: Option<String>,
}

#[derive(Deserialize)]
pub struct CreateSlotRequest {
    pub name: String,
    #[serde(default)]
    pub capacity: Option<i64>,
}

#[derive(Deserialize, Default)]
pub struct UpdateSlotRequest {
    #[serde(default)]
    pub name: Option<String>,
    /// Tri-state: absent = don't touch, `Some(Some(n))` = resize,
    /// `Some(None)` = clear (unlimited).
    #[serde(default, deserialize_with = "deserialize_some")]
    pub capacity: Option<Option<i64>>,
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
    pub reminder_minutes: Option<i64>,
    pub reminder_sent_at: Option<i64>,
    /// Hub-level event (events.md §5): visible hub-wide regardless of
    /// anchor-channel read access. Create-time only.
    pub hub_wide: bool,
    /// Fan the announcement/reminder cards out to every descendant of the
    /// anchor channel (events.md §6).
    pub propagate_to_children: bool,
}

#[derive(Serialize, Clone)]
pub struct EventWithRsvps {
    #[serde(flatten)]
    pub event: EventResponse,
    pub rsvp_counts: RsvpCounts,
    pub slots: Vec<SlotResponse>,
}

#[derive(Serialize, Clone)]
pub struct SlotResponse {
    pub id: String,
    pub name: String,
    pub capacity: Option<i64>,
    pub position: i64,
    pub claimed: i64,
    pub claimants: Vec<String>,
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

/// Staging-panel data surface (events.md §7.5) — one queued voice-move
/// assignment. Field names are load-bearing: the web staging panel is built
/// against this exact shape.
#[derive(Serialize, sqlx::FromRow)]
pub struct EventMoveAssignmentResponse {
    pub user_pubkey: String,
    pub target_channel_id: String,
    pub assigned_by: String,
    pub created_at: i64,
    /// Computed, not stored: true when `user_pubkey` lacks effective
    /// `READ_MESSAGES` on `target_channel_id`, meaning a move applied to
    /// them would land them in voice-only presence rather than normal
    /// channel access (events.md §7.4). The client can't see another
    /// member's channel permissions, so the hub resolves this per row.
    pub voice_only: bool,
}

/// Raw DB row for `event_move_assignments` -- `voice_only` on
/// `EventMoveAssignmentResponse` is computed, not stored, so it's resolved
/// separately per row and folded in after the fetch.
#[derive(sqlx::FromRow)]
struct EventMoveAssignmentRow {
    user_pubkey: String,
    target_channel_id: String,
    assigned_by: String,
    created_at: i64,
}

/// Auto-spawned squad channels (events.md §7.5). `count` is bounded to
/// `1..=20`; `name_prefix` defaults to `"Squad"` when absent.
#[derive(Deserialize)]
pub struct CreateSquadRoomsRequest {
    pub count: i64,
    #[serde(default)]
    pub name_prefix: Option<String>,
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

async fn load_rsvp_counts(
    db: &sqlx::PgPool,
    event_id: &str,
) -> Result<RsvpCounts, (StatusCode, String)> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) as cnt FROM event_rsvps WHERE event_id = $1 GROUP BY status",
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

/// Insert a card message into the channel and broadcast it over WS. Shared
/// by the "event created" card and the reminder card (events.md §3).
/// The creator's users row is guaranteed to exist (they just authenticated).
async fn post_card_message(
    state: &AppState,
    channel_id: &str,
    sender: &str,
    content: String,
) -> Result<(), (StatusCode, String)> {
    let msg_id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

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

/// Returns `channel_id` plus every descendant of it in the `channels` tree
/// (any depth) when `propagate` is true; otherwise just `[channel_id]`
/// (events.md §6). Mirrors the same BFS-over-`parent_id` shape
/// `routes::channels::delete_channel` uses to collect a subtree, reused here
/// for card fan-out rather than deletion.
async fn propagation_targets(
    db: &sqlx::PgPool,
    channel_id: &str,
    propagate: bool,
) -> Result<Vec<String>, (StatusCode, String)> {
    if !propagate {
        return Ok(vec![channel_id.to_string()]);
    }

    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(channel_id.to_string());
    let mut frontier: Vec<String> = vec![channel_id.to_string()];
    while !frontier.is_empty() {
        let children: Vec<String> =
            sqlx::query_scalar("SELECT id FROM channels WHERE parent_id = ANY($1)")
                .bind(&frontier)
                .fetch_all(db)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
        frontier = children
            .into_iter()
            .filter(|c| seen.insert(c.clone()))
            .collect();
    }
    Ok(seen.into_iter().collect())
}

/// "Event created" card: title + formatted start time. Fans out to every
/// descendant of the anchor when `event.propagate_to_children` is set
/// (events.md §6) — one event row, N cards.
async fn post_event_card(
    state: &AppState,
    event: &EventResponse,
) -> Result<(), (StatusCode, String)> {
    // Format starts_at as a simple UTC string for the card content.
    // We avoid pulling in chrono — a direct conversion is fine for display.
    let dt = format_unix_utc(event.starts_at);
    let content = format!("**{}** — {}", event.title, dt);
    let targets =
        propagation_targets(&state.db, &event.channel_id, event.propagate_to_children).await?;
    for channel_id in targets {
        post_card_message(state, &channel_id, &event.creator_pubkey, content.clone()).await?;
    }
    Ok(())
}

/// Reminder card (events.md §3): posted by the reminder worker when
/// `starts_at - reminder_minutes * 60 <= now`. `pub(crate)` so
/// `reminder_worker` can call it. Fans out the same way `post_event_card`
/// does (events.md §6).
pub(crate) async fn post_event_reminder_card(
    state: &AppState,
    event: &EventResponse,
    reminder_minutes: i64,
) -> Result<(), (StatusCode, String)> {
    let content = format!(
        "**{}** — starts in {} minutes",
        event.title, reminder_minutes
    );
    let targets =
        propagation_targets(&state.db, &event.channel_id, event.propagate_to_children).await?;
    for channel_id in targets {
        post_card_message(state, &channel_id, &event.creator_pubkey, content.clone()).await?;
    }
    Ok(())
}

/// Slots for an event, ordered by `position`, each carrying its current
/// claimants (`status = 'going'` rows pointed at it). Used to build
/// `EventWithRsvps.slots`.
async fn load_slots(
    db: &sqlx::PgPool,
    event_id: &str,
) -> Result<Vec<SlotResponse>, (StatusCode, String)> {
    #[derive(sqlx::FromRow)]
    struct SlotRow {
        id: String,
        name: String,
        capacity: Option<i64>,
        position: i64,
    }

    let slots: Vec<SlotRow> = sqlx::query_as(
        "SELECT id, name, capacity, position FROM event_slots
         WHERE event_id = $1 ORDER BY position ASC, created_at ASC",
    )
    .bind(event_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let claims: Vec<(String, String)> = sqlx::query_as(
        "SELECT slot_id, user_pubkey FROM event_rsvps
         WHERE event_id = $1 AND status = 'going' AND slot_id IS NOT NULL",
    )
    .bind(event_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(slots
        .into_iter()
        .map(|slot| {
            let claimants: Vec<String> = claims
                .iter()
                .filter(|(slot_id, _)| slot_id == &slot.id)
                .map(|(_, pubkey)| pubkey.clone())
                .collect();
            SlotResponse {
                id: slot.id,
                name: slot.name,
                capacity: slot.capacity,
                position: slot.position,
                claimed: claimants.len() as i64,
                claimants,
            }
        })
        .collect())
}

/// Row of an existing slot, verified to belong to `event_id`. 404s otherwise
/// (covers both "slot doesn't exist" and "slot belongs to a different
/// event").
async fn fetch_slot_row(
    db: &sqlx::PgPool,
    event_id: &str,
    slot_id: &str,
) -> Result<(String, Option<i64>, i64), (StatusCode, String)> {
    let row: Option<(String, Option<i64>, i64)> = sqlx::query_as(
        "SELECT name, capacity, position FROM event_slots WHERE id = $1 AND event_id = $2",
    )
    .bind(slot_id)
    .bind(event_id)
    .fetch_optional(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    row.ok_or((StatusCode::NOT_FOUND, "Slot not found".to_string()))
}

async fn count_slot_claims(db: &sqlx::PgPool, slot_id: &str) -> Result<i64, (StatusCode, String)> {
    sqlx::query_scalar("SELECT COUNT(*) FROM event_rsvps WHERE slot_id = $1 AND status = 'going'")
        .bind(slot_id)
        .fetch_one(db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}

async fn slot_claimants(
    db: &sqlx::PgPool,
    slot_id: &str,
) -> Result<Vec<String>, (StatusCode, String)> {
    sqlx::query_scalar(
        "SELECT user_pubkey FROM event_rsvps WHERE slot_id = $1 AND status = 'going'",
    )
    .bind(slot_id)
    .fetch_all(db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
}

/// Authorization for slot management routes: the event's creator, or a
/// holder of `CREATE_EVENTS` resolved through the event's channel-scoped
/// permission cascade (`channel_permissions`) -- matches the channel-aware
/// gate `create_event` uses, rather than the hub-wide `ADMIN` check
/// `update_event`/`delete_event` use today. Returns the event's channel id.
async fn require_slot_management_access(
    state: &AppState,
    user: &AuthUser,
    event_id: &str,
) -> Result<String, (StatusCode, String)> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT creator_pubkey, channel_id FROM hub_events WHERE id = $1")
            .bind(event_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (creator, channel_id) =
        row.ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    if creator != user.public_key {
        let perms =
            permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
        perms.require(permissions::CREATE_EVENTS)?;
    }

    Ok(channel_id)
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
    // Verify channel exists.
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM channels WHERE id = $1")
        .bind(&req.channel_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Channel not found".to_string()));
    }

    // Channel-scoped gate (§3.5): CREATE_EVENTS must be checked against the
    // ancestor-chain overwrite cascade for the target channel, not the
    // hub-wide baseline -- otherwise a user denied on this channel could
    // still create events targeting it.
    let perms =
        permissions::channel_permissions(&state.db, &user.public_key, &req.channel_id).await?;
    perms.require(permissions::CREATE_EVENTS)?;

    // events.md §5: a hub-wide event additionally requires hub-level
    // CREATE_EVENTS (the plain, non-channel-scoped baseline) -- a member who
    // only holds CREATE_EVENTS via a channel overwrite in one sub-tree must
    // not be able to post an announcement visible to the whole hub.
    if req.hub_wide {
        let hub_perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        hub_perms.require(permissions::CREATE_EVENTS)?;
    }

    if req.title.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "title is required".to_string()));
    }

    for slot in &req.slots {
        if slot.name.trim().is_empty() {
            return Err((StatusCode::BAD_REQUEST, "slot name is required".to_string()));
        }
    }

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();
    let description = req.description.unwrap_or_default();

    sqlx::query(
        "INSERT INTO hub_events (id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at, reminder_minutes, hub_wide, propagate_to_children)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
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
    .bind(req.reminder_minutes)
    .bind(req.hub_wide)
    .bind(req.propagate_to_children)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    for (position, slot) in req.slots.iter().enumerate() {
        sqlx::query(
            "INSERT INTO event_slots (id, event_id, name, capacity, position, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&id)
        .bind(&slot.name)
        .bind(slot.capacity)
        .bind(position as i64)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

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
        reminder_minutes: req.reminder_minutes,
        reminder_sent_at: None,
        hub_wide: req.hub_wide,
        propagate_to_children: req.propagate_to_children,
    };

    post_event_card(&state, &event).await?;

    Ok((StatusCode::CREATED, Json(event)))
}

/// GET /events
pub async fn list_events(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Query(params): Query<ListEventsParams>,
) -> Result<Json<Vec<EventWithRsvps>>, (StatusCode, String)> {
    let limit = params.limit.unwrap_or(20).min(100);
    let upcoming = params.upcoming.unwrap_or(false);
    let now = crate::auth::handlers::unix_timestamp();

    let rows: Vec<EventResponse> = if upcoming {
        sqlx::query_as(
            "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at, reminder_minutes, reminder_sent_at, hub_wide, propagate_to_children
             FROM hub_events WHERE starts_at >= $1 ORDER BY starts_at ASC LIMIT $2",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query_as(
            "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at, reminder_minutes, reminder_sent_at, hub_wide, propagate_to_children
             FROM hub_events ORDER BY starts_at ASC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&state.db)
        .await
    }
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Read-gating (§3.5): drop any event whose channel the caller lacks
    // effective READ_MESSAGES on, so title/description/location/channel_id
    // for hidden channels never reach the client (matches `channels.rs`
    // list_channels' batch-filter approach). events.md §5: a `hub_wide`
    // event skips this filter entirely -- every member sees it regardless
    // of anchor-channel access.
    let readable = permissions::channels_with_permission(
        &state.db,
        &user.public_key,
        permissions::READ_MESSAGES,
    )
    .await?;

    let mut result = Vec::with_capacity(rows.len());
    for event in rows {
        if !event.hub_wide && !readable.contains(&event.channel_id) {
            continue;
        }
        let rsvp_counts = load_rsvp_counts(&state.db, &event.id).await?;
        let slots = load_slots(&state.db, &event.id).await?;
        result.push(EventWithRsvps {
            event,
            rsvp_counts,
            slots,
        });
    }
    Ok(Json(result))
}

/// GET /events/:id
pub async fn get_event(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(event_id): Path<String>,
) -> Result<Json<EventWithRsvps>, (StatusCode, String)> {
    let event: Option<EventResponse> = sqlx::query_as(
        "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at, reminder_minutes, reminder_sent_at, hub_wide, propagate_to_children
         FROM hub_events WHERE id = $1",
    )
    .bind(&event_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let event = event.ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    // Read-gating (§3.5): the event id itself doesn't reveal the channel, so
    // a hidden-channel event 404s here rather than 403ing -- 403 would
    // confirm the event's existence to a caller who can't see its channel.
    // events.md §5: a `hub_wide` event bypasses this gate entirely -- it's
    // public to the hub by construction, so an unreadable anchor never 404s
    // it.
    if !event.hub_wide {
        let perms =
            permissions::channel_permissions(&state.db, &user.public_key, &event.channel_id)
                .await?;
        if !perms.has(permissions::READ_MESSAGES) {
            return Err((StatusCode::NOT_FOUND, "Event not found".to_string()));
        }
    }

    let rsvp_counts = load_rsvp_counts(&state.db, &event_id).await?;
    let slots = load_slots(&state.db, &event_id).await?;
    Ok(Json(EventWithRsvps {
        event,
        rsvp_counts,
        slots,
    }))
}

/// PUT /events/:id
pub async fn update_event(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(event_id): Path<String>,
    Json(req): Json<UpdateEventRequest>,
) -> Result<Json<EventResponse>, (StatusCode, String)> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT creator_pubkey, hub_wide FROM hub_events WHERE id = $1")
            .bind(&event_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (creator, hub_wide) = row.ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    if creator != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    // events.md §5: `hub_wide` is create-time only -- reject an attempted
    // flip with a clear 400 rather than silently ignoring it.
    if let Some(requested_hub_wide) = req.hub_wide {
        if requested_hub_wide != hub_wide {
            return Err((
                StatusCode::BAD_REQUEST,
                "hub_wide cannot be changed after creation".to_string(),
            ));
        }
    }

    if let Some(title) = &req.title {
        sqlx::query("UPDATE hub_events SET title = $1 WHERE id = $2")
            .bind(title)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(desc) = &req.description {
        sqlx::query("UPDATE hub_events SET description = $1 WHERE id = $2")
            .bind(desc)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(starts) = req.starts_at {
        sqlx::query("UPDATE hub_events SET starts_at = $1 WHERE id = $2")
            .bind(starts)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(ends) = req.ends_at {
        sqlx::query("UPDATE hub_events SET ends_at = $1 WHERE id = $2")
            .bind(ends)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(loc) = &req.location {
        sqlx::query("UPDATE hub_events SET location = $1 WHERE id = $2")
            .bind(loc)
            .bind(&event_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    // events.md §3: providing `reminder_minutes` at all (whether setting a
    // new offset or explicitly clearing it with `null`) resets
    // `reminder_sent_at` to NULL, so a previously-sent reminder can fire
    // again for the newly-picked offset. This is the documented composer
    // behavior for "clearing and re-picking the reminder offset".
    if let Some(reminder_minutes) = req.reminder_minutes {
        sqlx::query(
            "UPDATE hub_events SET reminder_minutes = $1, reminder_sent_at = NULL WHERE id = $2",
        )
        .bind(reminder_minutes)
        .bind(&event_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let updated: EventResponse = sqlx::query_as(
        "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at, reminder_minutes, reminder_sent_at, hub_wide, propagate_to_children
         FROM hub_events WHERE id = $1",
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
        sqlx::query_as("SELECT creator_pubkey FROM hub_events WHERE id = $1")
            .bind(&event_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let (creator,) = row.ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    if creator != user.public_key {
        let perms = permissions::user_permissions(&state.db, &user.public_key).await?;
        perms.require(permissions::ADMIN)?;
    }

    // events.md §7.5: squad rooms are linked to this event by a plain
    // `channels.event_id` column with no FK (see migrations.rs), so they
    // must be cleaned up explicitly here rather than relying on
    // ON-DELETE-CASCADE -- an occupied room mid-conversation is deleted too
    // (event deletion, unlike the event-end sweep, isn't expected to
    // preserve occupied rooms; the organizer explicitly removed the event).
    delete_event_squad_rooms(&state, &event_id).await?;

    sqlx::query("DELETE FROM hub_events WHERE id = $1")
        .bind(&event_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Deletes every squad room linked to `event_id` (`channels.event_id`),
/// mirroring `routes::channels::delete_channel`'s manual multi-table cascade
/// (squad rooms are always leaves -- nothing can be created under a
/// non-category channel -- so there's no descendant walk to do). Broadcasts
/// `channels_updated` if anything was removed. No-op if the event has no
/// rooms.
async fn delete_event_squad_rooms(
    state: &AppState,
    event_id: &str,
) -> Result<(), (StatusCode, String)> {
    let room_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM channels WHERE event_id = $1")
        .bind(event_id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if room_ids.is_empty() {
        return Ok(());
    }

    for table in [
        "messages",
        "channel_bans",
        "channel_settings",
        "alliance_shared_channels",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE channel_id = ANY($1)"))
            .bind(&room_ids)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    sqlx::query("DELETE FROM channels WHERE id = ANY($1)")
        .bind(&room_ids)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let json: std::sync::Arc<str> = std::sync::Arc::from(
        serde_json::to_string(&WsServerMessage::ChannelsUpdated)
            .unwrap()
            .as_str(),
    );
    let _ = state.chat_tx.send((ChatEvent::ChannelsUpdated, json));

    Ok(())
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

    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM hub_events WHERE id = $1")
        .bind(&event_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Event not found".to_string()));
    }

    // events.md §2: a slot claim only exists alongside status == "going".
    // Any other status (or an RSVP with no slot_id) clears the claim.
    let slot_id = if req.status == "going" {
        req.slot_id.clone()
    } else {
        None
    };

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    if let Some(slot_id) = &slot_id {
        // Lock the slot row so two concurrent claims on the same slot can't
        // both pass the capacity check (events.md §2). Also validates the
        // slot belongs to this event.
        let capacity: Option<Option<i64>> = sqlx::query_scalar(
            "SELECT capacity FROM event_slots WHERE id = $1 AND event_id = $2 FOR UPDATE",
        )
        .bind(slot_id)
        .bind(&event_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

        let capacity = match capacity {
            Some(cap) => cap,
            None => {
                let _ = tx.rollback().await;
                return Err((StatusCode::NOT_FOUND, "Slot not found".to_string()));
            }
        };

        if let Some(cap) = capacity {
            // Exclude the caller's own existing claim so switching between
            // slots (or re-claiming the same slot) never counts against
            // themselves.
            let claimed: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM event_rsvps
                 WHERE slot_id = $1 AND status = 'going' AND user_pubkey <> $2",
            )
            .bind(slot_id)
            .bind(&user.public_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            if claimed >= cap {
                let _ = tx.rollback().await;
                return Err((
                    StatusCode::CONFLICT,
                    format!("slot is full ({claimed}/{cap})"),
                ));
            }
        }
    }

    sqlx::query(
        "INSERT INTO event_rsvps (event_id, user_pubkey, status, slot_id)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT(event_id, user_pubkey) DO UPDATE SET status = excluded.status, slot_id = excluded.slot_id",
    )
    .bind(&event_id)
    .bind(&user.public_key)
    .bind(&req.status)
    .bind(&slot_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    tx.commit()
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
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM hub_events WHERE id = $1")
        .bind(&event_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    if exists.is_none() {
        return Err((StatusCode::NOT_FOUND, "Event not found".to_string()));
    }

    let entries: Vec<RsvpEntry> =
        sqlx::query_as("SELECT user_pubkey, status FROM event_rsvps WHERE event_id = $1")
            .bind(&event_id)
            .fetch_all(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(Json(entries))
}

/// GET /events/:id/assignments
///
/// Staging-panel data surface (events.md §7.5). Gated on: (event creator OR
/// channel-scoped `CREATE_EVENTS` -- `require_slot_management_access`, the
/// same rule slot management uses) AND channel-scoped `MOVE_MEMBERS`.
///
/// Both permission checks are resolved against the event's own **anchor**
/// channel, not a move's destination: unlike a single `voice_move` (which
/// resolves `MOVE_MEMBERS` against that one move's destination, §7.1),
/// this endpoint has no single destination to scope against -- it surfaces
/// every assignment for the whole event, potentially targeting many
/// different channels. The anchor channel is the natural analogue, matching
/// how `CREATE_EVENTS` is already resolved here for slot management.
///
/// 404s (not 403s) when the event doesn't exist or the caller can't read
/// its anchor channel, matching `get_event`'s "an id alone can't confirm a
/// hidden channel's existence" posture; a caller who *can* read the channel
/// but isn't an organizer/mover gets 403.
pub async fn list_event_assignments(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(event_id): Path<String>,
) -> Result<Json<Vec<EventMoveAssignmentResponse>>, (StatusCode, String)> {
    let channel_id: Option<String> =
        sqlx::query_scalar("SELECT channel_id FROM hub_events WHERE id = $1")
            .bind(&event_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    let channel_id = channel_id.ok_or((StatusCode::NOT_FOUND, "Event not found".to_string()))?;

    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    if !perms.has(permissions::READ_MESSAGES) {
        return Err((StatusCode::NOT_FOUND, "Event not found".to_string()));
    }

    // Organizer gate (creator or channel-scoped CREATE_EVENTS) -- reuses the
    // same helper slot management uses. Re-derives the channel id, which we
    // already have, but keeps this endpoint's authorization identical to
    // slot management's rather than hand-rolling a second copy.
    require_slot_management_access(&state, &user, &event_id).await?;
    // Mover gate: channel-scoped MOVE_MEMBERS against the anchor channel.
    perms.require(permissions::MOVE_MEMBERS)?;

    let rows: Vec<EventMoveAssignmentRow> = sqlx::query_as(
        "SELECT user_pubkey, target_channel_id, assigned_by, created_at
         FROM event_move_assignments
         WHERE event_id = $1
         ORDER BY created_at ASC",
    )
    .bind(&event_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    // Per-row permission resolve: each assignment can target a different
    // channel, so there's no single (user, channel) pair to batch against.
    // Assignment counts are event-scoped (raid-sized), so N `channel_permissions`
    // calls (each its own ancestor-chain round trip) is acceptable for v1
    // rather than building a batch resolver for a small, bounded list.
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let target_perms =
            permissions::channel_permissions(&state.db, &row.user_pubkey, &row.target_channel_id)
                .await?;
        out.push(EventMoveAssignmentResponse {
            voice_only: !target_perms.has(permissions::READ_MESSAGES),
            user_pubkey: row.user_pubkey,
            target_channel_id: row.target_channel_id,
            assigned_by: row.assigned_by,
            created_at: row.created_at,
        });
    }

    Ok(Json(out))
}

/// POST /events/:id/squad-rooms
///
/// Auto-spawned squad channels (events.md §7.5). Creates `count` temp
/// voice-capable channels named "`<name_prefix>` 1".."`<name_prefix>`
/// `count`" (prefix defaults to "Squad"), parented under the event's anchor
/// channel, each with `channels.event_id` set to this event -- lets clients
/// identify "this event's rooms" and the reminder-worker sweep clean them up
/// at event end (§7.5's updated lifetime rule).
///
/// Gated identically to `GET /events/:id/assignments`: (event creator OR
/// channel-scoped `CREATE_EVENTS` on the anchor -- `require_slot_management_access`)
/// AND channel-scoped `MOVE_MEMBERS` on the anchor.
pub async fn create_squad_rooms(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(event_id): Path<String>,
    Json(req): Json<CreateSquadRoomsRequest>,
) -> Result<(StatusCode, Json<Vec<ChannelResponse>>), (StatusCode, String)> {
    let channel_id = require_slot_management_access(&state, &user, &event_id).await?;
    let perms = permissions::channel_permissions(&state.db, &user.public_key, &channel_id).await?;
    perms.require(permissions::MOVE_MEMBERS)?;

    if !(1..=20).contains(&req.count) {
        return Err((
            StatusCode::BAD_REQUEST,
            "count must be between 1 and 20".to_string(),
        ));
    }

    let prefix = req
        .name_prefix
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("Squad");
    if prefix.chars().count() > 40 {
        return Err((
            StatusCode::BAD_REQUEST,
            "name_prefix must be at most 40 characters".to_string(),
        ));
    }

    // Depth safety: the rooms sit one level below the anchor (events.md §7.5
    // -- "the spawned rooms live under the event's anchor channel"), unlike
    // the join-to-create spawner's sibling placement (temp-voice-channels.md
    // §2), so a depth check is needed here where it wasn't there.
    let max_depth = crate::routes::channels::read_max_depth(&state.db).await;
    if max_depth > 0 {
        let new_depth = crate::routes::channels::node_depth(&state.db, Some(&channel_id)).await?;
        if new_depth > max_depth - 1 {
            return Err((StatusCode::BAD_REQUEST, "depth_exceeded".to_string()));
        }
    }

    let now = crate::auth::handlers::unix_timestamp();
    let mut created = Vec::with_capacity(req.count as usize);

    for i in 1..=req.count {
        let base_name = format!("{prefix} {i}");
        let mut name = base_name.clone();
        let mut attempt = 0u32;
        loop {
            let id = Uuid::new_v4().to_string();
            let next_order: i64 =
                sqlx::query_scalar("SELECT COALESCE(MAX(display_order), -1) + 1 FROM channels")
                    .fetch_one(&state.db)
                    .await
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

            let result = sqlx::query(
                "INSERT INTO channels
                    (id, name, created_by, parent_id, is_category, display_order, channel_type, created_at, is_temporary, event_id)
                 VALUES ($1, $2, $3, $4, FALSE, $5, 'text', $6, TRUE, $7)",
            )
            .bind(&id)
            .bind(&name)
            .bind(&user.public_key)
            .bind(&channel_id)
            .bind(next_order)
            .bind(now)
            .bind(&event_id)
            .execute(&state.db)
            .await;

            match result {
                Ok(_) => {
                    created.push(ChannelResponse {
                        id,
                        name: name.clone(),
                        created_by: user.public_key.clone(),
                        parent_id: Some(channel_id.clone()),
                        is_category: false,
                        display_order: next_order,
                        description: None,
                        icon: None,
                        color: None,
                        custom_icon_svg: None,
                        created_at: now,
                        channel_type: "text".to_string(),
                        banner_url: None,
                        banner_file_id: None,
                        is_temporary: true,
                        owner_pubkey: None,
                        spawner_name_template: None,
                        event_id: Some(event_id.clone()),
                        forum_require_tag: false,
                    });
                    break;
                }
                Err(sqlx::Error::Database(dbe)) if dbe.code().is_some_and(|c| c == "23505") => {
                    attempt += 1;
                    if attempt > 50 {
                        return Err((
                            StatusCode::CONFLICT,
                            "Could not allocate a unique room name".to_string(),
                        ));
                    }
                    name = format!("{base_name} ({attempt})");
                }
                Err(e) => {
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))
                }
            }
        }
    }

    let json: std::sync::Arc<str> = std::sync::Arc::from(
        serde_json::to_string(&WsServerMessage::ChannelsUpdated)
            .unwrap()
            .as_str(),
    );
    let _ = state.chat_tx.send((ChatEvent::ChannelsUpdated, json));

    Ok((StatusCode::CREATED, Json(created)))
}

// ---------------------------------------------------------------------------
// Slot management (events.md §2)
// ---------------------------------------------------------------------------

/// POST /events/:id/slots
pub async fn create_slot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(event_id): Path<String>,
    Json(req): Json<CreateSlotRequest>,
) -> Result<(StatusCode, Json<SlotResponse>), (StatusCode, String)> {
    require_slot_management_access(&state, &user, &event_id).await?;

    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "slot name is required".to_string()));
    }

    let position: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(position) + 1, 0) FROM event_slots WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    let id = Uuid::new_v4().to_string();
    let now = crate::auth::handlers::unix_timestamp();

    sqlx::query(
        "INSERT INTO event_slots (id, event_id, name, capacity, position, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&id)
    .bind(&event_id)
    .bind(&req.name)
    .bind(req.capacity)
    .bind(position)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok((
        StatusCode::CREATED,
        Json(SlotResponse {
            id,
            name: req.name,
            capacity: req.capacity,
            position,
            claimed: 0,
            claimants: Vec::new(),
        }),
    ))
}

/// PATCH /events/:id/slots/:slot_id
pub async fn update_slot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((event_id, slot_id)): Path<(String, String)>,
    Json(req): Json<UpdateSlotRequest>,
) -> Result<Json<SlotResponse>, (StatusCode, String)> {
    require_slot_management_access(&state, &user, &event_id).await?;
    fetch_slot_row(&state.db, &event_id, &slot_id).await?;

    if let Some(name) = &req.name {
        if name.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "slot name cannot be empty".to_string(),
            ));
        }
    }

    // Reject shrinking capacity below the current claim count (events.md
    // §2) -- demote-first via the RSVP/slot-switch path, not a silent drop.
    if let Some(Some(new_capacity)) = req.capacity {
        let claimed = count_slot_claims(&state.db, &slot_id).await?;
        if new_capacity < claimed {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("capacity {new_capacity} is below current claim count {claimed}"),
            ));
        }
    }

    if let Some(name) = &req.name {
        sqlx::query("UPDATE event_slots SET name = $1 WHERE id = $2")
            .bind(name)
            .bind(&slot_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }
    if let Some(capacity) = req.capacity {
        sqlx::query("UPDATE event_slots SET capacity = $1 WHERE id = $2")
            .bind(capacity)
            .bind(&slot_id)
            .execute(&state.db)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;
    }

    let (name, capacity, position) = fetch_slot_row(&state.db, &event_id, &slot_id).await?;
    let claimants = slot_claimants(&state.db, &slot_id).await?;

    Ok(Json(SlotResponse {
        id: slot_id,
        name,
        capacity,
        position,
        claimed: claimants.len() as i64,
        claimants,
    }))
}

/// DELETE /events/:id/slots/:slot_id
pub async fn delete_slot(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((event_id, slot_id)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    require_slot_management_access(&state, &user, &event_id).await?;
    fetch_slot_row(&state.db, &event_id, &slot_id).await?;

    // Demote-first is deliberate (events.md §2 decisions): deleting claims
    // as a side effect of structure editing is silent data loss a raid
    // organizer would discover at raid time.
    let claimed = count_slot_claims(&state.db, &slot_id).await?;
    if claimed > 0 {
        return Err((
            StatusCode::CONFLICT,
            format!("slot has {claimed} claimant(s); move them off the slot before deleting"),
        ));
    }

    sqlx::query("DELETE FROM event_slots WHERE id = $1")
        .bind(&slot_id)
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("DB error: {e}")))?;

    Ok(StatusCode::NO_CONTENT)
}
