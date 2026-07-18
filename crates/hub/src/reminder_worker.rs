//! Background worker that posts a reminder card into an event's channel a
//! configurable number of minutes before it starts (docs/docs/events.md §3).
//!
//! Ticks every 60s, following the same fixed-interval polling shape as
//! `dm_worker` / `banlist_worker`. A row is due when it has a
//! `reminder_minutes` offset, hasn't been sent yet (`reminder_sent_at IS
//! NULL`), and the reminder instant has arrived but the event hasn't
//! started. `reminder_sent_at` is set in the same pass that posts the card,
//! so a due event is only ever selected once it's actually unsent --
//! idempotent across restarts by construction (no separate "claim" step
//! needed; a crash between posting the card and marking it sent would send
//! at most one duplicate card, no different from the risk any single-writer
//! worker in this codebase already carries).
//!
//! Same tick also prunes expired queued voice-move assignments (events.md
//! §7.3): extending this worker's existing 60s sweep rather than adding a
//! dedicated `staging_worker` keeps a single-purpose-but-small worker count
//! (the doc offers a dedicated worker as the alternative if this one
//! shouldn't grow -- it's one extra DELETE per tick, judged small enough to
//! fold in here).
//!
//! Also extended (events.md §7.5, updated lifetime) to prune auto-spawned
//! squad rooms belonging to an ended event: an *empty* room is deleted
//! immediately (no need to wait out the ordinary temp-channel empty-grace,
//! since the event ending is itself the trigger); an *occupied* room is left
//! alone -- it just stops accepting new joins (enforced at the voice-join
//! gate in `routes/ws/handlers/voice.rs`) and dies via the normal
//! `temp_channel_worker` empty-GC path once it drains. Never yanked
//! mid-conversation.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::routes::events::{post_event_reminder_card, EventResponse};
use crate::state::AppState;

/// How often the worker wakes to look for due reminders.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Err(e) = tick(&state).await {
                tracing::warn!("event reminder worker tick failed: {e}");
            }
        }
    });
}

/// Run a single pass over `hub_events` looking for due, unsent reminders.
/// Public so tests can drive a single tick directly against a seeded event.
pub async fn tick(state: &AppState) -> Result<(), sqlx::Error> {
    let now = crate::auth::handlers::unix_timestamp();

    let due: Vec<EventResponse> = sqlx::query_as(
        "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at, reminder_minutes, reminder_sent_at, hub_wide, propagate_to_children
         FROM hub_events
         WHERE reminder_minutes IS NOT NULL
           AND reminder_sent_at IS NULL
           AND starts_at - (reminder_minutes * 60) <= $1
           AND starts_at > $1",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await?;

    for event in due {
        let Some(minutes) = event.reminder_minutes else {
            // Can't happen given the WHERE clause, but keep the loop robust.
            continue;
        };

        if let Err((_, msg)) = post_event_reminder_card(state, &event, minutes).await {
            tracing::warn!(
                "event reminder worker: failed to post card for event {}: {msg}",
                event.id
            );
            continue;
        }

        sqlx::query("UPDATE hub_events SET reminder_sent_at = $1 WHERE id = $2")
            .bind(now)
            .bind(&event.id)
            .execute(&state.db)
            .await?;
    }

    // events.md §7.3: assignments die with the event and are pruned at event
    // end. An event with no `ends_at` keeps its assignments until the event
    // row itself is deleted (ON DELETE CASCADE handles that case).
    sqlx::query(
        "DELETE FROM event_move_assignments
         WHERE event_id IN (
             SELECT id FROM hub_events WHERE ends_at IS NOT NULL AND ends_at < $1
         )",
    )
    .bind(now)
    .execute(&state.db)
    .await?;

    prune_ended_event_squad_rooms(state, now).await?;

    Ok(())
}

/// events.md §7.5 (updated lifetime): for every squad room linked to an
/// ended event (`channels.event_id` -> `hub_events.ends_at < now`), delete
/// it immediately if it currently holds no voice participants; leave it
/// alone otherwise (it stops accepting new joins via the voice-join gate and
/// dies through the ordinary temp-channel empty-GC once it drains). An event
/// with no `ends_at` never matches here -- its rooms clean up on event
/// delete only (`routes::events::delete_event`).
async fn prune_ended_event_squad_rooms(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    let ended_room_ids: Vec<String> = sqlx::query_scalar(
        "SELECT c.id FROM channels c
         JOIN hub_events e ON e.id = c.event_id
         WHERE c.event_id IS NOT NULL AND e.ends_at IS NOT NULL AND e.ends_at < $1",
    )
    .bind(now)
    .fetch_all(&state.db)
    .await?;

    if ended_room_ids.is_empty() {
        return Ok(());
    }

    let occupied: HashSet<String> = {
        let voice = state.voice_channels.read().await;
        voice
            .iter()
            .filter(|(_, members)| !members.is_empty())
            .map(|(id, _)| id.clone())
            .collect()
    };

    let empty_ids: Vec<String> = ended_room_ids
        .into_iter()
        .filter(|id| !occupied.contains(id))
        .collect();
    if empty_ids.is_empty() {
        return Ok(());
    }

    for table in [
        "messages",
        "channel_bans",
        "channel_settings",
        "alliance_shared_channels",
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE channel_id = ANY($1)"))
            .bind(&empty_ids)
            .execute(&state.db)
            .await?;
    }
    sqlx::query("DELETE FROM channels WHERE id = ANY($1)")
        .bind(&empty_ids)
        .execute(&state.db)
        .await?;

    let json: std::sync::Arc<str> = std::sync::Arc::from(
        serde_json::to_string(&WsServerMessage::ChannelsUpdated)
            .unwrap()
            .as_str(),
    );
    let _ = state.chat_tx.send((ChatEvent::ChannelsUpdated, json));
    tracing::info!(
        "reminder worker: GC'd {} empty squad room(s) from ended event(s)",
        empty_ids.len()
    );

    Ok(())
}
