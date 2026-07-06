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

use std::sync::Arc;
use std::time::Duration;

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
        "SELECT id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at, reminder_minutes, reminder_sent_at
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

        if let Err((_, msg)) =
            post_event_reminder_card(state, &event.channel_id, &event, minutes).await
        {
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

    Ok(())
}
