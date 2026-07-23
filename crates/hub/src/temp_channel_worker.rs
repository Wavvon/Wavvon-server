//! Background worker that garbage-collects join-to-create temporary voice
//! channels (docs/docs/temp-voice-channels.md §3).
//!
//! Ticks every 30s, following the same fixed-interval polling shape as
//! `dm_worker` / `reminder_worker`. Each pass:
//!
//! 1. Stamps `empty_since = now` on any temp channel that currently holds no
//!    voice participants and hasn't been stamped yet. The normal "last
//!    participant left" case is already stamped by `leave_voice`, so this is
//!    a no-op for it; what this step actually catches is temp rooms
//!    orphaned by a hub crash or restart -- the voice roster is always empty
//!    right after boot, so the very first tick stamps every surviving temp
//!    channel and it ages out through the same path below. One code path,
//!    no separate boot-time sweep.
//! 2. Deletes temp channels whose `empty_since` is older than the 60s grace
//!    period, using the same manual multi-table delete `delete_channel`
//!    uses (there's no DB-level `ON DELETE CASCADE` on `messages.channel_id`
//!    -- only `channel_permission_overwrites`, `channel_pins`, and
//!    `upload_files` cascade automatically).
//!
//! A join clears a temp channel's `empty_since` back to `NULL` (see
//! `handle_voice_join`), so a room that gets rejoined within the grace
//! period survives.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::AppState;

/// How often the worker wakes to sweep temp channels.
const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Grace period, in seconds, a temp channel may sit empty before deletion.
/// Long enough to absorb voice reconnects and "oops, wrong room" rejoins,
/// short enough that dead rooms don't linger (was 60s; felt too slow).
pub const GRACE_SECS: i64 = 30;

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if let Err(e) = tick(&state).await {
                tracing::warn!("temp channel worker tick failed: {e}");
            }
        }
    });
}

/// Run a single GC pass. Public so tests can drive it directly against a
/// seeded `empty_since`.
pub async fn tick(state: &AppState) -> Result<(), sqlx::Error> {
    let now = crate::auth::handlers::unix_timestamp();

    stamp_unoccupied_temp_channels(state, now).await?;
    delete_expired_temp_channels(state, now).await?;

    Ok(())
}

/// Stamps `empty_since = now` on every temp channel that isn't currently
/// holding voice participants and hasn't been stamped yet.
async fn stamp_unoccupied_temp_channels(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    let unstamped: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM channels WHERE is_temporary = TRUE AND empty_since IS NULL",
    )
    .fetch_all(&state.db)
    .await?;

    if unstamped.is_empty() {
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

    for id in unstamped {
        if occupied.contains(&id) {
            continue;
        }
        sqlx::query("UPDATE channels SET empty_since = $1 WHERE id = $2")
            .bind(now)
            .bind(&id)
            .execute(&state.db)
            .await?;
    }

    Ok(())
}

/// Deletes every temp channel whose `empty_since` is older than
/// `GRACE_SECS`, and broadcasts `channels_updated` if anything was removed.
async fn delete_expired_temp_channels(state: &AppState, now: i64) -> Result<(), sqlx::Error> {
    let cutoff = now - GRACE_SECS;
    let due: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM channels
         WHERE is_temporary = TRUE AND empty_since IS NOT NULL AND empty_since < $1",
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;

    let mut deleted = 0usize;
    for id in due {
        match delete_temp_channel(state, &id).await {
            Ok(()) => deleted += 1,
            Err(e) => tracing::warn!("temp channel worker: failed to delete channel {id}: {e}"),
        }
    }

    if deleted > 0 {
        let json: std::sync::Arc<str> = std::sync::Arc::from(
            serde_json::to_string(&WsServerMessage::ChannelsUpdated)
                .unwrap()
                .as_str(),
        );
        let _ = state.chat_tx.send((ChatEvent::ChannelsUpdated, json));
        tracing::info!("temp channel worker: GC'd {deleted} empty room(s)");
    }

    Ok(())
}

/// Deletes a single temp channel and its dependents. Mirrors
/// `routes::channels::delete_channel`'s manual cascade (messages,
/// channel_bans, channel_settings, alliance_shared_channels) -- temp rooms
/// are always leaves (nothing can be created under a non-category channel),
/// so there's no child-channel check to make.
async fn delete_temp_channel(state: &AppState, channel_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM messages WHERE channel_id = $1")
        .bind(channel_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM channel_bans WHERE channel_id = $1")
        .bind(channel_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM channel_settings WHERE channel_id = $1")
        .bind(channel_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM alliance_shared_channels WHERE channel_id = $1")
        .bind(channel_id)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM channels WHERE id = $1")
        .bind(channel_id)
        .execute(&state.db)
        .await?;
    Ok(())
}
