//! Background worker that auto-moves idle voice participants into the hub's
//! configured AFK channel (Discord/TeamSpeak-style "AFK channel").
//!
//! Ticks every 30s, following the same fixed-interval polling shape as
//! `temp_channel_worker`. Disabled unless the `afk_channel_id` hub setting is
//! set. Each pass finds voice participants (outside the AFK channel itself)
//! whose `voice_last_active` stamp is older than `afk_timeout_secs` and
//! pushes them the same `voice_move` control message the manual move
//! primitive uses (events.md §7.1) — the hub never yanks anyone server-side;
//! the target's client runs its normal leave-and-join. The push carries
//! `auto: true` so the client moves immediately with the rejoin-escape-hatch
//! toast instead of prompting (an AFK user isn't there to answer a prompt).

use std::sync::Arc;

use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::routes::hub::{read_setting, DEFAULT_AFK_TIMEOUT_SECS};
use crate::state::AppState;

const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

pub fn spawn(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            run_sweep(&state).await;
        }
    });
}

/// Single sweep pass. Public for tests.
pub async fn run_sweep(state: &AppState) {
    let afk_channel_id = match read_setting(&state.db, "afk_channel_id").await {
        Some(id) if !id.is_empty() => id,
        _ => return,
    };
    let timeout_secs: i64 = read_setting(&state.db, "afk_timeout_secs")
        .await
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_AFK_TIMEOUT_SECS as i64);

    // The push carries the destination's name because the target's local
    // channel list may not contain it (mirrors the manual move path). A
    // vanished or category channel disables the sweep rather than erroring.
    let afk_channel_name: String =
        match sqlx::query_scalar("SELECT name FROM channels WHERE id = $1 AND is_category = false")
            .bind(&afk_channel_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
        {
            Some(name) => name,
            None => return,
        };

    let now = crate::auth::handlers::unix_timestamp();

    // Snapshot idle candidates under short read locks, then drop the locks
    // before the per-candidate permission queries below.
    let candidates: Vec<(String, String)> = {
        let channels = state.voice_channels.read().await;
        let last_active = state.voice_last_active.read().await;
        channels
            .iter()
            .filter(|(channel_id, _)| **channel_id != afk_channel_id)
            .flat_map(|(channel_id, participants)| {
                participants
                    .keys()
                    .map(move |pk| (channel_id.clone(), pk.clone()))
            })
            .filter(|(_, pk)| {
                // A participant with no stamp (shouldn't happen — join
                // stamps) is treated as active rather than instantly moved.
                last_active
                    .get(pk)
                    .is_some_and(|last| now - last >= timeout_secs)
            })
            .collect()
    };

    for (source_channel_id, pubkey) in candidates {
        // Same gate as the manual, event-less move: never move someone into
        // a channel they can't read — it would reveal a hidden channel.
        // The exception that keeps a check, and keeps it on VOICE_JOIN
        // (permissions.md §3, Voice): every other move has a `move_members`
        // holder whose authority stands in for the target's own admission,
        // but the hub moves an idle member on its own, so there is nobody to
        // stand in. No grant is minted here for the same reason.
        let can_join = match crate::permissions::channel_permissions(
            &state.db,
            &pubkey,
            &afk_channel_id,
        )
        .await
        {
            Ok(perms) => perms.has(crate::permissions::VOICE_JOIN),
            Err(_) => false,
        };
        if !can_join {
            continue;
        }

        let push = WsServerMessage::VoiceMove {
            target_channel_id: afk_channel_id.clone(),
            target_channel_name: afk_channel_name.clone(),
            source_channel_id: Some(source_channel_id),
            event_id: None,
            auto: true,
        };
        let ev = ChatEvent::VoiceMove {
            to_pubkey: pubkey.clone(),
        };
        let json: std::sync::Arc<str> =
            std::sync::Arc::from(serde_json::to_string(&push).unwrap().as_str());
        let _ = state.chat_tx.send((ev, json));

        // Re-stamp so a client that ignores the push is re-pushed only once
        // per timeout window, not on every 30s tick.
        state
            .voice_last_active
            .write()
            .await
            .insert(pubkey.clone(), now);

        tracing::info!(
            "AFK sweep: moving {} -> channel {}",
            &pubkey[..16.min(pubkey.len())],
            &afk_channel_id[..8.min(afk_channel_id.len())]
        );
    }
}
