use std::collections::HashSet;

use crate::routes::chat_models::{VoiceParticipantInfo, VoiceRosterEntry};
use crate::state::AppState;

pub async fn get_voice_participants(
    state: &AppState,
    channel_id: &str,
) -> Vec<VoiceParticipantInfo> {
    let channels = state.voice_channels.read().await;
    let Some(participants) = channels.get(channel_id) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for pk in participants.keys() {
        let row: Option<(Option<String>, i64)> =
            sqlx::query_as("SELECT display_name, is_bot FROM users WHERE public_key = $1")
                .bind(pk)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();

        let (display_name, is_bot) = match row {
            Some((dn, b)) => (dn, b != 0),
            None => (None, false),
        };

        result.push(VoiceParticipantInfo {
            public_key: pk.clone(),
            display_name,
            is_bot,
        });
    }
    result
}

/// Resolve "user" and "channel" target defs into SocketAddrs.
/// Role targets require a DB query and must be handled by the caller via `resolve_role_addrs`.
pub(super) async fn resolve_whisper_targets(
    state: &AppState,
    defs: &[crate::state::WhisperTargetDef],
    exclude_addr: std::net::SocketAddr,
) -> HashSet<std::net::SocketAddr> {
    let voice_channels = state.voice_channels.read().await;
    let mut addrs = HashSet::new();
    for def in defs {
        match def.target_type.as_str() {
            "user" => {
                // Search all channels for the target pubkey.
                for participants in voice_channels.values() {
                    if let Some(addr) = participants.get(&def.id) {
                        if *addr != exclude_addr {
                            addrs.insert(*addr);
                        }
                    }
                }
            }
            "channel" => {
                if let Some(participants) = voice_channels.get(&def.id) {
                    for addr in participants.values() {
                        if *addr != exclude_addr {
                            addrs.insert(*addr);
                        }
                    }
                }
            }
            _ => {} // "role" handled separately; unknown types silently ignored
        }
    }
    addrs
}

/// Resolve all users with `role_id` that are currently in voice into SocketAddrs.
pub(super) async fn resolve_role_addrs(
    state: &AppState,
    role_id: &str,
    exclude_addr: std::net::SocketAddr,
) -> HashSet<std::net::SocketAddr> {
    let role_users: Vec<String> =
        sqlx::query_scalar("SELECT user_public_key FROM user_roles WHERE role_id = $1")
            .bind(role_id)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();

    let voice_channels = state.voice_channels.read().await;
    let mut addrs = HashSet::new();
    for pk in &role_users {
        for participants in voice_channels.values() {
            if let Some(addr) = participants.get(pk.as_str()) {
                if *addr != exclude_addr {
                    addrs.insert(*addr);
                }
            }
        }
    }
    addrs
}

/// Walk every active whisper session and rebuild its resolved SocketAddr set from stored defs.
/// Called after any VoiceJoin or VoiceLeave so the live target set stays correct.
pub(super) async fn re_resolve_whisper_sessions(state: &AppState) {
    // Snapshot the current defs outside the write lock.
    let defs_map: Vec<(String, Vec<crate::state::WhisperTargetDef>)> = {
        state
            .whisper_target_defs
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    for (sender_pk, defs) in defs_map {
        // Find the sender's current SocketAddr (they may have just left voice).
        let sender_addr = {
            let vc = state.voice_channels.read().await;
            vc.values().find_map(|p| p.get(&sender_pk)).copied()
        };
        let sender_addr = match sender_addr {
            Some(a) => a,
            None => {
                // Sender is no longer in voice; their session will be cleaned up by leave_voice.
                continue;
            }
        };
        let mut new_addrs = resolve_whisper_targets(state, &defs, sender_addr).await;
        for def in &defs {
            if def.target_type == "role" {
                new_addrs.extend(resolve_role_addrs(state, &def.id, sender_addr).await);
            }
        }
        state
            .whisper_targets
            .write()
            .await
            .insert(sender_pk, new_addrs);
    }
}

pub(super) async fn get_voice_roster(state: &AppState, channel_id: &str) -> Vec<VoiceRosterEntry> {
    let sender_ids = state.voice_sender_ids.read().await;
    let ch_map = match sender_ids.get(channel_id) {
        Some(m) => m.clone(),
        None => return vec![],
    };
    drop(sender_ids);

    let mut result = Vec::new();
    for (pk, sid) in ch_map {
        let display_name: Option<String> =
            sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
                .bind(&pk)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        result.push(VoiceRosterEntry {
            sender_id: sid,
            public_key: pk,
            display_name,
        });
    }
    result
}
