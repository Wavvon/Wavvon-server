mod bans;
mod channel_mod;
mod helpers;
mod models;

// Re-export all public items so server.rs paths remain unchanged.
pub use bans::{
    ban_user, kick_user, list_bans, list_mutes, mute_user, timeout_user, unban_user, unmute_user,
};
pub use channel_mod::{
    channel_ban, channel_ban_v2, channel_unban, channel_unban_v2, channel_voice_mute,
    channel_voice_unmute, get_talk_power, list_channel_bans, list_channel_bans_v2,
    list_channel_voice_mutes, list_raise_hands, list_voice_mutes, lower_hand, raise_hand,
    set_talk_power, voice_mute, voice_unmute,
};
// Enforcement helpers — re-exported at the `crate::routes::moderation` path so
// messages.rs, dms.rs, and auth middleware can call them without path changes.
pub use helpers::{
    get_federation_banlist, has_raised_hand, is_banned, is_channel_banned, is_channel_voice_muted,
    is_denied_by_federated_policy, is_federated_banned, is_muted, is_voice_muted,
};
