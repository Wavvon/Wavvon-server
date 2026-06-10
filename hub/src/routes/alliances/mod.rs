mod channels;
mod crud;
mod membership;
mod models;

// Re-export all public items so server.rs paths remain unchanged.
pub use channels::{
    get_alliance_channel_messages, list_shared_channels, post_alliance_channel_message,
    share_channel, unshare_channel,
};
pub use crud::{create_alliance, get_alliance, leave_alliance, list_alliances};
pub use membership::{
    accept_pending_invite, create_invite, decline_pending_invite, join_alliance,
    join_alliance_local, list_pending_invites, push_invite_handler,
    receive_federation_alliance_invite,
};
