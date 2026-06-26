mod admin;
mod bot_api;
mod external;
mod models;
pub mod screenshare;
pub mod voice;

// Re-export all public items so server.rs paths remain unchanged.
pub use admin::{
    admin_audit_log, admin_create_bot, admin_delete_bot, admin_get_bot, admin_list_bots,
    admin_set_webhook,
};
pub use bot_api::{bot_ack_events, bot_poll, bot_send_message, bot_set_commands};
pub use external::{
    ext_accept_invite, ext_bot_me, ext_invite_bot, ext_list_bots, ext_remove_bot,
    ext_update_bot_commands, ext_update_bot_profile, ext_update_bot_subscriptions,
};
// Re-export the audit log types that tests or other modules may reference.
pub use models::{AuditLogEntry, AuditLogQuery, AuditLogResponse};
