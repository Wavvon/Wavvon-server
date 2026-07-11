mod conversations;
mod keys;
mod messages;
mod models;

// Re-export all public items so server.rs paths remain unchanged.
pub use conversations::{
    add_conversation_member, create_conversation, get_conversation, list_conversations,
    remove_conversation_member, AddMemberRequest,
};
pub use keys::{get_sender_keys, push_sender_keys};
pub use messages::{deliver_federated_dm_public, list_dm_messages, receive_federated_dm, send_dm};
