use crate::routes::chat_models::Attachment;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct CreateConversationRequest {
    pub members: Vec<String>, // public keys of other participants (not including yourself)
    /// Optional: where each remote member is reachable. Missing entries = local member.
    #[serde(default)]
    pub member_hubs: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct ConversationResponse {
    pub id: String,
    pub conv_type: String,
    pub members: Vec<String>,
    pub created_at: i64,
    /// Most recent message timestamp; falls back to created_at when the
    /// conversation has no messages yet. Used by the client to sort the
    /// conversation list by recent activity rather than creation order.
    #[serde(default)]
    pub last_activity_at: i64,
}

#[derive(Deserialize)]
pub struct SendDmRequest {
    /// Plaintext content — None when the message is encrypted.
    pub content: Option<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// Present instead of content when the message is E2E encrypted.
    pub encrypted_envelope: Option<EncryptedDmEnvelope>,
}

/// Wire envelope for an E2E encrypted 1:1 DM.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedDmEnvelope {
    pub sender_pubkey: String,
    pub conv_id: String,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub dh_pubkey_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DmMessageResponse {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    /// None when is_encrypted is true
    pub content: Option<String>,
    pub created_at: i64,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    /// True when at least one outbox row for this message exhausted retries
    /// (`bounced_at` is set). Lets the client mark the bubble "delivery
    /// failed". Always false for received messages and for messages with no
    /// remote recipients.
    #[serde(default)]
    pub delivery_failed: bool,
    /// True when the message body is E2E encrypted
    #[serde(default)]
    pub is_encrypted: bool,
    /// Present when is_encrypted is true
    pub encrypted_envelope: Option<EncryptedDmEnvelope>,
}

/// Hub-to-hub DM delivery envelope (POST /federation/dm).
#[derive(Serialize, Deserialize)]
pub struct FederatedDmRequest {
    pub message_id: String,
    pub conversation_id: String,
    pub conv_type: String,
    pub sender: String,
    pub members: Vec<String>,
    pub content: Option<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub signature: Option<String>,
    pub created_at: i64,
    pub encrypted_envelope: Option<EncryptedDmEnvelope>,
}
