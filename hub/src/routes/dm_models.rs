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
    /// Present instead of content when the message is 1:1 E2E encrypted.
    pub encrypted_envelope: Option<EncryptedDmEnvelope>,
    /// Present instead of content when the message is group E2E encrypted.
    pub group_encrypted_envelope: Option<GroupEncryptedEnvelope>,
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

/// Wire envelope for a group E2E encrypted DM.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct GroupEncryptedEnvelope {
    pub sender_pubkey: String,
    pub conv_id: String,
    pub sender_key_version: u32,
    pub iteration: u32,
    pub ciphertext_hex: String,
    pub nonce_hex: String,
    pub signature_hex: String,
}

/// One recipient blob in a sender-key distribution push.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SenderKeyRecipientBlob {
    pub recipient_pubkey: String,
    /// AES-256-GCM ciphertext of (chain_key[32] || iteration_be[4])
    pub wrapped_key_hex: String,
    pub wrap_nonce_hex: String,
    pub iteration: u32,
}

/// Body for PUT /conversations/:id/sender-keys
#[derive(Deserialize)]
pub struct PushSenderKeyRequest {
    pub sender_key_version: u32,
    pub recipients: Vec<SenderKeyRecipientBlob>,
    /// Ed25519 sig over canonical bytes (see design doc)
    pub signature_hex: String,
}

/// Row returned from GET /conversations/:id/sender-keys
#[derive(Serialize)]
pub struct GroupSenderKeyEntry {
    pub sender_pubkey: String,
    pub sender_key_version: u32,
    pub iteration: u32,
    pub wrapped_key_hex: String,
    pub wrap_nonce_hex: String,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DmMessageResponse {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    /// None when is_encrypted or is_group_encrypted is true
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
    /// True when the message body is 1:1 E2E encrypted
    #[serde(default)]
    pub is_encrypted: bool,
    /// Present when is_encrypted is true
    pub encrypted_envelope: Option<EncryptedDmEnvelope>,
    /// Present when the message is group E2E encrypted
    pub group_encrypted_envelope: Option<GroupEncryptedEnvelope>,
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
    pub group_encrypted_envelope: Option<GroupEncryptedEnvelope>,
    /// Self-reported URL of the sending hub. Used by the receiving hub to
    /// auto-register the sender in its `peers` table on first contact.
    /// Optional for backward compatibility; missing entries are stored as an
    /// empty string until the peer is properly added via /federation/peers.
    #[serde(default)]
    pub sender_hub_url: Option<String>,
}
