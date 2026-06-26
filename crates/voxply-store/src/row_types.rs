/// Data-transfer objects returned by HubStore trait methods.
/// Field names and types match the SQLite schema in migrations.rs.
use serde::{Deserialize, Serialize};

// ---- Users ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRow {
    pub public_key: String,
    pub display_name: Option<String>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub approval_status: String,
    pub avatar: Option<String>,
    pub master_pubkey: Option<String>,
    pub is_bot: i64,
    pub is_bot_removed: i64,
    pub bot_invite_token: Option<String>,
    pub bot_invite_expires: Option<i64>,
    pub is_webhook: i64,
    pub lobby_status: String,
    pub lobby_entered_at: Option<i64>,
    pub pow_level: i64,
}

// ---- Sessions ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRow {
    pub token: String,
    pub public_key: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub expiry_warned_at: Option<i64>,
}

// ---- SubkeyCerts / revocations ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubkeyCertRow {
    pub master_pubkey: String,
    pub subkey_pubkey: String,
    pub device_label: String,
    pub issued_at: i64,
    pub not_after: Option<i64>,
    pub fallback_hubs_json: String,
    pub signature: String,
    pub registered_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubkeyRevocationRow {
    pub master_pubkey: String,
    pub subkey_pubkey: String,
    pub revoked_at: i64,
    pub signature: String,
    pub registered_at: i64,
}

// ---- Channels ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRow {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub parent_id: Option<String>,
    pub is_category: i64,
    pub display_order: i64,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub custom_icon_svg: Option<String>,
    pub created_at: i64,
    pub channel_type: String,
    pub banner_url: Option<String>,
    pub banner_file_id: Option<String>,
    pub min_talk_power: i64,
    pub retention_days: Option<i64>,
}

/// Input for creating a channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewChannel {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub parent_id: Option<String>,
    pub is_category: bool,
    pub display_order: i64,
    pub description: Option<String>,
    pub channel_type: String,
    pub created_at: i64,
    pub banner_url: Option<String>,
    pub banner_file_id: Option<String>,
}

/// Partial update for a channel (all fields optional).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelPatch {
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub parent_id: Option<Option<String>>,
    pub icon: Option<Option<String>>,
    pub color: Option<Option<String>>,
    pub custom_icon_svg: Option<Option<String>>,
    pub min_talk_power: Option<i64>,
    pub retention_days: Option<Option<i64>>,
    pub banner_url: Option<Option<String>>,
    pub banner_file_id: Option<Option<String>>,
}

// ---- Messages ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRow {
    pub id: String,
    pub channel_id: String,
    pub sender: String,
    pub sender_name: Option<String>,
    pub content: String,
    pub attachments: Option<String>,
    pub reply_to: Option<String>,
    pub created_at: i64,
    pub edited_at: Option<i64>,
    pub reply_count: i64,
    pub visible_to_pubkey: Option<String>,
    pub embeds: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewMessage {
    pub id: String,
    pub channel_id: String,
    pub sender: String,
    pub content: String,
    pub attachments: Option<String>,
    pub reply_to: Option<String>,
    pub created_at: i64,
    pub visible_to_pubkey: Option<String>,
}

// ---- Roles ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleRow {
    pub id: String,
    pub name: String,
    pub priority: i64,
    pub display_separately: i64,
    pub created_at: i64,
    pub talk_power: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewRole {
    pub id: String,
    pub name: String,
    pub priority: i64,
    pub display_separately: bool,
    pub created_at: i64,
    pub permissions: Vec<String>,
}

/// Aggregated permissions for a user (union of all assigned roles).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserPerms {
    pub roles: Vec<RoleRow>,
    pub effective: std::collections::HashSet<String>,
    pub max_priority: i64,
}

// ---- Invites ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteRow {
    pub code: String,
    pub created_by: String,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

// ---- Moderation ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRow {
    pub target_public_key: String,
    pub banned_by: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuteRow {
    pub target_public_key: String,
    pub muted_by: String,
    pub reason: Option<String>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewReport {
    pub id: String,
    pub message_id: String,
    pub reporter_pubkey: String,
    pub reason: String,
    pub reported_at: i64,
}

// ---- Bots ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotProfileRow {
    pub pubkey: String,
    pub name: String,
    pub avatar_url: Option<String>,
    pub description: Option<String>,
    pub webhook_url: Option<String>,
    pub homepage_url: Option<String>,
    pub capabilities: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotRow {
    pub public_key: String,
    pub display_name: String,
    pub created_by: String,
    pub token_hash: String,
    pub webhook_url: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotCommandRow {
    pub pubkey: String,
    pub name: String,
    pub description: String,
    pub args: Option<String>,
    pub scope: String,
    pub privileged: i64,
    pub cooldown_seconds: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BotEventQueueRow {
    pub id: String,
    pub bot_pubkey: String,
    pub event_type: String,
    pub payload: String,
    pub created_at: i64,
    pub delivered: i64,
}

// ---- DMs ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationRow {
    pub id: String,
    pub conv_type: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmMessageRow {
    pub id: String,
    pub conversation_id: String,
    pub sender: String,
    pub content: Option<String>,
    pub signature: Option<String>,
    pub created_at: i64,
    pub attachments: Option<String>,
    pub is_encrypted: i64,
    pub ciphertext_json: Option<String>,
    pub is_group_encrypted: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendRow {
    pub user_a: String,
    pub user_b: String,
    pub status: String,
    pub created_at: i64,
    pub hub_url: Option<String>,
    pub display_name: Option<String>,
}

// ---- Federation ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRow {
    pub public_key: String,
    pub name: String,
    pub url: String,
    pub added_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedChannelRow {
    pub id: String,
    pub peer_public_key: String,
    pub remote_id: String,
    pub name: String,
    pub created_at: i64,
    pub last_synced_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedBanRow {
    pub source_hub_pubkey: String,
    pub target_master_pubkey: String,
    pub reason: Option<String>,
    pub added_at: i64,
    pub synced_at: i64,
}

// ---- Polls ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollRow {
    pub id: String,
    pub channel_id: String,
    pub creator_pubkey: String,
    pub question: String,
    pub options: String,
    pub ends_at: Option<i64>,
    pub max_choices: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollVoteRow {
    pub poll_id: String,
    pub user_pubkey: String,
    pub option_ids: String,
}

// ---- Events / calendar ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubEventRow {
    pub id: String,
    pub channel_id: String,
    pub creator_pubkey: String,
    pub title: String,
    pub description: String,
    pub starts_at: i64,
    pub ends_at: Option<i64>,
    pub location: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRsvpRow {
    pub event_id: String,
    pub user_pubkey: String,
    pub status: String,
}

// ---- Certifications ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertIssuanceRow {
    pub id: String,
    pub subject_pubkey: String,
    pub pow_level: Option<i64>,
    pub member_since: i64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub revoked_at: Option<i64>,
    pub standing: String,
    pub payload_json: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserCertRow {
    pub id: String,
    pub master_pubkey: String,
    pub issuer_pubkey: String,
    pub issuer_url: String,
    pub payload_json: String,
    pub signature: String,
    pub expires_at: i64,
}

// ---- Badge federation ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadgeOfferRow {
    pub id: String,
    pub from_hub_pubkey: String,
    pub from_hub_url: String,
    pub label: String,
    pub note: Option<String>,
    pub payload: String,
    pub signature: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubBadgeRow {
    pub id: String,
    pub issuer_pubkey: String,
    pub issuer_url: String,
    pub label: String,
    pub payload: String,
    pub signature: String,
    pub accepted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedBadgeRow {
    pub id: String,
    pub recipient_hub_url: String,
    pub recipient_hub_pubkey: String,
    pub label: String,
    pub payload: String,
    pub signature: String,
    pub issued_at: String,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
}

// ---- Recovery ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySettingsRow {
    pub owner_pubkey: String,
    pub threshold: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationRequestRow {
    pub id: String,
    pub old_pubkey: String,
    pub new_pubkey: String,
    pub reason: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
}

// ---- Uploads ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFileRow {
    pub id: String,
    pub filename: String,
    pub original_name: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub uploader_pubkey: String,
    pub channel_id: String,
    pub created_at: i64,
}

// ---- Pairing ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingOfferRow {
    pub pairing_token: String,
    pub master_pubkey: String,
    pub home_hubs_json: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub offer_signature: String,
    pub state: String,
    pub subkey_pubkey: Option<String>,
    pub device_label: Option<String>,
    pub claim_proof: Option<String>,
    pub cert_json: Option<String>,
    pub wrapped_key_hex: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

// ---- DH keys ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhKeyRow {
    pub pubkey: String,
    pub dh_pubkey_hex: String,
    pub signature_hex: String,
    pub published_at: i64,
}

// ---- Prefs blobs ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefsBlobRow {
    pub master_pubkey: String,
    pub blob_version: i64,
    pub ciphertext_hex: String,
    pub signature: String,
    pub updated_at: i64,
}

// ---- Hub settings ----

/// Generic key-value setting row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingRow {
    pub key: String,
    pub value: String,
}

// ---- Audit log ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogRow {
    pub id: String,
    pub seq: i64,
    pub event_type: String,
    pub at: i64,
    pub actor_pubkey: Option<String>,
    pub target_pubkey: Option<String>,
    pub channel_id: Option<String>,
    pub payload_json: String,
}

// ---- Pins ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinRow {
    pub channel_id: String,
    pub message_id: String,
    pub pinned_by: String,
    pub pinned_at: i64,
}

// ---- Posts (forum) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostRow {
    pub id: String,
    pub channel_id: String,
    pub author_pubkey: String,
    pub title: String,
    pub body: String,
    pub created_at: i64,
    pub edited_at: Option<i64>,
    pub is_pinned: i64,
    pub is_locked: i64,
    pub reply_count: i64,
    pub last_activity_at: i64,
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostReplyRow {
    pub id: String,
    pub post_id: String,
    pub author_pubkey: String,
    pub body: String,
    pub created_at: i64,
    pub edited_at: Option<i64>,
    pub reply_to_id: Option<String>,
    pub deleted_at: Option<i64>,
}

// ---- Alliances ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllianceRow {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: i64,
}

// ---- Webhooks ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookRow {
    pub id: String,
    pub channel_id: String,
    pub secret_token_hash: String,
    pub display_name: String,
    pub avatar_url: Option<String>,
    pub created_by_pubkey: String,
    pub rate_limit: i64,
    pub active: i64,
    pub created_at: i64,
}

// ---- Surveys ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurveyRow {
    pub id: String,
    pub enabled: i64,
    pub updated_at: i64,
}

// ---- Unread tracking ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelLastReadRow {
    pub user_pubkey: String,
    pub channel_id: String,
    pub last_read_at: i64,
}
