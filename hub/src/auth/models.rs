use serde::{Deserialize, Serialize};
use voxply_identity::SubkeyCert;

use crate::routes::bot_models::BotMeta;

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub public_key: String,
}

#[derive(Serialize, Deserialize)]
pub struct ChallengeResponse {
    pub challenge: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub public_key: String,
    pub challenge: String,
    pub signature: String,
    pub invite_code: Option<String>,
    pub security_nonce: Option<u64>,
    pub security_level: Option<u32>,
    /// Multi-device: when present, `public_key` is the device's
    /// subkey and the cert links it to a master. The hub uses the
    /// master to find the canonical user row across devices.
    #[serde(default)]
    pub subkey_cert: Option<SubkeyCert>,
    /// Bot challenge token (required when challenge_mode != 'off').
    #[serde(default)]
    pub challenge_token: Option<String>,
    /// External bot self-declaration. When true, the hub expects a
    /// pre-existing `users` row with approval_status='bot_pending'.
    #[serde(default)]
    pub is_bot: Option<bool>,
    /// Bot metadata to upsert on successful auth. Only processed when
    /// is_bot=true.
    #[serde(default)]
    pub bot_meta: Option<BotMeta>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyResponse {
    pub token: String,
    /// "lobby" when lobby is enabled and the user's pow_level is below min_security_level,
    /// otherwise "member".
    #[serde(default)]
    pub scope: String,
}

/// Optional challenge token presented during auth/verify when challenge_mode != 'off'.
#[derive(Deserialize, Default)]
pub struct ChallengeTokenField {
    #[serde(default)]
    pub challenge_token: Option<String>,
}
