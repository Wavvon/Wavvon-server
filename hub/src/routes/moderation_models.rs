use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct BanRequest {
    pub target_public_key: String,
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct BanResponse {
    pub target_public_key: String,
    pub banned_by: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct MuteRequest {
    pub target_public_key: String,
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct TimeoutRequest {
    pub target_public_key: String,
    pub reason: Option<String>,
    pub duration_seconds: u64,
}

#[derive(Serialize, Deserialize)]
pub struct MuteResponse {
    pub target_public_key: String,
    pub muted_by: String,
    pub reason: Option<String>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct KickRequest {
    pub target_public_key: String,
}

#[derive(Deserialize)]
pub struct ChannelBanRequest {
    pub target_public_key: String,
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ChannelBanResponse {
    pub channel_id: String,
    pub target_public_key: String,
    pub banned_by: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct VoiceMuteRequest {
    pub target_public_key: String,
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VoiceMuteResponse {
    pub target_public_key: String,
    pub muted_by: String,
    pub reason: Option<String>,
    pub created_at: i64,
}

#[derive(Deserialize)]
pub struct SetTalkPowerRequest {
    pub min_talk_power: i64,
}

#[derive(Serialize)]
pub struct TalkPowerResponse {
    pub channel_id: String,
    pub min_talk_power: i64,
}
