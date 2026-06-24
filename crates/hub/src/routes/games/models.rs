use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Request body for installing a game (Tier 1 minimal admin route).
/// Only the fields required to create a `hub_games` row. Extended install
/// (manifest-URL fetch, capability grants) is the full Tier 1 admin surface
/// which is designed but not yet built — this endpoint covers the minimal path
/// used by the Tier 2 session tests and the inline-manifest install path.
#[derive(Deserialize)]
pub struct InstallGameRequest {
    pub name: String,
    pub entry_url: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub thumbnail_url: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub min_players: Option<i64>,
    #[serde(default)]
    pub max_players: Option<i64>,
}

#[derive(Serialize)]
pub struct InstalledGameResponse {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    pub version: String,
    pub description: Option<String>,
    pub thumbnail_url: Option<String>,
    pub author: Option<String>,
    pub min_players: i64,
    pub max_players: i64,
}

#[derive(Deserialize)]
pub struct CreateSessionRequest {
    pub game_id: String,
    /// The channel this session is anchored to.
    pub channel_id: String,
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub channel_id: String,
    pub game_id: String,
    pub host_pubkey: String,
    pub players: Vec<String>,
    pub state_json: serde_json::Value,
    pub created_at: String,
    pub ended_at: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchStateRequest {
    pub patch: serde_json::Value,
}

#[derive(Deserialize)]
pub struct SetKvRequest {
    pub value: String,
}

#[derive(Serialize)]
pub struct KvResponse {
    pub session_id: String,
    pub key: String,
    pub value: String,
    pub updated_at: String,
}

// ===========================================================================
// Spec Tier 2 session types
// ===========================================================================

#[derive(Deserialize)]
pub struct CreateSessionV2Request {
    pub channel_id: String,
    #[serde(default)]
    pub max_players: Option<i64>,
}

#[derive(Deserialize)]
pub struct ListSessionsQuery {
    pub channel_id: Option<String>,
}

#[derive(Serialize)]
pub struct SessionV2Response {
    pub session_id: String,
    pub game_id: String,
    pub channel_id: String,
    pub host_pubkey: String,
    pub status: String,
    pub players: Vec<PlayerInfo>,
    pub max_players: Option<i64>,
    pub created_at: i64,
    pub last_event_at: i64,
}

#[derive(Serialize)]
pub struct PlayerInfo {
    pub pubkey: String,
    pub display_name: Option<String>,
    pub joined_at: i64,
    pub connected: bool,
}

#[derive(Serialize)]
pub struct ListSessionsResponse {
    pub sessions: Vec<SessionV2Response>,
}

// ===========================================================================
// Farm-aware Tier 1 admin types
// ===========================================================================

/// Shared manifest shape returned by the farm's GET /farm/games/:id
#[derive(serde::Deserialize)]
pub(super) struct FarmGameManifest {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub thumbnail_url: Option<String>,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default = "default_one")]
    pub min_players: i64,
    #[serde(default = "default_one")]
    pub max_players: i64,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

fn default_one() -> i64 {
    1
}

#[derive(serde::Serialize)]
pub struct EnabledGameEntry {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub min_players: i64,
    pub max_players: i64,
}

#[derive(serde::Serialize)]
pub struct ListEnabledGamesResponse {
    pub games: Vec<EnabledGameEntry>,
}

#[derive(serde::Deserialize)]
pub struct SetChannelScopeRequest {
    pub channel_ids: Vec<String>,
}

#[derive(serde::Deserialize)]
pub struct SetPermissionsRequest {
    pub capabilities: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct AdminGameEntry {
    pub id: String,
    pub name: String,
    pub entry_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    pub min_players: i64,
    pub max_players: i64,
    pub enabled: bool,
    pub enabled_by: Option<String>,
    pub enabled_at: Option<String>,
    /// Channel IDs this game is restricted to. Empty vec = all channels.
    pub channel_scope: Vec<String>,
    /// Capability grants for this game on this hub.
    pub capabilities: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct AdminListGamesResponse {
    pub games: Vec<AdminGameEntry>,
}
