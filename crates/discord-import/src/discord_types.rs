//! Raw Discord Bot API v10 JSON shapes, trimmed to the fields `mapping`
//! needs. Snowflakes are strings; permission bitfields are stringified
//! u64s; see <https://discord.com/developers/docs/resources/guild> and
//! <https://discord.com/developers/docs/resources/channel>.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordGuild {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordRole {
    pub id: String,
    pub name: String,
    /// RGB integer; 0 means "no color" in the Discord UI.
    #[serde(default)]
    pub color: i64,
    #[serde(default)]
    pub hoist: bool,
    /// Higher = higher in the role hierarchy. `@everyone` is always 0.
    #[serde(default)]
    pub position: i64,
    /// Stringified u64 bitfield.
    pub permissions: String,
}

/// Discord channel `type` values relevant to structure import. Stage (13),
/// Directory (14) and the deprecated Store (6) have no Wavvon equivalent
/// and are skipped (§4).
pub const CHANNEL_TYPE_TEXT: i64 = 0;
pub const CHANNEL_TYPE_VOICE: i64 = 2;
pub const CHANNEL_TYPE_CATEGORY: i64 = 4;
pub const CHANNEL_TYPE_ANNOUNCEMENT: i64 = 5;
pub const CHANNEL_TYPE_STORE: i64 = 6;
pub const CHANNEL_TYPE_STAGE: i64 = 13;
pub const CHANNEL_TYPE_DIRECTORY: i64 = 14;
pub const CHANNEL_TYPE_FORUM: i64 = 15;

/// Discord permission-overwrite `type`: 0 = role, 1 = member.
pub const OVERWRITE_TYPE_ROLE: i64 = 0;
pub const OVERWRITE_TYPE_MEMBER: i64 = 1;

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordChannel {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: i64,
    pub name: String,
    #[serde(default)]
    pub position: i64,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub permission_overwrites: Vec<DiscordOverwrite>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DiscordOverwrite {
    /// Role id or member id, depending on `kind`.
    pub id: String,
    #[serde(rename = "type")]
    pub kind: i64,
    /// Stringified u64 bitfield.
    pub allow: String,
    /// Stringified u64 bitfield.
    pub deny: String,
}
