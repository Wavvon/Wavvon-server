//! The neutral, reviewable manifest format that sits between `export` and
//! `apply` (docs/docs/discord-import.md §3). Versioned so future manifest
//! producers (Matrix, Slack, hand-written) can target the same shape.

use serde::{Deserialize, Serialize};

pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub source: Source,
    pub roles: Vec<RoleEntry>,
    pub channels: Vec<ChannelEntry>,
    /// Human-readable notes surfaced by `export`: skipped channel kinds,
    /// member-overwrite deltas, possible allow/deny conflicts, text+voice
    /// merge suggestions. Never silent (§4 "Not imported").
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Source {
    pub kind: String,
    pub guild_id: String,
    pub guild_name: String,
    pub exported_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleEntry {
    /// Manifest-local id, referenced by channel overwrites. `export` uses
    /// the Discord role snowflake directly since it's already a stable,
    /// unique string and needs no separate counter.
    pub r#ref: String,
    pub name: String,
    /// Rescaled from Discord `position` to preserve relative order.
    pub priority: i64,
    /// Discord "hoist".
    #[serde(default)]
    pub display_separately: bool,
    /// `#RRGGBB`, or `None` when Discord reports no color (role color 0).
    #[serde(default)]
    pub color: Option<String>,
    pub permissions: Vec<String>,
    /// Discord permission bits with no Wavvon equivalent. Kept for the
    /// report, never applied.
    #[serde(default)]
    pub unmapped: Vec<String>,
    /// True for Discord's `@everyone` role. `apply` maps this ref to the
    /// hub's builtin-everyone role instead of creating a new one.
    #[serde(default)]
    pub is_everyone: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    Category,
    Text,
    Voice,
    Announcement,
    Forum,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelEntry {
    /// Manifest-local id (the Discord channel snowflake).
    pub r#ref: String,
    pub name: String,
    pub kind: ChannelKind,
    /// `ref` of the parent category, or `None` for a top-level channel or
    /// a category itself.
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub overwrites: Vec<Overwrite>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Overwrite {
    /// `ref` of the role this overwrite targets (may be the `@everyone`
    /// ref, resolved to the hub's builtin-everyone role at apply time).
    pub role: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = Manifest {
            version: MANIFEST_VERSION,
            source: Source {
                kind: "discord".to_string(),
                guild_id: "111".to_string(),
                guild_name: "Test Guild".to_string(),
                exported_at: 1_700_000_000,
            },
            roles: vec![
                RoleEntry {
                    r#ref: "111".to_string(),
                    name: "@everyone".to_string(),
                    priority: 0,
                    display_separately: false,
                    color: None,
                    permissions: vec!["read_messages".to_string()],
                    unmapped: vec![],
                    is_everyone: true,
                },
                RoleEntry {
                    r#ref: "222".to_string(),
                    name: "Raid Lead".to_string(),
                    priority: 40,
                    display_separately: true,
                    color: Some("#e67e22".to_string()),
                    permissions: vec!["send_messages".to_string(), "manage_messages".to_string()],
                    unmapped: vec!["MENTION_EVERYONE".to_string()],
                    is_everyone: false,
                },
            ],
            channels: vec![ChannelEntry {
                r#ref: "c1".to_string(),
                name: "Games".to_string(),
                kind: ChannelKind::Category,
                parent: None,
                overwrites: vec![Overwrite {
                    role: "222".to_string(),
                    allow: vec!["read_messages".to_string()],
                    deny: vec![],
                }],
            }],
            warnings: vec!["suggestion: text+voice pair".to_string()],
        };

        let json = serde_json::to_string_pretty(&manifest).expect("serialize");
        let back: Manifest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(manifest, back);

        // The wire shape uses "ref", not the Rust raw-identifier spelling.
        assert!(json.contains("\"ref\""));
        assert!(!json.contains("r#ref"));
        // Channel kinds are lowercase strings per §3.
        assert!(json.contains("\"category\""));
    }
}
