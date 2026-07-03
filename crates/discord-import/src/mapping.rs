//! Pure Discord → manifest mapping (docs/docs/discord-import.md §4). No
//! network I/O; `discord_client` fetches the raw JSON, this module turns it
//! into a `Manifest`.

use std::collections::{HashMap, HashSet};

use crate::discord_types::{
    DiscordChannel, DiscordGuild, DiscordRole, CHANNEL_TYPE_ANNOUNCEMENT, CHANNEL_TYPE_CATEGORY,
    CHANNEL_TYPE_DIRECTORY, CHANNEL_TYPE_FORUM, CHANNEL_TYPE_STAGE, CHANNEL_TYPE_STORE,
    CHANNEL_TYPE_TEXT, CHANNEL_TYPE_VOICE, OVERWRITE_TYPE_MEMBER, OVERWRITE_TYPE_ROLE,
};
use crate::manifest::{ChannelEntry, ChannelKind, Manifest, Overwrite, RoleEntry, Source};
use crate::permissions_table::map_bits;

/// Discord `position` -> Wavvon `priority`, preserving relative order with
/// headroom for the operator to hand-insert a role between two imported
/// ones before applying.
fn rescale_priority(position: i64) -> i64 {
    position * 10
}

/// Maps a Discord channel `type` integer to the manifest kind, or `None`
/// for kinds with no Wavvon equivalent (Stage, Directory, Store, and any
/// future type Discord adds that we don't recognize).
fn discord_channel_kind(type_int: i64) -> Option<ChannelKind> {
    match type_int {
        CHANNEL_TYPE_TEXT => Some(ChannelKind::Text),
        CHANNEL_TYPE_VOICE => Some(ChannelKind::Voice),
        CHANNEL_TYPE_CATEGORY => Some(ChannelKind::Category),
        CHANNEL_TYPE_ANNOUNCEMENT => Some(ChannelKind::Announcement),
        CHANNEL_TYPE_FORUM => Some(ChannelKind::Forum),
        CHANNEL_TYPE_STAGE | CHANNEL_TYPE_DIRECTORY | CHANNEL_TYPE_STORE => None,
        _ => None,
    }
}

/// Discord's `@everyone` role always has an id equal to the guild id --
/// that's the stable, un-renameable way to identify it (its display name
/// is "@everyone" but that's not part of the API contract).
fn is_everyone_role(role: &DiscordRole, guild_id: &str) -> bool {
    role.id == guild_id
}

/// Case/emoji-insensitive-ish name normalization used to suggest
/// text+voice pairs: strips everything but alphanumerics/space/hyphen,
/// lowercases, and drops "voice"/"chat" filler words.
fn normalize_pair_name(name: &str) -> String {
    let stripped: String = name
        .chars()
        .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '-' || *c == '_')
        .map(|c| if c == '-' || c == '_' { ' ' } else { c })
        .collect();
    stripped
        .to_lowercase()
        .split_whitespace()
        .filter(|t| *t != "voice" && *t != "chat")
        .collect::<Vec<_>>()
        .join(" ")
}

/// Builds the manifest's channel list in apply-friendly order: categories
/// first (by Discord position), then each category's children (by
/// position), then top-level channels that aren't under any kept category.
/// Order within siblings is preserved, matching §3's "array order" rule.
fn ordered_channels<'a>(kept: &[&'a DiscordChannel]) -> Vec<&'a DiscordChannel> {
    let mut categories: Vec<&DiscordChannel> = kept
        .iter()
        .filter(|c| c.kind == CHANNEL_TYPE_CATEGORY)
        .copied()
        .collect();
    categories.sort_by_key(|c| c.position);

    let known_category_ids: HashSet<&str> = categories.iter().map(|c| c.id.as_str()).collect();

    let mut ordered: Vec<&DiscordChannel> = Vec::with_capacity(kept.len());
    for cat in &categories {
        ordered.push(cat);
        let mut children: Vec<&DiscordChannel> = kept
            .iter()
            .filter(|c| {
                c.kind != CHANNEL_TYPE_CATEGORY && c.parent_id.as_deref() == Some(cat.id.as_str())
            })
            .copied()
            .collect();
        children.sort_by_key(|c| c.position);
        ordered.extend(children);
    }

    let mut orphans: Vec<&DiscordChannel> = kept
        .iter()
        .filter(|c| {
            c.kind != CHANNEL_TYPE_CATEGORY
                && !c
                    .parent_id
                    .as_deref()
                    .map(|p| known_category_ids.contains(p))
                    .unwrap_or(false)
        })
        .copied()
        .collect();
    orphans.sort_by_key(|c| c.position);
    ordered.extend(orphans);

    ordered
}

/// Adds a warning for each same-parent text+voice channel pair whose
/// normalized names match. Never merges -- §4/§7 "suggest, never
/// auto-merge".
fn suggest_text_voice_pairs(ordered: &[&DiscordChannel], warnings: &mut Vec<String>) {
    let mut by_parent: HashMap<Option<&str>, Vec<&DiscordChannel>> = HashMap::new();
    for ch in ordered {
        if ch.kind == CHANNEL_TYPE_TEXT || ch.kind == CHANNEL_TYPE_VOICE {
            by_parent
                .entry(ch.parent_id.as_deref())
                .or_default()
                .push(ch);
        }
    }

    // Deterministic iteration: sort group keys before iterating.
    let mut keys: Vec<Option<&str>> = by_parent.keys().copied().collect();
    keys.sort();

    for key in keys {
        let group = &by_parent[&key];
        let texts: Vec<&&DiscordChannel> = group
            .iter()
            .filter(|c| c.kind == CHANNEL_TYPE_TEXT)
            .collect();
        let voices: Vec<&&DiscordChannel> = group
            .iter()
            .filter(|c| c.kind == CHANNEL_TYPE_VOICE)
            .collect();
        for t in &texts {
            let tn = normalize_pair_name(&t.name);
            for v in &voices {
                if normalize_pair_name(&v.name) == tn {
                    warnings.push(format!(
                        "suggestion: '{}' and '{}' look like a text+voice pair -- Wavvon channels are unified; consider deleting one from the manifest (never auto-merged)",
                        t.name, v.name
                    ));
                }
            }
        }
    }
}

/// Turns a fetched guild + its roles + its channels into a `Manifest`.
/// `exported_at` is a unix timestamp supplied by the caller so this
/// function stays pure (no `SystemTime::now()` call inside).
pub fn build_manifest(
    guild: &DiscordGuild,
    roles: &[DiscordRole],
    channels: &[DiscordChannel],
    exported_at: i64,
) -> Manifest {
    let mut warnings = Vec::new();

    // --- roles -----------------------------------------------------------
    let mut role_entries = Vec::with_capacity(roles.len());
    for role in roles {
        let is_everyone = is_everyone_role(role, &guild.id);
        let bits: u64 = role.permissions.parse().unwrap_or(0);
        let (mapped, unmapped) = map_bits(bits);
        let color = if role.color == 0 {
            None
        } else {
            Some(format!("#{:06x}", role.color))
        };
        role_entries.push(RoleEntry {
            r#ref: role.id.clone(),
            name: role.name.clone(),
            priority: rescale_priority(role.position),
            display_separately: role.hoist,
            color,
            permissions: mapped,
            unmapped,
            is_everyone,
        });
    }

    // --- channels ----------------------------------------------------------
    let mut kept: Vec<&DiscordChannel> = Vec::new();
    for ch in channels {
        match discord_channel_kind(ch.kind) {
            Some(_) => kept.push(ch),
            None => warnings.push(format!(
                "channel '{}' has Discord type {} (Stage/Directory/Store/unrecognized) -- skipped, no Wavvon equivalent",
                ch.name, ch.kind
            )),
        }
    }

    let ordered = ordered_channels(&kept);
    let known_category_ids: HashSet<&str> = ordered
        .iter()
        .filter(|c| c.kind == CHANNEL_TYPE_CATEGORY)
        .map(|c| c.id.as_str())
        .collect();

    let mut channel_entries = Vec::with_capacity(ordered.len());
    for ch in &ordered {
        let kind = discord_channel_kind(ch.kind).expect("filtered to supported kinds above");
        let parent = if kind == ChannelKind::Category {
            None
        } else {
            ch.parent_id
                .clone()
                .filter(|p: &String| known_category_ids.contains(p.as_str()))
        };

        let mut overwrites = Vec::new();
        for ow in &ch.permission_overwrites {
            if ow.kind == OVERWRITE_TYPE_MEMBER {
                warnings.push(format!(
                    "channel '{}': per-user overwrite for member {} skipped -- Wavvon per-user overwrites aren't supported; hand-fix with a role",
                    ch.name, ow.id
                ));
                continue;
            }
            if ow.kind != OVERWRITE_TYPE_ROLE {
                continue; // defensive: ignore any future overwrite kind
            }

            let allow_bits: u64 = ow.allow.parse().unwrap_or(0);
            let deny_bits: u64 = ow.deny.parse().unwrap_or(0);
            let (allow_mapped, allow_unmapped) = map_bits(allow_bits);
            let (deny_mapped, deny_unmapped) = map_bits(deny_bits);

            if !allow_unmapped.is_empty() || !deny_unmapped.is_empty() {
                let mut names = allow_unmapped;
                names.extend(deny_unmapped);
                names.sort();
                names.dedup();
                warnings.push(format!(
                    "channel '{}': role overwrite for role {} includes unmapped Discord permission(s): {} -- not applied",
                    ch.name,
                    ow.id,
                    names.join(", ")
                ));
            }

            overwrites.push(Overwrite {
                role: ow.id.clone(),
                allow: allow_mapped,
                deny: deny_mapped,
            });
        }

        channel_entries.push(ChannelEntry {
            r#ref: ch.id.clone(),
            name: ch.name.clone(),
            kind,
            parent,
            overwrites,
        });
    }

    // Flag channels where two different roles disagree on the same
    // permission (one allows, one denies): Discord resolves deny-wins
    // across a member's roles, Wavvon resolves allow-wins (§4).
    for entry in &channel_entries {
        let mut allow_set: HashSet<&str> = HashSet::new();
        let mut deny_set: HashSet<&str> = HashSet::new();
        for ow in &entry.overwrites {
            allow_set.extend(ow.allow.iter().map(String::as_str));
            deny_set.extend(ow.deny.iter().map(String::as_str));
        }
        let mut conflicted: Vec<&str> = allow_set.intersection(&deny_set).copied().collect();
        if !conflicted.is_empty() {
            conflicted.sort();
            warnings.push(format!(
                "channel '{}': roles disagree on permission(s) {} -- Discord resolves deny-wins across a member's roles, Wavvon resolves allow-wins; review after import",
                entry.name,
                conflicted.join(", ")
            ));
        }
    }

    suggest_text_voice_pairs(&ordered, &mut warnings);

    Manifest {
        version: crate::manifest::MANIFEST_VERSION,
        source: Source {
            kind: "discord".to_string(),
            guild_id: guild.id.clone(),
            guild_name: guild.name.clone(),
            exported_at,
        },
        roles: role_entries,
        channels: channel_entries,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discord_types::{DiscordChannel, DiscordGuild, DiscordRole};

    /// A representative guild fixture: nested categories, every supported
    /// channel kind plus one Stage channel to skip, roles with
    /// colors/hoist, both a role and a member overwrite, and a text+voice
    /// name pair. Shapes follow the documented Discord API v10 JSON
    /// (snowflakes as strings, `type` integers, stringified bitfields).
    fn fixture_guild() -> DiscordGuild {
        DiscordGuild {
            id: "1000".to_string(),
            name: "Test Guild".to_string(),
        }
    }

    fn fixture_roles() -> Vec<DiscordRole> {
        serde_json::from_str(
            r#"[
                {"id": "1000", "name": "@everyone", "color": 0, "hoist": false, "position": 0, "permissions": "1024"},
                {"id": "2001", "name": "Raid Lead", "color": 15105570, "hoist": true, "position": 3, "permissions": "8"},
                {"id": "2002", "name": "Moderator", "color": 0, "hoist": true, "position": 2, "permissions": "1099780064768"}
            ]"#,
        )
        .expect("valid role fixture json")
    }

    /// Builds a stringified Discord permission bitfield from a list of bit
    /// positions, so overwrite fixtures below don't need hand-computed
    /// decimal literals.
    fn bits(shifts: &[u32]) -> String {
        let v: u64 = shifts.iter().map(|s| 1u64 << s).sum();
        v.to_string()
    }

    fn fixture_channels() -> Vec<DiscordChannel> {
        let games_cat = r#"{"id": "3000", "type": 4, "name": "Games", "position": 0, "parent_id": null, "permission_overwrites": []}"#
            .to_string();
        let raid_lead_allow = bits(&[10]); // VIEW_CHANNEL
        let raid_lead_deny: String = "0".to_string();
        let mod_allow = bits(&[10]); // VIEW_CHANNEL allow
        let mod_deny = bits(&[11]); // SEND_MESSAGES deny -- conflicts with a hypothetical allow elsewhere
        let raids_text = format!(
            r#"{{"id": "3001", "type": 0, "name": "raids", "position": 0, "parent_id": "3000",
                "permission_overwrites": [
                    {{"id": "2001", "type": 0, "allow": "{raid_lead_allow}", "deny": "{raid_lead_deny}"}},
                    {{"id": "2002", "type": 0, "allow": "{mod_allow}", "deny": "{mod_deny}"}},
                    {{"id": "9999", "type": 1, "allow": "0", "deny": "0"}}
                ]}}"#
        );
        let raids_voice = r#"{"id": "3002", "type": 2, "name": "🔊 Raids", "position": 1, "parent_id": "3000", "permission_overwrites": []}"#.to_string();
        let announcements = r#"{"id": "3003", "type": 5, "name": "announcements", "position": 1, "parent_id": null, "permission_overwrites": []}"#.to_string();
        let forum = r#"{"id": "3004", "type": 15, "name": "help-forum", "position": 2, "parent_id": null, "permission_overwrites": []}"#.to_string();
        let stage = r#"{"id": "3005", "type": 13, "name": "Town Hall", "position": 3, "parent_id": null, "permission_overwrites": []}"#.to_string();

        let json =
            format!("[{games_cat},{raids_text},{raids_voice},{announcements},{forum},{stage}]");
        serde_json::from_str(&json).expect("valid channel fixture json")
    }

    #[test]
    fn maps_roles_including_everyone_and_colors() {
        let manifest = build_manifest(&fixture_guild(), &fixture_roles(), &[], 1_700_000_000);
        assert_eq!(manifest.roles.len(), 3);

        let everyone = manifest.roles.iter().find(|r| r.r#ref == "1000").unwrap();
        assert!(everyone.is_everyone);
        assert_eq!(everyone.color, None);

        let raid_lead = manifest.roles.iter().find(|r| r.r#ref == "2001").unwrap();
        assert!(!raid_lead.is_everyone);
        assert_eq!(raid_lead.color.as_deref(), Some("#e67e22"));
        assert!(raid_lead.display_separately);
        assert_eq!(raid_lead.permissions, vec!["admin".to_string()]);

        let moderator = manifest.roles.iter().find(|r| r.r#ref == "2002").unwrap();
        assert_eq!(moderator.color, None); // color 0 => no color
    }

    #[test]
    fn skips_stage_channel_with_warning() {
        let manifest = build_manifest(&fixture_guild(), &[], &fixture_channels(), 0);
        assert!(!manifest.channels.iter().any(|c| c.r#ref == "3005"));
        assert!(manifest
            .warnings
            .iter()
            .any(|w| w.contains("Town Hall") && w.contains("skipped")));
    }

    #[test]
    fn category_comes_before_its_children_in_output_order() {
        let manifest = build_manifest(&fixture_guild(), &[], &fixture_channels(), 0);
        let idx = |r: &str| manifest.channels.iter().position(|c| c.r#ref == r).unwrap();
        assert!(idx("3000") < idx("3001")); // category before child
        assert!(idx("3000") < idx("3002"));
    }

    #[test]
    fn maps_channel_kinds() {
        let manifest = build_manifest(&fixture_guild(), &[], &fixture_channels(), 0);
        let kind_of = |r: &str| {
            manifest
                .channels
                .iter()
                .find(|c| c.r#ref == r)
                .unwrap()
                .kind
        };
        assert_eq!(kind_of("3000"), ChannelKind::Category);
        assert_eq!(kind_of("3001"), ChannelKind::Text);
        assert_eq!(kind_of("3002"), ChannelKind::Voice);
        assert_eq!(kind_of("3003"), ChannelKind::Announcement);
        assert_eq!(kind_of("3004"), ChannelKind::Forum);
    }

    #[test]
    fn role_overwrite_maps_and_member_overwrite_is_skipped_with_warning() {
        let manifest = build_manifest(&fixture_guild(), &[], &fixture_channels(), 0);
        let raids = manifest
            .channels
            .iter()
            .find(|c| c.r#ref == "3001")
            .unwrap();
        // Two role overwrites kept, the member overwrite dropped.
        assert_eq!(raids.overwrites.len(), 2);
        assert!(manifest
            .warnings
            .iter()
            .any(|w| w.contains("per-user overwrite") && w.contains("9999")));
    }

    #[test]
    fn no_conflict_warning_when_roles_agree() {
        // Fixture overwrites: both roles allow read_messages, and the only
        // deny (send_messages) has no matching allow anywhere on the
        // channel -- not a same-permission disagreement.
        let manifest = build_manifest(&fixture_guild(), &[], &fixture_channels(), 0);
        assert!(!manifest.warnings.iter().any(|w| w.contains("disagree")));
    }

    #[test]
    fn genuine_allow_deny_conflict_is_flagged() {
        let games_cat = r#"{"id": "3000", "type": 4, "name": "Games", "position": 0, "parent_id": null, "permission_overwrites": []}"#.to_string();
        let allow_send = bits(&[11]);
        let deny_send = bits(&[11]);
        let ch = format!(
            r#"{{"id": "3001", "type": 0, "name": "general", "position": 0, "parent_id": "3000",
                "permission_overwrites": [
                    {{"id": "2001", "type": 0, "allow": "{allow_send}", "deny": "0"}},
                    {{"id": "2002", "type": 0, "allow": "0", "deny": "{deny_send}"}}
                ]}}"#
        );
        let channels: Vec<DiscordChannel> =
            serde_json::from_str(&format!("[{games_cat},{ch}]")).unwrap();
        let manifest = build_manifest(&fixture_guild(), &[], &channels, 0);
        assert!(manifest
            .warnings
            .iter()
            .any(|w| w.contains("disagree") && w.contains("send_messages")));
    }

    #[test]
    fn suggests_text_voice_pair_without_merging() {
        let manifest = build_manifest(&fixture_guild(), &[], &fixture_channels(), 0);
        assert_eq!(manifest.channels.len(), 5); // stage excluded, nothing merged
        assert!(manifest
            .warnings
            .iter()
            .any(|w| w.contains("text+voice pair") && w.contains("raids")));
    }

    #[test]
    fn unmapped_overwrite_bits_are_reported() {
        let games_cat = r#"{"id": "3000", "type": 4, "name": "Games", "position": 0, "parent_id": null, "permission_overwrites": []}"#.to_string();
        let mention_everyone = bits(&[17]);
        let ch = format!(
            r#"{{"id": "3001", "type": 0, "name": "general", "position": 0, "parent_id": "3000",
                "permission_overwrites": [
                    {{"id": "2001", "type": 0, "allow": "{mention_everyone}", "deny": "0"}}
                ]}}"#
        );
        let channels: Vec<DiscordChannel> =
            serde_json::from_str(&format!("[{games_cat},{ch}]")).unwrap();
        let manifest = build_manifest(&fixture_guild(), &[], &channels, 0);
        assert!(manifest
            .warnings
            .iter()
            .any(|w| w.contains("unmapped") && w.contains("MENTION_EVERYONE")));
    }
}
