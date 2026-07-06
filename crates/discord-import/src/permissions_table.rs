//! Discord permission bit → Wavvon permission constant mapping
//! (docs/docs/discord-import.md §4). Every named Discord flag is listed
//! here even when it has no Wavvon equivalent, so the `unmapped` list in
//! the manifest reports a readable name instead of a raw bit index.
//!
//! Bit positions per the Discord API permissions-bitwise-flags reference.

pub struct DiscordPermFlag {
    pub bit: u32,
    pub name: &'static str,
    /// `Some(wavvon_constant)` when §4's table maps this bit; `None` means
    /// it has no Wavvon equivalent and is reported as unmapped.
    pub wavvon: Option<&'static str>,
}

pub const TABLE: &[DiscordPermFlag] = &[
    flag(0, "CREATE_INSTANT_INVITE", None),
    flag(1, "KICK_MEMBERS", Some("kick_members")),
    flag(2, "BAN_MEMBERS", Some("ban_members")),
    flag(3, "ADMINISTRATOR", Some("admin")),
    flag(4, "MANAGE_CHANNELS", Some("manage_channels")),
    flag(5, "MANAGE_GUILD", None),
    flag(6, "ADD_REACTIONS", None),
    flag(7, "VIEW_AUDIT_LOG", None),
    flag(8, "PRIORITY_SPEAKER", None),
    flag(9, "STREAM", None),
    flag(10, "VIEW_CHANNEL", Some("read_messages")),
    flag(11, "SEND_MESSAGES", Some("send_messages")),
    flag(12, "SEND_TTS_MESSAGES", None),
    flag(13, "MANAGE_MESSAGES", Some("manage_messages")),
    flag(14, "EMBED_LINKS", None),
    flag(15, "ATTACH_FILES", None),
    flag(16, "READ_MESSAGE_HISTORY", None),
    flag(17, "MENTION_EVERYONE", None),
    flag(18, "USE_EXTERNAL_EMOJIS", None),
    flag(19, "VIEW_GUILD_INSIGHTS", None),
    flag(20, "CONNECT", None),
    flag(21, "SPEAK", None),
    flag(22, "MUTE_MEMBERS", Some("mute_members")),
    flag(23, "DEAFEN_MEMBERS", Some("mute_members")),
    flag(24, "MOVE_MEMBERS", None),
    flag(25, "USE_VAD", None),
    flag(26, "CHANGE_NICKNAME", None),
    flag(27, "MANAGE_NICKNAMES", None),
    flag(28, "MANAGE_ROLES", Some("manage_roles")),
    flag(29, "MANAGE_WEBHOOKS", None),
    flag(30, "MANAGE_GUILD_EXPRESSIONS", None),
    flag(31, "USE_APPLICATION_COMMANDS", None),
    flag(32, "REQUEST_TO_SPEAK", None),
    flag(33, "MANAGE_EVENTS", Some("create_events")),
    flag(34, "MANAGE_THREADS", None),
    flag(35, "CREATE_PUBLIC_THREADS", None),
    flag(36, "CREATE_PRIVATE_THREADS", None),
    flag(37, "USE_EXTERNAL_STICKERS", None),
    flag(38, "SEND_MESSAGES_IN_THREADS", None),
    flag(39, "USE_EMBEDDED_ACTIVITIES", None),
    flag(40, "MODERATE_MEMBERS", Some("timeout_members")),
    flag(41, "VIEW_CREATOR_MONETIZATION_ANALYTICS", None),
    flag(42, "USE_SOUNDBOARD", None),
    flag(43, "CREATE_GUILD_EXPRESSIONS", None),
    flag(44, "CREATE_EVENTS", Some("create_events")),
    flag(45, "USE_EXTERNAL_SOUNDS", None),
    flag(46, "SEND_VOICE_MESSAGES", None),
    flag(49, "SEND_POLLS", None),
    flag(50, "USE_EXTERNAL_APPS", None),
];

const fn flag(bit: u32, name: &'static str, wavvon: Option<&'static str>) -> DiscordPermFlag {
    DiscordPermFlag { bit, name, wavvon }
}

/// Splits a Discord permission bitfield into (mapped Wavvon constants,
/// unmapped Discord flag names). Bits with no entry in `TABLE` (including
/// bits beyond any flag Discord has documented) fall back to
/// `UNKNOWN_BIT_<n>` so nothing is silently dropped.
pub fn map_bits(bitfield: u64) -> (Vec<String>, Vec<String>) {
    let mut mapped = Vec::new();
    let mut unmapped = Vec::new();

    for bit in 0..64u32 {
        if bitfield & (1u64 << bit) == 0 {
            continue;
        }
        match TABLE.iter().find(|f| f.bit == bit) {
            Some(f) => match f.wavvon {
                Some(w) => mapped.push(w.to_string()),
                None => unmapped.push(f.name.to_string()),
            },
            None => unmapped.push(format!("UNKNOWN_BIT_{bit}")),
        }
    }

    mapped.sort();
    mapped.dedup();
    (mapped, unmapped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrator_maps_to_admin() {
        let (mapped, unmapped) = map_bits(1 << 3);
        assert_eq!(mapped, vec!["admin".to_string()]);
        assert!(unmapped.is_empty());
    }

    #[test]
    fn view_channel_maps_to_read_messages() {
        let (mapped, _) = map_bits(1 << 10);
        assert_eq!(mapped, vec!["read_messages".to_string()]);
    }

    #[test]
    fn send_messages_maps_to_send_messages() {
        let (mapped, _) = map_bits(1 << 11);
        assert_eq!(mapped, vec!["send_messages".to_string()]);
    }

    #[test]
    fn moderate_members_maps_to_timeout_members() {
        let (mapped, _) = map_bits(1 << 40);
        assert_eq!(mapped, vec!["timeout_members".to_string()]);
    }

    #[test]
    fn mute_and_deafen_both_map_to_mute_members_deduped() {
        let (mapped, _) = map_bits((1 << 22) | (1 << 23));
        assert_eq!(mapped, vec!["mute_members".to_string()]);
    }

    #[test]
    fn create_and_manage_events_both_map_to_create_events_deduped() {
        let (mapped, _) = map_bits((1 << 33) | (1 << 44));
        assert_eq!(mapped, vec!["create_events".to_string()]);
    }

    #[test]
    fn unmapped_bit_is_reported_by_name() {
        let (mapped, unmapped) = map_bits(1 << 17); // MENTION_EVERYONE
        assert!(mapped.is_empty());
        assert_eq!(unmapped, vec!["MENTION_EVERYONE".to_string()]);
    }

    #[test]
    fn unknown_future_bit_falls_back_to_placeholder_name() {
        let (mapped, unmapped) = map_bits(1 << 60);
        assert!(mapped.is_empty());
        assert_eq!(unmapped, vec!["UNKNOWN_BIT_60".to_string()]);
    }
}
