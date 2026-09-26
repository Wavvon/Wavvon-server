//! What this hub can do, as a list of strings clients test membership in.
//!
//! Advertised on `GET /info` as `capabilities`. Clients decide what to render
//! by asking "is this string in the list", **never** by comparing `version` —
//! see decisions.md ("Hub capabilities are advertised, not inferred from a
//! version number"). `version` stays in `/info` for display.
//!
//! Why this matters here more than in most federated products: each hub bakes
//! a web client into its own image and serves it, and that client is
//! multi-hub. The copy served by hub A talks to hubs B and C, so there is no
//! "client and server update together" — the client's version is decided by
//! whichever hub the user happened to open and bears no relation to the hubs
//! it then talks to.
//!
//! **Adding a feature? Add its string here, in the same commit.** A forgotten
//! capability fails visibly (the feature never appears on this hub) rather
//! than silently. The list only ever grows — a removed string means every
//! older client stops offering the feature, which is a breaking change and
//! waits for a major (decisions.md, "Wire changes are additive").
//!
//! Keep it sorted; the test below enforces that so two features added in
//! parallel conflict in the merge instead of landing twice.

/// Capability strings this build advertises.
///
/// Seeded with the cases where a newer client would otherwise call an
/// endpoint an older hub does not have, or silently get a worse answer.
pub const CAPABILITIES: &[&str] = &[
    // Alliance management is delegable: `alliances.manage` carries the
    // hub-scoped acts, and `alliance_managers` — a per-alliance grant list over
    // local roles — carries the ones that belong to one relationship (inviting
    // another hub, sharing a channel, the per-share policies). Gated so a
    // client does not offer a delegation an older hub, where all ten endpoints
    // want the hub-wide permission, would answer 403 to.
    "alliance.permissions",
    // There is no bot account. A program joins like anyone — an invite, a
    // keypair, a session — and a member holding `apps.register` registers a
    // profile, slash commands and event subscriptions for it under `/me/app`.
    // This replaces `bots.external`, which is gone rather than kept as a
    // synonym: a client that still tests for it is offering `POST /bots` and
    // a capability grant panel, and both endpoints answer 404 now. Removing
    // a published string is a breaking change and it is taken deliberately
    // here, in beta, because the alternative is an admin panel that looks
    // alive and cannot work.
    "apps.register",
    // Every channel in `GET /channels` carries `can_move_members`: the
    // caller's own `voice.move_members` there, resolved channel-scoped. A
    // client that does not see this string has no way to know which
    // destinations it may offer, so its move picker keeps listing them all and
    // the refusal arrives when the move is issued.
    "channels.move.targets",
    // `DELETE /me` — a member can remove themselves from the hub: profile and
    // roles cleared, the pubkey kept as the anchor moderation and message
    // history point at. Gated because a client must not offer "leave this
    // community" against a hub that would answer 404, leaving the person
    // believing they left.
    "hub.leave",
    // `GET /invites` hides the invites that can no longer admit anyone and
    // carries `status` (`live`, `expired`, `used_up`) on the ones it shows;
    // `?include_inactive=true` asks for the history. A client that cannot see
    // this string is talking to a hub that returns every row ever minted and
    // no status, so it must keep working the answer out from `uses`,
    // `max_uses` and `expires_at` itself.
    "invites.status",
    // `/info` carries `max_attachment_bytes` and hub admin can change it. A
    // client that does not see this string is talking to a hub whose cap is a
    // compile-time 3 MB, so it must keep using its own constant rather than
    // trusting a field that will not be there.
    "limits.attachments",
    // `GET /users`, `GET /conversations/{id}/messages` and `GET
    // /admin/reports` honour `limit` + a keyset `cursor`. Without this the
    // hub ignores both and returns one truncated page — a client that pages
    // to exhaustion against an older hub sees a short list, not an error.
    "list.cursor",
    // The same `limit` + keyset `cursor` dialect on the rest of the lists that
    // grow with use: `GET /moderation/bans`, `/moderation/mutes`, `/invites`,
    // `/hub/pending`, `/conversations`, `/channels/{id}/pins` and
    // `/channels/{id}/polls`. A second string rather than widening
    // `list.cursor`, because a client that pages one of these against a hub
    // advertising only `list.cursor` would page an endpoint that ignores the
    // cursor and hand back the first page over and over.
    "list.cursor.lists",
    // Device pairing: subkey certs presented at `/auth/verify`, and the
    // ECIES-wrapped canonical DH material a paired device needs for DMs.
    "pairing.subkey",
    // The permission catalogue is served by the hub and no longer copied into
    // each client: GET /permissions lists every id with its scope, and
    // GET /users/{pubkey}/permissions/why explains one answer. A client that
    // cannot see this string is talking to a hub whose permission ids are the
    // old snake_case set, so it must keep rendering its own built-in list —
    // the two spellings share no ids, and there is no dual-reading period
    // (permissions.md §6).
    "permissions.catalogue",
    // Recovery contacts: signed `wavvon/recovery-request/v1` and
    // `wavvon/recovery-attestation/v1` envelopes and the endpoints behind
    // them.
    "recovery.attestation",
    // WebRTC screen-share v2 signalling (SDP/ICE relay). Mirrors the older
    // `screen_share_v2` boolean, which stays for clients that read it.
    "screenshare.v2",
    // A member of an allied hub can join voice in a channel this hub shares
    // with that alliance: the mint route on their hub, the grant field on
    // `/auth/verify` here, and the visitor scope behind it (alliances.md).
    // Gated because a client that cannot see this string must not offer a
    // voice affordance on an alliance channel it would then fail to join.
    "voice.alliance",
    // `pong` carries `outbound_loss_pct`: the relay counts gaps in the
    // sender's own cleartext `ctr` sequence, which is the only place outbound
    // loss can be measured at all. Gated because a client that cannot tell
    // "this hub does not report it" from "loss is zero" would show a
    // reassuring 0.0% against every older hub.
    "voice.loss",
    // Voice admission is its own permission, `voice.join`, independent of
    // `read_messages` in both directions (permissions.md §3, Voice). Two
    // things a client may only do once it sees this string: offer `voice.join`
    // as a channel overwrite — an older hub's validator rejects the id as
    // unknown — and stop treating a read deny as though it also closed voice,
    // because on this hub it does not. Named for the shape the alliance work
    // uses (`alliance.permissions`), not for the permission id, which is a
    // different namespace that happens to read the same.
    "voice.permissions",
    // `min_talk_power` gates transmitting, not joining, and the floor is
    // granted by a moderator rather than taken with `raise-hand`. Two things
    // a client may only do once it sees this string: read `may_speak` on
    // `voice_joined` — an older hub never sends it, and defaulting a missing
    // field to "muted" would silence every member on every hub that predates
    // this — and offer the grant route, which an older hub answers 404. On an
    // older hub a raised hand is still how the threshold is cleared.
    "voice.talk",
    // Voice over WebTransport/QUIC with E2E sender keys (voice-transport-v2).
    // The raw-UDP and `/voice/ws` relays it replaced are gone, so a client
    // that does not see this string has no voice path to this hub at all.
    "voice.wt",
    // The WS answers `ping` with `pong`, echoing the nonce. Without this a
    // client measuring latency would wait for a reply that never comes and
    // show a dead "—" forever, so the readout has to be gated on it.
    "ws.ping",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_and_unique() {
        let mut sorted = CAPABILITIES.to_vec();
        sorted.sort_unstable();
        assert_eq!(CAPABILITIES, sorted.as_slice(), "keep CAPABILITIES sorted");

        sorted.dedup();
        assert_eq!(CAPABILITIES.len(), sorted.len(), "duplicate capability");
    }

    /// One spelling, so a client's string literal either matches or the
    /// capability was never advertised — no "was it a dash or a dot" bugs.
    #[test]
    fn names_are_lowercase_dotted() {
        for cap in CAPABILITIES {
            assert!(!cap.is_empty(), "empty capability string");
            assert!(
                cap.split('.').all(|part| !part.is_empty()
                    && part
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())),
                "capability {cap:?} must be lowercase alphanumeric segments joined by dots",
            );
        }
    }
}
