# Voxply Hub Workspace — Roadmap

## Next up
_Fully designed features ready to build. Design docs in `docs/` (wiki)._

- **Android multi-device pairing UI** — QR pairing flow already on desktop + web; Android client missing it. `docs/multi-device.md`
- **Identity export with passphrase** — passphrase-wrapped `identity.json` export/import; Tauri command + UI. `docs/future-features.md` § Identity recovery
- **Games Tier 1 completion** — hub admin Games tab (channel scope, capability grants) + 5 remaining SDK calls. `docs/gaming.md`
- **E2E encrypted DMs (v1)** — static ECDH 1:1 DM encryption; group DM sender-key. Full design done. `docs/e2e-encryption.md`
- **Proximity / spatial voice** — voice zones, position updates, client-side gain attenuation. `docs/proximity-voice.md`
- **Whisper** — hub-routed targeted audio to user / channel / role sets. `docs/whisper.md`
- **Moderation enhancements** — three independent pieces, each designed:
  - Federated ban lists (opt-in signed blocklist + subscription policy)
  - Auto-moderation webhook (pre-store message filter)
  - Content reporting queue (admin review, pending/dismissed states)
  - `docs/moderation-enhancements.md`
- **Games Tier 2 client SDK** — party sessions, WS relay, shared KV; server-side already shipped. `docs/gaming.md`

## Wishlist
_Larger projects not yet started or still undesigned._

- **Farm model Phases 1-3** — move auth to farm, multi-hub tenancy, hub-creation flow + admin panel. `docs/farm-impl.md`
- **Discovery v2** — hub uptime tracking, farm catalog, global cross-catalog search, analytics. `docs/discovery-v2.md`
- **Missions + sparks** — sponsor-driven missions, spark balance, cosmetic rewards, anti-fraud layers. `docs/missions.md`
- **E2E v2 — Double Ratchet** — forward secrecy / Signal-style ratchet upgrade from static ECDH. `docs/e2e-encryption.md`
- **Games Tier 3 MMO** — persistent shared world, cross-hub zones, farm matchmaking. `docs/gaming.md`
- **Custom themes / user skins** — user-created CSS token skins, `.voxplyskin` format. `docs/custom-themes.md`
- **OAuth social verification badges** — link GitHub / Steam / etc. as opt-in profile flair. `docs/future-features.md`

## Known issues / future work

- **Cross-farm cert relay** — hub certifications work per-hub; revocations don't propagate across farms. `docs/hub-certifications.md`
- **Per-hub subkey revocation propagation** — revoking a subkey on hub A isn't automatically known to hub B. `docs/multi-device.md`
- **Bot deferred scope** — voice/screen-share injection, bot DMs, outgoing webhooks, bot-launched game modals have no timeline. `docs/future-features.md`
- **Forum per-post read cursors** — forum channels use channel-level unread tracking only; per-post cursors deferred. `docs/forum.md`
- **Forum: reactions + attachments on posts** — not yet supported. `docs/forum.md`

## Won't do

- Central authority of any kind (global hub directory, global identity service, DHT)
- Subscriptions, premium tiers, or in-chat advertising
- Telemetry collection or data sales
- Global web-of-trust or negative reputation / shared ban lists
