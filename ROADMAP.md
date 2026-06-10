# Voxply Hub — Roadmap

## Next up

- Desktop client wire-type update: identity crate SubkeyCert/PairingOffer changes need version pins coordinated with Voxply-desktop
- MUSL aarch64 binary: validate on real ARM hardware once CI produces the artifact

## Wishlist

- Rate-limit the `/preview` endpoint globally (currently per-request SSRF checks only)
- Search: expose a `flush` admin endpoint for operator-driven reindex without restart
- Federation: honour `federated_bans` in outbound messages, not just inbound auth
- Voice relay: tie UDP relay session lifetime to the WS session validated by `validate_ws_token`

## Known issues

- `alliance_flow.rs` test emits an unused-variable warning for `hub_a_state` (pre-existing, not introduced here)
- `migrations.rs` test emits an unused-import warning for `sqlx::AnyPool` (pre-existing)

## Won't do

- Synchronous reader reload on every search-index write (removed in favour of lazy reload on query)
- Per-message Tantivy commit with blocking reader reload (the old behaviour; replaced by commit-per-doc + lazy read-path reload)
