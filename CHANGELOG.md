# Changelog

All notable changes to Wavvon Server (hub + farm) are documented here.

## [0.3.2] — 2026-07-06
### Bug Fixes
- Skip auto-owner grant when owner_pubkey is configured
- Fix aarch64 musl cross-build: replace gnu-gcc with cargo-zigbuild

aarch64-linux-gnu-gcc targets GNU/glibc ABI; building for
aarch64-unknown-linux-musl requires a musl-compatible toolchain.
aws-lc-sys and ring both compile C code at build time, producing
glibc-ABI objects that the musl linker rejects.

Switch the aarch64 step to cargo-zigbuild: Zig ships its own musl
headers for every target and handles C dependencies correctly.
The x86_64-musl and Docker builds are unchanged.
- Strip UTF-8 BOM introduced by bulk rename
- Add missing bots_allow_camera field to test AppState initialisers
- Decode requires_camera as i64 for AnyPool compatibility
- Regenerate wire protocol test vectors for wavvon/ domain prefix
- Remove silent first-user owner auto-grant in hub auth
- Unwrap_or_else with literal to unwrap_or (clippy)
- Port seed tests from SQLite in-memory to PostgreSQL
- Port farm crate SQL from SQLite placeholders to PostgreSQL
- Replace remaining SQLite placeholders and rowid with PostgreSQL equivalents
- Grant builtin-owner to the first user who authenticates on a hub
- Replace all SQLite BOOLEAN integer patterns with PostgreSQL bool types
- Convert SQLite ? placeholders to PostgreSQL \$N in test files
- Millisecond message timestamps and PostgreSQL unique-constraint detection
- Use is_some_and instead of map_or(false, ...) for clippy compat
- Use SELECT EXISTS to avoid int4/i64 type mismatch in PeerHub extractor
- Replace SQLite-only MAX() scalar and FTS5 MATCH with PostgreSQL equivalents
- Bind channel_ban_v2 created_at as i64 not &String for BIGINT column
- Bind survey enabled/required as bool not 1i64/0i64 for BOOLEAN columns
- Guarantee screen_share_started arrives before first chunk on slow CI
- Suppress duplicate screen_share_started when chunk-relay arm sends it first
- Complete timestamp hygiene — TEXT→BIGINT, remove chrono, consolidate unix_now
- Clippy redundant_closure in webauthn credential ID map
- Add ws_key_senders to AppState init in main.rs
- Clippy single-element loop in restore command
- TestServer::new returns TestServer directly in axum-test v19
- Server_url returns Result<Url> in axum-test v19
- Insert system user before bootstrap channel inserts (FK constraint)
- Seed system user in bootstrap unit test and integration test
- Use real TcpListener in bootstrap template test (TestServer has no HTTP address)
- Add GET /join/:code info endpoint; fix mark_channel_read to use ms timestamps
- Use PostgreSQL placeholders (\) and bool for geo_unverified in farms routes
- Use PostgreSQL placeholders in revalidation tick queries
- Make cargo test --workspace work on Windows without manual setup
- Scope vendored openssl to windows only
- Close channel-permission read/write gating gaps from the 2026-07-04 audit
- Tear down ephemeral test databases automatically
- Spawn-on-join temp voice channels on the web voice relay
- Vendor OpenSSL on all targets so release builds link
- Switching a banner's image source clears the other column

### Documentation
- Fix renamed GitHub URLs, PostgreSQL reality, Postgres sidecar in compose

### Features
- Add mini_app_url optional field to bot registration (M1)
- Add bot mini-app WS message types and join handler (M2)
- Voice bot auth path and is_bot participant flag (M3)
- Video bot screenshare REST auth path (M4)
- M8 — add requires_camera to bot registration and allow_camera hub gate
- Replace SQLite with PostgreSQL throughout the server
- Migrate from SQLite to PostgreSQL
- Double Ratchet v2 signing bytes and envelope wire types
- First-run bootstrap from template URL or wizard token
- V3 proximity voice — zone state integration tests
- V4 voice encryption key distribution via ws_key_senders
- Implement ME1 federated ban list admin routes and ME2 circuit breaker
- Implement outgoing webhooks
- Channel-scoped role permission overwrites
- Add role categories with role color/icon appearance
- Add Discord guild structure import tool
- Event role-slot sign-ups and reminders
- Join-to-create temporary voice channels
- Soundboard + bot voice injection gate
- Pubkey-based whisper routing so whisper works for web clients

### Refactoring
- Move all Rust crates under crates/
- Rename crates/server to crates/agent, package voxply-agent
- Flatten crates/tools/ — move demo-seed directly under crates/
- Remove game state, migrations, row types, and test file (S5)
- Remove games routes, WS types, farm routes, and GameStore trait (S1-S4)
- Merge wavvon-store and wavvon-store-postgres into single store crate
- Consolidate iso_from_unix into auth/handlers

### Tests
- Skip member_online/member_offline frames in ws_voice_join_and_recv
- Skip member_online/offline frames in screen_share_flow tests
- De-flake cross-hub DM delivery tests


## [0.2.3] — 2026-06-12
### Bug Fixes
- Harden auth, invites, SSRF, uploads, and session checks
- Enforce federated_bans on outbound messages and DMs
- Address security and correctness issues from audit
- Guard /federation/dm with PeerHub extractor
- Clippy double_ended_iterator_last in XFF parsing
- Resolve remaining clippy lints (rfind in XFF parsing, print_literal in help)
- Pin Docker builder and runtime stages to the same Debian release
- Deterministic pow_flow below-minimum test

### Documentation
- Add CONTRIBUTING.md
- Add wire-format spec and deterministic test vectors
- Rewrite README as a self-hoster landing page
- Restore the AI-assistance transparency note

### Features
- Allow multiple concurrent screen sharers per channel
- Cross-channel stream subscription (decouple streaming from voice)
- Voxply-hub update subcommand
- Rate-limit GET /preview per user (10 req/60 s)
- POST /admin/search/reindex — operator-driven index rebuild
- Networked voice Phase 1 — token-gated UDP source-address learning
- Optionally self-serve the web client

### Performance
- Lazy search reload, message rate-limit eviction, users N+1 fix
- Single public-info fetch per farm per revalidation sweep

### Refactoring
- Split routes/ws.rs into directory module
- Split routes/games.rs into directory module

### Tests
- Pin DhKeyRecord and DM-envelope wire vectors


## [0.2.0] — 2026-05-30
### Bug Fixes
- Re-encode test files as UTF-8 (em-dash was written as Windows-1252)
- Switch reqwest to rustls-tls, remove OpenSSL dependency

### Features
- Add max_channel_depth hub setting with server-side depth enforcement
- Enforce minimum PoW level on hub authentication
- Add forum channel type with posts, replies, and FTS
- Channel ban, voice mute, and talk power enforcement
- Hub self-tags and federated badge issue/accept/decline
- Tier 2 party multiplayer session backend
- Hub certification issuance, auth gate, and admin routes
- Recovery contacts, DM block enforcement, and screen share v2 signaling
- Farm-level game install and per-hub enable/disable



