# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## What this repo is

The **Wavvon server** — a Rust workspace for a self-hosted, federated voice+text
community platform. This repo is self-contained: you can clone, build, test and
run a hub from it alone.

Sibling repos (you don't need them checked out):

| Repo | Contents |
|---|---|
| [Wavvon-clients](https://github.com/Wavvon/Wavvon-clients) | Web + desktop clients, shared TS packages, voice crate |
| [Wavvon-discovery](https://github.com/Wavvon/Wavvon-discovery) | Optional public hub directory site |
| [Wavvon-docs](https://github.com/Wavvon/Wavvon-docs) | Architecture wiki (70+ docs) + `openapi.yaml` |

**Read the wiki before grepping.** Start at
[docs/README.md](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/README.md)
for the reading order. Wiki links below point at that repo; clone it alongside
this one if you want them offline.

Commit to **`develop`**. See `CONTRIBUTING.md`.

---

## Commands

```bash
cargo check --workspace
cargo check --all-targets --workspace    # `check` alone does NOT compile tests
cargo clippy --all-targets --workspace   # NOTE: CI tracks `stable`, which may be AHEAD of yours
cargo fmt --all                          # required before every commit; CI gates on --check
cargo test --workspace -- --test-threads=4   # bounded: the default saturates Postgres
                                             # max_connections and flakes with PoolTimedOut
cargo test -p wavvon-hub                 # single crate
cargo build --release
```

Hub CLI (binary at `target/release/wavvon-hub`) — `--help` is the source of
truth; `--doctor` is an option, not a subcommand:

```bash
./target/release/wavvon-hub setup        # interactive wizard: docker-compose.yml + .env
./target/release/wavvon-hub migrate      # apply DB migrations
./target/release/wavvon-hub --doctor     # pre-flight checks (ports, TLS, disk, DB mode)
./target/release/wavvon-hub admin stats  # admin <stats|users|channels|tokens|backup|restore>
./target/release/wavvon-hub admin users set-owner <pubkey>   # bootstrap ownership
./target/release/wavvon-hub backup FILE
./target/release/wavvon-hub restore FILE [--force]
./target/release/wavvon-hub db move --to URL     # copy the DB elsewhere; never switches mode
./target/release/wavvon-hub rotate-key
./target/release/wavvon-hub update [--check]     # Linux x86_64 only
```

The farm has an equivalent `migrate` subcommand. All binaries are configured
via `WAVVON_*` environment variables or a config file — see the
[hub operator guide](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/hub-operator-guide.md).
To get a hub running locally, use the **`run-hub`** skill in `.claude/skills/`.

---

## Architecture

### `hub` — the community server

Entry: `crates/hub/src/main.rs` -> `lib.rs` -> `server.rs`

Axum HTTP + WebSocket (port 3000), WebTransport/QUIC voice relay over UDP 3001
(voice transport v2 — the raw-UDP and `/voice/ws` relays it replaced are gone),
sqlx + Tantivy FTS. Handles: channels (text + voice + forum + banner + spawner),
messages, polls/events (incl. organizer staging), roles + role categories,
moderation, E2E DMs, federation (outbox DMs, alliances, federated ban lists),
bots/webhooks, soundboard, recovery-contact attestation, and background workers
for DM outbox delivery, ban-list sync, data retention + rotation-request expiry,
and cert maintenance.

It is also a **home hub** for whoever designates it: `routes/identity.rs` holds
the personal axis — the master-signed `HomeHubList` designation, the device
registry (`subkey_certs`) and revocations, pairing's short-lived state, and the
user's encrypted prefs blob. A DM accepted here is mirror-forwarded to the
recipient's other home hubs through the same outbox. See the wiki's
`home-hub.md`; the split from community-axis state is the two-axis rule below.

Layout under `crates/hub/src/`:
- `routes/` — one file per HTTP resource group
- `auth/` — Ed25519 challenge-response
- `federation/` — hub-to-hub HTTPS + WebSocket
- `state.rs` — `AppState`
- `permissions.rs` — role-based access control
- `capabilities.rs` — the feature-string list served by `GET /info`
- `db/migrations.rs` — schema (destructive changes allowed until 1.0)
- `db/version.rs` — minimum supported PostgreSQL server, checked before migrations

### `identity` — wire-format authority

Entry: `crates/identity/src/lib.rs`. Pure Rust, no async, no I/O.

Defines every signed envelope type: `HomeHubList`, `SubkeyCert`, `PairingOffer`,
DM envelopes, prefs blob, recovery request/attestation
(`wavvon/recovery-request/v1`, `wavvon/recovery-attestation/v1`), and more. Each
has a versioned tag (`b"wavvon/<name>/v1\0"`) and length-prefixed binary
encoding. Also: BIP39 recovery phrases (24 words <-> secret key), X25519 ECDH
from an Ed25519 seed for E2E DMs, AES-256-GCM, PoW helpers.

**Every client must match this crate byte-for-byte.** Test vectors live in
`crates/identity/tests/wire_vectors.rs` and are mirrored in the clients repo
(TypeScript and desktop Rust), each asserting the same vectors. Changing an
envelope is a cross-repo operation — use the **`wire-format-change`** skill.

### `store` — database abstraction

Entry: `crates/store/src/lib.rs`. Trait-based: `HubStore` = `AuthStore +
UserStore + ChannelStore + MessageStore + RoleStore + DmStore + FederationStore +
BotStore + ...`. The hub holds `Arc<dyn HubStore>`. PostgreSQL is the one and
only backend (`crates/store/src/impls/`). The trait split's value today is error
normalization and keeping SQL out of route handlers — prefer it over raw
`sqlx::query` in new hub code.

### `hub-env` — cross-process config keys

Entry: `crates/hub-env/src/lib.rs`. Dependency-free; holds only the **names** of
the `WAVVON_*` env keys that cross a process boundary, shared by hub, farm and
agent.

It exists because those names were string literals on both sides and drifted:
farm and agent spent months setting `WAVVON_HUB_DB` and `WAVVON_HUB_HTTP_PORT`,
names the hub has never read, so spawned hubs ignored their allocated port and
shared one database — silently. Never spell such a name as a literal.
`wavvon_hub::settings` has a test that sets every spawnable key and asserts it
reaches `Settings`.

### The rest

- **`farm`** — fleet control plane: hub lifecycle (spawn, monitor, stop), server registration, reverse-proxy to hub processes, farm-level SSO. Partially implemented; see the wiki's `farm-model.md` and `farm-impl.md`.
- **`agent`** — fleet worker node. Reverse-connects to farm over WebSocket, spawns and monitors local hub processes on its behalf. No HTTP surface.
- **`demo-seed`** — populates a running hub with realistic demo data for screenshots.
- **`bot-kit`, `ttt-bot`, `discord-import`** — bot SDK, example bot, importer.

---

## Non-obvious constraints

**CI's clippy can be newer than yours, and it fails the build.** `build.yml`
uses `dtolnay/rust-toolchain@…  # stable`, so it picks up new lints the day
they land. A local toolchain a few weeks old gives a clean
`cargo clippy --workspace -- -D warnings` and a red pipeline — which has now
happened twice in a row, on `result_large_err` and then `result_unit_err`,
the second only reachable because fixing the first let clippy get past it.
`rustup update stable` before trusting a green local clippy run, and expect
the fix to be a real one: these lints have been right both times.

**Migrations: destructive changes are fine until 1.0.** This is beta. There is
no database in the field whose upgrade path anyone has promised, so `DROP`,
`ALTER ... TYPE`, renames and reshaping a table are all available — take them
when they give the better schema instead of bending the design around a
constraint that does not apply yet.

**From 1.0.0 the additive-only rule starts, and it is absolute**: only
`CREATE TABLE IF NOT EXISTS` and `ALTER TABLE ADD COLUMN`, with column
additions wrapped so an "already exists" error is ignored. The reason to write
that down now is that folding a destructive change into a `CREATE TABLE` after
that point silently produces databases missing a column, with no error until a
query touches it (see the `migrations.rs` header) — so the day the floor lands,
this stops being a preference.

Prefer the additive shape anyway when it costs nothing: a schema whose history
is additive is one you can reason about. Just do not pay design debt for it
before 1.0.

**PostgreSQL: one backend, a declared floor, a configurable pool.** PostgreSQL is
the only backend, and reopening that needs a new entry in the wiki's
`decisions.md` — the reasoning is recorded there. The hub declares a **minimum
server version** (`db/version.rs`, currently PG 14) and checks it *before*
migrations, so an old server gets a sentence instead of a half-applied schema; CI
runs the matrix against both ends of the supported range. Pool size is
`WAVVON_DB_MAX_CONNECTIONS` (default 5) on hub and farm — it caps concurrent
*queries*, not concurrent users, and the sum across hubs sharing one server must
stay under its `max_connections`.

**The hub bundles PostgreSQL, and the mode is chosen by absence.** With no
`WAVVON_DATABASE_URL` the hub starts and manages its own server
(`crates/hub/src/embedded_pg.rs`); with one, it uses that and never touches a
server it did not create. Installs are version-scoped
(`<data_root>/pg/<version>/`) and the previous major's binaries are never
deleted, because they are what can still read old data. On a major mismatch the
hub **refuses with instructions** rather than starting — half-migrating a data
directory is unrecoverable. `--doctor` reports which mode is active and where
the data lives; `backup`/`restore` go through the bundled `pg_dump`.

One live caveat: **bundled mode does not work on musl** (the archive's `initdb`
wants `libicuuc.so.74`, which no current Alpine ships, and its `libpq.so.5` also
wants krb5) even though the release still publishes musl targets advertising a
no-prerequisites path. It is an open item in the wiki's `next-up.md`. The Docker
image is unaffected: it is `debian:trixie-slim`, so it gets the glibc archive.

The **major-upgrade path is walked end to end** as of 2026-09-10, by
`e2e-topology`'s `pgupgrade` stage — fill a bundled hub, back it up, meet the
refusal, follow its instructions, and come back under the same public key with
the data intact. Reach for that stage before touching `embedded_pg.rs` or
`db/dump.rs`: it found two bugs on its first run that no in-process test could,
because both live in the sequence rather than in a function. What still needs
two binaries carrying two majors, and is PostgreSQL's contract rather than
ours, is whether a `pg_dump` from major N restores into N+1.

**List endpoints paginate with one dialect:** an array plus `limit` and a keyset
cursor. No envelope, no offset paging, no second shape. A paginated endpoint also
needs a client that *pages* — raising a cap without one just moves the silent
truncation to a bigger number.

**Adding a hub feature a client branches on? Add its capability string.**
`GET /info` carries `capabilities`, and clients decide what to render by testing
membership — never by comparing `version`. One sorted list in
`crates/hub/src/capabilities.rs`; add the line in the same commit that adds the
feature. This bites here more than elsewhere because each hub serves its own
baked-in web client and that client is multi-hub — the copy served by hub A talks
to hubs B and C, so there is no "client and server update together". Strings
never change spelling once published (that's a removal, and removals wait for a
major).

**Duplicate endpoints get folded, not versioned side by side.** Two route
families over one table means two half-specified behaviours that disagree —
`/moderation/channels/{id}/bans` and `/channels/{id}/bans` did exactly that and
silently erased ban reasons. `/channels/{id}/bans` is now the only channel-ban
API; `/channels/{id}/members` was deleted (it ignored its `channel_id` and
returned the `/users` rows).

**Silent fallthroughs are the bug class to watch for here.** Duplicated env-var
name literals let farm/agent configure hubs with keys the hub never read, and a
client's WebSocket enum matched unknown events as `Other => {}`, so four hub
features were simply absent with no symptom. Both cost months. When you add a
catch-all arm or a cross-process string, make the unknown case say something.

Two hub-side instances from 2026-09-07, both the "transient read as final"
variant: the DM outbox dropped an unparsable envelope with `.ok()` and
delivered the message hollow, recording it a success — and the naive fix
(propagate the error) would have parked the whole queue behind one bad row,
so the two failures are now distinguished, `Db` ending the pass and
`Unreadable` bouncing that row alone. The other was the demo bot exiting on a
429 from the shared per-IP auth limiter while waiting to be invited, which
kept the clients' live workflow red for days.

Its 2026-09-10 shape: **one slot for a thing that has several.**
`ws_key_senders` was `HashMap<pubkey, sender>` with an unconditional insert on
connect and an unconditional remove on disconnect — so a second socket for the
same identity overwrote the first, and then the first socket's teardown removed
the entry the second had just written. The survivor was registered nowhere and
every targeted message to it was dropped silently; for voice that is no sender
key, so every datagram is discarded at the key lookup and the call is silent
while the roster, the transport and the relay all look right. Two tabs, a
paired device, or the overlap of an ordinary reconnect arranges it. The map is
now nested by `session_id`, which `bot_sessions` and the screen-share teardown
next door had been doing all along, each with a comment saying why. **When you
add a per-user map, ask how many sockets one user has** — the answer is not
one, and the failure is quiet.

**The auth limiter is per IP and one login costs two requests** — a shared
address (office, school, CGNAT) spends the default budget on ordinary
arrivals, and to the person turned away it looks like a hub that will not have
them. `WAVVON_AUTH_RATE_BURST` / `WAVVON_AUTH_RATE_PER_SEC` exist for that;
the defaults are unchanged. If you are debugging "the client keeps landing on
the welcome screen", check for 429s before anything else.

**Recovery/attestation signing uses the identity key the hub knows the user by**
(the roster pubkey), NOT a derived multi-device master key — contacts are
designated and requests approved against hub-known pubkeys. The master key signs
only multi-device material (subkey certs, etc.).

**Two-axis state model.** Community-axis state (channels, messages, roles) lives
on community hubs. Personal-axis state (prefs, DM history, block/mute/ignore,
home hub list, custom themes, drafts) lives on the user's home hub(s). Don't mix
them.

**Identity is a keypair, not an account.** No email, password, or username.
Identity = Ed25519 public key (hex). Multi-device via BIP39 master phrase +
signed subkey certs. Auth accepts an optional subkey cert — see
`resolve_canonical_identity` in `crates/hub/src/auth/handlers.rs`; don't bypass
it in endpoints that key off user identity.

**Resolving a roster pubkey to its master: use `master_of`, never
`users.master_pubkey` alone.** Clients register a device cert when they
*connect*, which is strictly earlier than the auth that presents it and writes
`users.master_pubkey` — so `subkey_certs` is the only place the link exists for
a while, and often forever. The DM fan-out read `users` alone while the
mirror path already fell back to certs, so the same recipient was mirrored to
and never fanned out to, silently. Anything that answers "which master is this
member?" goes through one resolver.

---

## Tests

Integration tests in `crates/hub/tests/*_flow.rs` use `axum_test::TestServer`
against a **fresh, isolated PostgreSQL database per test**
(`common::create_test_db()` creates it via `PgPoolOptions` and runs the real
migrations). Set `TEST_DATABASE_URL` if your server isn't
`postgres://postgres:postgres@localhost:5432`. Locally,
`docker run -d -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16-alpine`
suffices.

New endpoints need at minimum a happy-path and a rejection test.

A `PoolTimedOut` failure is almost always `max_connections` exhaustion under
parallelism, not a real fault — re-run the single binary, or cap with
`-- --test-threads=4`.

**A test that can skip itself must be unable to skip in CI.** Print
`WAVVON-TEST-SKIPPED:` and CI fails on it (`build.yml`); `cargo test` runs with
`--nocapture` there because it otherwise swallows the output of passing tests,
and the guard would grep a log that cannot contain what it looks for. Skips are
legitimate — `pg_dump` and a built `wavvon-hub` are not on every dev box — but a
green run that did not execute the test is worse than no test. A backup test
"passing" in 0.00s is what that looks like.

**A new config variant needs a test that executes it, not one that tests its
inputs.** `hub_isolation = 'schema'` shipped with unit tests over the URL it
builds and nothing that had ever started a hub behind one; the failure mode was
migrating into `public` and silently sharing it again. Enumerable config means
one end-to-end test per value.

---

## Conventions

- Code comments in **English**, and only when the WHY is non-obvious. Don't explain WHAT.
- No comments in GitHub Actions workflow files — explain the choice in the commit message or the docs.
- Design decisions go in the wiki's `decisions.md` (newest entry at the top: decision / alternatives / tradeoff / outcome). Mark superseded entries; don't delete them.
- Competitor references are allowed — factual, no logos, no disparagement.
