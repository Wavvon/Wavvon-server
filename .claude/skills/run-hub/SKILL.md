---
name: run-hub
description: Get a Wavvon hub running locally from source — PostgreSQL, migrations, config, first owner, and a clean database per run. Use when asked to run, start, smoke-test or reset a local hub, or when a client needs a hub to talk to.
---

# Run a Wavvon hub locally

Running the hub means running **PostgreSQL too** — it is the only backend and
there is no embedded fallback. Start the database first, without being asked.

## 1. PostgreSQL

Minimum supported server version is declared in `crates/hub/src/db/version.rs`
(currently 14) and checked *before* migrations, so an old server gives you a
sentence instead of a half-applied schema.

```bash
docker run -d --name wavvon-pg -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 postgres:16-alpine
```

`docker-compose.dev.yml` in this repo provides an equivalent. **Run one, not
both** — two Postgres containers on 5432 conflict, and the symptom is a
connection that succeeds against the wrong database.

Create a database for this run:

```bash
docker exec wavvon-pg psql -U postgres -c 'CREATE DATABASE wavvon'
```

## 2. Build and migrate

```bash
cargo build --release -p wavvon-hub
export WAVVON_DATABASE_URL=postgres://postgres:postgres@localhost:5432/wavvon
./target/release/wavvon-hub migrate
./target/release/wavvon-hub doctor    # ports, TLS, disk — run it before blaming the code
```

## 3. Run

```bash
WAVVON_DATABASE_URL=postgres://postgres:postgres@localhost:5432/wavvon \
WAVVON_HTTP_PORT=3000 \
WAVVON_VOICE_UDP_PORT=3001 \
WAVVON_PUBLIC_URL=http://localhost:3000 \
./target/release/wavvon-hub
```

**The working directory matters.** The hub writes `hub_identity.json` (its
Ed25519 key) and the Tantivy search index into the **current directory**. Run it
from a dedicated data directory and stay consistent — starting it elsewhere
generates a *new* hub identity, which reads as "all my accounts are gone".

**A second hub in the same directory will not start.** It dies with
`Failed to acquire Lockfile: LockBusy` — the Tantivy index takes a writer lock,
and the identity file would be shared too. Give every hub its own directory,
which matters most where it is least obvious: running two hubs to test
federation, and running one from the monorepo root while another is already
there. The failure is easy to misread, because a hub that dies on startup looks
downstream like a wall of unrelated client timeouts.

**`WAVVON_PUBLIC_URL` is not optional in practice.** Without it
`/info.voice_wt_url` is null and clients cannot connect voice at all; invite
links and passkeys degrade the same way. A farm-spawned hub derives its own and
doesn't need it set.

**An empty `WAVVON_*` value means "unset".** That matters mainly in a
container, where clearing a baked-in `ENV` is the only thing you *can* do: the
official image sets `WAVVON_WEB_CLIENT_DIR=/web-client`, and
`-e WAVVON_WEB_CLIENT_DIR=` is how you run API-only — which is what you want
when a client dev server, or a Playwright run, is serving the client under test
instead. Until 2026-08-22 that exited with `WAVVON_WEB_CLIENT_DIR '' does not
exist`, so a hub older than that cannot do it.

Never spell a `WAVVON_*` name as a string literal in code — the names live in the
`hub-env` crate. See `CLAUDE.md`.

## 4. Become the owner

A fresh hub starts **`invite_only=true`** with no owner. Two ways in:

- **Set the owner up front:** `WAVVON_OWNER_PUBKEY=<64-char hex>` on first boot seeds that key as owner. The pubkey is your client identity's public key.
- **Use the printed invite:** with no owner configured, the hub mints a one-time owner-granting invite and logs it as `First-boot owner invite: http://localhost:3000/join/<code>`. Join through that link and you are owner. It is a no-op once the hub has a real user.

After the fact, on a hub you already control:

```bash
./target/release/wavvon-hub admin users set-owner <pubkey>
./target/release/wavvon-hub admin stats
```

## 5. Reset

The cheapest reset is a new database, not surgery on the old one:

```bash
docker exec wavvon-pg psql -U postgres -c 'DROP DATABASE IF EXISTS wavvon_scratch'
docker exec wavvon-pg psql -U postgres -c 'CREATE DATABASE wavvon_scratch'
```

Then `migrate` and run against it. To also reset the hub's *identity*, remove
`hub_identity.json` from the data directory — that makes it a different hub, so
do it deliberately.

## Gotchas

- **`PoolTimedOut`** under a parallel test run is PostgreSQL's `max_connections`, not a real fault. Re-run the single binary or use `-- --test-threads=4`. `WAVVON_DB_MAX_CONNECTIONS` (default 5) caps concurrent *queries* per hub — the sum across hubs sharing one server must stay under the server's `max_connections`.
- **A leftover `wavvon-hub` process locks the build output.** On Windows cargo reports "Access denied (os error 5)". Kill the process; don't clean the target directory.
- **Migrations are additive**, so pointing a newer binary at an older database is fine. The reverse is not.
- **Ports**: 3000 TCP (HTTP + WebSocket) and 3001 UDP (voice). The UDP one is the one people forget — behind a proxy that only forwards TCP, everything works except voice.
- Health and capability check, useful as a one-line smoke test:

```bash
curl -s http://localhost:3000/info | head -c 400
```

  `capabilities` in that response is what clients branch on. If a feature you
  just added isn't there, you forgot `crates/hub/src/capabilities.rs`.
