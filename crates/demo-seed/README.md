# demo-seed

Populates a **running** Wavvon hub with realistic demo content — channels, users,
and a believable community conversation — so you can take README screenshots or
bootstrap a public demo hub.

## Prerequisites

- A Wavvon hub running with a **fresh (empty) database**.
  The seeder checks for existing channels on startup and exits immediately if any
  are found, so it cannot corrupt a hub that already has content.
- Rust toolchain (the tool lives in the workspace, no separate install needed).

## Usage

```sh
# From the workspace root (C:/repo/Wavvon/hub):
cargo run -p demo-seed
```

Default target: `http://localhost:3000`

### Environment variables

| Variable    | Default                   | Description                                                 |
|-------------|---------------------------|-------------------------------------------------------------|
| `HUB_URL`   | `http://localhost:3000`   | Base URL of the hub to seed                                 |
| `CREDS_OUT` | `demo-credentials.json`   | Path where identity credentials are written (gitignored)    |

```sh
HUB_URL=https://demo.wavvon.app cargo run -p demo-seed
```

## What gets created

| Thing                   | Detail                                                              |
|-------------------------|---------------------------------------------------------------------|
| **Hub branding**        | Name: "Wavvon HQ", description: "The official Wavvon community hub"|
| **Channels**            | Categories: Community, Gaming, Dev, Voice                          |
|                         | Channels: #welcome (pinned msg), #general, #game-night, #dev-talk, Lounge |
| **Identities**          | 8 total — Nova (admin/owner) + 7 members                           |
| **Messages**            | ~30 realistic messages across #general, #game-night, #dev-talk     |
| **Poll**                | "What time Friday works best for game night?" in #game-night       |
| **Pinned message**      | Welcome message in #welcome                                        |
| **Reactions**           | Emoji reactions on several messages                                |

## Credentials output

The seeder writes `demo-credentials.json` (path controlled by `CREDS_OUT`) with:
- `hub_url` — the hub that was seeded
- `admin` — Nova's public key, session token, and 24-word recovery phrase
- `members[]` — same for each of the 7 member identities

**This file contains live session tokens. Do not commit it.** It is gitignored
in the workspace root `.gitignore`.

Recovery phrases are 24-word BIP39 mnemonics. You can load any identity in the
Wavvon desktop client using "Restore from recovery phrase".

## Admin / owner bootstrap

The **first** identity to complete `POST /auth/verify` on a hub with zero users
is automatically assigned the `builtin-owner` role (see
`hub/src/auth/handlers.rs::assign_initial_roles`). That role carries the `admin`
permission, which unlocks:

- `PATCH /hub` — rename / describe the hub
- `POST /channels` — create channels (any authenticated user can do this by default)
- `POST /channels/:id/pins/:msg_id` — pin messages (requires `manage_messages`)
- `PATCH /admin/settings/*` — change lobby, PoW, moderation settings

Nova is that first identity, so she is the hub owner.

## Lobby / PoW defaults

On a default-config hub:
- `min_security_level = 0` — no PoW required
- `lobby_enabled = true` — lobby is on, but with level 0 required every user
  immediately gets `scope = "member"` on their first login

No PoW computation is needed. If you have bumped `min_security_level` above 0,
lower it back to 0 before running the seeder (or the seeder will exit with a clear
error explaining the situation).

## Re-seeding / idempotency

The seeder is designed for **fresh hubs only**. On a non-fresh hub it detects
existing channels and exits with an error message rather than duplicating content.
To re-seed: wipe the database and restart the hub, then run demo-seed again.
