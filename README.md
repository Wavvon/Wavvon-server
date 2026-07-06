# Wavvon Server

[![Build check](https://github.com/Wavvon/Wavvon-server/actions/workflows/build.yml/badge.svg)](https://github.com/Wavvon/Wavvon-server/actions/workflows/build.yml)
[![Release](https://github.com/Wavvon/Wavvon-server/actions/workflows/release.yml/badge.svg)](https://github.com/Wavvon/Wavvon-server/actions/workflows/release.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

**Run your community on your own terms.** Wavvon is an open-source,
federated voice + text chat platform with no central servers and no
accounts. A **hub** is your community's home — a single self-hosted
binary (Rust, backed by PostgreSQL) that serves text channels, live
voice, screen share, end-to-end-encrypted DMs, forums, bots, and
moderation. Identity
is an Ed25519 keypair owned by the user, not a login owned by a
company, and hubs federate directly with each other — so your community
stays connected to the wider network while you keep full control of
your data.

This repository is the entire backend: the hub server plus the optional
fleet tooling (farm controller, server agent, seed registry) and the
canonical identity crate.

![A community served by a single hub binary - unified channels, voice, presence](https://raw.githubusercontent.com/Wavvon/Wavvon-docs/main/assets/screenshot-channel.png)

## Highlights

- **You own everything.** All community data lives in your own
  PostgreSQL database next to the hub. One-command backup and restore
  (`wavvon-hub backup` / `wavvon-hub restore`) plus the hub keypair in
  `hub_identity.json`. No telemetry, no phoning home.
- **No accounts.** Users are Ed25519 keypairs with BIP39 recovery
  phrases. Multi-device via QR pairing and master-signed subkey
  certificates. Nothing to register, nothing to leak.
- **Unified channels** — every channel is text + voice. Markdown,
  attachments, reactions, replies/threads, pins, polls, events, custom
  emojis, full-text search (Tantivy), and forum-style channels.
- **Voice & video** — Opus-over-UDP relay (codec handled client-side),
  WebRTC video and multi-sharer screen share with the hub acting as
  signaler.
- **E2E-encrypted DMs** — 1:1 and group DMs encrypted client-side
  (X25519 derived from Ed25519, AES-256-GCM, group sender keys). The
  hub relays ciphertext only, with a federated outbox for cross-hub
  delivery.
- **Federation & alliances** — hubs authenticate to each other with
  signatures; alliances let multiple hubs share channels, mentions, and
  reactions. Opt-in federated ban lists.
- **Anti-abuse without a central authority** — proof-of-work security
  lobby, bot challenge, approval queue, onboarding questionnaire,
  reputation certifications that carry across hubs.
- **Moderation** — custom roles and permissions, ban / mute / timeout /
  kick, channel bans, content reporting queue, auto-mod webhook.
- **Bots** — invite by public key, slash commands, webhook delivery.
- **Operable** — `GET /health`, Prometheus `GET /metrics`, structured
  JSON logs, optional OTLP traces, backup/restore CLI, hub key
  rotation, additive-only migrations.

## Run a hub in 2 minutes

### Docker (recommended)

```bash
git clone https://github.com/Wavvon/Wavvon-server
cd Wavvon-server
docker compose up -d
```

The bundled `docker-compose.yml` starts the hub plus a PostgreSQL
sidecar. Prefer a guided install? The interactive wizard generates a
tailored compose file and `.env` for you:

```bash
wavvon-hub setup
```

Your hub is now serving HTTP on port 3000 and voice UDP on port 3001.
Open a [Wavvon client](https://github.com/Wavvon/Wavvon-clients), click
**Add hub**, and enter `http://your-server:3000`.

### Prebuilt binary (Linux, static musl — no dependencies)

Download the latest `wavvon-hub-linux-x86_64` from the
[releases page](https://github.com/Wavvon/Wavvon-server/releases),
then point it at a PostgreSQL database:

```bash
chmod +x wavvon-hub-linux-x86_64
WAVVON_DATABASE_URL=postgres://user:pass@localhost:5432/wavvon ./wavvon-hub-linux-x86_64
```

### From source

```bash
cargo run --release -p wavvon-hub
```

Without `WAVVON_DATABASE_URL` the hub connects to
`postgres://postgres:postgres@localhost:5432/wavvon`.

### Make yourself the owner

A fresh hub has no owner. Set yours before opening the hub to users —
your public key is shown in the client under **Settings → Identity**:

```bash
# docker-compose.yml / environment, or shell env:
WAVVON_OWNER_PUBKEY=<your-64-char-ed25519-public-key>

# or after first boot, via the CLI:
wavvon-hub admin users set-owner <pubkey>
```

For production setups (systemd, TLS, reverse proxy, backups, upgrades,
hardening) see the
[hosting guide](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/hosting.md)
and the
[hub operator guide](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/hub-operator-guide.md).

## Configuration

Defaults work out of the box. Override via `hub.toml` (copy
[`hub.toml.example`](hub.toml.example)) or `WAVVON_*` environment
variables — env vars win.

| Setting | Env var | Default | Purpose |
|---|---|---|---|
| `database_url` | `WAVVON_DATABASE_URL` | `postgres://postgres:postgres@localhost:5432/wavvon` | PostgreSQL connection |
| `http_port` | `WAVVON_HTTP_PORT` | `3000` | HTTP + WebSocket API |
| `voice_udp_port` | `WAVVON_VOICE_UDP_PORT` | `3001` | Voice relay (UDP) |
| `tls_cert` / `tls_key` | `WAVVON_TLS_CERT` / `WAVVON_TLS_KEY` | — | Enable HTTPS (set both) |
| `owner_pubkey` | `WAVVON_OWNER_PUBKEY` | — | Hub owner identity |
| `discovery_url` | `WAVVON_DISCOVERY_URL` | `https://discovery.wavvon.io` | Hub directory base URL |
| `template_url` / `bootstrap_token` | `WAVVON_TEMPLATE_URL` / `WAVVON_BOOTSTRAP_TOKEN` | — | First-boot channel/role template |
| `log_format` | `WAVVON_LOG_FORMAT` | `text` | `text` or `json` |
| `otlp_endpoint` | `WAVVON_OTLP_ENDPOINT` | — | OpenTelemetry traces |
| `search_backend` | `WAVVON_SEARCH_BACKEND` | `tantivy` | `tantivy` or `none` |

Community data lives in PostgreSQL (`WAVVON_DATABASE_URL`); the hub's
own keypair lives in `hub_identity.json` in the working directory
(`/data` in the Docker image) — back up both, e.g. with
`wavvon-hub backup <file>`.

## What's in this workspace

| Crate | What it is |
|---|---|
| `hub/` | The community server — HTTP/WS API, voice relay, federation, workers |
| `identity/` | Ed25519 keypairs, BIP39 recovery, PoW helpers — the canonical wire-format authority |
| `farm/` | Optional control plane for running a fleet of hubs |
| `agent/` | Fleet worker that runs hubs on compute nodes for a farm |
| `seed/` | Self-hostable cross-farm discovery registry |
| `store/` | Trait-based storage layer with the PostgreSQL backend |
| `demo-seed/` | Populates a running hub with demo content |
| `discord-import/` | Import an existing Discord community into a hub |

Multi-hub deployments use `docker-compose.farm.yml` — see
[farm-model.md](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/farm-model.md).

## Building & testing

```bash
cargo check --workspace               # fast type check
cargo test --workspace                # integration tests
cargo build --release -p wavvon-hub   # release binary
```

## Write your own client

The hub speaks plain HTTP + WebSocket — no SDK required:

1. Generate an Ed25519 keypair; your hex-encoded public key is your identity.
2. `POST /auth/challenge`, sign the challenge with your private key,
   `POST /auth/verify` → Bearer session token.
3. REST API with `Authorization: Bearer <token>`; real-time events over
   `GET /ws?token=<token>`.

The full contract is documented in
[`openapi.yaml`](https://github.com/Wavvon/Wavvon-docs/blob/main/openapi.yaml)
(every REST endpoint) and
[`ws-protocol.md`](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/ws-protocol.md)
(every WebSocket message), with identity rules in
[`identity.md`](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/identity.md).

## The Wavvon project

| Repo | What it is |
|---|---|
| **Wavvon-server** *(this repo)* | Hub server, farm tooling, identity crate (Rust) |
| [Wavvon-clients](https://github.com/Wavvon/Wavvon-clients) | All clients (desktop / web / Android) + shared packages |
| [Wavvon-discovery](https://github.com/Wavvon/Wavvon-discovery) | Optional public hub directory |
| [Wavvon-docs](https://github.com/Wavvon/Wavvon-docs) | Architecture wiki, roadmap, API spec |

Start with the
[architecture overview](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/architecture.md)
and the [roadmap](https://github.com/Wavvon/Wavvon-docs/blob/main/ROADMAP.md).

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
branching model and
[decisions.md](https://github.com/Wavvon/Wavvon-docs/blob/main/docs/decisions.md)
for design rationale before proposing big changes.

## License

[GNU Affero General Public License v3.0](LICENSE). Network use of a
modified version requires offering the corresponding source to users —
deliberately chosen for a federated platform.

## Built with AI assistance

This project was built with substantial help from
[Claude](https://claude.ai) (Anthropic's AI assistant). The product
owner directs architecture, features, and tradeoffs; Claude drafts
most of the code, tests, and documentation, which is then reviewed,
adjusted, and accepted.

Calling this out for transparency — it's not a fully hand-written
codebase, and pretending otherwise wouldn't be honest.
