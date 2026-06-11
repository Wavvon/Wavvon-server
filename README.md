# Voxply Server

[![Build check](https://github.com/Voxply/Voxply-server/actions/workflows/build.yml/badge.svg)](https://github.com/Voxply/Voxply-server/actions/workflows/build.yml)
[![Release](https://github.com/Voxply/Voxply-server/actions/workflows/release.yml/badge.svg)](https://github.com/Voxply/Voxply-server/actions/workflows/release.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

**Run your community on your own terms.** Voxply is an open-source,
federated voice + text chat platform with no central servers and no
accounts. A **hub** is your community's home — a single self-hosted
binary (Rust + SQLite) that serves text channels, live voice, screen
share, end-to-end-encrypted DMs, forums, bots, and moderation. Identity
is an Ed25519 keypair owned by the user, not a login owned by a
company, and hubs federate directly with each other — so your community
stays connected to the wider network while you keep full control of
your data.

This repository is the entire backend: the hub server plus the optional
fleet tooling (farm controller, server agent, seed registry) and the
canonical identity crate.

![A community served by a single hub binary - unified channels, voice, presence](https://raw.githubusercontent.com/Voxply/Voxply/main/assets/screenshot-channel.png)

## Highlights

- **You own everything.** All community data lives in one SQLite file
  on your machine. Back it up with two files (`hub.db` +
  `hub_identity.json`). No telemetry, no phoning home.
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
git clone https://github.com/Voxply/Voxply-server
cd Voxply-server
docker compose up -d
```

Or without cloning anything:

```bash
docker run -d --name voxply-hub \
  -p 3000:3000 -p 3001:3001/udp \
  -v voxply-hub-data:/data \
  ghcr.io/voxply/hub:latest
```

Your hub is now serving HTTP on port 3000 and voice UDP on port 3001.
Open a [Voxply client](https://github.com/Voxply/Voxply-desktop), click
**Add hub**, and enter `http://your-server:3000`.

### Prebuilt binary (Linux, static musl — no dependencies)

```bash
curl -LO https://github.com/Voxply/Voxply-server/releases/latest/download/voxply-hub-linux-x86_64
chmod +x voxply-hub-linux-x86_64
./voxply-hub-linux-x86_64
```

### From source

```bash
cargo run --release -p voxply-hub
```

### Make yourself the owner

A fresh hub has no owner. Set yours before opening the hub to users —
your public key is shown in the client under **Settings → Identity**:

```bash
# docker-compose.yml / environment, or shell env:
VOXPLY_OWNER_PUBKEY=<your-64-char-ed25519-public-key>

# or after first boot, via the CLI:
voxply-hub admin users set-owner <pubkey>
```

For production setups (systemd, TLS, reverse proxy, backups, upgrades,
hardening) see the
[hosting guide](https://github.com/Voxply/Voxply/blob/main/docs/hosting.md)
and the
[hub operator guide](https://github.com/Voxply/Voxply/blob/main/docs/hub-operator-guide.md).

## Configuration

Defaults work out of the box. Override via `hub.toml` (copy
[`hub.toml.example`](hub.toml.example)) or `VOXPLY_*` environment
variables — env vars win.

| Setting | Env var | Default | Purpose |
|---|---|---|---|
| `http_port` | `VOXPLY_HTTP_PORT` | `3000` | HTTP + WebSocket API |
| `voice_udp_port` | `VOXPLY_VOICE_UDP_PORT` | `3001` | Voice relay (UDP) |
| `tls_cert` / `tls_key` | `VOXPLY_TLS_CERT` / `VOXPLY_TLS_KEY` | — | Enable HTTPS (set both) |
| `owner_pubkey` | `VOXPLY_OWNER_PUBKEY` | — | Hub owner identity |
| `discovery_url` | `VOXPLY_DISCOVERY_URL` | `https://discovery.voxply.io` | Hub directory base URL |
| `template_url` / `bootstrap_token` | `VOXPLY_TEMPLATE_URL` / `VOXPLY_BOOTSTRAP_TOKEN` | — | First-boot channel/role template |
| `log_format` | `VOXPLY_LOG_FORMAT` | `text` | `text` or `json` |
| `otlp_endpoint` | `VOXPLY_OTLP_ENDPOINT` | — | OpenTelemetry traces |
| `search_backend` | `VOXPLY_SEARCH_BACKEND` | `tantivy` | `tantivy` or `none` |

All hub state lives in the working directory (`/data` in the Docker
image): `hub.db` (SQLite) and `hub_identity.json` (the hub's keypair —
back it up).

## What's in this workspace

| Crate | What it is |
|---|---|
| `hub/` | The community server — HTTP/WS API, voice relay, federation, workers |
| `identity/` | Ed25519 keypairs, BIP39 recovery, PoW helpers — the canonical wire-format authority |
| `farm/` | Optional control plane for running a fleet of hubs |
| `server/` | Server agent that runs hubs on compute nodes for a farm |
| `seed/` | Self-hostable cross-farm discovery registry |
| `voxply-store/` + `voxply-store-sqlite/` | Trait-based storage layer + the SQLite backend |

Multi-hub deployments use `docker-compose.farm.yml` — see
[farm-model.md](https://github.com/Voxply/Voxply/blob/main/docs/farm-model.md).

## Building & testing

```bash
cargo check --workspace               # fast type check
cargo test --workspace                # integration tests
cargo build --release -p voxply-hub   # release binary
```

## Write your own client

The hub speaks plain HTTP + WebSocket — no SDK required:

1. Generate an Ed25519 keypair; your hex-encoded public key is your identity.
2. `POST /auth/challenge`, sign the challenge with your private key,
   `POST /auth/verify` → Bearer session token.
3. REST API with `Authorization: Bearer <token>`; real-time events over
   `GET /ws?token=<token>`.

The full contract is documented in
[`openapi.yaml`](https://github.com/Voxply/Voxply/blob/main/openapi.yaml)
(every REST endpoint) and
[`ws-protocol.md`](https://github.com/Voxply/Voxply/blob/main/docs/ws-protocol.md)
(every WebSocket message), with identity rules in
[`identity.md`](https://github.com/Voxply/Voxply/blob/main/docs/identity.md).

## The Voxply project

| Repo | What it is |
|---|---|
| **Voxply-server** *(this repo)* | Hub server, farm tooling, identity crate (Rust) |
| [Voxply-desktop](https://github.com/Voxply/Voxply-desktop) | Desktop client — Windows / macOS / Linux (Tauri 2 + React) |
| [Voxply-web](https://github.com/Voxply/Voxply-web) | Browser client (text + DMs) |
| [Voxply-android](https://github.com/Voxply/Voxply-android) | Android client (Tauri 2) |
| [Voxply-discovery](https://github.com/Voxply/Voxply-discovery) | Optional public hub directory |
| [Voxply](https://github.com/Voxply/Voxply) | Architecture wiki, roadmap, API spec |

Start with the
[architecture overview](https://github.com/Voxply/Voxply/blob/main/docs/architecture.md)
and the [roadmap](https://github.com/Voxply/Voxply/blob/main/ROADMAP.md).

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
branching model and
[decisions.md](https://github.com/Voxply/Voxply/blob/main/docs/decisions.md)
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
