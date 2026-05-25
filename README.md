# Voxply-server

Hub server for the [Voxply](https://github.com/YOUR_ORG/Voxply) platform.
Handles authentication, channels, messaging, federation, voice relay,
alliances, bots, security lobby, and all hub-side logic.

Part of the Voxply project — see the
[docs repo](https://github.com/YOUR_ORG/Voxply) for architecture,
API spec, and roadmap.

## Technologies

- **Rust** — memory-safe, async, zero-cost abstractions
- **Axum 0.8** — HTTP + WebSocket server framework
- **SQLite** via sqlx — embedded database, no separate process
- **tokio** — async runtime
- **Ed25519** (voxply-identity) — keypair-based identity, no accounts
- **SHA-256 PoW** — proof-of-work security levels
- **UDP** — raw voice packet relay (codec handled client-side)
- **reqwest** — outbound HTTP for federation

## Quick start

```bash
cargo run -p voxply-hub
# HTTP on 0.0.0.0:3000  |  Voice UDP on 0.0.0.0:3001
# VOXPLY_HTTP_PORT / VOXPLY_VOICE_UDP_PORT to override
# VOXPLY_TLS_CERT + VOXPLY_TLS_KEY for HTTPS
```

For production deployment (systemd, TLS, backups, upgrades) see
[`docs/hosting.md`](docs/hosting.md).

## Building & testing

```bash
cargo check --workspace          # fast type check
cargo test --workspace           # run all integration tests
cargo build --release -p voxply-hub   # release binary
```

Or using Docker:

```bash
docker compose up --build        # see voxply-hub/docker-compose.yml
```

## API

The complete API reference is in [`openapi.yaml`](openapi.yaml) —
every endpoint, request/response shape, auth flow, and PoW algorithm
documented in OpenAPI 3.0. Implement a client in any language against
this spec.

## How to create your client

The hub speaks a plain HTTP + WebSocket API — no SDK needed. Here is
the minimum path to a working client in any language:

### 1 — Generate a keypair

Create an **Ed25519** keypair and encode the 32-byte public key as a
lowercase hex string. Optionally derive a **BIP39** 24-word mnemonic
from the private-key seed for backup.

### 2 — Solve proof-of-work

Call `GET /auth/pow-challenge` to receive a challenge string and a
`difficulty` (integer, number of leading zero bits required).

Iterate a `nonce` (unsigned 64-bit little-endian) until:

```
SHA256( UTF8(public_key_hex) || LE64(nonce) )
```

has at least `difficulty` leading zero bits. Submit the solution to
`POST /auth/register` (first visit) or `POST /auth/pow-verify`.

### 3 — Sign the auth challenge

After PoW, call `POST /auth/challenge` to receive a short challenge
string. Sign the **raw UTF-8 bytes** of that string with your Ed25519
private key. Encode the resulting 64-byte signature as a lowercase hex
string and submit it to `POST /auth/verify`. The response contains a
session token (Bearer).

### 4 — Use the REST API

Include `Authorization: Bearer <token>` on every request. All
request/response bodies are JSON. See `openapi.yaml` for the full
schema of every endpoint.

### 5 — Connect over WebSocket

Open `ws://<host>/ws?token=<token>`. The hub streams events as
newline-delimited JSON objects with a `type` field
(`message_created`, `member_joined`, `voice_state_update`, …).
Send `{"type":"heartbeat"}` every 30 s to keep the connection alive.

### 6 — Voice (optional)

Open a UDP socket and send Opus packets prefixed with a 4-byte
little-endian `channel_id` to the voice port (default 3001). The hub
relays packets to all other participants in the same voice channel.

## Built with AI assistance

This project was built with substantial help from
[Claude](https://claude.ai) (Anthropic's AI assistant). The product
owner directs architecture, features, and tradeoffs; Claude drafts
most of the code, tests, and documentation, which is then reviewed,
adjusted, and accepted.

Calling this out for transparency — it's not a fully hand-written
codebase, and pretending otherwise wouldn't be honest.

## License

[GNU Affero General Public License v3.0](LICENSE). Network use of a
modified version requires offering the corresponding source to users —
important for a federated platform.
