# ttt-bot

Phase 1 demo bot for the game modal (`bot-capability-layer.md` §7):
`/ttt @user` posts a launch card, both players click Play, and moves flow
through the hub's WS relay while this process owns the board.

## Run against a dev hub

```bash
cargo run -p ttt-bot
```

It prints its pubkey and waits. As a hub admin (owner token), invite it and
grant the game-modal capability:

```bash
curl -X POST $HUB_URL/bots -H "Authorization: Bearer $OWNER_TOKEN" \
  -d '{"pubkey": "<printed pubkey>"}'
curl -X PUT $HUB_URL/admin/bots/<pubkey>/capabilities \
  -H "Authorization: Bearer $OWNER_TOKEN" \
  -d '{"capabilities": ["can_use_interactive_ui"]}'
```

The bot then auto-authenticates and is ready — type `/ttt @someone` in a
channel it can post to.

Env vars: `HUB_URL` (default `http://localhost:3000`), `BOT_BIND_ADDR`
(default `127.0.0.1:8089`), `BOT_PUBLIC_URL` (default matches bind addr),
`IDENTITY_PATH` (default `~/.wavvon/ttt-bot-identity.json`).
