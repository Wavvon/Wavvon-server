//! `bot-kit`: the reusable multiplayer-lobby module for game-bots
//! (bot-capability-layer.md §10, "Phase 3 — multiplayer lobby helper").
//!
//! The hub relays opaque `mini_app_message` JSON between a bot and every
//! client that has joined its mini-app modal in a channel
//! (`hub/src/routes/ws/handlers/mini_app.rs`); it knows nothing about
//! rosters, games, or turns (bot-capability-layer.md decision 4, "the hub
//! stays dumb about games"). Every game-bot re-implements the same three
//! things on top of that relay: a roster keyed by channel, liveness
//! tracking from a small `hello`/`bye`/`ping` message convention, and a
//! per-viewer send loop. This crate is that generalization, lifted out of
//! `ttt-bot`'s original `Mutex<HashMap<channel_id, GameSession>>`.
//!
//! A game-bot depends on this crate, writes its own game state `S` and move
//! validator, and gets roster maintenance + fan-out for free.

pub mod lobby;
pub mod relay;

pub use lobby::{Lobby, PlayerMeta, DEFAULT_HEARTBEAT_TIMEOUT};
pub use relay::{broadcast, send_to, WsSink};
