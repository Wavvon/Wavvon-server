//! Outgoing webhooks: the hub POSTs `hub_event` envelopes to admin-registered
//! external HTTPS URLs as hub events occur.
//!
//! Not to be confused with `routes::webhooks` (incoming webhooks — an
//! external service POSTs a message *into* a channel). See
//! `docs/docs/outgoing-webhooks.md` for the full design.
//!
//! - `models` — DB row shapes and the 9 admin route DTOs.
//! - `routes` — the 9 `/admin/outgoing-webhooks` handlers.
//! - `delivery` — single-attempt HMAC signing + HTTP POST + delivery log.
//! - `worker` — subscription lookup, rate cap, retry scheduling, auto-disable.

pub mod delivery;
pub mod models;
pub mod routes;
pub mod worker;
