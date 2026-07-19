//! Per-channel roster + author game state, maintained from the
//! `hello`/`bye`/`ping` message convention (bot-capability-layer.md §10).
//!
//! Deliberately synchronous (`std::sync::Mutex`, not `tokio::sync::Mutex`):
//! every operation here is a quick in-memory map mutation with no `.await`
//! inside the critical section, so a blocking lock is simpler and cheaper
//! than an async one, and it lets tests drive the roster with plain
//! `#[test]` instead of a runtime.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default unheard-from window before a roster entry is evicted (~30s,
/// bot-capability-layer.md §10 "Default fix").
pub const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);

/// What the lobby knows about one joined player. Game-specific extras
/// (ready flags, team slots) are the wire convention's `roster` message
/// concern, not this struct's -- a game-bot builds that JSON itself from
/// `roster_pubkeys()` plus its own state `S`.
#[derive(Clone, Debug)]
pub struct PlayerMeta {
    pub display_name: Option<String>,
    pub last_seen: Instant,
}

struct Channel<S> {
    roster: HashMap<String, PlayerMeta>,
    state: S,
}

/// Registry of active game/lobby sessions keyed by channel id. One `Lobby`
/// is shared across every channel a game-bot process handles.
pub struct Lobby<S> {
    timeout: Duration,
    channels: Mutex<HashMap<String, Channel<S>>>,
}

impl<S> Lobby<S> {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            channels: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_default_timeout() -> Self {
        Self::new(DEFAULT_HEARTBEAT_TIMEOUT)
    }

    /// Starts (or replaces) a channel's session with an empty roster.
    pub fn start(&self, channel_id: impl Into<String>, state: S) {
        self.channels.lock().unwrap().insert(
            channel_id.into(),
            Channel {
                roster: HashMap::new(),
                state,
            },
        );
    }

    /// Ends a channel's session, returning its state if one was active.
    pub fn end(&self, channel_id: &str) -> Option<S> {
        self.channels
            .lock()
            .unwrap()
            .remove(channel_id)
            .map(|c| c.state)
    }

    /// `hello`: joins/refreshes `pubkey` (reconnects just update the same
    /// entry -- the relay's "last session per pubkey wins" semantics need no
    /// extra dedup here since the roster is already keyed by pubkey), then
    /// evicts anyone stale. Returns the live roster, or `None` if this
    /// channel has no active session.
    pub fn hello(
        &self,
        channel_id: &str,
        pubkey: &str,
        display_name: Option<String>,
        now: Instant,
    ) -> Option<Vec<String>> {
        let mut channels = self.channels.lock().unwrap();
        let c = channels.get_mut(channel_id)?;
        c.roster.insert(
            pubkey.to_string(),
            PlayerMeta {
                display_name,
                last_seen: now,
            },
        );
        evict(&mut c.roster, self.timeout, now);
        Some(roster_keys(&c.roster))
    }

    /// `bye`: removes `pubkey` immediately (best-effort client signal).
    pub fn bye(&self, channel_id: &str, pubkey: &str, now: Instant) -> Option<Vec<String>> {
        let mut channels = self.channels.lock().unwrap();
        let c = channels.get_mut(channel_id)?;
        c.roster.remove(pubkey);
        evict(&mut c.roster, self.timeout, now);
        Some(roster_keys(&c.roster))
    }

    /// `ping`: refreshes liveness for an already-joined `pubkey`.
    pub fn heartbeat(&self, channel_id: &str, pubkey: &str, now: Instant) -> Option<Vec<String>> {
        let mut channels = self.channels.lock().unwrap();
        let c = channels.get_mut(channel_id)?;
        if let Some(meta) = c.roster.get_mut(pubkey) {
            meta.last_seen = now;
        }
        evict(&mut c.roster, self.timeout, now);
        Some(roster_keys(&c.roster))
    }

    /// Evicts anyone unheard-from for longer than the timeout without
    /// waiting for the next convention message. Cheap enough to call on
    /// every inbound frame (ttt-bot does; ponytail: fine at this scale, add
    /// a periodic sweep task if a lobby can go silent for a while).
    pub fn evict_stale(&self, channel_id: &str, now: Instant) -> Option<Vec<String>> {
        let mut channels = self.channels.lock().unwrap();
        let c = channels.get_mut(channel_id)?;
        evict(&mut c.roster, self.timeout, now);
        Some(roster_keys(&c.roster))
    }

    /// Current live roster pubkeys, without evicting.
    pub fn roster(&self, channel_id: &str) -> Option<Vec<String>> {
        let channels = self.channels.lock().unwrap();
        channels.get(channel_id).map(|c| roster_keys(&c.roster))
    }

    /// Mutable access to the author's game state `S` for a channel, e.g. to
    /// validate and apply a move. `None` if no session is active.
    pub fn with_state<R>(&self, channel_id: &str, f: impl FnOnce(&mut S) -> R) -> Option<R> {
        let mut channels = self.channels.lock().unwrap();
        channels.get_mut(channel_id).map(|c| f(&mut c.state))
    }
}

fn evict(roster: &mut HashMap<String, PlayerMeta>, timeout: Duration, now: Instant) {
    roster.retain(|_, meta| now.saturating_duration_since(meta.last_seen) < timeout);
}

fn roster_keys(roster: &HashMap<String, PlayerMeta>) -> Vec<String> {
    let mut keys: Vec<String> = roster.keys().cloned().collect();
    keys.sort();
    keys
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(30);

    #[test]
    fn hello_grows_roster_and_targets_both() {
        let lobby: Lobby<()> = Lobby::new(TIMEOUT);
        let t0 = Instant::now();
        lobby.start("ch1", ());

        let after_p1 = lobby.hello("ch1", "p1", None, t0).unwrap();
        assert_eq!(after_p1, vec!["p1"]);

        let after_p2 = lobby.hello("ch1", "p2", None, t0).unwrap();
        assert_eq!(after_p2, vec!["p1", "p2"]);
    }

    #[test]
    fn bye_shrinks_roster() {
        let lobby: Lobby<()> = Lobby::new(TIMEOUT);
        let t0 = Instant::now();
        lobby.start("ch1", ());
        lobby.hello("ch1", "p1", None, t0);
        lobby.hello("ch1", "p2", None, t0);

        let after_bye = lobby.bye("ch1", "p1", t0).unwrap();
        assert_eq!(after_bye, vec!["p2"]);
    }

    #[test]
    fn heartbeat_keeps_a_player_alive_past_timeout() {
        let lobby: Lobby<()> = Lobby::new(TIMEOUT);
        let t0 = Instant::now();
        lobby.start("ch1", ());
        lobby.hello("ch1", "p1", None, t0);
        lobby.hello("ch1", "p2", None, t0);

        // p1 pings again well before the timeout; p2 never does.
        let t_ping = t0 + Duration::from_secs(20);
        lobby.heartbeat("ch1", "p1", t_ping);

        // Past the 30s window from t0 for p2, but only 11s since p1's ping.
        let t_check = t0 + Duration::from_secs(31);
        let roster = lobby.evict_stale("ch1", t_check).unwrap();
        assert_eq!(roster, vec!["p1"]);
    }

    #[test]
    fn timeout_evicts_everyone_unheard_from() {
        let lobby: Lobby<()> = Lobby::new(TIMEOUT);
        let t0 = Instant::now();
        lobby.start("ch1", ());
        lobby.hello("ch1", "p1", None, t0);
        lobby.hello("ch1", "p2", None, t0);

        let t_check = t0 + Duration::from_secs(31);
        let roster = lobby.evict_stale("ch1", t_check).unwrap();
        assert!(roster.is_empty());
    }

    #[test]
    fn reconnect_dedups_by_pubkey() {
        let lobby: Lobby<()> = Lobby::new(TIMEOUT);
        let t0 = Instant::now();
        lobby.start("ch1", ());
        lobby.hello("ch1", "p1", None, t0);
        // Same pubkey reconnecting (a fresh mini-app session, new hello)
        // must not duplicate the roster entry -- mirrors the relay's
        // "last session per pubkey wins" semantics.
        let roster = lobby
            .hello(
                "ch1",
                "p1",
                Some("Alice".to_string()),
                t0 + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(roster, vec!["p1"]);
    }

    #[test]
    fn unknown_channel_is_none() {
        let lobby: Lobby<()> = Lobby::new(TIMEOUT);
        assert!(lobby.hello("missing", "p1", None, Instant::now()).is_none());
        assert!(lobby.roster("missing").is_none());
    }

    #[test]
    fn with_state_mutates_and_end_returns_it() {
        let lobby: Lobby<u32> = Lobby::new(TIMEOUT);
        lobby.start("ch1", 0u32);
        lobby.with_state("ch1", |n| *n += 1);
        lobby.with_state("ch1", |n| *n += 1);
        assert_eq!(lobby.end("ch1"), Some(2));
        // Ended -- gone now.
        assert!(lobby.roster("ch1").is_none());
    }
}
