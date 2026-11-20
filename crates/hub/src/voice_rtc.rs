//! WebRTC adapter for the voice relay (voice-transport-v3.md).
//!
//! Every voice peer runs on one UDP socket: str0m is sans-IO, so a single
//! task owns the socket and all peers and demultiplexes datagrams by ICE
//! credentials (`Rtc::accepts`). The hub is ICE-lite with host candidates on
//! its public address, so no STUN or TURN service is involved. Each peer has
//! one out-of-band negotiated data channel, unordered and without
//! retransmission, carrying the sealed voice packets the relay forwards.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::change::SdpOffer;
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};

use crate::state::{AppState, PendingVoiceBind};
use crate::voice_relay::{self, VoiceLink};

/// The data channel's stream id; both sides create it out of band, so no
/// in-band open handshake is needed before the first packet.
pub const VOICE_CHANNEL_ID: u16 = 0;

/// How the rest of the hub talks to the run loop that owns the socket.
pub struct RtcHandle {
    cmd: mpsc::UnboundedSender<Cmd>,
}

enum Cmd {
    Offer {
        bind: PendingVoiceBind,
        sdp: String,
        reply: oneshot::Sender<Result<String, String>>,
    },
    Send {
        peer: u64,
        packet: Vec<u8>,
    },
    Close {
        peer: u64,
    },
}

impl RtcHandle {
    /// Answers a client's offer for a bound member. The answer carries the
    /// hub's ICE-lite candidates; the peer is attached to the relay at once,
    /// and packets sent before the channel is up are simply dropped.
    pub async fn answer(&self, bind: PendingVoiceBind, sdp: String) -> Result<String, String> {
        let (reply, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::Offer { bind, sdp, reply })
            .map_err(|_| "voice WebRTC relay is not running".to_string())?;
        rx.await
            .map_err(|_| "voice WebRTC relay stopped".to_string())?
    }
}

struct RtcLink {
    peer: u64,
    cmd: mpsc::UnboundedSender<Cmd>,
}

impl VoiceLink for RtcLink {
    fn send(&self, packet: &[u8]) {
        let _ = self.cmd.send(Cmd::Send {
            peer: self.peer,
            packet: packet.to_vec(),
        });
    }

    fn close(&self, _reason: &str) {
        let _ = self.cmd.send(Cmd::Close { peer: self.peer });
    }
}

struct Peer {
    id: u64,
    rtc: Rtc,
    channel: ChannelId,
    bind: PendingVoiceBind,
    opened: Instant,
}

/// Binds the voice WebRTC socket on `port` (`0` = ephemeral, for tests),
/// advertising `public_ips` as host candidates (loopback when empty), and
/// starts the run loop. Returns the port actually bound.
pub async fn start(
    state: Arc<AppState>,
    port: u16,
    public_ips: Vec<IpAddr>,
) -> anyhow::Result<u16> {
    let socket = UdpSocket::bind(("0.0.0.0", port)).await?;
    let bound = socket.local_addr()?.port();
    let ips = if public_ips.is_empty() {
        vec![IpAddr::from([127, 0, 0, 1])]
    } else {
        public_ips
    };
    // ponytail: IPv4 only, one socket. Add a second socket on `[::]` when a
    // hub needs IPv6 voice.
    let candidates: Vec<SocketAddr> = ips
        .into_iter()
        .filter(|ip| ip.is_ipv4())
        .map(|ip| SocketAddr::new(ip, bound))
        .collect();

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let handle = RtcHandle {
        cmd: cmd_tx.clone(),
    };
    if state.voice_rtc.set(handle).is_err() {
        anyhow::bail!("voice WebRTC relay already started");
    }
    tokio::spawn(run(state, socket, candidates, cmd_rx, cmd_tx));
    Ok(bound)
}

async fn run(
    state: Arc<AppState>,
    socket: UdpSocket,
    candidates: Vec<SocketAddr>,
    mut cmd_rx: mpsc::UnboundedReceiver<Cmd>,
    cmd_tx: mpsc::UnboundedSender<Cmd>,
) {
    let mut peers: Vec<Peer> = Vec::new();
    let mut next_id: u64 = 1;
    let mut buf = vec![0u8; 2000];

    loop {
        let mut deadline = Instant::now() + Duration::from_millis(100);
        let mut i = 0;
        while i < peers.len() {
            match drive(&state, &socket, &mut peers[i]).await {
                Some(t) => {
                    deadline = deadline.min(t);
                    i += 1;
                }
                None => {
                    let peer = peers.swap_remove(i);
                    end_peer(&state, &peer, "closed").await;
                }
            }
        }

        let wait = deadline.saturating_duration_since(Instant::now());
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let Ok((n, source)) = received else { continue };
                let Ok(contents) = buf[..n].try_into() else { continue };
                // ponytail: the first candidate stands in for the local
                // address the datagram hit; exact with one public address.
                let Some(&destination) = candidates.first() else { continue };
                let input = Input::Receive(
                    Instant::now(),
                    Receive { proto: Protocol::Udp, source, destination, contents },
                );
                if let Some(peer) = peers.iter_mut().find(|p| p.rtc.accepts(&input)) {
                    if let Err(e) = peer.rtc.handle_input(input) {
                        tracing::debug!(peer = peer.id, "voice RTC input failed: {e}");
                        peer.rtc.disconnect();
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { return };
                match cmd {
                    Cmd::Offer { bind, sdp, reply } => {
                        let id = next_id;
                        next_id += 1;
                        match new_peer(id, bind, &sdp, &candidates) {
                            Ok((peer, answer)) => {
                                let link = Arc::new(RtcLink { peer: id, cmd: cmd_tx.clone() });
                                voice_relay::attach(&state, &peer.bind, link).await;
                                tracing::info!(
                                    member = short(&peer.bind.pubkey),
                                    channel = %peer.bind.channel_id,
                                    "voice RTC session opened"
                                );
                                peers.push(peer);
                                let _ = reply.send(Ok(answer));
                            }
                            Err(e) => {
                                let _ = reply.send(Err(e));
                            }
                        }
                    }
                    Cmd::Send { peer, packet } => {
                        if let Some(p) = peers.iter_mut().find(|p| p.id == peer) {
                            if let Some(mut ch) = p.rtc.channel(p.channel) {
                                let _ = ch.write(true, &packet);
                            }
                        }
                    }
                    Cmd::Close { peer } => {
                        if let Some(p) = peers.iter_mut().find(|p| p.id == peer) {
                            p.rtc.disconnect();
                        }
                    }
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }

        let now = Instant::now();
        for peer in &mut peers {
            let _ = peer.rtc.handle_input(Input::Timeout(now));
        }
    }
}

fn new_peer(
    id: u64,
    bind: PendingVoiceBind,
    sdp: &str,
    candidates: &[SocketAddr],
) -> Result<(Peer, String), String> {
    let offer = SdpOffer::from_sdp_string(sdp).map_err(|e| format!("invalid offer: {e}"))?;
    let mut rtc = Rtc::builder().set_ice_lite(true).build(Instant::now());
    for addr in candidates {
        let candidate = Candidate::host(*addr, "udp").map_err(|e| e.to_string())?;
        rtc.add_local_candidate(candidate);
    }
    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .map_err(|e| format!("offer refused: {e}"))?;
    let channel = rtc.direct_api().create_data_channel(ChannelConfig {
        label: "voice".to_string(),
        ordered: false,
        reliability: Reliability::MaxRetransmits { retransmits: 0 },
        negotiated: Some(VOICE_CHANNEL_ID),
        protocol: String::new(),
    });
    Ok((
        Peer {
            id,
            rtc,
            channel,
            bind,
            opened: Instant::now(),
        },
        answer.to_sdp_string(),
    ))
}

/// Polls a peer until it asks to be woken later. `None` once the peer is
/// gone and should be dropped.
async fn drive(state: &AppState, socket: &UdpSocket, peer: &mut Peer) -> Option<Instant> {
    loop {
        if !peer.rtc.is_alive() {
            return None;
        }
        match peer.rtc.poll_output() {
            Ok(Output::Timeout(t)) => return Some(t),
            Ok(Output::Transmit(t)) => {
                let _ = socket.send_to(&t.contents, t.destination).await;
            }
            Ok(Output::Event(Event::ChannelData(data))) if data.id == peer.channel => {
                voice_relay::relay(state, &peer.bind.channel_id, &peer.bind.pubkey, &data.data)
                    .await;
            }
            Ok(Output::Event(Event::IceConnectionStateChange(
                IceConnectionState::Disconnected,
            ))) => {
                peer.rtc.disconnect();
            }
            Ok(Output::Event(_)) => {}
            Err(e) => {
                tracing::debug!(peer = peer.id, "voice RTC output failed: {e}");
                peer.rtc.disconnect();
            }
        }
    }
}

async fn end_peer(state: &AppState, peer: &Peer, reason: &str) {
    tracing::info!(
        member = short(&peer.bind.pubkey),
        channel = %peer.bind.channel_id,
        secs = peer.opened.elapsed().as_secs(),
        reason,
        "voice RTC session closed"
    );
    voice_relay::detach(state, &peer.bind).await;
}

fn short(pubkey: &str) -> &str {
    &pubkey[..pubkey.len().min(12)]
}
