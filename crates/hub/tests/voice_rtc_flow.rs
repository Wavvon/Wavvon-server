//! Integration coverage for the WebRTC voice relay (voice-transport-v3.md):
//! two members join voice over the main WS, bind a WebRTC peer each with
//! `voice_rtc_offer`, and a packet sent on one data channel arrives on the
//! other with the relay's routing prefix — real str0m peers over real UDP.
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio_tungstenite::tungstenite::Message as TsMessage;
use wavvon_hub::auth::models::{ChallengeResponse, VerifyResponse};
use wavvon_hub::routes::chat_models::ChannelResponse;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;

use crate::common;

async fn start_hub() -> (String, Arc<AppState>, common::TestDbGuard) {
    let (db, guard) = self::common::create_test_db().await;
    let state = Arc::new(AppState {
        hub_name: "voice-rtc-test".to_string(),
        ..common::base_state(db)
    });
    wavvon_hub::voice_rtc::start(state.clone(), 0, vec![])
        .await
        .expect("voice WebRTC relay should start");

    let app = server::create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://127.0.0.1:{http_port}"), state, guard)
}

async fn authenticate_http(base: &str, identity: &Identity) -> String {
    let client = reqwest::Client::new();
    let pub_key = identity.public_key_hex();
    let resp: ChallengeResponse = client
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "public_key": pub_key }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let challenge_bytes = hex::decode(&resp.challenge).unwrap();
    let signature =
        identity.sign(&wavvon_identity::auth_challenge_signing_bytes(&challenge_bytes).unwrap());
    let verify: VerifyResponse = client
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "public_key": pub_key,
            "challenge": resp.challenge,
            "signature": hex::encode(signature.to_bytes()),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    verify.token
}

async fn create_voice_channel(base: &str, token: &str, name: &str) -> ChannelResponse {
    reqwest::Client::new()
        .post(format!("{base}/channels"))
        .bearer_auth(token)
        .json(&json!({ "name": name, "channel_type": "voice" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn connect_ws(base: &str, token: &str) -> Ws {
    let url = format!("{}/ws?token={}", base.replace("http://", "ws://"), token);
    tokio_tungstenite::connect_async(&url).await.unwrap().0
}

async fn next_of_type(ws: &mut Ws, kind: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(Ok(TsMessage::Text(raw))) = ws.next().await {
                let v: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
                if v["type"] == kind {
                    return v;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{kind} not received"))
}

async fn join_voice(ws: &mut Ws, channel_id: &str) -> String {
    next_of_type(ws, "hello").await;
    ws.send(TsMessage::Text(
        json!({ "type": "voice_join", "channel_id": channel_id }).to_string(),
    ))
    .await
    .unwrap();
    next_of_type(ws, "voice_joined").await["voice_token"]
        .as_str()
        .unwrap()
        .to_string()
}

/// A browser-shaped peer: not ICE-lite, one negotiated, unordered,
/// non-retransmitting data channel on stream 0.
struct Peer {
    rtc: Rtc,
    socket: UdpSocket,
    local: SocketAddr,
    channel: ChannelId,
    pending: Option<SdpPendingOffer>,
}

impl Peer {
    async fn new() -> (Self, String) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let local = socket.local_addr().unwrap();
        let mut rtc = Rtc::builder().build(Instant::now());
        rtc.add_local_candidate(Candidate::host(local, "udp").unwrap());
        let mut change = rtc.sdp_api();
        let channel = change.add_channel_with_config(ChannelConfig {
            label: "voice".to_string(),
            ordered: false,
            reliability: Reliability::MaxRetransmits { retransmits: 0 },
            negotiated: Some(0),
            protocol: String::new(),
        });
        let (offer, pending) = change.apply().expect("an offer");
        (
            Peer {
                rtc,
                socket,
                local,
                channel,
                pending: Some(pending),
            },
            offer.to_sdp_string(),
        )
    }

    fn accept(&mut self, sdp: &str) {
        let answer = SdpAnswer::from_sdp_string(sdp).expect("a valid answer");
        let pending = self.pending.take().unwrap();
        self.rtc.sdp_api().accept_answer(pending, answer).unwrap();
    }

    fn send(&mut self, packet: &[u8]) {
        if let Some(mut ch) = self.rtc.channel(self.channel) {
            let _ = ch.write(true, packet);
        }
    }

    /// Runs the peer for `budget`, returning the data-channel messages it got.
    async fn pump(&mut self, budget: Duration) -> Vec<Vec<u8>> {
        let end = Instant::now() + budget;
        let mut got = Vec::new();
        let mut buf = vec![0u8; 2000];
        while Instant::now() < end {
            let deadline = loop {
                match self.rtc.poll_output().unwrap() {
                    Output::Timeout(t) => break t.min(end),
                    Output::Transmit(t) => {
                        let _ = self.socket.send_to(&t.contents, t.destination).await;
                    }
                    Output::Event(Event::ChannelData(d)) => got.push(d.data),
                    Output::Event(_) => {}
                }
            };
            let wait = deadline.saturating_duration_since(Instant::now());
            if let Ok(Ok((n, source))) =
                tokio::time::timeout(wait, self.socket.recv_from(&mut buf)).await
            {
                if let Ok(contents) = buf[..n].try_into() {
                    let input = Input::Receive(
                        Instant::now(),
                        Receive {
                            proto: Protocol::Udp,
                            source,
                            destination: self.local,
                            contents,
                        },
                    );
                    let _ = self.rtc.handle_input(input);
                }
            }
            let _ = self.rtc.handle_input(Input::Timeout(Instant::now()));
        }
        got
    }
}

async fn bind_peer(ws: &mut Ws, voice_token: &str) -> Peer {
    let (mut peer, offer) = Peer::new().await;
    ws.send(TsMessage::Text(
        json!({ "type": "voice_rtc_offer", "token": voice_token, "sdp": offer }).to_string(),
    ))
    .await
    .unwrap();
    let answer = next_of_type(ws, "voice_rtc_answer").await;
    peer.accept(answer["sdp"].as_str().unwrap());
    peer
}

/// A's packet reaches B over WebRTC with A's routing prefix, verbatim.
#[tokio::test]
async fn packet_relays_between_two_webrtc_peers() {
    let (base, _state, _guard) = start_hub().await;
    let a = Identity::generate();
    let b = Identity::generate();
    let token_a = authenticate_http(&base, &a).await;
    let token_b = authenticate_http(&base, &b).await;
    let ch = create_voice_channel(&base, &token_a, "rtc-relay").await;

    let mut ws_a = connect_ws(&base, &token_a).await;
    let vt_a = join_voice(&mut ws_a, &ch.id).await;
    let mut ws_b = connect_ws(&base, &token_b).await;
    let vt_b = join_voice(&mut ws_b, &ch.id).await;

    let mut peer_a = bind_peer(&mut ws_a, &vt_a).await;
    let mut peer_b = bind_peer(&mut ws_b, &vt_b).await;

    let payload: &[u8] = b"sealed-opus-frame";
    let mut received = Vec::new();
    for _ in 0..60 {
        peer_a.send(payload);
        let (_, got_b) = tokio::join!(
            peer_a.pump(Duration::from_millis(50)),
            peer_b.pump(Duration::from_millis(50))
        );
        if let Some(p) = got_b.into_iter().next() {
            received = p;
            break;
        }
    }
    assert!(!received.is_empty(), "B never received A's packet");
    assert_eq!(&received[3..], payload, "payload is forwarded verbatim");
    assert_eq!(received[2], 0x00, "normal packet type");
}

/// An offer with a token nobody minted is refused, and no answer is sent.
#[tokio::test]
async fn offer_with_unknown_token_is_refused() {
    let (base, _state, _guard) = start_hub().await;
    let a = Identity::generate();
    let token_a = authenticate_http(&base, &a).await;
    let mut ws = connect_ws(&base, &token_a).await;
    next_of_type(&mut ws, "hello").await;

    let (_peer, offer) = Peer::new().await;
    ws.send(TsMessage::Text(
        json!({ "type": "voice_rtc_offer", "token": "00", "sdp": offer }).to_string(),
    ))
    .await
    .unwrap();
    let err = next_of_type(&mut ws, "error").await;
    assert_eq!(err["context"], "voice_rtc_offer");
}
