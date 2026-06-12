use crate::routes::chat_models::{ChatEvent, WsServerMessage};
use crate::state::AppState;

/// Broadcast a v2 signaling envelope via `chat_tx` using `ChatEvent::ScreenShareSignal`
/// so the WS dispatch loop delivers it only to `to_pubkey`.
pub(super) fn send_v2_signal(
    state: &AppState,
    channel_id: String,
    to_pubkey: String,
    msg: WsServerMessage,
) {
    let ev = ChatEvent::ScreenShareSignal {
        channel_id,
        to_pubkey,
    };
    let json: std::sync::Arc<str> =
        std::sync::Arc::from(serde_json::to_string(&msg).unwrap().as_str());
    let _ = state.chat_tx.send((ev, json));
}
