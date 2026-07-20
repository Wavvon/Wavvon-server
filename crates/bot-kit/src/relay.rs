//! Wraps the `mini_app_message` bot->player relay
//! (`hub/src/routes/ws/handlers/mini_app.rs`) so a game-bot never
//! hand-builds the envelope. Generalizes ttt-bot's original per-viewer send
//! loop (bot-capability-layer.md §10).

use futures_util::SinkExt;
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{Error as WsError, Message as WsMessage};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// The sink half of a bot's hub `/ws` connection, as returned by
/// `tokio_tungstenite::connect_async(..).split()`.
pub type WsSink = futures_util::stream::SplitSink<
    WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    WsMessage,
>;

/// Sends one `mini_app_message` frame addressed to `to_pubkey`. `payload` is
/// the game-specific JSON body -- the hub relays it opaquely.
pub async fn send_to(
    tx: &mut WsSink,
    bot_id: &str,
    channel_id: &str,
    to_pubkey: &str,
    payload: Value,
) -> Result<(), WsError> {
    let out = json!({
        "type": "mini_app_message",
        "bot_id": bot_id,
        "channel_id": channel_id,
        "payload": payload.to_string(),
        "to_pubkey": to_pubkey,
    });
    tx.send(WsMessage::Text(out.to_string())).await
}

/// Sends a per-viewer payload (built by `per_viewer`) to every pubkey in
/// `targets`. A send failure for one viewer doesn't stop the others --
/// matches the original loop's fire-and-forget semantics.
pub async fn broadcast<F>(
    tx: &mut WsSink,
    bot_id: &str,
    channel_id: &str,
    targets: impl IntoIterator<Item = String>,
    mut per_viewer: F,
) where
    F: FnMut(&str) -> Value,
{
    for target in targets {
        let payload = per_viewer(&target);
        let _ = send_to(tx, bot_id, channel_id, &target, payload).await;
    }
}
