use axum::extract::ws::{Message, WebSocket};
use futures_util::SinkExt;

use super::conn_state::DispatchResult;
use crate::routes::chat_models::WsServerMessage;

pub(super) mod app;
pub(super) mod chat;
pub(super) mod mini_app;
pub(super) mod screen;
pub(super) mod voice;

type WsTx = futures_util::stream::SplitSink<WebSocket, Message>;

/// Answers the client's request on this connection with an `Error` frame. The
/// connection carries on, so a handler returns the `Continue` this gives back.
async fn send_error(ws_tx: &mut WsTx, context: &str, message: impl Into<String>) -> DispatchResult {
    let err = WsServerMessage::Error {
        context: context.to_string(),
        message: message.into(),
    };
    let _ = ws_tx
        .send(Message::Text(serde_json::to_string(&err).unwrap().into()))
        .await;
    DispatchResult::Continue
}
