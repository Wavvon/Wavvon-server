use std::sync::Arc;

use axum::extract::ws::Message;
use futures_util::SinkExt;
use tokio::sync::mpsc;

use crate::state::AppState;

use crate::routes::chat_models::WsClientMessage;
use crate::routes::ws::conn_state::{ConnState, DispatchResult};

type WsTx = futures_util::stream::SplitSink<axum::extract::ws::WebSocket, Message>;

pub(in crate::routes::ws) async fn handle_resume(
    cs: &mut ConnState,
    state: &Arc<AppState>,
    ws_tx: &mut WsTx,
    bot_tx: &mpsc::Sender<String>,
    msg: WsClientMessage,
) -> DispatchResult {
    let since_seq = match msg {
        WsClientMessage::Resume { since_seq } => since_seq,
        _ => return DispatchResult::Continue,
    };

    // Only bots can resume.
    if !cs.is_bot {
        return DispatchResult::Continue;
    }

    cs.is_replaying = true;

    let live_seq = crate::bots::events::current_seq(state).await;

    let replay_tx = bot_tx.clone();
    let result =
        crate::bots::events::replay_events_for_bot(state, &cs.public_key, since_seq, &replay_tx)
            .await;

    cs.is_replaying = false;

    match result {
        crate::bots::events::ReplayResult::Unavailable {
            earliest_seq,
            earliest_at,
        } => {
            let msg = serde_json::json!({
                "type": "replay_unavailable",
                "earliest_seq": earliest_seq,
                "earliest_at": earliest_at,
            });
            if ws_tx
                .send(Message::Text(msg.to_string().into()))
                .await
                .is_err()
            {
                return DispatchResult::Break;
            }
        }
        crate::bots::events::ReplayResult::Complete { replayed } => {
            let msg = serde_json::json!({
                "type": "replay_complete",
                "replayed": replayed,
                "live_from_seq": live_seq,
            });
            if ws_tx
                .send(Message::Text(msg.to_string().into()))
                .await
                .is_err()
            {
                return DispatchResult::Break;
            }
        }
    }

    // Flush buffered live events that arrived during replay.
    for buffered in cs.replay_buffer.drain(..) {
        if ws_tx.send(Message::Text(buffered.into())).await.is_err() {
            return DispatchResult::Break;
        }
    }

    DispatchResult::Continue
}
