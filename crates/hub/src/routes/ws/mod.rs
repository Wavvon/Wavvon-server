mod conn_state;
mod connection;
mod handlers;
mod screen_share;
mod voice;

use std::sync::Arc;

use axum::extract::WebSocketUpgrade;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::routes::chat_models::WsParams;
use crate::state::AppState;

pub use connection::leave_voice;
pub use connection::leave_voice_for_test;
pub use voice::apply_pending_voice_move_assignment;
pub use voice::get_voice_participants;
pub use voice::get_voice_roster;
pub use voice::push_event_move;
pub use voice::voice_identity;

pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<WsParams>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Delegate to the shared session-validity helper so the WS admission
    // checks never drift from what the HTTP AuthUser middleware enforces
    // (session expiry, revocation, approval_status, bans).
    let auth = crate::auth::handlers::validate_ws_token(&state, &params.token).await?;
    let public_key = auth.public_key;

    // An alliance-voice visitor is confined to the one channel their grant
    // admitted them to. Resolved here, once, rather than per message: an
    // expired visit then reads as "not a visitor and not a member", which the
    // dispatch confinement turns into a socket that can do nothing.
    let alliance_voice_channel = if auth.scope == "alliance_voice" {
        crate::routes::alliances::admitted_channel(&state, &public_key).await
    } else {
        None
    };

    tracing::info!(
        "WebSocket connected: {}",
        &public_key[..16.min(public_key.len())]
    );

    Ok(ws.on_upgrade(move |socket| {
        connection::handle_socket(
            socket,
            state,
            public_key,
            auth.mini_app_channel_id,
            alliance_voice_channel,
        )
    }))
}
