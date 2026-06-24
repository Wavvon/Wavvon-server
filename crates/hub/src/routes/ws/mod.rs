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
pub use voice::get_voice_participants;

pub async fn ws_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<WsParams>,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    // Delegate to the shared session-validity helper so the WS admission
    // checks never drift from what the HTTP AuthUser middleware enforces
    // (session expiry, revocation, approval_status, bans).
    let public_key = crate::auth::handlers::validate_ws_token(&state.db, &params.token).await?;

    tracing::info!(
        "WebSocket connected: {}",
        &public_key[..16.min(public_key.len())]
    );

    Ok(ws.on_upgrade(move |socket| connection::handle_socket(socket, state, public_key)))
}
