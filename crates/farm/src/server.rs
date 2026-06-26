use std::sync::Arc;

use axum::routing::{any, delete, get, patch, post};
use axum::Router;
use tower_http::trace::TraceLayer;

use crate::routes;
use crate::state::FarmState;

pub fn create_router(state: Arc<FarmState>) -> Router {
    Router::new()
        // Public probe endpoint — the hub fetches this on startup to cache the pubkey.
        .route("/farm/info", get(routes::health::farm_info))
        // Auth endpoints — same wire shape as the hub's existing auth routes.
        .route("/auth/challenge", post(routes::auth::challenge))
        .route("/auth/verify", post(routes::auth::verify))
        .route("/auth/renew", post(routes::auth::renew))
        // Belt-and-braces revocation check for hubs.
        .route(
            "/farm/auth/revoke-check",
            post(routes::revoke::revoke_check),
        )
        // Hub management routes.
        .route(
            "/farm/hubs",
            get(routes::hubs::list_hubs).post(routes::hubs::create_hub),
        )
        .route("/farm/hubs/{hub_id}", get(routes::hubs::get_hub))
        .route(
            "/farm/hubs/{hub_id}/suspend",
            patch(routes::hubs::suspend_hub),
        )
        .route("/farm/hubs/{hub_id}", delete(routes::hubs::delete_hub))
        // Server agent management routes.
        .route(
            "/farm/admin/server-token",
            post(routes::servers::generate_server_token),
        )
        .route("/farm/admin/servers", get(routes::servers::list_servers))
        .route("/ws/agent", get(routes::servers::ws_agent_handler))
        // TOTP 2FA routes for admin account.
        .route(
            "/farm/admin/totp/setup",
            post(routes::admin_auth::totp_setup),
        )
        .route(
            "/farm/admin/totp/confirm",
            post(routes::admin_auth::totp_confirm),
        )
        .route(
            "/farm/admin/totp/disable",
            post(routes::admin_auth::totp_disable),
        )
        // Phase 3 — farm settings (admin).
        .route(
            "/farm/settings",
            get(routes::admin::get_settings).patch(routes::admin::patch_settings),
        )
        // Phase 3 — per-user quota (authenticated).
        .route("/farm/me/hub-quota", get(routes::admin::me_hub_quota))
        // Phase 3 — farm user index and session revocation (admin).
        .route("/farm/users", get(routes::admin::list_users))
        .route(
            "/farm/users/{pubkey}/revoke-sessions",
            post(routes::admin::revoke_user_sessions),
        )
        // Phase 3 — public discovery probe (unauthenticated).
        .route("/farm/public-info", get(routes::admin::public_info))
        // Hub heartbeat — pushed by each hub every 60 s.
        .route(
            "/farm/heartbeat",
            post(routes::heartbeat::receive_heartbeat),
        )
        // Farm admin fleet view — requires farm admin auth.
        .route("/farm/admin/fleet", get(routes::heartbeat::get_fleet))
        // Proxy catch-all — must be last (fallback for all /hub/<id>/... requests).
        .route("/hub/{hub_id}/{*path}", any(crate::proxy::proxy_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
