use std::sync::Arc;

use axum::routing::{any, delete, get, patch, post};
use axum::Router;
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::routes;
use crate::state::FarmState;

/// Mirrors the hub's `build_cors_layer` — same setting name, same shape.
/// Duplicated rather than shared because the alternative is the farm
/// depending on the whole hub crate for one layer.
fn build_cors_layer(cors_origins: &str) -> CorsLayer {
    let allow_methods = AllowMethods::list([
        axum::http::Method::GET,
        axum::http::Method::POST,
        axum::http::Method::PUT,
        axum::http::Method::PATCH,
        axum::http::Method::DELETE,
        axum::http::Method::OPTIONS,
    ]);
    let allow_headers = AllowHeaders::list([
        axum::http::header::AUTHORIZATION,
        axum::http::header::CONTENT_TYPE,
    ]);
    let layer = CorsLayer::new()
        .allow_methods(allow_methods)
        .allow_headers(allow_headers)
        .max_age(std::time::Duration::from_secs(86400));
    if cors_origins.trim() == "*" {
        return layer.allow_origin(AllowOrigin::any());
    }
    let mut origins: Vec<axum::http::HeaderValue> = Vec::new();
    for raw in cors_origins
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        match raw.parse::<axum::http::HeaderValue>() {
            Ok(v) => origins.push(v),
            Err(_) => tracing::warn!(origin = raw, "CORS: invalid origin string ignored"),
        }
    }
    if origins.is_empty() {
        tracing::warn!(
            cors_origins,
            "CORS: no valid origins parsed — all browser cross-origin requests will be blocked"
        );
    }
    layer.allow_origin(AllowOrigin::list(origins))
}

pub fn create_router(state: Arc<FarmState>) -> Router {
    create_router_with_cors(state, "*")
}

pub fn create_router_with_cors(state: Arc<FarmState>, cors_origins: &str) -> Router {
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
        // Registered before /farm/hubs/{hub_id} for readability only — the
        // two differ in segment count, so they cannot collide.
        .route(
            "/farm/hubs/by-pubkey/{pubkey}",
            get(routes::slugs::hub_address_by_pubkey),
        )
        .route("/farm/hubs/{hub_id}", get(routes::hubs::get_hub))
        .route(
            "/farm/hubs/{hub_id}/suspend",
            patch(routes::hubs::suspend_hub),
        )
        .route(
            "/farm/hubs/{hub_id}/restart",
            post(routes::hubs::force_restart_hub),
        )
        .route("/farm/hubs/{hub_id}", delete(routes::hubs::delete_hub))
        // Hub addresses (slug.rs): owner-chosen aliases. Registered before
        // the agent routes for no reason other than grouping with the hub
        // routes they belong to.
        .route(
            "/farm/hubs/{hub_id}/slugs",
            get(routes::slugs::list_slugs).post(routes::slugs::claim_slug),
        )
        .route(
            "/farm/hubs/{hub_id}/slugs/{slug}",
            delete(routes::slugs::release_slug),
        )
        .route(
            "/farm/hubs/{hub_id}/slugs/{slug}/canonical",
            axum::routing::put(routes::slugs::promote_slug),
        )
        // Server agent management routes.
        .route(
            "/farm/admin/server-token",
            post(routes::servers::generate_server_token),
        )
        .route("/farm/admin/servers", get(routes::servers::list_servers))
        .route(
            "/farm/admin/servers/{server_id}",
            patch(routes::servers::update_server),
        )
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
        // Hub heartbeat — pushed by each hub every 60 s.
        .route(
            "/farm/heartbeat",
            post(routes::heartbeat::receive_heartbeat),
        )
        // Farm admin fleet view — requires farm admin auth.
        .route("/farm/admin/fleet", get(routes::heartbeat::get_fleet))
        // CORS on the farm's own routes only. The proxied hub answers with
        // its *own* CORS headers, and a second set added here would arrive as
        // a duplicate Access-Control-Allow-Origin, which a browser rejects
        // outright — so the proxy route is merged in after this layer.
        .layer(build_cors_layer(cors_origins))
        // Proxy catch-all — must be last (fallback for all /hub/<serial>/...
        // requests). Routed by the hub's pubkey ("serial"), not the opaque
        // `hubs.id` PK — see farm-impl.md "Serial routing — first slice".
        .merge(Router::new().route("/hub/{serial}/{*path}", any(crate::proxy::proxy_handler)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
