use std::sync::Arc;

use axum::middleware::from_fn;
use axum::routing::{delete, get, patch, post, put};
use axum::{extract::Request, middleware::Next, response::Response, Router};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::federation;
use crate::rate_limit::{self, Config, RateLimiter};
use crate::routes;
use crate::state::AppState;
use crate::web_client::WebClientConfig;

async fn attach_request_id(req: Request, next: Next) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    tracing::trace!(request_id = %id, method = %req.method(), uri = %req.uri(), "request");
    let mut resp = next.run(req).await;
    if let Ok(v) = id.parse::<axum::http::HeaderValue>() {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

/// Build the CORS layer from the `cors_origins` setting string.
///
/// `"*"` → permissive any-origin.
/// Anything else is treated as a comma-separated list of exact origin strings
/// (e.g. `"https://app.example.com,https://other.io"`).
pub fn build_cors_layer(cors_origins: &str) -> CorsLayer {
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

    let cors = if cors_origins.trim() == "*" {
        CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods(allow_methods)
            .allow_headers(allow_headers)
            .max_age(std::time::Duration::from_secs(86400))
    } else {
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
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(allow_methods)
            .allow_headers(allow_headers)
            .max_age(std::time::Duration::from_secs(86400))
    };
    cors
}

pub fn create_router(state: Arc<AppState>) -> Router {
    create_router_with_cors(state, "*")
}

pub fn create_router_with_cors(state: Arc<AppState>, cors_origins: &str) -> Router {
    create_router_full(state, cors_origins, false, None)
}

/// Full constructor used by `main()` — exposes all knobs tests don't need.
pub fn create_router_full(
    state: Arc<AppState>,
    cors_origins: &str,
    trusted_proxy: bool,
    web_client: Option<Arc<WebClientConfig>>,
) -> Router {
    let auth_limiter = RateLimiter::new(Config::AUTH, trusted_proxy);
    let write_limiter = RateLimiter::new(Config::WRITE, trusted_proxy);

    // Rate-limited auth sub-router (strict, because anyone can hit these).
    let auth_routes = Router::new()
        .route("/auth/challenge", post(auth::handlers::challenge))
        .route("/auth/verify", post(auth::handlers::verify))
        .route("/auth/renew", post(auth::handlers::renew))
        .route(
            "/auth/webauthn/begin",
            post(routes::webauthn::register_begin),
        )
        .route(
            "/auth/webauthn/finish",
            post(routes::webauthn::register_finish),
        )
        .route(
            "/auth/webauthn/assert/begin",
            post(routes::webauthn::assert_begin),
        )
        .route(
            "/auth/webauthn/assert/finish",
            post(routes::webauthn::assert_finish),
        )
        .route(
            "/auth/device-token/create",
            post(routes::webauthn::device_token_create),
        )
        .route(
            "/auth/device-token/redeem",
            post(routes::webauthn::device_token_redeem),
        )
        .layer(from_fn(move |req, next| {
            let l = auth_limiter.clone();
            async move { rate_limit::enforce(l, req, next).await }
        }));

    // Rate-limited write sub-router (channels, messages, DMs, etc.).
    let write_routes = Router::new()
        .route("/channels", post(routes::channels::create_channel))
        .route(
            "/channels/{channel_id}/messages",
            post(routes::messages::send_message),
        )
        .route("/conversations", post(routes::dms::create_conversation))
        .route(
            "/conversations/{conversation_id}/messages",
            post(routes::dms::send_dm),
        )
        .layer(from_fn(move |req, next| {
            let l = write_limiter.clone();
            async move { rate_limit::enforce(l, req, next).await }
        }));

    let api_router = Router::new()
        .route("/health", get(routes::health::get_health))
        .route("/info", get(routes::health::info))
        .route("/key-rotation", get(routes::key_rotation::get_key_rotation))
        .route("/metrics", get(routes::metrics::metrics))
        .route("/hub", axum::routing::patch(routes::hub::update_hub))
        .route("/hub/members", get(routes::hub::list_members))
        .route("/hub/settings", get(routes::hub::get_hub_settings))
        .route("/hub/pending", get(routes::hub::list_pending))
        .route(
            "/hub/pending/{target_key}/approve",
            post(routes::hub::approve_user),
        )
        .route(
            "/hub/icons",
            get(routes::hub_icons::list_icons).post(routes::hub_icons::create_icon),
        )
        .route(
            "/hub/icons/{icon_id}",
            axum::routing::patch(routes::hub_icons::rename_icon)
                .delete(routes::hub_icons::delete_icon),
        )
        .route(
            "/admin/settings/pow",
            get(routes::hub::get_pow_settings).patch(routes::hub::patch_pow_settings),
        )
        .route(
            "/admin/settings/channel-depth",
            get(routes::hub::get_channel_depth).patch(routes::hub::patch_channel_depth),
        )
        .route(
            "/admin/settings/moderation",
            get(routes::hub::get_moderation_settings).patch(routes::hub::patch_moderation_settings),
        )
        // ---- ME1: Federated ban list admin routes ----
        .route(
            "/admin/banlist/sources",
            get(routes::banlist::list_sources)
                .post(routes::banlist::add_source)
                .delete(routes::banlist::delete_source)
                .patch(routes::banlist::update_source),
        )
        .route("/admin/banlist/entries", get(routes::banlist::list_entries))
        .route(
            "/admin/banlist/overrides",
            get(routes::banlist::list_overrides).post(routes::banlist::add_override),
        )
        .route(
            "/admin/banlist/overrides/{pubkey}",
            delete(routes::banlist::delete_override),
        )
        .route(
            "/admin/settings/banlist",
            get(routes::banlist::get_banlist_settings)
                .patch(routes::banlist::patch_banlist_settings),
        )
        .route(
            "/admin/settings/listing",
            patch(routes::listing::patch_listing),
        )
        .route(
            "/admin/settings/tags",
            get(routes::tags::get_tags).patch(routes::tags::patch_tags),
        )
        .route(
            "/admin/directory-sign",
            post(routes::directory::sign_for_directory),
        )
        .route(
            "/profile/{pubkey}",
            get(routes::profile::get_profile).put(routes::profile::put_profile),
        )
        .merge(auth_routes)
        .merge(write_routes)
        .route("/me", get(routes::me::me).patch(routes::me::update_me))
        .route("/me/credentials", get(routes::webauthn::list_credentials))
        .route(
            "/me/credentials/{id}",
            patch(routes::webauthn::rename_credential).delete(routes::webauthn::delete_credential),
        )
        .route("/me/devices", get(routes::webauthn::list_devices))
        .route("/me/devices/{id}", delete(routes::webauthn::revoke_device))
        .route("/channels", get(routes::channels::list_channels))
        .route(
            "/channels/{channel_id}",
            axum::routing::patch(routes::channels::update_channel)
                .delete(routes::channels::delete_channel),
        )
        .route(
            "/channels/reorder",
            post(routes::channels::reorder_channels),
        )
        // ---- Channel permission overwrites (Nested Channels §3.6) ----
        .route(
            "/channels/{channel_id}/permissions",
            get(routes::channel_permissions::get_channel_permissions),
        )
        .route(
            "/channels/{channel_id}/permissions/{role_id}",
            put(routes::channel_permissions::put_channel_permissions)
                .delete(routes::channel_permissions::delete_channel_permissions),
        )
        .route(
            "/channels/{channel_id}/my-permissions",
            get(routes::channel_permissions::get_my_channel_permissions),
        )
        .route(
            "/channels/{channel_id}/messages",
            get(routes::messages::get_messages),
        )
        .route(
            "/channels/{channel_id}/messages/{message_id}",
            axum::routing::patch(routes::messages::edit_message)
                .delete(routes::messages::delete_message),
        )
        .route(
            "/channels/{channel_id}/messages/{message_id}/reactions",
            post(routes::messages::add_reaction),
        )
        .route(
            "/channels/{channel_id}/messages/{message_id}/reactions/{emoji}",
            axum::routing::delete(routes::messages::remove_reaction),
        )
        // ---- Content reporting (Task #33) ----
        .route(
            "/messages/{id}/report",
            post(routes::reports::report_message),
        )
        .route("/admin/reports", get(routes::reports::list_reports))
        .route(
            "/admin/reports/{id}/review",
            post(routes::reports::review_report),
        )
        // ---- Admin bot management (internal service accounts) ----
        .route(
            "/admin/bots",
            get(routes::bots::admin_list_bots).post(routes::bots::admin_create_bot),
        )
        .route(
            "/admin/bots/{pubkey}",
            get(routes::bots::admin_get_bot).delete(routes::bots::admin_delete_bot),
        )
        .route(
            "/admin/bots/{pubkey}/webhook",
            put(routes::bots::admin_set_webhook),
        )
        .route("/admin/audit-log", get(routes::bots::admin_audit_log))
        // ---- Bot API (token auth, internal service accounts) ----
        .route("/bot/commands", put(routes::bots::bot_set_commands))
        .route("/bot/send", post(routes::bots::bot_send_message))
        .route("/bot/poll", get(routes::bots::bot_poll))
        .route(
            "/bot/events",
            axum::routing::delete(routes::bots::bot_ack_events),
        )
        // ---- External bot system ----
        // /bots/me, /bots/me/profile, /bots/me/commands, /bots/me/subscriptions
        // must be registered before /bots/{pubkey} so axum doesn't match "me"
        // as a path parameter.
        .route("/bots/me", get(routes::bots::ext_bot_me))
        .route(
            "/bots/me/profile",
            put(routes::bots::ext_update_bot_profile),
        )
        .route(
            "/bots/me/commands",
            put(routes::bots::ext_update_bot_commands),
        )
        .route(
            "/bots/me/subscriptions",
            put(routes::bots::ext_update_bot_subscriptions),
        )
        .route("/bots/accept-invite", post(routes::bots::ext_accept_invite))
        .route(
            "/bots",
            get(routes::bots::ext_list_bots).post(routes::bots::ext_invite_bot),
        )
        .route("/bots/{pubkey}", delete(routes::bots::ext_remove_bot))
        // ---- Bot voice REST endpoints ----
        .route(
            "/bots/{id}/voice/join",
            post(routes::bots::voice::bot_voice_join),
        )
        .route(
            "/bots/{id}/voice/leave",
            delete(routes::bots::voice::bot_voice_leave),
        )
        // ---- Bot screenshare REST endpoints ----
        .route(
            "/bots/{id}/screenshare/start",
            post(routes::bots::screenshare::bot_screenshare_start),
        )
        .route(
            "/bots/{id}/screenshare/stop",
            delete(routes::bots::screenshare::bot_screenshare_stop),
        )
        // ---- Incoming webhooks ----
        .route(
            "/admin/webhooks",
            get(routes::webhooks::list_webhooks).post(routes::webhooks::create_webhook),
        )
        .route(
            "/admin/webhooks/{id}",
            delete(routes::webhooks::delete_webhook).patch(routes::webhooks::regenerate_webhook),
        )
        .route(
            "/webhooks/{id}/{token}",
            post(routes::webhooks::post_webhook_message),
        )
        // ---- Outgoing webhooks (hub -> external URL push) ----
        .route(
            "/admin/outgoing-webhooks",
            get(crate::outgoing_webhooks::routes::list_webhooks)
                .post(crate::outgoing_webhooks::routes::create_webhook),
        )
        .route(
            "/admin/outgoing-webhooks/{id}",
            patch(crate::outgoing_webhooks::routes::update_webhook)
                .delete(crate::outgoing_webhooks::routes::delete_webhook),
        )
        .route(
            "/admin/outgoing-webhooks/{id}/subscriptions",
            get(crate::outgoing_webhooks::routes::list_subscriptions)
                .put(crate::outgoing_webhooks::routes::replace_subscriptions),
        )
        .route(
            "/admin/outgoing-webhooks/{id}/rotate-secret",
            post(crate::outgoing_webhooks::routes::rotate_secret),
        )
        .route(
            "/admin/outgoing-webhooks/{id}/enable",
            post(crate::outgoing_webhooks::routes::enable_webhook),
        )
        .route(
            "/admin/outgoing-webhooks/{id}/deliveries",
            get(crate::outgoing_webhooks::routes::list_deliveries),
        )
        .route("/users", get(routes::users::list_users))
        .route(
            "/users/{pubkey}/profile",
            get(routes::users::get_user_profile),
        )
        .route(
            "/channels/{channel_id}/members",
            get(routes::users::channel_members),
        )
        .route(
            "/voice/populations",
            get(routes::channels::voice_populations),
        )
        .route(
            "/voice/active-users",
            get(routes::channels::voice_active_users),
        )
        .route(
            "/voice/participants",
            get(routes::channels::voice_channel_participants),
        )
        .route("/voice/ws", get(routes::voice_ws::handle_voice_ws))
        .route("/ws", get(routes::ws::ws_handler))
        .route("/conversations", get(routes::dms::list_conversations))
        .route(
            "/conversations/{conversation_id}",
            get(routes::dms::get_conversation),
        )
        .route(
            "/conversations/{conversation_id}/messages",
            get(routes::dms::list_dm_messages),
        )
        .route(
            "/conversations/{conversation_id}/sender-keys",
            get(routes::dms::get_sender_keys).put(routes::dms::push_sender_keys),
        )
        .route(
            "/conversations/{conversation_id}/members",
            post(routes::dms::add_conversation_member),
        )
        .route(
            "/conversations/{conversation_id}/members/{pubkey}",
            delete(routes::dms::remove_conversation_member),
        )
        .route("/federation/dm", post(routes::dms::receive_federated_dm))
        .route(
            "/federation/badge-offer",
            post(federation::handlers::receive_badge_offer),
        )
        .route(
            "/federation/badge-revocations",
            get(routes::badges::federation_badge_revocations),
        )
        .route(
            "/federation/banlist",
            get(routes::moderation::get_federation_banlist),
        )
        .route("/federation/listing", get(routes::listing::get_listing))
        .route(
            "/friends",
            get(routes::friends::list_friends).post(routes::friends::send_friend_request),
        )
        .route(
            "/friends/pending",
            get(routes::friends::list_pending_requests),
        )
        .route(
            "/friends/{public_key}/accept",
            post(routes::friends::accept_friend_request),
        )
        .route(
            "/friends/{public_key}",
            axum::routing::delete(routes::friends::remove_friend),
        )
        .route(
            "/roles",
            get(routes::roles::list_roles).post(routes::roles::create_role),
        )
        .route(
            "/roles/{role_id}",
            axum::routing::patch(routes::roles::update_role).delete(routes::roles::delete_role),
        )
        .route(
            "/role-categories",
            get(routes::role_categories::list_role_categories)
                .post(routes::role_categories::create_role_category),
        )
        .route(
            "/role-categories/{category_id}",
            axum::routing::patch(routes::role_categories::update_role_category)
                .delete(routes::role_categories::delete_role_category),
        )
        .route(
            "/roles/{role_id}/members",
            get(routes::roles::list_role_members),
        )
        .route(
            "/users/{public_key}/roles",
            get(routes::roles::get_user_roles),
        )
        .route(
            "/users/{public_key}/roles/{role_id}",
            put(routes::roles::assign_role).delete(routes::roles::remove_role),
        )
        .route(
            "/invites",
            get(routes::invites::list_invites).post(routes::invites::create_invite),
        )
        .route(
            "/invites/{code}",
            axum::routing::delete(routes::invites::revoke_invite),
        )
        // ---- Join links (Feature 5) ----
        .route(
            "/join/{code}",
            get(routes::invites::get_join_info).post(routes::invites::join_with_invite),
        )
        // ---- Unread counts (Feature 2) ----
        // Must be registered before /channels/{channel_id} to avoid "unread" being matched as a path param.
        .route("/channels/unread", get(routes::channels::get_unread_counts))
        .route(
            "/channels/{channel_id}/read",
            post(routes::channels::mark_channel_read),
        )
        .route(
            "/moderation/bans",
            get(routes::moderation::list_bans).post(routes::moderation::ban_user),
        )
        .route(
            "/moderation/bans/{target_key}",
            axum::routing::delete(routes::moderation::unban_user),
        )
        .route(
            "/moderation/mutes",
            get(routes::moderation::list_mutes).post(routes::moderation::mute_user),
        )
        .route(
            "/moderation/mutes/{target_key}",
            axum::routing::delete(routes::moderation::unmute_user),
        )
        .route(
            "/moderation/timeout",
            post(routes::moderation::timeout_user),
        )
        .route("/moderation/kick", post(routes::moderation::kick_user))
        .route(
            "/moderation/channels/{channel_id}/bans",
            get(routes::moderation::list_channel_bans).post(routes::moderation::channel_ban),
        )
        .route(
            "/moderation/channels/{channel_id}/bans/{target_key}",
            axum::routing::delete(routes::moderation::channel_unban),
        )
        .route(
            "/moderation/voice-mutes",
            get(routes::moderation::list_voice_mutes).post(routes::moderation::voice_mute),
        )
        .route(
            "/moderation/voice-mutes/{target_key}",
            axum::routing::delete(routes::moderation::voice_unmute),
        )
        .route(
            "/channels/{channel_id}/talk-power",
            get(routes::moderation::get_talk_power).post(routes::moderation::set_talk_power),
        )
        // ---- Channel-scoped moderation (pubkey field, task #6/#7/#8) ----
        .route(
            "/channels/{channel_id}/bans",
            get(routes::moderation::list_channel_bans_v2).post(routes::moderation::channel_ban_v2),
        )
        .route(
            "/channels/{channel_id}/bans/{pubkey}",
            axum::routing::delete(routes::moderation::channel_unban_v2),
        )
        .route(
            "/channels/{channel_id}/voice-mutes",
            get(routes::moderation::list_channel_voice_mutes)
                .post(routes::moderation::channel_voice_mute),
        )
        .route(
            "/channels/{channel_id}/voice-mutes/{pubkey}",
            axum::routing::delete(routes::moderation::channel_voice_unmute),
        )
        .route(
            "/channels/{channel_id}/raise-hand",
            post(routes::moderation::raise_hand),
        )
        .route(
            "/channels/{channel_id}/raise-hand/{pubkey}",
            axum::routing::delete(routes::moderation::lower_hand),
        )
        .route(
            "/channels/{channel_id}/raise-hands",
            get(routes::moderation::list_raise_hands),
        )
        .route(
            "/alliances",
            get(routes::alliances::list_alliances).post(routes::alliances::create_alliance),
        )
        .route(
            "/alliances/join",
            post(routes::alliances::join_alliance_local),
        )
        .route(
            "/alliances/pending-invites",
            get(routes::alliances::list_pending_invites),
        )
        .route(
            "/alliances/pending-invites/{invite_id}/accept",
            post(routes::alliances::accept_pending_invite),
        )
        .route(
            "/alliances/pending-invites/{invite_id}",
            axum::routing::delete(routes::alliances::decline_pending_invite),
        )
        .route(
            "/alliances/{alliance_id}",
            get(routes::alliances::get_alliance),
        )
        .route(
            "/alliances/{alliance_id}/invite",
            post(routes::alliances::create_invite),
        )
        .route(
            "/alliances/{alliance_id}/push-invite",
            post(routes::alliances::push_invite_handler),
        )
        .route(
            "/alliances/{alliance_id}/join",
            post(routes::alliances::join_alliance),
        )
        .route(
            "/alliances/{alliance_id}/leave",
            axum::routing::delete(routes::alliances::leave_alliance),
        )
        .route(
            "/alliances/{alliance_id}/channels",
            get(routes::alliances::list_shared_channels).post(routes::alliances::share_channel),
        )
        .route(
            "/alliances/{alliance_id}/channels/{channel_id}",
            axum::routing::delete(routes::alliances::unshare_channel),
        )
        .route(
            "/alliances/{alliance_id}/channels/{channel_id}/messages",
            get(routes::alliances::get_alliance_channel_messages)
                .post(routes::alliances::post_alliance_channel_message),
        )
        .route(
            "/federation/alliance-invite",
            post(routes::alliances::receive_federation_alliance_invite),
        )
        .route(
            "/identity/{master}/designation",
            get(routes::identity::get_designation).post(routes::identity::put_designation),
        )
        .route(
            "/identity/{master}/devices",
            get(routes::identity::list_devices).post(routes::identity::post_device),
        )
        .route(
            "/identity/{master}/revocations",
            get(routes::identity::list_revocations).post(routes::identity::post_revocation),
        )
        .route(
            "/identity/{master}/prefs",
            get(routes::identity::get_prefs).put(routes::identity::put_prefs),
        )
        .route(
            "/identity/{pubkey}/dh-key",
            get(routes::dh_keys::get_dh_key).put(routes::dh_keys::put_dh_key),
        )
        .route("/identity/pairing/offer", post(routes::pairing::post_offer))
        .route("/identity/pairing/claim", post(routes::pairing::post_claim))
        .route(
            "/identity/pairing/complete",
            post(routes::pairing::post_complete),
        )
        .route(
            "/identity/pairing/status/{token}",
            get(routes::pairing::get_status),
        )
        // ---- Certification routes (Task #20 / #21) ----
        .route("/admin/certs", get(routes::certs::admin_list))
        .route("/admin/certs/{pubkey}", post(routes::certs::admin_issue))
        .route(
            "/admin/certs/{pubkey}/badge",
            post(routes::certs::admin_grant_badge),
        )
        .route(
            "/admin/certs/{pubkey}/revoke",
            post(routes::certs::admin_revoke),
        )
        .route(
            "/admin/settings/certs",
            get(routes::certs::get_cert_settings).patch(routes::certs::patch_cert_settings),
        )
        .route(
            "/identity/{pubkey}/certs",
            get(routes::certs::list_user_certs),
        )
        .route("/certs/revocations", get(routes::certs::get_revocations))
        // ---- Badge admin routes ----
        .route("/badges/pending", get(routes::badges::list_pending))
        .route(
            "/badges/pending/{id}/accept",
            post(routes::badges::accept_pending),
        )
        .route(
            "/badges/pending/{id}/decline",
            post(routes::badges::decline_pending),
        )
        .route("/badges", get(routes::badges::list_badges))
        .route("/badges/{id}", delete(routes::badges::delete_badge))
        .route("/admin/badges/issue", post(routes::badges::issue_badge))
        .route("/admin/badges/issued", get(routes::badges::list_issued))
        .route(
            "/admin/badges/issued/{id}/revoke",
            axum::routing::delete(routes::badges::revoke_issued_badge),
        )
        .route("/federation/peers", get(federation::handlers::list_peers))
        .route("/federation/peers", post(federation::handlers::add_peer))
        .route(
            "/federation/peers/{peer_key}/channels",
            get(federation::handlers::peer_channels),
        )
        .route(
            "/federation/channels",
            get(federation::handlers::all_federated_channels),
        )
        .route(
            "/federation/channels/{fed_channel_id}/messages",
            get(federation::handlers::federated_messages)
                .post(federation::handlers::send_federated_message),
        )
        // ---- Lobby ----
        .route("/lobby/status", get(routes::lobby::get_status))
        .route("/lobby/submit-pow", post(routes::lobby::submit_pow))
        .route("/lobby/welcome", get(routes::lobby::get_welcome))
        .route(
            "/hub/settings/lobby",
            put(routes::lobby::update_lobby_settings),
        )
        // ---- Bot Challenge ----
        .route("/challenge/new", get(routes::challenge::new_challenge))
        .route(
            "/challenge/verify",
            post(routes::challenge::verify_challenge),
        )
        .route(
            "/hub/settings/challenge",
            put(routes::challenge::update_challenge_settings),
        )
        // ---- Survey ----
        .route("/survey/current", get(routes::survey::get_current))
        .route("/survey/submit", post(routes::survey::submit_survey))
        .route(
            "/admin/survey",
            get(routes::survey::admin_get_survey).put(routes::survey::admin_put_survey),
        )
        .route(
            "/admin/survey/responses",
            get(routes::survey::admin_list_responses),
        )
        .route(
            "/admin/survey/responses/{pubkey}",
            get(routes::survey::admin_get_response_for_pubkey),
        )
        // ---- Forum ----
        // Search must be registered before /:post_id so axum doesn't match "search"
        // as a path parameter.
        .route(
            "/channels/{channel_id}/posts/search",
            get(routes::posts::search_posts),
        )
        .route(
            "/channels/{channel_id}/posts",
            get(routes::posts::list_posts).post(routes::posts::create_post),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}",
            get(routes::posts::get_post)
                .patch(routes::posts::edit_post)
                .delete(routes::posts::delete_post),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/replies",
            post(routes::posts::create_reply),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}",
            patch(routes::posts::edit_reply).delete(routes::posts::delete_reply),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/pin",
            post(routes::posts::pin_post).delete(routes::posts::unpin_post),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/lock",
            post(routes::posts::lock_post).delete(routes::posts::unlock_post),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/read",
            post(routes::posts::mark_post_read),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/reactions",
            post(routes::posts::add_post_reaction),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/reactions/{emoji}",
            delete(routes::posts::remove_post_reaction),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}/reactions",
            post(routes::posts::add_reply_reaction),
        )
        .route(
            "/channels/{channel_id}/posts/{post_id}/replies/{reply_id}/reactions/{emoji}",
            delete(routes::posts::remove_reply_reaction),
        )
        // ---- Recovery contacts (Task #24) ----
        .route(
            "/recovery/contacts",
            put(routes::recovery::put_contacts).get(routes::recovery::get_contacts),
        )
        .route(
            "/recovery/contacts/{pubkey}",
            delete(routes::recovery::delete_contact),
        )
        .route(
            "/recovery/rotate-key",
            post(routes::recovery::post_rotate_key),
        )
        .route("/recovery/requests", get(routes::recovery::get_my_requests))
        .route(
            "/admin/recovery/pending",
            get(routes::recovery::admin_list_pending),
        )
        .route(
            "/admin/recovery/{id}/approve",
            post(routes::recovery::admin_approve),
        )
        .route(
            "/admin/recovery/{id}/deny",
            post(routes::recovery::admin_deny),
        )
        // ---- DM block set (Task #25) ----
        .route(
            "/identity/dm-blocks",
            put(routes::identity::put_dm_blocks).get(routes::identity::get_dm_blocks),
        )
        // ---- Global message search (Task #28) ----
        .route("/search", get(routes::search::search_messages))
        // ---- Admin search reindex ----
        .route(
            "/admin/search/reindex",
            post(routes::admin_search::admin_reindex),
        )
        // ---- Custom emojis (Task #29) ----
        .route("/emojis", get(routes::emojis::list_emojis))
        .route("/emojis/{id}/image", get(routes::emojis::get_emoji_image))
        .route("/admin/emojis", post(routes::emojis::create_emoji))
        .route(
            "/admin/emojis/{id}",
            axum::routing::delete(routes::emojis::delete_emoji),
        )
        // ---- Events / calendar (Task #30) ----
        .route(
            "/events",
            post(routes::events::create_event).get(routes::events::list_events),
        )
        .route(
            "/events/{event_id}",
            get(routes::events::get_event)
                .put(routes::events::update_event)
                .delete(routes::events::delete_event),
        )
        .route("/events/{event_id}/rsvp", post(routes::events::rsvp_event))
        .route("/events/{event_id}/rsvps", get(routes::events::list_rsvps))
        .route(
            "/events/{event_id}/slots",
            post(routes::events::create_slot),
        )
        .route(
            "/events/{event_id}/slots/{slot_id}",
            patch(routes::events::update_slot).delete(routes::events::delete_slot),
        )
        .route(
            "/events/{event_id}/assignments",
            get(routes::events::list_event_assignments),
        )
        // ---- File uploads ----
        .route(
            "/channels/{channel_id}/upload",
            post(routes::uploads::upload_file),
        )
        .route("/uploads/{filename}", get(routes::uploads::serve_upload))
        // ---- Soundboard (soundboard.md §1) ----
        .route(
            "/soundboard",
            get(routes::soundboard::list_clips).post(routes::soundboard::upload_clip),
        )
        .route(
            "/soundboard/{id}",
            axum::routing::delete(routes::soundboard::delete_clip),
        )
        .route(
            "/soundboard/{id}/audio",
            get(routes::soundboard::get_clip_audio),
        )
        .route(
            "/soundboard/{id}/played",
            post(routes::soundboard::mark_played),
        )
        // ---- Message pinning ----
        .route(
            "/channels/{channel_id}/pins/{message_id}",
            post(routes::pins::pin_message).delete(routes::pins::unpin_message),
        )
        .route("/channels/{channel_id}/pins", get(routes::pins::list_pins))
        // ---- Native polls (Task #31) ----
        .route(
            "/channels/{channel_id}/polls",
            get(routes::polls::list_polls).post(routes::polls::create_poll),
        )
        .route(
            "/polls/{poll_id}",
            get(routes::polls::get_poll).delete(routes::polls::delete_poll),
        )
        .route("/polls/{poll_id}/vote", post(routes::polls::vote_poll))
        // ---- Link preview ----
        .route("/preview", get(routes::preview::get_preview))
        .layer(build_cors_layer(cors_origins))
        .layer(TraceLayer::new_for_http())
        .layer(from_fn(attach_request_id))
        .with_state(state);

    // Attach the SPA fallback when a web client directory is configured.
    // All named API routes above take priority; only truly unmatched paths
    // reach the fallback.  The fallback itself is NOT a `.route()` call so
    // it does not appear in the OpenAPI coverage check.
    if let Some(cfg) = web_client {
        let fallback = crate::web_client::build_fallback(cfg);
        api_router.fallback_service(fallback)
    } else {
        api_router
    }
}
