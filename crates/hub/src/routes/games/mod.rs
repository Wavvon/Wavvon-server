mod admin;
mod helpers;
mod models;
mod session_v1;
mod session_v2;

// Re-export all public items so server.rs paths remain unchanged.
pub use admin::{
    admin_list_games, disable_game, enable_game, install_game, list_enabled_games,
    set_game_channels, set_game_permissions,
};
pub use models::{
    AdminGameEntry, AdminListGamesResponse, CreateSessionRequest, CreateSessionV2Request,
    EnabledGameEntry, InstallGameRequest, InstalledGameResponse, KvResponse,
    ListEnabledGamesResponse, ListSessionsQuery, ListSessionsResponse, PatchStateRequest,
    PlayerInfo, SessionResponse, SessionV2Response, SetChannelScopeRequest, SetKvRequest,
    SetPermissionsRequest,
};
pub use session_v1::{
    create_session, end_session, get_session, get_shared_kv, join_session, patch_state,
    set_shared_kv,
};
pub use session_v2::{
    create_session_v2, force_end_session, get_session_v2, join_session_v2, leave_session,
    list_sessions,
};
