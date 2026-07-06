// ── abstract layer (was wavvon-store) ──────────────────────────────────────
pub mod error;
pub mod row_types;
pub mod traits;

pub use error::StoreError;
pub use row_types::*;

pub use traits::auth::AuthStore;
pub use traits::badges::BadgeStore;
pub use traits::bots::BotStore;
pub use traits::certs::CertStore;
pub use traits::channels::ChannelStore;
pub use traits::dms::DmStore;
pub use traits::events::EventStore;
pub use traits::federation::FederationStore;
pub use traits::invites::InviteStore;
pub use traits::messages::MessageStore;
pub use traits::migrate::Migrate;
pub use traits::moderation::ModerationStore;
pub use traits::polls::PollStore;
pub use traits::recovery::RecoveryStore;
pub use traits::roles::RoleStore;
pub use traits::settings::SettingsStore;
pub use traits::transactional::Transactional;
pub use traits::uploads::UploadStore;
pub use traits::users::UserStore;

pub trait HubStore:
    AuthStore
    + UserStore
    + ChannelStore
    + MessageStore
    + RoleStore
    + InviteStore
    + ModerationStore
    + SettingsStore
    + BotStore
    + DmStore
    + FederationStore
    + PollStore
    + EventStore
    + CertStore
    + BadgeStore
    + RecoveryStore
    + UploadStore
    + Migrate
    + Send
    + Sync
{
}

impl<T> HubStore for T where
    T: AuthStore
        + UserStore
        + ChannelStore
        + MessageStore
        + RoleStore
        + InviteStore
        + ModerationStore
        + SettingsStore
        + BotStore
        + DmStore
        + FederationStore
        + PollStore
        + EventStore
        + CertStore
        + BadgeStore
        + RecoveryStore
        + UploadStore
        + Migrate
        + Send
        + Sync
{
}

// ── concrete PostgreSQL implementation (was wavvon-store-postgres) ─────────
mod error_map;
mod impls;
pub mod migrations;

use sqlx::PgPool;

/// PostgreSQL implementation of all `HubStore` traits.
pub struct PostgresStore(pub PgPool);

impl PostgresStore {
    pub fn new(pool: PgPool) -> Self {
        Self(pool)
    }

    pub fn pool(&self) -> &PgPool {
        &self.0
    }
}
