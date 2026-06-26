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

/// The combined store bound used for `Arc<dyn HubStore>`.
///
/// `Transactional` is intentionally excluded here because its generic `T`
/// parameter makes it non-dyn-compatible (object-safe). Callers that need
/// transactions hold a concrete `&SqliteStore` (or another concrete backend)
/// and call `with_transaction` directly.
///
/// Route handlers hold `Arc<dyn HubStore>` and call any trait method without
/// caring which backend is active. The blanket impl below means any type
/// that satisfies all the component traits automatically satisfies `HubStore`.
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
