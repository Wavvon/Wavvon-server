use crate::error::StoreError;
use crate::row_types::{BadgeOfferRow, HubBadgeRow, IssuedBadgeRow};
use async_trait::async_trait;

#[async_trait]
pub trait BadgeStore: Send + Sync {
    // ---- Badge offers (incoming from remote hubs) ----

    async fn insert_badge_offer(&self, b: &BadgeOfferRow) -> Result<(), StoreError>;

    async fn list_badge_offers(&self) -> Result<Vec<BadgeOfferRow>, StoreError>;

    async fn delete_badge_offer(&self, id: &str) -> Result<(), StoreError>;

    // ---- Accepted badges ----

    async fn accept_badge(&self, b: &HubBadgeRow) -> Result<(), StoreError>;

    async fn list_hub_badges(&self) -> Result<Vec<HubBadgeRow>, StoreError>;

    async fn revoke_hub_badge(&self, id: &str) -> Result<(), StoreError>;

    // ---- Issued badges (sent to remote hubs) ----

    async fn insert_issued_badge(&self, b: &IssuedBadgeRow) -> Result<(), StoreError>;

    async fn list_issued_badges(&self) -> Result<Vec<IssuedBadgeRow>, StoreError>;

    async fn revoke_issued_badge(&self, id: &str, revoked_at: &str) -> Result<(), StoreError>;
}
