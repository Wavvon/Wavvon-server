use async_trait::async_trait;
use crate::error::StoreError;
use crate::row_types::{HubEventRow, EventRsvpRow};

#[async_trait]
pub trait EventStore: Send + Sync {
    async fn create_event(&self, e: &HubEventRow) -> Result<(), StoreError>;

    async fn get_event(&self, id: &str) -> Result<Option<HubEventRow>, StoreError>;

    async fn list_events(&self, channel_id: &str) -> Result<Vec<HubEventRow>, StoreError>;

    async fn delete_event(&self, id: &str) -> Result<(), StoreError>;

    async fn upsert_rsvp(&self, r: &EventRsvpRow) -> Result<(), StoreError>;

    async fn list_rsvps(&self, event_id: &str) -> Result<Vec<EventRsvpRow>, StoreError>;

    async fn delete_rsvp(&self, event_id: &str, user_pubkey: &str) -> Result<(), StoreError>;
}
