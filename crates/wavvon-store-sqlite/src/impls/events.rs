use async_trait::async_trait;
use sqlx::Row;
use wavvon_store::{EventRsvpRow, EventStore, HubEventRow, StoreError};

use crate::error_map::map_err;
use crate::SqliteStore;

fn row_to_event(r: sqlx::any::AnyRow) -> HubEventRow {
    HubEventRow {
        id: r.get("id"),
        channel_id: r.get("channel_id"),
        creator_pubkey: r.get("creator_pubkey"),
        title: r.get("title"),
        description: r.get("description"),
        starts_at: r.get("starts_at"),
        ends_at: r.get("ends_at"),
        location: r.get("location"),
        created_at: r.get("created_at"),
    }
}

#[async_trait]
impl EventStore for SqliteStore {
    async fn create_event(&self, e: &HubEventRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO hub_events
             (id, channel_id, creator_pubkey, title, description, starts_at, ends_at, location, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&e.id)
        .bind(&e.channel_id)
        .bind(&e.creator_pubkey)
        .bind(&e.title)
        .bind(&e.description)
        .bind(e.starts_at)
        .bind(e.ends_at)
        .bind(&e.location)
        .bind(e.created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_event(&self, id: &str) -> Result<Option<HubEventRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, channel_id, creator_pubkey, title, description,
                    starts_at, ends_at, location, created_at
             FROM hub_events WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_event))
    }

    async fn list_events(&self, channel_id: &str) -> Result<Vec<HubEventRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, channel_id, creator_pubkey, title, description,
                    starts_at, ends_at, location, created_at
             FROM hub_events WHERE channel_id = ? ORDER BY starts_at ASC",
        )
        .bind(channel_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_event).collect())
    }

    async fn delete_event(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM hub_events WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn upsert_rsvp(&self, r: &EventRsvpRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO event_rsvps (event_id, user_pubkey, status) VALUES (?, ?, ?)
             ON CONFLICT(event_id, user_pubkey) DO UPDATE SET status = excluded.status",
        )
        .bind(&r.event_id)
        .bind(&r.user_pubkey)
        .bind(&r.status)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_rsvps(&self, event_id: &str) -> Result<Vec<EventRsvpRow>, StoreError> {
        let rows =
            sqlx::query("SELECT event_id, user_pubkey, status FROM event_rsvps WHERE event_id = ?")
                .bind(event_id)
                .fetch_all(self.pool())
                .await
                .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| EventRsvpRow {
                event_id: r.get("event_id"),
                user_pubkey: r.get("user_pubkey"),
                status: r.get("status"),
            })
            .collect())
    }

    async fn delete_rsvp(&self, event_id: &str, user_pubkey: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM event_rsvps WHERE event_id = ? AND user_pubkey = ?")
            .bind(event_id)
            .bind(user_pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }
}
