use async_trait::async_trait;
use sqlx::Row;
use voxply_store::{BadgeOfferRow, BadgeStore, HubBadgeRow, IssuedBadgeRow, StoreError};

use crate::error_map::map_err;
use crate::SqliteStore;

#[async_trait]
impl BadgeStore for SqliteStore {
    async fn insert_badge_offer(&self, b: &BadgeOfferRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO badge_offers
             (id, from_hub_pubkey, from_hub_url, label, note, payload, signature, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&b.id)
        .bind(&b.from_hub_pubkey)
        .bind(&b.from_hub_url)
        .bind(&b.label)
        .bind(&b.note)
        .bind(&b.payload)
        .bind(&b.signature)
        .bind(&b.created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_badge_offers(&self) -> Result<Vec<BadgeOfferRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, from_hub_pubkey, from_hub_url, label, note, payload, signature, created_at
             FROM badge_offers ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| BadgeOfferRow {
                id: r.get("id"),
                from_hub_pubkey: r.get("from_hub_pubkey"),
                from_hub_url: r.get("from_hub_url"),
                label: r.get("label"),
                note: r.get("note"),
                payload: r.get("payload"),
                signature: r.get("signature"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn delete_badge_offer(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM badge_offers WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn accept_badge(&self, b: &HubBadgeRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO hub_badges
             (id, issuer_pubkey, issuer_url, label, payload, signature, accepted_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&b.id)
        .bind(&b.issuer_pubkey)
        .bind(&b.issuer_url)
        .bind(&b.label)
        .bind(&b.payload)
        .bind(&b.signature)
        .bind(&b.accepted_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_hub_badges(&self) -> Result<Vec<HubBadgeRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, issuer_pubkey, issuer_url, label, payload, signature, accepted_at
             FROM hub_badges ORDER BY accepted_at DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| HubBadgeRow {
                id: r.get("id"),
                issuer_pubkey: r.get("issuer_pubkey"),
                issuer_url: r.get("issuer_url"),
                label: r.get("label"),
                payload: r.get("payload"),
                signature: r.get("signature"),
                accepted_at: r.get("accepted_at"),
            })
            .collect())
    }

    async fn revoke_hub_badge(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM hub_badges WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn insert_issued_badge(&self, b: &IssuedBadgeRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO issued_badges
             (id, recipient_hub_url, recipient_hub_pubkey, label, payload,
              signature, issued_at, expires_at, revoked_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&b.id)
        .bind(&b.recipient_hub_url)
        .bind(&b.recipient_hub_pubkey)
        .bind(&b.label)
        .bind(&b.payload)
        .bind(&b.signature)
        .bind(&b.issued_at)
        .bind(&b.expires_at)
        .bind(&b.revoked_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_issued_badges(&self) -> Result<Vec<IssuedBadgeRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, recipient_hub_url, recipient_hub_pubkey, label, payload,
                    signature, issued_at, expires_at, revoked_at
             FROM issued_badges ORDER BY issued_at DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| IssuedBadgeRow {
                id: r.get("id"),
                recipient_hub_url: r.get("recipient_hub_url"),
                recipient_hub_pubkey: r.get("recipient_hub_pubkey"),
                label: r.get("label"),
                payload: r.get("payload"),
                signature: r.get("signature"),
                issued_at: r.get("issued_at"),
                expires_at: r.get("expires_at"),
                revoked_at: r.get("revoked_at"),
            })
            .collect())
    }

    async fn revoke_issued_badge(&self, id: &str, revoked_at: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE issued_badges SET revoked_at = ? WHERE id = ?",
        )
        .bind(revoked_at)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }
}
