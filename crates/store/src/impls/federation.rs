use crate::{AllianceRow, FederatedChannelRow, FederationStore, PeerRow, StoreError};
use async_trait::async_trait;
use sqlx::Row;

use crate::error_map::map_err;
use crate::PostgresStore;

#[async_trait]
impl FederationStore for PostgresStore {
    async fn upsert_peer(&self, p: &PeerRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO peers (public_key, name, url, added_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT(public_key) DO UPDATE SET name = excluded.name, url = excluded.url",
        )
        .bind(&p.public_key)
        .bind(&p.name)
        .bind(&p.url)
        .bind(p.added_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_peer(&self, public_key: &str) -> Result<Option<PeerRow>, StoreError> {
        let row =
            sqlx::query("SELECT public_key, name, url, added_at FROM peers WHERE public_key = $1")
                .bind(public_key)
                .fetch_optional(self.pool())
                .await
                .map_err(map_err)?;
        Ok(row.map(|r| PeerRow {
            public_key: r.get("public_key"),
            name: r.get("name"),
            url: r.get("url"),
            added_at: r.get("added_at"),
        }))
    }

    async fn list_peers(&self) -> Result<Vec<PeerRow>, StoreError> {
        let rows =
            sqlx::query("SELECT public_key, name, url, added_at FROM peers ORDER BY added_at DESC")
                .fetch_all(self.pool())
                .await
                .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| PeerRow {
                public_key: r.get("public_key"),
                name: r.get("name"),
                url: r.get("url"),
                added_at: r.get("added_at"),
            })
            .collect())
    }

    async fn delete_peer(&self, public_key: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM peers WHERE public_key = $1")
            .bind(public_key)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn upsert_federated_channel(&self, ch: &FederatedChannelRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO federated_channels
             (id, peer_public_key, remote_id, name, created_at, last_synced_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT(peer_public_key, remote_id) DO UPDATE SET
               name = excluded.name,
               last_synced_at = excluded.last_synced_at",
        )
        .bind(&ch.id)
        .bind(&ch.peer_public_key)
        .bind(&ch.remote_id)
        .bind(&ch.name)
        .bind(ch.created_at)
        .bind(ch.last_synced_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_federated_channels(
        &self,
        peer_pubkey: &str,
    ) -> Result<Vec<FederatedChannelRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, peer_public_key, remote_id, name, created_at, last_synced_at
             FROM federated_channels WHERE peer_public_key = $1",
        )
        .bind(peer_pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| FederatedChannelRow {
                id: r.get("id"),
                peer_public_key: r.get("peer_public_key"),
                remote_id: r.get("remote_id"),
                name: r.get("name"),
                created_at: r.get("created_at"),
                last_synced_at: r.get("last_synced_at"),
            })
            .collect())
    }

    async fn get_federated_channel(
        &self,
        peer_pubkey: &str,
        remote_id: &str,
    ) -> Result<Option<FederatedChannelRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, peer_public_key, remote_id, name, created_at, last_synced_at
             FROM federated_channels
             WHERE peer_public_key = $1 AND remote_id = $2",
        )
        .bind(peer_pubkey)
        .bind(remote_id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| FederatedChannelRow {
            id: r.get("id"),
            peer_public_key: r.get("peer_public_key"),
            remote_id: r.get("remote_id"),
            name: r.get("name"),
            created_at: r.get("created_at"),
            last_synced_at: r.get("last_synced_at"),
        }))
    }

    async fn create_alliance(
        &self,
        id: &str,
        name: &str,
        created_by: &str,
        created_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO alliances (id, name, created_by, created_at) VALUES ($1, $2, $3, $4)",
        )
        .bind(id)
        .bind(name)
        .bind(created_by)
        .bind(created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_alliance(&self, id: &str) -> Result<Option<AllianceRow>, StoreError> {
        let row =
            sqlx::query("SELECT id, name, created_by, created_at FROM alliances WHERE id = $1")
                .bind(id)
                .fetch_optional(self.pool())
                .await
                .map_err(map_err)?;
        Ok(row.map(|r| AllianceRow {
            id: r.get("id"),
            name: r.get("name"),
            created_by: r.get("created_by"),
            created_at: r.get("created_at"),
        }))
    }

    async fn list_alliances(&self) -> Result<Vec<AllianceRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, name, created_by, created_at FROM alliances ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| AllianceRow {
                id: r.get("id"),
                name: r.get("name"),
                created_by: r.get("created_by"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn add_alliance_member(
        &self,
        alliance_id: &str,
        hub_public_key: &str,
        hub_name: &str,
        hub_url: &str,
        joined_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO alliance_members
             (alliance_id, hub_public_key, hub_name, hub_url, joined_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(alliance_id, hub_public_key) DO UPDATE SET
               hub_name = excluded.hub_name, hub_url = excluded.hub_url",
        )
        .bind(alliance_id)
        .bind(hub_public_key)
        .bind(hub_name)
        .bind(hub_url)
        .bind(joined_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remove_alliance_member(
        &self,
        alliance_id: &str,
        hub_public_key: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM alliance_members WHERE alliance_id = $1 AND hub_public_key = $2")
            .bind(alliance_id)
            .bind(hub_public_key)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn list_alliance_members(
        &self,
        alliance_id: &str,
    ) -> Result<Vec<(String, String, String)>, StoreError> {
        let rows = sqlx::query(
            "SELECT hub_public_key, hub_name, hub_url
             FROM alliance_members WHERE alliance_id = $1",
        )
        .bind(alliance_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("hub_public_key"),
                    r.get::<String, _>("hub_name"),
                    r.get::<String, _>("hub_url"),
                )
            })
            .collect())
    }

    async fn create_pending_alliance_invite(
        &self,
        id: &str,
        alliance_id: &str,
        alliance_name: &str,
        from_hub_url: &str,
        from_hub_name: &str,
        from_hub_public_key: &str,
        invite_token: &str,
        created_at: i64,
        message: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO pending_alliance_invites
             (id, alliance_id, alliance_name, from_hub_url, from_hub_name,
              from_hub_public_key, invite_token, created_at, message)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(alliance_id)
        .bind(alliance_name)
        .bind(from_hub_url)
        .bind(from_hub_name)
        .bind(from_hub_public_key)
        .bind(invite_token)
        .bind(created_at)
        .bind(message)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_pending_alliance_invites(&self) -> Result<Vec<AllianceRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, alliance_name, from_hub_public_key, created_at
             FROM pending_alliance_invites ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| AllianceRow {
                id: r.get("id"),
                name: r.get("alliance_name"),
                created_by: r.get("from_hub_public_key"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn delete_pending_alliance_invite(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM pending_alliance_invites WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn upsert_home_hub(
        &self,
        master_pubkey: &str,
        hubs_json: &str,
        issued_at: i64,
        sequence: i64,
        signature: &str,
        updated_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO home_hub_designations
             (master_pubkey, hubs_json, issued_at, sequence, signature, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT(master_pubkey) DO UPDATE SET
               hubs_json = excluded.hubs_json,
               issued_at = excluded.issued_at,
               sequence = excluded.sequence,
               signature = excluded.signature,
               updated_at = excluded.updated_at",
        )
        .bind(master_pubkey)
        .bind(hubs_json)
        .bind(issued_at)
        .bind(sequence)
        .bind(signature)
        .bind(updated_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_home_hub(
        &self,
        master_pubkey: &str,
    ) -> Result<Option<(String, i64, i64, String)>, StoreError> {
        let row = sqlx::query(
            "SELECT hubs_json, issued_at, sequence, signature
             FROM home_hub_designations WHERE master_pubkey = $1",
        )
        .bind(master_pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| {
            (
                r.get::<String, _>("hubs_json"),
                r.get::<i64, _>("issued_at"),
                r.get::<i64, _>("sequence"),
                r.get::<String, _>("signature"),
            )
        }))
    }

    async fn upsert_public_hub_profile(
        &self,
        pubkey: &str,
        profile_json: &str,
        updated_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO public_hub_profiles (pubkey, profile_json, updated_at)
             VALUES ($1, $2, $3)
             ON CONFLICT(pubkey) DO UPDATE SET
               profile_json = excluded.profile_json,
               updated_at = excluded.updated_at",
        )
        .bind(pubkey)
        .bind(profile_json)
        .bind(updated_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_public_hub_profile(
        &self,
        pubkey: &str,
    ) -> Result<Option<(String, i64)>, StoreError> {
        let row = sqlx::query(
            "SELECT profile_json, updated_at FROM public_hub_profiles WHERE pubkey = $1",
        )
        .bind(pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| {
            (
                r.get::<String, _>("profile_json"),
                r.get::<i64, _>("updated_at"),
            )
        }))
    }
}
