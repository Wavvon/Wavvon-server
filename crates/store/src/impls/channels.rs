use crate::{ChannelPatch, ChannelRow, ChannelStore, NewChannel, StoreError};
use async_trait::async_trait;
use sqlx::Row;

use crate::error_map::map_err;
use crate::PostgresStore;

fn row_to_channel(r: sqlx::postgres::PgRow) -> ChannelRow {
    ChannelRow {
        id: r.get("id"),
        name: r.get("name"),
        created_by: r.get("created_by"),
        parent_id: r.get("parent_id"),
        // PostgreSQL BOOLEAN → i64 for ChannelRow compatibility
        is_category: if r.get::<bool, _>("is_category") {
            1
        } else {
            0
        },
        display_order: r.get("display_order"),
        description: r.get("description"),
        icon: r.get("icon"),
        color: r.get("color"),
        custom_icon_svg: r.get("custom_icon_svg"),
        created_at: r.get("created_at"),
        channel_type: r.get("channel_type"),
        banner_url: r.get("banner_url"),
        banner_file_id: r.get("banner_file_id"),
        min_talk_power: r.get("min_talk_power"),
        retention_days: r.get("retention_days"),
    }
}

#[async_trait]
impl ChannelStore for PostgresStore {
    async fn create_channel(&self, ch: &NewChannel) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO channels
             (id, name, created_by, parent_id, is_category, display_order,
              description, channel_type, created_at, banner_url, banner_file_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&ch.id)
        .bind(&ch.name)
        .bind(&ch.created_by)
        .bind(&ch.parent_id)
        .bind(ch.is_category)
        .bind(ch.display_order)
        .bind(&ch.description)
        .bind(&ch.channel_type)
        .bind(ch.created_at)
        .bind(&ch.banner_url)
        .bind(&ch.banner_file_id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_channel(&self, id: &str) -> Result<Option<ChannelRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, name, created_by, parent_id, is_category, display_order,
                    description, icon, color, custom_icon_svg, created_at, channel_type,
                    banner_url, banner_file_id, min_talk_power, retention_days
             FROM channels WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_channel))
    }

    async fn list_channels(&self) -> Result<Vec<ChannelRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, name, created_by, parent_id, is_category, display_order,
                    description, icon, color, custom_icon_svg, created_at, channel_type,
                    banner_url, banner_file_id, min_talk_power, retention_days
             FROM channels ORDER BY display_order, created_at",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_channel).collect())
    }

    async fn update_channel(&self, id: &str, patch: &ChannelPatch) -> Result<(), StoreError> {
        let mut parts: Vec<&str> = Vec::new();
        if let Some(opt) = &patch.description {
            sqlx::query("UPDATE channels SET description = $1 WHERE id = $2")
                .bind(opt.as_deref())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("description");
        }
        if let Some(opt) = &patch.icon {
            sqlx::query("UPDATE channels SET icon = $1 WHERE id = $2")
                .bind(opt.as_deref())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("icon");
        }
        if let Some(opt) = &patch.color {
            sqlx::query("UPDATE channels SET color = $1 WHERE id = $2")
                .bind(opt.as_deref())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("color");
        }
        if let Some(opt) = &patch.custom_icon_svg {
            sqlx::query("UPDATE channels SET custom_icon_svg = $1 WHERE id = $2")
                .bind(opt.as_deref())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("custom_icon_svg");
        }
        if let Some(opt) = &patch.parent_id {
            sqlx::query("UPDATE channels SET parent_id = $1 WHERE id = $2")
                .bind(opt.as_deref())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("parent_id");
        }
        if let Some(mtp) = patch.min_talk_power {
            sqlx::query("UPDATE channels SET min_talk_power = $1 WHERE id = $2")
                .bind(mtp)
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("min_talk_power");
        }
        if let Some(opt) = &patch.retention_days {
            sqlx::query("UPDATE channels SET retention_days = $1 WHERE id = $2")
                .bind(*opt)
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("retention_days");
        }
        if let Some(opt) = &patch.banner_url {
            sqlx::query("UPDATE channels SET banner_url = $1 WHERE id = $2")
                .bind(opt.as_deref())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("banner_url");
        }
        if let Some(opt) = &patch.banner_file_id {
            sqlx::query("UPDATE channels SET banner_file_id = $1 WHERE id = $2")
                .bind(opt.as_deref())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("banner_file_id");
        }
        if let Some(name) = &patch.name {
            sqlx::query("UPDATE channels SET name = $1 WHERE id = $2")
                .bind(name.as_str())
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
            parts.push("name");
        }
        let _ = parts;
        Ok(())
    }

    async fn delete_channel(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM channels WHERE id = $1")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_channel_order(&self, id: &str, order: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE channels SET display_order = $1 WHERE id = $2")
            .bind(order)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn max_channel_order(&self) -> Result<i64, StoreError> {
        sqlx::query_scalar::<_, i64>("SELECT COALESCE(MAX(display_order), -1) FROM channels")
            .fetch_one(self.pool())
            .await
            .map_err(map_err)
    }

    async fn child_count(&self, parent_id: &str) -> Result<i64, StoreError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM channels WHERE parent_id = $1")
            .bind(parent_id)
            .fetch_one(self.pool())
            .await
            .map_err(map_err)
    }

    async fn parent_id_of(&self, channel_id: &str) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar::<_, Option<String>>("SELECT parent_id FROM channels WHERE id = $1")
            .bind(channel_id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_err)
            .map(|opt| opt.flatten())
    }

    async fn list_leaf_channel_ids(&self) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>("SELECT id FROM channels WHERE is_category = FALSE")
            .fetch_all(self.pool())
            .await
            .map_err(map_err)
    }

    async fn mark_read(&self, pubkey: &str, channel_id: &str, at: i64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO channel_last_read (user_pubkey, channel_id, last_read_at)
             VALUES ($1, $2, $3)
             ON CONFLICT(user_pubkey, channel_id) DO UPDATE SET last_read_at = excluded.last_read_at",
        )
        .bind(pubkey)
        .bind(channel_id)
        .bind(at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn last_read_at(
        &self,
        pubkey: &str,
        channel_id: &str,
    ) -> Result<Option<i64>, StoreError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT last_read_at FROM channel_last_read WHERE user_pubkey = $1 AND channel_id = $2",
        )
        .bind(pubkey)
        .bind(channel_id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)
    }

    async fn unread_count(&self, channel_id: &str, after: i64) -> Result<i64, StoreError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM messages WHERE channel_id = $1 AND created_at > $2",
        )
        .bind(channel_id)
        .bind(after)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)
    }
}
