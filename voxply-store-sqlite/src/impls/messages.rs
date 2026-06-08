use async_trait::async_trait;
use sqlx::Row;
use voxply_store::{MessageRow, MessageStore, NewMessage, PinRow, StoreError};

use crate::error_map::map_err;
use crate::SqliteStore;

fn row_to_message(r: sqlx::any::AnyRow) -> MessageRow {
    MessageRow {
        id: r.get("id"),
        channel_id: r.get("channel_id"),
        sender: r.get("sender"),
        sender_name: r.get("sender_name"),
        content: r.get("content"),
        attachments: r.get("attachments"),
        reply_to: r.get("reply_to"),
        created_at: r.get("created_at"),
        edited_at: r.get("edited_at"),
        reply_count: r.get("reply_count"),
        visible_to_pubkey: r.try_get("visible_to_pubkey").ok().flatten(),
        embeds: r.try_get("embeds").ok().flatten(),
    }
}

const MSG_SELECT: &str =
    "SELECT m.id, m.channel_id, m.sender, u.display_name AS sender_name,
            m.content, m.attachments, m.reply_to, m.created_at, m.edited_at,
            COALESCE(m.reply_count, 0) AS reply_count,
            m.visible_to_pubkey, m.embeds
     FROM messages m LEFT JOIN users u ON m.sender = u.public_key";

#[async_trait]
impl MessageStore for SqliteStore {
    async fn insert_message(&self, m: &NewMessage) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO messages
             (id, channel_id, sender, content, attachments, reply_to, created_at, visible_to_pubkey)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&m.id)
        .bind(&m.channel_id)
        .bind(&m.sender)
        .bind(&m.content)
        .bind(&m.attachments)
        .bind(&m.reply_to)
        .bind(m.created_at)
        .bind(&m.visible_to_pubkey)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_message(&self, id: &str) -> Result<Option<MessageRow>, StoreError> {
        let sql = format!("{MSG_SELECT} WHERE m.id = ?");
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_err)?;
        Ok(row.map(row_to_message))
    }

    async fn page_messages(
        &self,
        channel_id: &str,
        before: Option<&str>,
        limit: i64,
    ) -> Result<Vec<MessageRow>, StoreError> {
        let rows = if let Some(before_id) = before {
            let sql = format!(
                "{MSG_SELECT}
                 WHERE m.channel_id = ? AND m.rowid < (SELECT rowid FROM messages WHERE id = ?)
                 ORDER BY m.created_at DESC, m.rowid DESC LIMIT ?"
            );
            sqlx::query(&sql)
                .bind(channel_id)
                .bind(before_id)
                .bind(limit)
                .fetch_all(self.pool())
                .await
                .map_err(map_err)?
        } else {
            let sql = format!(
                "{MSG_SELECT}
                 WHERE m.channel_id = ?
                 ORDER BY m.created_at DESC, m.rowid DESC LIMIT ?"
            );
            sqlx::query(&sql)
                .bind(channel_id)
                .bind(limit)
                .fetch_all(self.pool())
                .await
                .map_err(map_err)?
        };
        Ok(rows.into_iter().map(row_to_message).collect())
    }

    async fn thread_messages(
        &self,
        channel_id: &str,
        root_id: &str,
        limit: i64,
    ) -> Result<Vec<MessageRow>, StoreError> {
        let sql = format!(
            "{MSG_SELECT}
             WHERE m.channel_id = ? AND m.reply_to = ?
             ORDER BY m.created_at ASC, m.rowid ASC LIMIT ?"
        );
        let rows = sqlx::query(&sql)
            .bind(channel_id)
            .bind(root_id)
            .bind(limit)
            .fetch_all(self.pool())
            .await
            .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_message).collect())
    }

    async fn messages_by_ids(&self, ids: &[String]) -> Result<Vec<MessageRow>, StoreError> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let placeholders = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "{MSG_SELECT}
             WHERE m.id IN ({placeholders})
             ORDER BY m.created_at DESC, m.rowid DESC"
        );
        let mut q = sqlx::query(&sql);
        for id in ids {
            q = q.bind(id);
        }
        let rows = q.fetch_all(self.pool()).await.map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_message).collect())
    }

    async fn edit_message(&self, id: &str, content: &str, edited_at: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE messages SET content = ?, edited_at = ? WHERE id = ?")
            .bind(content)
            .bind(edited_at)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete_message(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM messages WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn increment_reply_count(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE messages SET reply_count = COALESCE(reply_count, 0) + 1 WHERE id = ?",
        )
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn decrement_reply_count(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE messages SET reply_count = MAX(0, COALESCE(reply_count, 0) - 1) WHERE id = ?",
        )
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn add_reaction(
        &self,
        message_id: &str,
        emoji: &str,
        user: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO message_reactions (message_id, emoji, user_key, created_at)
             VALUES (?, ?, ?, ?) ON CONFLICT (message_id, emoji, user_key) DO NOTHING",
        )
        .bind(message_id)
        .bind(emoji)
        .bind(user)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remove_reaction(
        &self,
        message_id: &str,
        emoji: &str,
        user: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM message_reactions WHERE message_id = ? AND emoji = ? AND user_key = ?",
        )
        .bind(message_id)
        .bind(emoji)
        .bind(user)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn reaction_summary(
        &self,
        message_id: &str,
        viewer: &str,
    ) -> Result<Vec<(String, i64, bool)>, StoreError> {
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT emoji, COUNT(*) as cnt,
                    MAX(CASE WHEN user_key = ? THEN 1 ELSE 0 END) as mine
             FROM message_reactions
             WHERE message_id = ?
             GROUP BY emoji
             ORDER BY MIN(created_at) ASC",
        )
        .bind(viewer)
        .bind(message_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(|(e, c, m)| (e, c, m != 0)).collect())
    }

    async fn reaction_summary_anon(
        &self,
        message_id: &str,
    ) -> Result<Vec<(String, i64)>, StoreError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT emoji, COUNT(*) as cnt
             FROM message_reactions
             WHERE message_id = ?
             GROUP BY emoji
             ORDER BY MIN(created_at) ASC",
        )
        .bind(message_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows)
    }

    async fn pin_message(
        &self,
        channel_id: &str,
        message_id: &str,
        pinned_by: &str,
        pinned_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO channel_pins (channel_id, message_id, pinned_by, pinned_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(channel_id, message_id) DO NOTHING",
        )
        .bind(channel_id)
        .bind(message_id)
        .bind(pinned_by)
        .bind(pinned_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn unpin_message(&self, channel_id: &str, message_id: &str) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM channel_pins WHERE channel_id = ? AND message_id = ?",
        )
        .bind(channel_id)
        .bind(message_id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_pins(&self, channel_id: &str) -> Result<Vec<PinRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT channel_id, message_id, pinned_by, pinned_at
             FROM channel_pins WHERE channel_id = ? ORDER BY pinned_at DESC",
        )
        .bind(channel_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| PinRow {
                channel_id: r.get("channel_id"),
                message_id: r.get("message_id"),
                pinned_by: r.get("pinned_by"),
                pinned_at: r.get("pinned_at"),
            })
            .collect())
    }
}
