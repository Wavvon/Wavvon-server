use async_trait::async_trait;
use sqlx::Row;
use wavvon_store::{ConversationRow, DhKeyRow, DmMessageRow, DmStore, FriendRow, StoreError};

use crate::error_map::map_err;
use crate::PostgresStore;

#[async_trait]
impl DmStore for PostgresStore {
    async fn create_conversation(
        &self,
        id: &str,
        conv_type: &str,
        created_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query("INSERT INTO conversations (id, conv_type, created_at) VALUES (?, ?, ?)")
            .bind(id)
            .bind(conv_type)
            .bind(created_at)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn get_conversation(&self, id: &str) -> Result<Option<ConversationRow>, StoreError> {
        let row = sqlx::query("SELECT id, conv_type, created_at FROM conversations WHERE id = ?")
            .bind(id)
            .fetch_optional(self.pool())
            .await
            .map_err(map_err)?;
        Ok(row.map(|r| ConversationRow {
            id: r.get("id"),
            conv_type: r.get("conv_type"),
            created_at: r.get("created_at"),
        }))
    }

    async fn conversations_for_user(
        &self,
        pubkey: &str,
    ) -> Result<Vec<ConversationRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT c.id, c.conv_type, c.created_at
             FROM conversations c
             INNER JOIN conversation_members cm ON c.id = cm.conversation_id
             WHERE cm.public_key = ?
             ORDER BY c.created_at DESC",
        )
        .bind(pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| ConversationRow {
                id: r.get("id"),
                conv_type: r.get("conv_type"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn find_dm_conversation(
        &self,
        user_a: &str,
        user_b: &str,
    ) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            "SELECT c.id FROM conversations c
             INNER JOIN conversation_members ma ON c.id = ma.conversation_id AND ma.public_key = ?
             INNER JOIN conversation_members mb ON c.id = mb.conversation_id AND mb.public_key = ?
             WHERE c.conv_type = 'dm'
             LIMIT 1",
        )
        .bind(user_a)
        .bind(user_b)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)
    }

    async fn add_conversation_member(
        &self,
        conv_id: &str,
        pubkey: &str,
        joined_at: i64,
        hub_url: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO conversation_members (conversation_id, public_key, joined_at, hub_url)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(conversation_id, public_key) DO NOTHING",
        )
        .bind(conv_id)
        .bind(pubkey)
        .bind(joined_at)
        .bind(hub_url)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remove_conversation_member(
        &self,
        conv_id: &str,
        pubkey: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM conversation_members WHERE conversation_id = ? AND public_key = ?",
        )
        .bind(conv_id)
        .bind(pubkey)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn conversation_members(
        &self,
        conv_id: &str,
    ) -> Result<Vec<(String, Option<String>)>, StoreError> {
        let rows = sqlx::query(
            "SELECT public_key, hub_url FROM conversation_members WHERE conversation_id = ?",
        )
        .bind(conv_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("public_key"),
                    r.get::<Option<String>, _>("hub_url"),
                )
            })
            .collect())
    }

    async fn is_conversation_member(
        &self,
        conv_id: &str,
        pubkey: &str,
    ) -> Result<bool, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM conversation_members
             WHERE conversation_id = ? AND public_key = ?",
        )
        .bind(conv_id)
        .bind(pubkey)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)?;
        Ok(count > 0)
    }

    async fn insert_dm_message(&self, m: &DmMessageRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO dm_messages
             (id, conversation_id, sender, content, signature, created_at,
              attachments, is_encrypted, ciphertext_json, is_group_encrypted)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&m.id)
        .bind(&m.conversation_id)
        .bind(&m.sender)
        .bind(&m.content)
        .bind(&m.signature)
        .bind(m.created_at)
        .bind(&m.attachments)
        .bind(m.is_encrypted != 0)
        .bind(&m.ciphertext_json)
        .bind(m.is_group_encrypted != 0)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_dm_messages(
        &self,
        conv_id: &str,
        before_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<DmMessageRow>, StoreError> {
        // PostgreSQL has no rowid. Paginate by (created_at, id) tuple.
        let rows = if let Some(bid) = before_id {
            sqlx::query(
                "SELECT id, conversation_id, sender, content, signature, created_at,
                        attachments, is_encrypted, ciphertext_json, is_group_encrypted
                 FROM dm_messages
                 WHERE conversation_id = ?
                   AND (created_at, id) < (
                     (SELECT created_at FROM dm_messages WHERE id = ?),
                     ?
                   )
                 ORDER BY created_at DESC, id DESC LIMIT ?",
            )
            .bind(conv_id)
            .bind(bid)
            .bind(bid)
            .bind(limit)
            .fetch_all(self.pool())
            .await
            .map_err(map_err)?
        } else {
            sqlx::query(
                "SELECT id, conversation_id, sender, content, signature, created_at,
                        attachments, is_encrypted, ciphertext_json, is_group_encrypted
                 FROM dm_messages WHERE conversation_id = ?
                 ORDER BY created_at DESC, id DESC LIMIT ?",
            )
            .bind(conv_id)
            .bind(limit)
            .fetch_all(self.pool())
            .await
            .map_err(map_err)?
        };
        Ok(rows
            .into_iter()
            .map(|r| DmMessageRow {
                id: r.get("id"),
                conversation_id: r.get("conversation_id"),
                sender: r.get("sender"),
                content: r.get("content"),
                signature: r.get("signature"),
                created_at: r.get("created_at"),
                attachments: r.get("attachments"),
                // PostgreSQL BOOLEAN → i64 for DmMessageRow compatibility
                is_encrypted: if r.get::<bool, _>("is_encrypted") {
                    1
                } else {
                    0
                },
                ciphertext_json: r.get("ciphertext_json"),
                is_group_encrypted: if r.get::<bool, _>("is_group_encrypted") {
                    1
                } else {
                    0
                },
            })
            .collect())
    }

    async fn delete_dm_message(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM dm_messages WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn block_user(&self, owner: &str, blocked: &str) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO dm_blocks (owner_pubkey, blocked_pubkey) VALUES (?, ?)
             ON CONFLICT DO NOTHING",
        )
        .bind(owner)
        .bind(blocked)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn unblock_user(&self, owner: &str, blocked: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM dm_blocks WHERE owner_pubkey = ? AND blocked_pubkey = ?")
            .bind(owner)
            .bind(blocked)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn is_blocked(&self, owner: &str, blocked: &str) -> Result<bool, StoreError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dm_blocks WHERE owner_pubkey = ? AND blocked_pubkey = ?",
        )
        .bind(owner)
        .bind(blocked)
        .fetch_one(self.pool())
        .await
        .map_err(map_err)?;
        Ok(count > 0)
    }

    async fn upsert_friend(&self, f: &FriendRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO friends (user_a, user_b, status, created_at, hub_url, display_name)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(user_a, user_b) DO UPDATE SET
               status = excluded.status,
               hub_url = excluded.hub_url,
               display_name = excluded.display_name",
        )
        .bind(&f.user_a)
        .bind(&f.user_b)
        .bind(&f.status)
        .bind(f.created_at)
        .bind(&f.hub_url)
        .bind(&f.display_name)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_friend(
        &self,
        user_a: &str,
        user_b: &str,
    ) -> Result<Option<FriendRow>, StoreError> {
        let row = sqlx::query(
            "SELECT user_a, user_b, status, created_at, hub_url, display_name
             FROM friends WHERE user_a = ? AND user_b = ?",
        )
        .bind(user_a)
        .bind(user_b)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| FriendRow {
            user_a: r.get("user_a"),
            user_b: r.get("user_b"),
            status: r.get("status"),
            created_at: r.get("created_at"),
            hub_url: r.get("hub_url"),
            display_name: r.get("display_name"),
        }))
    }

    async fn list_friends(&self, pubkey: &str) -> Result<Vec<FriendRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT user_a, user_b, status, created_at, hub_url, display_name
             FROM friends WHERE user_a = ? OR user_b = ?",
        )
        .bind(pubkey)
        .bind(pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| FriendRow {
                user_a: r.get("user_a"),
                user_b: r.get("user_b"),
                status: r.get("status"),
                created_at: r.get("created_at"),
                hub_url: r.get("hub_url"),
                display_name: r.get("display_name"),
            })
            .collect())
    }

    async fn delete_friend(&self, user_a: &str, user_b: &str) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM friends WHERE (user_a = ? AND user_b = ?) OR (user_a = ? AND user_b = ?)",
        )
        .bind(user_a)
        .bind(user_b)
        .bind(user_b)
        .bind(user_a)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn upsert_dh_key(&self, k: &DhKeyRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO dh_keys (pubkey, dh_pubkey_hex, signature_hex, published_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(pubkey) DO UPDATE SET
               dh_pubkey_hex = excluded.dh_pubkey_hex,
               signature_hex = excluded.signature_hex,
               published_at = excluded.published_at",
        )
        .bind(&k.pubkey)
        .bind(&k.dh_pubkey_hex)
        .bind(&k.signature_hex)
        .bind(k.published_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_dh_key(&self, pubkey: &str) -> Result<Option<DhKeyRow>, StoreError> {
        let row = sqlx::query(
            "SELECT pubkey, dh_pubkey_hex, signature_hex, published_at
             FROM dh_keys WHERE pubkey = ?",
        )
        .bind(pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| DhKeyRow {
            pubkey: r.get("pubkey"),
            dh_pubkey_hex: r.get("dh_pubkey_hex"),
            signature_hex: r.get("signature_hex"),
            published_at: r.get("published_at"),
        }))
    }

    async fn insert_sender_key_distribution(
        &self,
        id: &str,
        conv_id: &str,
        sender_pubkey: &str,
        recipient_pubkey: &str,
        sender_key_version: i64,
        iteration: i64,
        wrapped_key_hex: &str,
        wrap_nonce_hex: &str,
        created_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO group_sender_key_distributions
             (id, conv_id, sender_pubkey, recipient_pubkey, sender_key_version,
              iteration, wrapped_key_hex, wrap_nonce_hex, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(conv_id, sender_pubkey, recipient_pubkey, sender_key_version) DO NOTHING",
        )
        .bind(id)
        .bind(conv_id)
        .bind(sender_pubkey)
        .bind(recipient_pubkey)
        .bind(sender_key_version)
        .bind(iteration)
        .bind(wrapped_key_hex)
        .bind(wrap_nonce_hex)
        .bind(created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_sender_key_distributions(
        &self,
        conv_id: &str,
        sender_pubkey: &str,
        recipient_pubkey: &str,
    ) -> Result<Vec<(i64, i64, String, String)>, StoreError> {
        let rows = sqlx::query(
            "SELECT sender_key_version, iteration, wrapped_key_hex, wrap_nonce_hex
             FROM group_sender_key_distributions
             WHERE conv_id = ? AND sender_pubkey = ? AND recipient_pubkey = ?
             ORDER BY sender_key_version DESC, iteration DESC",
        )
        .bind(conv_id)
        .bind(sender_pubkey)
        .bind(recipient_pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("sender_key_version"),
                    r.get::<i64, _>("iteration"),
                    r.get::<String, _>("wrapped_key_hex"),
                    r.get::<String, _>("wrap_nonce_hex"),
                )
            })
            .collect())
    }

    async fn insert_dm_outbox_entry(
        &self,
        message_id: &str,
        recipient_hub_url: &str,
        next_attempt_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO dm_outbox (message_id, recipient_hub_url, attempts, next_attempt_at)
             VALUES (?, ?, 0, ?)",
        )
        .bind(message_id)
        .bind(recipient_hub_url)
        .bind(next_attempt_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn pending_dm_outbox(
        &self,
        now: i64,
        limit: i64,
    ) -> Result<Vec<(String, String, i64)>, StoreError> {
        let rows = sqlx::query(
            "SELECT message_id, recipient_hub_url, attempts
             FROM dm_outbox
             WHERE bounced_at IS NULL AND next_attempt_at <= ?
             ORDER BY next_attempt_at ASC LIMIT ?",
        )
        .bind(now)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("message_id"),
                    r.get::<String, _>("recipient_hub_url"),
                    r.get::<i64, _>("attempts"),
                )
            })
            .collect())
    }

    async fn mark_dm_outbox_delivered(
        &self,
        message_id: &str,
        hub_url: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM dm_outbox WHERE message_id = ? AND recipient_hub_url = ?")
            .bind(message_id)
            .bind(hub_url)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn record_dm_outbox_failure(
        &self,
        message_id: &str,
        hub_url: &str,
        error: &str,
        next_attempt_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE dm_outbox SET attempts = attempts + 1, last_error = ?, next_attempt_at = ?
             WHERE message_id = ? AND recipient_hub_url = ?",
        )
        .bind(error)
        .bind(next_attempt_at)
        .bind(message_id)
        .bind(hub_url)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }
}
