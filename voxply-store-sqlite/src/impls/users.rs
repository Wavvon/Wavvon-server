use std::collections::HashMap;

use async_trait::async_trait;
use sqlx::Row;
use voxply_store::{StoreError, UserRow, UserStore};

use crate::error_map::map_err;
use crate::SqliteStore;

#[async_trait]
impl UserStore for SqliteStore {
    async fn upsert_user(&self, pubkey: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO users (public_key, first_seen_at, last_seen_at)
             VALUES (?, ?, ?)
             ON CONFLICT(public_key) DO UPDATE SET last_seen_at = excluded.last_seen_at",
        )
        .bind(pubkey)
        .bind(now)
        .bind(now)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_user(&self, pubkey: &str) -> Result<Option<UserRow>, StoreError> {
        let row = sqlx::query(
            "SELECT public_key, display_name, first_seen_at, last_seen_at, approval_status,
                    avatar, master_pubkey, is_bot, is_bot_removed, bot_invite_token,
                    bot_invite_expires, is_webhook, lobby_status, lobby_entered_at, pow_level
             FROM users WHERE public_key = ?",
        )
        .bind(pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;

        Ok(row.map(|r| UserRow {
            public_key: r.get("public_key"),
            display_name: r.get("display_name"),
            first_seen_at: r.get("first_seen_at"),
            last_seen_at: r.get("last_seen_at"),
            approval_status: r.get("approval_status"),
            avatar: r.get("avatar"),
            master_pubkey: r.get("master_pubkey"),
            is_bot: r.get("is_bot"),
            is_bot_removed: r.get("is_bot_removed"),
            bot_invite_token: r.get("bot_invite_token"),
            bot_invite_expires: r.get("bot_invite_expires"),
            is_webhook: r.get("is_webhook"),
            lobby_status: r.get("lobby_status"),
            lobby_entered_at: r.get("lobby_entered_at"),
            pow_level: r.get("pow_level"),
        }))
    }

    async fn set_display_name(&self, pubkey: &str, name: Option<&str>) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET display_name = ? WHERE public_key = ?")
            .bind(name)
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_approval_status(&self, pubkey: &str, status: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET approval_status = ? WHERE public_key = ?")
            .bind(status)
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn list_members(&self, limit: i64, offset: i64) -> Result<Vec<UserRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT public_key, display_name, first_seen_at, last_seen_at, approval_status,
                    avatar, master_pubkey, is_bot, is_bot_removed, bot_invite_token,
                    bot_invite_expires, is_webhook, lobby_status, lobby_entered_at, pow_level
             FROM users ORDER BY first_seen_at DESC LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;

        Ok(rows
            .into_iter()
            .map(|r| UserRow {
                public_key: r.get("public_key"),
                display_name: r.get("display_name"),
                first_seen_at: r.get("first_seen_at"),
                last_seen_at: r.get("last_seen_at"),
                approval_status: r.get("approval_status"),
                avatar: r.get("avatar"),
                master_pubkey: r.get("master_pubkey"),
                is_bot: r.get("is_bot"),
                is_bot_removed: r.get("is_bot_removed"),
                bot_invite_token: r.get("bot_invite_token"),
                bot_invite_expires: r.get("bot_invite_expires"),
                is_webhook: r.get("is_webhook"),
                lobby_status: r.get("lobby_status"),
                lobby_entered_at: r.get("lobby_entered_at"),
                pow_level: r.get("pow_level"),
            })
            .collect())
    }

    async fn member_count(&self) -> Result<i64, StoreError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE is_bot = 0 AND approval_status = 'approved'",
        )
        .fetch_one(self.pool())
        .await
        .map_err(map_err)
    }

    async fn display_names_for(
        &self,
        pubkeys: &[String],
    ) -> Result<HashMap<String, Option<String>>, StoreError> {
        let mut map = HashMap::new();
        for pk in pubkeys {
            let name: Option<String> = sqlx::query_scalar(
                "SELECT display_name FROM users WHERE public_key = ?",
            )
            .bind(pk)
            .fetch_optional(self.pool())
            .await
            .map_err(map_err)?
            .flatten();
            map.insert(pk.clone(), name);
        }
        Ok(map)
    }

    async fn set_master_pubkey(&self, pubkey: &str, master: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET master_pubkey = ? WHERE public_key = ?")
            .bind(master)
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_lobby_status(
        &self,
        pubkey: &str,
        status: &str,
        entered_at: Option<i64>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE users SET lobby_status = ?, lobby_entered_at = ? WHERE public_key = ?",
        )
        .bind(status)
        .bind(entered_at)
        .bind(pubkey)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn set_avatar(&self, pubkey: &str, avatar: Option<&str>) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET avatar = ? WHERE public_key = ?")
            .bind(avatar)
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_is_bot(&self, pubkey: &str, is_bot: bool) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET is_bot = ? WHERE public_key = ?")
            .bind(if is_bot { 1i64 } else { 0 })
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_bot_invite_token(
        &self,
        pubkey: &str,
        token: Option<&str>,
        expires: Option<i64>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE users SET bot_invite_token = ?, bot_invite_expires = ? WHERE public_key = ?",
        )
        .bind(token)
        .bind(expires)
        .bind(pubkey)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn set_pow_level(&self, pubkey: &str, level: i64) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET pow_level = ? WHERE public_key = ?")
            .bind(level)
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }
}
