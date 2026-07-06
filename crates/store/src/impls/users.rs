use std::collections::HashMap;

use crate::{StoreError, UserRow, UserStore};
use async_trait::async_trait;
use sqlx::Row;

use crate::error_map::map_err;
use crate::PostgresStore;

fn row_to_user(r: sqlx::postgres::PgRow) -> UserRow {
    UserRow {
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
    }
}

#[async_trait]
impl UserStore for PostgresStore {
    async fn upsert_user(&self, pubkey: &str, now: i64) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO users (public_key, first_seen_at, last_seen_at)
             VALUES ($1, $2, $3)
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
             FROM users WHERE public_key = $1",
        )
        .bind(pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_user))
    }

    async fn set_display_name(&self, pubkey: &str, name: Option<&str>) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET display_name = $1 WHERE public_key = $2")
            .bind(name)
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_approval_status(&self, pubkey: &str, status: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET approval_status = $1 WHERE public_key = $2")
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
             FROM users ORDER BY first_seen_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_user).collect())
    }

    async fn member_count(&self) -> Result<i64, StoreError> {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE is_bot = FALSE AND approval_status = 'approved'",
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
            let name: Option<String> =
                sqlx::query_scalar("SELECT display_name FROM users WHERE public_key = $1")
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
        sqlx::query("UPDATE users SET master_pubkey = $1 WHERE public_key = $2")
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
            "UPDATE users SET lobby_status = $1, lobby_entered_at = $2 WHERE public_key = $3",
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
        sqlx::query("UPDATE users SET avatar = $1 WHERE public_key = $2")
            .bind(avatar)
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_is_bot(&self, pubkey: &str, is_bot: bool) -> Result<(), StoreError> {
        sqlx::query("UPDATE users SET is_bot = $1 WHERE public_key = $2")
            .bind(is_bot)
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
            "UPDATE users SET bot_invite_token = $1, bot_invite_expires = $2 WHERE public_key = $3",
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
        sqlx::query("UPDATE users SET pow_level = $1 WHERE public_key = $2")
            .bind(level)
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }
}
