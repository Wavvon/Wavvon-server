use crate::{BotCommandRow, BotEventQueueRow, BotProfileRow, BotRow, BotStore, StoreError};
use async_trait::async_trait;
use sqlx::Row;

use crate::error_map::map_err;
use crate::PostgresStore;

#[async_trait]
impl BotStore for PostgresStore {
    async fn upsert_bot_profile(&self, p: &BotProfileRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO bot_profiles(pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities, updated_at)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT(pubkey) DO UPDATE SET
               name=excluded.name, avatar_url=excluded.avatar_url,
               description=excluded.description, webhook_url=excluded.webhook_url,
               homepage_url=excluded.homepage_url, capabilities=excluded.capabilities,
               updated_at=excluded.updated_at",
        )
        .bind(&p.pubkey)
        .bind(&p.name)
        .bind(&p.avatar_url)
        .bind(&p.description)
        .bind(&p.webhook_url)
        .bind(&p.homepage_url)
        .bind(&p.capabilities)
        .bind(p.updated_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_bot_profile(&self, pubkey: &str) -> Result<Option<BotProfileRow>, StoreError> {
        let row = sqlx::query(
            "SELECT pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities, updated_at
             FROM bot_profiles WHERE pubkey = $1",
        )
        .bind(pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| BotProfileRow {
            pubkey: r.get("pubkey"),
            name: r.get("name"),
            avatar_url: r.get("avatar_url"),
            description: r.get("description"),
            webhook_url: r.get("webhook_url"),
            homepage_url: r.get("homepage_url"),
            capabilities: r.get("capabilities"),
            updated_at: r.get("updated_at"),
        }))
    }

    async fn list_bot_profiles(&self) -> Result<Vec<BotProfileRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT pubkey, name, avatar_url, description, webhook_url, homepage_url, capabilities, updated_at
             FROM bot_profiles",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| BotProfileRow {
                pubkey: r.get("pubkey"),
                name: r.get("name"),
                avatar_url: r.get("avatar_url"),
                description: r.get("description"),
                webhook_url: r.get("webhook_url"),
                homepage_url: r.get("homepage_url"),
                capabilities: r.get("capabilities"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }

    async fn delete_bot_profile(&self, pubkey: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM bot_profiles WHERE pubkey = $1")
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn replace_bot_commands(
        &self,
        pubkey: &str,
        cmds: &[BotCommandRow],
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM bot_commands WHERE pubkey = $1")
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        for cmd in cmds {
            sqlx::query(
                "INSERT INTO bot_commands(pubkey,name,description,args,scope,privileged,cooldown_seconds)
                 VALUES($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(pubkey)
            .bind(&cmd.name)
            .bind(&cmd.description)
            .bind(&cmd.args)
            .bind(&cmd.scope)
            .bind(cmd.privileged)
            .bind(cmd.cooldown_seconds)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        }
        Ok(())
    }

    async fn list_bot_commands(&self, pubkey: &str) -> Result<Vec<BotCommandRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT pubkey, name, description, args, scope, privileged, cooldown_seconds
             FROM bot_commands WHERE pubkey = $1",
        )
        .bind(pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| BotCommandRow {
                pubkey: r.get("pubkey"),
                name: r.get("name"),
                description: r.get("description"),
                args: r.get("args"),
                scope: r.get("scope"),
                privileged: r.get("privileged"),
                cooldown_seconds: r.get("cooldown_seconds"),
            })
            .collect())
    }

    async fn all_bot_commands(&self) -> Result<Vec<BotCommandRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT pubkey, name, description, args, scope, privileged, cooldown_seconds
             FROM bot_commands",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| BotCommandRow {
                pubkey: r.get("pubkey"),
                name: r.get("name"),
                description: r.get("description"),
                args: r.get("args"),
                scope: r.get("scope"),
                privileged: r.get("privileged"),
                cooldown_seconds: r.get("cooldown_seconds"),
            })
            .collect())
    }

    async fn set_bot_subscription(
        &self,
        bot_pubkey: &str,
        event_type: &str,
        channel_id: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO bot_subscriptions (bot_pubkey, event_type, channel_id)
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(bot_pubkey)
        .bind(event_type)
        .bind(channel_id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remove_bot_subscription(
        &self,
        bot_pubkey: &str,
        event_type: &str,
        channel_id: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM bot_subscriptions
             WHERE bot_pubkey = $1 AND event_type = $2 AND channel_id = $3",
        )
        .bind(bot_pubkey)
        .bind(event_type)
        .bind(channel_id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn bot_subscriptions(
        &self,
        bot_pubkey: &str,
    ) -> Result<Vec<(String, String)>, StoreError> {
        let rows = sqlx::query(
            "SELECT event_type, channel_id FROM bot_subscriptions WHERE bot_pubkey = $1",
        )
        .bind(bot_pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("event_type"),
                    r.get::<String, _>("channel_id"),
                )
            })
            .collect())
    }

    async fn bots_subscribed_to(
        &self,
        event_type: &str,
        channel_id: &str,
    ) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            "SELECT bot_pubkey FROM bot_subscriptions
             WHERE event_type = $1 AND (channel_id = '' OR channel_id = $2)",
        )
        .bind(event_type)
        .bind(channel_id)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)
    }

    async fn set_bot_channel_scope(
        &self,
        bot_pubkey: &str,
        channel_id: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO bot_channel_scope (bot_pubkey, channel_id) VALUES ($1, $2)
             ON CONFLICT DO NOTHING",
        )
        .bind(bot_pubkey)
        .bind(channel_id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn bot_channel_scope(&self, bot_pubkey: &str) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            "SELECT channel_id FROM bot_channel_scope WHERE bot_pubkey = $1",
        )
        .bind(bot_pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)
    }

    async fn create_bot(&self, b: &BotRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO bots (public_key, display_name, created_by, token_hash, webhook_url, mini_app_url, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&b.public_key)
        .bind(&b.display_name)
        .bind(&b.created_by)
        .bind(&b.token_hash)
        .bind(&b.webhook_url)
        .bind(&b.mini_app_url)
        .bind(b.created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_bot_by_pubkey(&self, pubkey: &str) -> Result<Option<BotRow>, StoreError> {
        let row = sqlx::query(
            "SELECT public_key, display_name, created_by, token_hash, webhook_url, mini_app_url, created_at
             FROM bots WHERE public_key = $1",
        )
        .bind(pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| BotRow {
            public_key: r.get("public_key"),
            display_name: r.get("display_name"),
            created_by: r.get("created_by"),
            token_hash: r.get("token_hash"),
            webhook_url: r.get("webhook_url"),
            mini_app_url: r.get("mini_app_url"),
            created_at: r.get("created_at"),
        }))
    }

    async fn list_bots(&self) -> Result<Vec<BotRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT public_key, display_name, created_by, token_hash, webhook_url, mini_app_url, created_at
             FROM bots ORDER BY created_at DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| BotRow {
                public_key: r.get("public_key"),
                display_name: r.get("display_name"),
                created_by: r.get("created_by"),
                token_hash: r.get("token_hash"),
                webhook_url: r.get("webhook_url"),
                mini_app_url: r.get("mini_app_url"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn delete_bot(&self, pubkey: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM bots WHERE public_key = $1")
            .bind(pubkey)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn enqueue_bot_event(&self, e: &BotEventQueueRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO bot_event_queue (id, bot_pubkey, event_type, payload, created_at, delivered)
             VALUES ($1, $2, $3, $4, $5, FALSE)",
        )
        .bind(&e.id)
        .bind(&e.bot_pubkey)
        .bind(&e.event_type)
        .bind(&e.payload)
        .bind(e.created_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn pending_bot_events(
        &self,
        bot_pubkey: &str,
        limit: i64,
    ) -> Result<Vec<BotEventQueueRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, bot_pubkey, event_type, payload, created_at, delivered
             FROM bot_event_queue
             WHERE bot_pubkey = $1 AND delivered = FALSE
             ORDER BY created_at ASC LIMIT $2",
        )
        .bind(bot_pubkey)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| BotEventQueueRow {
                id: r.get("id"),
                bot_pubkey: r.get("bot_pubkey"),
                event_type: r.get("event_type"),
                payload: r.get("payload"),
                created_at: r.get("created_at"),
                // PostgreSQL BOOLEAN → i64 for BotEventQueueRow compatibility
                delivered: if r.get::<bool, _>("delivered") { 1 } else { 0 },
            })
            .collect())
    }

    async fn mark_events_delivered(&self, ids: &[String]) -> Result<(), StoreError> {
        for id in ids {
            sqlx::query("UPDATE bot_event_queue SET delivered = TRUE WHERE id = $1")
                .bind(id)
                .execute(self.pool())
                .await
                .map_err(map_err)?;
        }
        Ok(())
    }

    async fn get_user_by_bot_invite_token(
        &self,
        token: &str,
        now: i64,
    ) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            "SELECT public_key FROM users
             WHERE bot_invite_token = $1 AND (bot_invite_expires IS NULL OR bot_invite_expires > $2)",
        )
        .bind(token)
        .bind(now)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)
    }
}
