use async_trait::async_trait;
use sqlx::Row;
use voxply_store::{GameSessionRow, GameStore, HubGameRow, StoreError};

use crate::error_map::map_err;
use crate::SqliteStore;

fn row_to_hub_game(r: sqlx::any::AnyRow) -> HubGameRow {
    HubGameRow {
        id: r.get("id"),
        name: r.get("name"),
        description: r.get("description"),
        version: r.get("version"),
        entry_url: r.get("entry_url"),
        thumbnail_url: r.get("thumbnail_url"),
        author: r.get("author"),
        min_players: r.get("min_players"),
        max_players: r.get("max_players"),
        installed_by: r.get("installed_by"),
        installed_at: r.get("installed_at"),
        manifest_url: r.get("manifest_url"),
    }
}

fn row_to_session(r: sqlx::any::AnyRow) -> GameSessionRow {
    GameSessionRow {
        id: r.get("id"),
        channel_id: r.get("channel_id"),
        game_id: r.get("game_id"),
        host_pubkey: r.get("host_pubkey"),
        state_json: r.get("state_json"),
        created_at: r.get("created_at"),
        ended_at: r.get("ended_at"),
        status: r.get("status"),
        snapshot: r.get("snapshot"),
        updated_at: r.get("updated_at"),
    }
}

#[async_trait]
impl GameStore for SqliteStore {
    async fn install_game(&self, g: &HubGameRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO hub_games
             (id, name, description, version, entry_url, thumbnail_url, author,
              min_players, max_players, installed_by, installed_at, manifest_url)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
               name=excluded.name, description=excluded.description,
               version=excluded.version, entry_url=excluded.entry_url,
               thumbnail_url=excluded.thumbnail_url, author=excluded.author,
               min_players=excluded.min_players, max_players=excluded.max_players,
               manifest_url=excluded.manifest_url",
        )
        .bind(&g.id)
        .bind(&g.name)
        .bind(&g.description)
        .bind(&g.version)
        .bind(&g.entry_url)
        .bind(&g.thumbnail_url)
        .bind(&g.author)
        .bind(g.min_players)
        .bind(g.max_players)
        .bind(&g.installed_by)
        .bind(g.installed_at)
        .bind(&g.manifest_url)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_game(&self, id: &str) -> Result<Option<HubGameRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, name, description, version, entry_url, thumbnail_url, author,
                    min_players, max_players, installed_by, installed_at, manifest_url
             FROM hub_games WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_hub_game))
    }

    async fn list_games(&self) -> Result<Vec<HubGameRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, name, description, version, entry_url, thumbnail_url, author,
                    min_players, max_players, installed_by, installed_at, manifest_url
             FROM hub_games ORDER BY installed_at DESC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_hub_game).collect())
    }

    async fn uninstall_game(&self, id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM hub_games WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn enable_game(
        &self,
        game_id: &str,
        enabled_at: &str,
        enabled_by: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO enabled_games (game_id, enabled_at, enabled_by)
             VALUES (?, ?, ?) ON CONFLICT(game_id) DO UPDATE SET
               enabled_at = excluded.enabled_at, enabled_by = excluded.enabled_by",
        )
        .bind(game_id)
        .bind(enabled_at)
        .bind(enabled_by)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn disable_game(&self, game_id: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM enabled_games WHERE game_id = ?")
            .bind(game_id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn is_game_enabled(&self, game_id: &str) -> Result<bool, StoreError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM enabled_games WHERE game_id = ?")
            .bind(game_id)
            .fetch_one(self.pool())
            .await
            .map_err(map_err)?;
        Ok(count > 0)
    }

    async fn assign_game_to_channel(
        &self,
        channel_id: &str,
        game_id: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO channel_games (channel_id, game_id) VALUES (?, ?)
             ON CONFLICT DO NOTHING",
        )
        .bind(channel_id)
        .bind(game_id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remove_game_from_channel(
        &self,
        channel_id: &str,
        game_id: &str,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM channel_games WHERE channel_id = ? AND game_id = ?")
            .bind(channel_id)
            .bind(game_id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn channel_games(&self, channel_id: &str) -> Result<Vec<String>, StoreError> {
        sqlx::query_scalar::<_, String>("SELECT game_id FROM channel_games WHERE channel_id = ?")
            .bind(channel_id)
            .fetch_all(self.pool())
            .await
            .map_err(map_err)
    }

    async fn create_game_session(&self, s: &GameSessionRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO game_sessions
             (id, channel_id, game_id, host_pubkey, state_json, created_at, status, snapshot, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&s.id)
        .bind(&s.channel_id)
        .bind(&s.game_id)
        .bind(&s.host_pubkey)
        .bind(&s.state_json)
        .bind(&s.created_at)
        .bind(&s.status)
        .bind(&s.snapshot)
        .bind(s.updated_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_game_session(&self, id: &str) -> Result<Option<GameSessionRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, channel_id, game_id, host_pubkey, state_json, created_at,
                    ended_at, status, snapshot, updated_at
             FROM game_sessions WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_session))
    }

    async fn update_game_session(
        &self,
        id: &str,
        state_json: &str,
        status: &str,
        updated_at: i64,
        snapshot: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE game_sessions SET state_json = ?, status = ?, updated_at = ?, snapshot = ?
             WHERE id = ?",
        )
        .bind(state_json)
        .bind(status)
        .bind(updated_at)
        .bind(snapshot)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn end_game_session(&self, id: &str, ended_at: &str) -> Result<(), StoreError> {
        sqlx::query("UPDATE game_sessions SET ended_at = ?, status = 'ended' WHERE id = ?")
            .bind(ended_at)
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn list_game_sessions(
        &self,
        channel_id: &str,
        limit: i64,
    ) -> Result<Vec<GameSessionRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, channel_id, game_id, host_pubkey, state_json, created_at,
                    ended_at, status, snapshot, updated_at
             FROM game_sessions WHERE channel_id = ?
             ORDER BY created_at DESC LIMIT ?",
        )
        .bind(channel_id)
        .bind(limit)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_session).collect())
    }

    async fn set_game_kv(
        &self,
        session_id: &str,
        key: &str,
        value: &str,
        updated_at: &str,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO game_shared_kv (session_id, key, value, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(session_id, key) DO UPDATE SET
               value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(session_id)
        .bind(key)
        .bind(value)
        .bind(updated_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_game_kv(&self, session_id: &str, key: &str) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            "SELECT value FROM game_shared_kv WHERE session_id = ? AND key = ?",
        )
        .bind(session_id)
        .bind(key)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)
    }

    async fn delete_game_kv(&self, session_id: &str, key: &str) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM game_shared_kv WHERE session_id = ? AND key = ?")
            .bind(session_id)
            .bind(key)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn set_game_channel_kv(
        &self,
        game_id: &str,
        channel_id: &str,
        key: &str,
        value: &str,
        updated_at: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO game_channel_kv (game_id, channel_id, key, value, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(game_id, channel_id, key) DO UPDATE SET
               value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(game_id)
        .bind(channel_id)
        .bind(key)
        .bind(value)
        .bind(updated_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_game_channel_kv(
        &self,
        game_id: &str,
        channel_id: &str,
        key: &str,
    ) -> Result<Option<String>, StoreError> {
        sqlx::query_scalar::<_, String>(
            "SELECT value FROM game_channel_kv WHERE game_id = ? AND channel_id = ? AND key = ?",
        )
        .bind(game_id)
        .bind(channel_id)
        .bind(key)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)
    }
}
