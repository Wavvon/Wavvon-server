//! Thin reqwest executor around the Discord Bot API v10. Fetches raw JSON
//! and deserializes it into `discord_types`; mapping to the manifest
//! happens in `mapping` (pure, no I/O).

use anyhow::{Context, Result};
use reqwest::Client;

use crate::discord_types::{DiscordChannel, DiscordGuild, DiscordRole};
use crate::retry::send;

const DISCORD_API_BASE: &str = "https://discord.com/api/v10";

pub async fn fetch_guild(client: &Client, token: &str, guild_id: &str) -> Result<DiscordGuild> {
    send(
        client
            .get(format!("{DISCORD_API_BASE}/guilds/{guild_id}"))
            .header("Authorization", format!("Bot {token}")),
    )
    .await
    .context("GET /guilds/:id failed")?
    .error_for_status()
    .context("GET /guilds/:id returned an error status -- check the bot token and that it's in the guild")?
    .json()
    .await
    .context("GET /guilds/:id response parse failed")
}

pub async fn fetch_roles(client: &Client, token: &str, guild_id: &str) -> Result<Vec<DiscordRole>> {
    send(
        client
            .get(format!("{DISCORD_API_BASE}/guilds/{guild_id}/roles"))
            .header("Authorization", format!("Bot {token}")),
    )
    .await
    .context("GET /guilds/:id/roles failed")?
    .error_for_status()
    .context("GET /guilds/:id/roles returned an error status")?
    .json()
    .await
    .context("GET /guilds/:id/roles response parse failed")
}

pub async fn fetch_channels(
    client: &Client,
    token: &str,
    guild_id: &str,
) -> Result<Vec<DiscordChannel>> {
    send(
        client
            .get(format!("{DISCORD_API_BASE}/guilds/{guild_id}/channels"))
            .header("Authorization", format!("Bot {token}")),
    )
    .await
    .context("GET /guilds/:id/channels failed")?
    .error_for_status()
    .context("GET /guilds/:id/channels returned an error status")?
    .json()
    .await
    .context("GET /guilds/:id/channels response parse failed")
}
