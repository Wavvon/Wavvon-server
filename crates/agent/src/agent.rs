use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio_tungstenite::tungstenite::Message;

use crate::hub_manager::HubManager;
use crate::settings::Settings;

pub async fn run(cfg: &Settings, manager: Arc<HubManager>) -> Result<()> {
    let ws_url = build_ws_url(&cfg.farm_url);
    tracing::info!(url = %ws_url, "Connecting to farm");

    let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .context("WebSocket connect failed")?;

    let (mut write, mut read) = ws_stream.split();

    // The farm's proxy has to know where this node is, and how to trust it:
    // without a host it keeps dialing 127.0.0.1 and every hub over here is
    // unreachable through the farm's domain (farm-model.md, "Multi-node data
    // plane"). Sent on every connect, so a node that moves or rotates its
    // certificate corrects the farm by reconnecting.
    let hello = serde_json::json!({
        "type": "hello",
        "version": "0.1.0",
        "token": cfg.server_token,
        "host": cfg.node_host,
        "tls_mode": cfg.node_tls,
        "cert_sha256": cfg.node_cert_sha256,
    });
    write.send(Message::Text(hello.to_string().into())).await?;

    while let Some(raw) = read.next().await {
        match raw {
            Err(e) => {
                // Transport error (not a close frame) — log and terminate so
                // the outer reconnect loop can re-establish the connection.
                tracing::warn!(error = %e, "Agent WS transport error");
                break;
            }
            Ok(msg) => match msg {
                Message::Text(text) => {
                    match serde_json::from_str::<serde_json::Value>(&text) {
                        Ok(val) => {
                            if let Some(reply) = handle_message(&val, &manager, cfg).await {
                                if let Err(e) = write.send(Message::Text(reply.into())).await {
                                    tracing::warn!(error = %e, "Agent WS send error");
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            // Malformed JSON from the farm — log and continue; do not crash.
                            tracing::warn!(error = %e, "Agent WS: received non-JSON message, skipping");
                        }
                    }
                }
                Message::Close(_) => break,
                _ => {}
            },
        }
    }

    Ok(())
}

async fn handle_message(
    msg: &serde_json::Value,
    manager: &HubManager,
    cfg: &Settings,
) -> Option<String> {
    let msg_type = msg.get("type")?.as_str()?;
    match msg_type {
        "ping" => {
            let ts = msg.get("ts").and_then(|v| v.as_i64()).unwrap_or(0);
            Some(serde_json::json!({"type": "pong", "ts": ts}).to_string())
        }
        "spawn_hub" => {
            let hub_id = msg.get("hub_id")?.as_str()?.to_string();
            let db_url = msg.get("db_url")?.as_str()?.to_string();
            let port = msg.get("port")?.as_u64()? as u16;
            // Fall back to the default when an older farm doesn't send it —
            // avoids a fatal bind collision if two hubs happen to spawn.
            let voice_port = msg
                .get("voice_port")
                .and_then(|v| v.as_u64())
                .map(|v| v as u16)
                .unwrap_or(3001);
            let owner_pubkey = msg
                .get("owner_pubkey")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let farm_url = msg
                .get("farm_url")
                .and_then(|v| v.as_str())
                .map(str::to_string);

            let resolved = match resolve_db(msg, cfg, &db_url).await {
                Ok(url) => url,
                Err(e) => {
                    return Some(serde_json::json!({"type": "error", "hub_id": hub_id, "code": "no_database", "message": e.to_string()}).to_string());
                }
            };

            match manager.spawn_hub(
                &hub_id,
                &resolved,
                port,
                voice_port,
                owner_pubkey.as_deref(),
                farm_url.as_deref(),
            ).await {
                Ok(()) => Some(serde_json::json!({"type": "hub_spawned", "hub_id": hub_id, "port": port, "voice_port": voice_port}).to_string()),
                Err(e) => Some(serde_json::json!({"type": "error", "hub_id": hub_id, "code": "spawn_failed", "message": e.to_string()}).to_string()),
            }
        }
        "restart_hub" => {
            let hub_id = msg.get("hub_id")?.as_str()?.to_string();
            let db_url = msg.get("db_url")?.as_str()?.to_string();
            let port = msg.get("port")?.as_u64()? as u16;
            let voice_port = msg
                .get("voice_port")
                .and_then(|v| v.as_u64())
                .map(|v| v as u16)
                .unwrap_or(3001);
            let owner_pubkey = msg
                .get("owner_pubkey")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let farm_url = msg
                .get("farm_url")
                .and_then(|v| v.as_str())
                .map(str::to_string);

            let resolved = match resolve_db(msg, cfg, &db_url).await {
                Ok(url) => url,
                Err(e) => {
                    return Some(serde_json::json!({"type": "error", "hub_id": hub_id, "code": "no_database", "message": e.to_string()}).to_string());
                }
            };

            match manager
                .restart_hub(
                    &hub_id,
                    &resolved,
                    port,
                    voice_port,
                    owner_pubkey.as_deref(),
                    farm_url.as_deref(),
                )
                .await
            {
                Ok(()) => Some(serde_json::json!({"type": "hub_restarted", "hub_id": hub_id, "port": port, "voice_port": voice_port}).to_string()),
                Err(e) => Some(serde_json::json!({"type": "error", "hub_id": hub_id, "code": "restart_failed", "message": e.to_string()}).to_string()),
            }
        }
        "stop_hub" => {
            let hub_id = msg.get("hub_id")?.as_str()?.to_string();
            match manager.stop_hub(&hub_id).await {
                Ok(()) => Some(serde_json::json!({"type": "hub_stopped", "hub_id": hub_id}).to_string()),
                Err(e) => Some(serde_json::json!({"type": "error", "hub_id": hub_id, "code": "stop_failed", "message": e.to_string()}).to_string()),
            }
        }
        "list_hubs" => {
            let hubs = manager.list_hubs().await;
            Some(serde_json::json!({"type": "hub_list", "hubs": hubs}).to_string())
        }
        _ => None,
    }
}

/// The database URL for a hub the farm asked this node to start.
///
/// Split out because spawn and restart must agree: a restart that fell back to
/// a different database would look like a hub that lost its history.
async fn resolve_db(
    msg: &serde_json::Value,
    cfg: &Settings,
    farm_db_url: &str,
) -> anyhow::Result<String> {
    crate::provision::resolve(
        cfg.db_template.as_deref(),
        msg.get("db_url_template").and_then(|v| v.as_str()),
        Some(farm_db_url),
        msg.get("db_name").and_then(|v| v.as_str()),
    )
    .await
}

fn build_ws_url(farm_url: &str) -> String {
    let base = farm_url.trim_end_matches('/');
    let ws_base = if base.starts_with("https://") {
        base.replacen("https://", "wss://", 1)
    } else {
        base.replacen("http://", "ws://", 1)
    };
    format!("{ws_base}/ws/agent")
}
