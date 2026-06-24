use anyhow::Result;
use sqlx::AnyPool;

pub struct BootstrapConfig {
    pub template_url: Option<String>,
    pub bootstrap_token: Option<String>,
    pub discovery_url: String,
}

/// Runs on first launch if template_url or bootstrap_token is set and the hub
/// has no channels yet (blank DB).
pub async fn maybe_bootstrap(
    db: &AnyPool,
    http: &reqwest::Client,
    cfg: &BootstrapConfig,
) -> Result<()> {
    // Check if already bootstrapped
    let bootstrapped: Option<String> = sqlx::query_scalar(
        "SELECT value FROM hub_settings WHERE key = 'bootstrapped_at' AND value != ''",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    if bootstrapped.is_some() {
        return Ok(());
    }

    // Check if hub already has channels
    let channel_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels")
        .fetch_one(db)
        .await
        .unwrap_or(0);
    if channel_count > 0 {
        return Ok(());
    }

    let template_json = if let Some(token) = &cfg.bootstrap_token {
        // Redeem bootstrap token from discovery
        let discovery_url = &cfg.discovery_url;
        match http
            .post(format!("{discovery_url}/api/bootstrap/redeem"))
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => resp.json::<serde_json::Value>().await.ok(),
            _ => {
                tracing::warn!("Failed to redeem bootstrap token; falling through to template_url");
                fetch_template(&cfg.template_url, http).await
            }
        }
    } else {
        fetch_template(&cfg.template_url, http).await
    };

    if let Some(template) = template_json {
        apply_template(db, &template).await?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string();
        sqlx::query("UPDATE hub_settings SET value = ? WHERE key = 'bootstrapped_at'")
            .bind(&now)
            .execute(db)
            .await
            .ok();
        tracing::info!("Hub bootstrapped from template");
    }

    Ok(())
}

async fn fetch_template(url: &Option<String>, http: &reqwest::Client) -> Option<serde_json::Value> {
    let url = url.as_ref()?;
    match http.get(url).send().await {
        Ok(resp) if resp.status().is_success() => resp.json().await.ok(),
        _ => {
            tracing::warn!("Failed to fetch template from {url}; starting with blank hub");
            None
        }
    }
}

async fn apply_template(db: &AnyPool, template: &serde_json::Value) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Apply hub name if present
    if let Some(name) = template.get("name").and_then(|v| v.as_str()) {
        sqlx::query("UPDATE hub_settings SET value = ? WHERE key = 'hub_name'")
            .bind(name)
            .execute(db)
            .await
            .ok();
    }

    // Create channels
    if let Some(channels) = template.get("channels").and_then(|v| v.as_array()) {
        for ch in channels {
            let name = ch.get("name").and_then(|v| v.as_str()).unwrap_or("general");
            let is_category = ch
                .get("is_category")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO channels(id, name, created_by, is_category, display_order, created_at)
                 VALUES(?, ?, 'system', ?, 0, ?) ON CONFLICT (id) DO NOTHING",
            )
            .bind(&id)
            .bind(name)
            .bind(is_category as i64)
            .bind(now)
            .execute(db)
            .await
            .ok();
        }
    }

    // Create roles
    if let Some(roles) = template.get("roles").and_then(|v| v.as_array()) {
        for role in roles {
            let name = role
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Member");
            let id = uuid::Uuid::new_v4().to_string();
            sqlx::query(
                "INSERT INTO roles(id, name, priority, created_at) VALUES(?,?,0,?) ON CONFLICT (id) DO NOTHING",
            )
            .bind(&id)
            .bind(name)
            .bind(now)
            .execute(db)
            .await
            .ok();
            if let Some(perms) = role.get("permissions").and_then(|v| v.as_array()) {
                for p in perms {
                    if let Some(perm) = p.as_str() {
                        sqlx::query(
                            "INSERT INTO role_permissions(role_id, permission) VALUES(?,?) ON CONFLICT (role_id, permission) DO NOTHING",
                        )
                        .bind(&id)
                        .bind(perm)
                        .execute(db)
                        .await
                        .ok();
                    }
                }
            }
        }
    }

    Ok(())
}
