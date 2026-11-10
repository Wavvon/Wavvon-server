use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;

use super::db::{backup, backup_out_path, cli_database_url, restore, restore_args};

/// `wavvon-hub admin <stats|users|channels|tokens|backup|restore>`.
pub async fn run() -> Result<()> {
    let admin_cmd = std::env::args().nth(2).unwrap_or_default();
    let (db_url, _started) = cli_database_url().await;
    let db = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .context("Cannot open DB for admin command")?;

    match admin_cmd.as_str() {
        "stats" => {
            let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
                .fetch_one(&db)
                .await
                .unwrap_or(0);
            let channels: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE is_category=false")
                    .fetch_one(&db)
                    .await
                    .unwrap_or(0);
            let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
                .fetch_one(&db)
                .await
                .unwrap_or(0);
            let bans: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bans")
                .fetch_one(&db)
                .await
                .unwrap_or(0);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "users": users,
                    "channels": channels,
                    "messages": messages,
                    "bans": bans
                }))
                .unwrap()
            );
        }
        "users" => {
            let action = std::env::args().nth(3).unwrap_or_default();
            match action.as_str() {
                "list" => {
                    let rows: Vec<(String, Option<String>, i64)> = sqlx::query_as(
                            "SELECT public_key, display_name, first_seen_at FROM users ORDER BY first_seen_at DESC LIMIT 50",
                        )
                        .fetch_all(&db)
                        .await
                        .unwrap_or_default();
                    let json: Vec<_> = rows
                        .iter()
                        .map(|(pk, dn, ts)| {
                            serde_json::json!({
                                "pubkey": pk,
                                "display_name": dn,
                                "first_seen_at": ts
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&json).unwrap());
                }
                "ban" => {
                    let pubkey = std::env::args()
                        .nth(4)
                        .context("Usage: admin users ban <pubkey>")?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    sqlx::query(
                            "INSERT INTO bans(target_public_key, banned_by, reason, created_at) VALUES($1,'cli','CLI ban',$2) ON CONFLICT (target_public_key) DO NOTHING",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db)
                        .await?;
                    wavvon_hub::ban_evasion::flag_banned(&db, &pubkey, None, now).await?;
                    println!("Banned {pubkey}");
                }
                "unban" => {
                    let pubkey = std::env::args()
                        .nth(4)
                        .context("Usage: admin users unban <pubkey>")?;
                    sqlx::query("DELETE FROM bans WHERE target_public_key = $1")
                        .bind(&pubkey)
                        .execute(&db)
                        .await?;
                    wavvon_hub::ban_evasion::unflag(&db, &pubkey).await?;
                    println!("Unbanned {pubkey}");
                }
                "set-owner" => {
                    let pubkey = std::env::args()
                        .nth(4)
                        .context("Usage: admin users set-owner <pubkey>")?;
                    let pubkey = pubkey.to_lowercase();
                    if pubkey.len() != 64 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
                        anyhow::bail!("Invalid pubkey: expected 64 hex characters");
                    }
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    // Revoke any existing owner first
                    let prev: Option<String> = sqlx::query_scalar(
                            "SELECT user_public_key FROM user_roles WHERE role_id = 'builtin-owner' LIMIT 1",
                        )
                        .fetch_optional(&db)
                        .await
                        .unwrap_or(None);
                    sqlx::query("DELETE FROM user_roles WHERE role_id = 'builtin-owner'")
                        .execute(&db)
                        .await?;
                    if let Some(p) = prev {
                        println!("Revoked owner from {}…", &p[..16.min(p.len())]);
                    }
                    // Ensure a minimal user record exists
                    sqlx::query(
                            "INSERT INTO users (public_key, first_seen_at, is_member) VALUES ($1, $2, TRUE)
                         ON CONFLICT (public_key) DO UPDATE SET is_member = TRUE",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db)
                        .await?;
                    sqlx::query(
                            "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ($1, 'builtin-owner', $2)
                             ON CONFLICT (user_public_key, role_id) DO UPDATE SET assigned_at = excluded.assigned_at",
                        )
                        .bind(&pubkey)
                        .bind(now)
                        .execute(&db)
                        .await?;
                    println!("Owner set to {pubkey}");
                }
                _ => println!("Usage: wavvon-hub admin users [list|ban|unban|set-owner] [pubkey]"),
            }
        }
        "channels" => {
            let action = std::env::args().nth(3).unwrap_or_default();
            match action.as_str() {
                "list" => {
                    let rows: Vec<(String, String)> = sqlx::query_as(
                            "SELECT id, name FROM channels WHERE is_category=false ORDER BY display_order",
                        )
                        .fetch_all(&db)
                        .await
                        .unwrap_or_default();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &rows
                                .iter()
                                .map(|(id, name)| serde_json::json!({"id": id, "name": name}))
                                .collect::<Vec<_>>()
                        )
                        .unwrap()
                    );
                }
                _ => println!("Usage: wavvon-hub admin channels [list]"),
            }
        }
        "tokens" => {
            let rows: Vec<(String, String, i64)> = sqlx::query_as(
                    "SELECT token, public_key, created_at FROM sessions ORDER BY created_at DESC LIMIT 20",
                )
                .fetch_all(&db)
                .await
                .unwrap_or_default();
            let json: Vec<_> = rows
                .iter()
                .map(|(t, pk, ts)| {
                    serde_json::json!({
                        "token_prefix": &t[..8.min(t.len())],
                        "public_key": pk,
                        "created_at": ts
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        "backup" => {
            let out = backup_out_path(3);
            backup(&out, &db_url).await?;
            println!("Backup written to {out}");
        }
        "restore" => {
            let (src, force) = restore_args(3, "Usage: admin restore <backup.tar.gz> [--force]")?;
            restore(&src, &db_url, force).await?;
            println!("Restore complete. Restart the hub.");
        }
        _ => {
            println!("Usage: wavvon-hub admin [stats|users|channels|tokens|backup|restore]");
        }
    }
    Ok(())
}
