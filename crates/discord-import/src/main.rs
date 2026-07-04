//! discord-import: migrates a Discord guild's structure (categories,
//! channels, roles, permission overwrites) onto a fresh Wavvon hub, via a
//! reviewable manifest file. See docs/docs/discord-import.md.
//!
//! Two subcommands, matching the two-stage design (§1):
//!
//!   discord-import export --guild <id> [--out import-manifest.json]
//!       Reads DISCORD_BOT_TOKEN from the environment.
//!
//!   discord-import apply --hub <url> [--manifest import-manifest.json] [--report import-report.txt]
//!       Runs against a fresh hub only (refuses if channels already exist).

mod discord_client;
mod discord_types;
mod hub_client;
mod manifest;
mod mapping;
mod permissions_table;
mod plan;
mod report;
mod retry;

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use reqwest::Client;
use wavvon_identity::Identity;

use manifest::Manifest;
use plan::Plan;
use report::ApplyReport;

fn get_flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map(String::as_str);

    match subcommand {
        Some("export") => run_export(&args).await,
        Some("apply") => run_apply(&args).await,
        _ => {
            eprintln!(
                "Usage:\n  \
                 discord-import export --guild <id> [--out import-manifest.json]\n  \
                 discord-import apply --hub <url> [--manifest import-manifest.json] [--report import-report.txt] [--insecure]\n\n\
                 --hub must be https:// unless the host is loopback (localhost/127.0.0.1/::1).\n\
                 --insecure disables TLS certificate verification and is only accepted for a loopback --hub."
            );
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

async fn run_export(args: &[String]) -> Result<()> {
    let guild_id = get_flag(args, "--guild")
        .context("--guild <id> is required")?
        .to_string();
    let out_path = get_flag(args, "--out")
        .unwrap_or("import-manifest.json")
        .to_string();

    let token = std::env::var("DISCORD_BOT_TOKEN")
        .context("DISCORD_BOT_TOKEN environment variable is required for export")?;

    let client = Client::builder()
        .user_agent("DiscordBot (https://wavvon.org, discord-import/0.1)")
        .build()
        .context("failed to build HTTP client")?;

    println!("Fetching guild {guild_id} ...");
    let guild = discord_client::fetch_guild(&client, &token, &guild_id).await?;
    println!("Guild: {}", guild.name);

    println!("Fetching roles ...");
    let roles = discord_client::fetch_roles(&client, &token, &guild_id).await?;
    println!("Fetched {} role(s).", roles.len());

    println!("Fetching channels ...");
    let channels = discord_client::fetch_channels(&client, &token, &guild_id).await?;
    println!("Fetched {} channel(s).", channels.len());

    let manifest = mapping::build_manifest(&guild, &roles, &channels, unix_now());

    let json = serde_json::to_string_pretty(&manifest).context("failed to serialize manifest")?;
    std::fs::write(&out_path, &json)
        .with_context(|| format!("failed to write manifest to {out_path}"))?;

    println!();
    println!("=============================================================");
    println!("Manifest written to {out_path}");
    println!(
        "  roles:    {} (including @everyone, mapped not created)",
        manifest.roles.len()
    );
    println!("  channels: {}", manifest.channels.len());
    println!("  warnings: {}", manifest.warnings.len());
    if !manifest.warnings.is_empty() {
        println!();
        println!("Review before applying:");
        for w in &manifest.warnings {
            println!("  * {w}");
        }
    }
    println!("=============================================================");

    Ok(())
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

async fn run_apply(args: &[String]) -> Result<()> {
    let hub_url = get_flag(args, "--hub")
        .context("--hub <url> is required")?
        .to_string();
    let manifest_path = get_flag(args, "--manifest")
        .unwrap_or("import-manifest.json")
        .to_string();
    let report_path = get_flag(args, "--report")
        .unwrap_or("import-report.txt")
        .to_string();
    let insecure = args.iter().any(|a| a == "--insecure");

    // D2: this tool authenticates with an owner-level token -- refuse to
    // send it over plaintext to a non-local hub. Loopback targets (local
    // dev/CI) are exempt from the scheme check.
    let parsed_hub_url =
        reqwest::Url::parse(&hub_url).with_context(|| format!("invalid --hub URL: {hub_url}"))?;
    let hub_is_loopback = parsed_hub_url
        .host_str()
        .map(|h| matches!(h, "localhost" | "127.0.0.1" | "::1"))
        .unwrap_or(false);
    if parsed_hub_url.scheme() != "https" && !hub_is_loopback {
        bail!(
            "--hub must use https:// (got '{}://') unless the host is loopback \
             (localhost/127.0.0.1/::1) -- refusing to send the owner token in cleartext \
             to a non-local hub.",
            parsed_hub_url.scheme()
        );
    }
    if insecure && !hub_is_loopback {
        bail!(
            "--insecure is only accepted when --hub targets a loopback host \
             (localhost/127.0.0.1/::1)."
        );
    }

    let manifest_json = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed to read manifest from {manifest_path}"))?;
    let manifest: Manifest =
        serde_json::from_str(&manifest_json).context("failed to parse manifest JSON")?;

    // Structural manifest problems (duplicate refs, dangling parent/role
    // refs) are hard failures, not fail-forward candidates -- fix the
    // manifest and re-run.
    let plan = plan::build_plan(&manifest)
        .map_err(|e| anyhow::anyhow!("manifest is structurally invalid: {e}"))?;

    println!("discord-import apply: target hub = {hub_url}");

    // D1: TLS verification is on by default. It is disabled only for an
    // explicit --insecure run against a loopback hub (checked above) --
    // this client authenticates with an owner-level session token, so
    // silently trusting any certificate would let a network MITM capture it.
    let mut client_builder = Client::builder();
    if insecure {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    let client = client_builder
        .build()
        .context("failed to build HTTP client")?;

    let health = client
        .get(format!("{hub_url}/health"))
        .send()
        .await
        .context("Could not reach hub -- is it running?")?;
    if !health.status().is_success() {
        bail!("Hub health check returned {}", health.status());
    }
    println!("Hub is reachable.");

    // Same admin-bootstrap posture as demo-seed: the first identity to
    // authenticate on a fresh hub is assigned builtin-owner, which carries
    // the 'admin' permission needed for role/channel management.
    let admin = Identity::generate();
    println!("Authenticating admin identity ...");
    let token = hub_client::authenticate(&client, &hub_url, &admin)
        .await
        .context("Admin authentication failed. If the hub already has users it is not fresh.")?;

    let channel_count = hub_client::existing_channel_count(&client, &hub_url, &token).await?;
    if channel_count > 0 {
        bail!(
            "Hub already has {channel_count} channel(s). discord-import apply requires a fresh \
             hub (empty DB) -- see docs/docs/discord-import.md §2. Wipe the DB and restart the \
             hub before re-running."
        );
    }

    let mut report = ApplyReport {
        manifest_warnings: manifest.warnings.clone(),
        ..Default::default()
    };

    let mut resolver = plan::RefResolver::new();
    if let Some(everyone_ref) = &plan.everyone_role_ref {
        resolver.seed_everyone(everyone_ref);
    }

    apply_roles(&client, &hub_url, &token, &plan, &mut resolver, &mut report).await;
    apply_channels(&client, &hub_url, &token, &plan, &mut resolver, &mut report).await;
    apply_overwrites(&client, &hub_url, &token, &plan, &resolver, &mut report).await;

    let report_text = report.render();
    std::fs::write(&report_path, &report_text)
        .with_context(|| format!("failed to write report to {report_path}"))?;

    println!();
    println!("{report_text}");
    println!("Report written to {report_path}");

    if report.had_failures() {
        std::process::exit(1);
    }
    Ok(())
}

async fn apply_roles(
    client: &Client,
    hub_url: &str,
    token: &str,
    plan: &Plan,
    resolver: &mut plan::RefResolver,
    report: &mut ApplyReport,
) {
    for step in &plan.role_steps {
        let new_role = hub_client::NewRole {
            name: &step.name,
            priority: step.priority,
            display_separately: step.display_separately,
            color: step.color.as_deref(),
            permissions: &step.permissions,
        };
        match hub_client::create_role(client, hub_url, token, &new_role).await {
            Ok(id) => {
                resolver.insert(&step.ref_id, &id);
                report.roles_created.push((step.name.clone(), id));
            }
            Err(e) => {
                report.roles_failed.push((step.name.clone(), e.to_string()));
            }
        }
    }
}

async fn apply_channels(
    client: &Client,
    hub_url: &str,
    token: &str,
    plan: &Plan,
    resolver: &mut plan::RefResolver,
    report: &mut ApplyReport,
) {
    // Steps are already ordered parent-before-child (see plan::build_plan),
    // so a parent's resolver entry (or lack of one, on failure) is always
    // settled before we reach any of its children.
    for step in &plan.channel_steps {
        let parent_id = match &step.parent_ref {
            Some(parent_ref) => match resolver.resolve(parent_ref) {
                Some(id) => Some(id.to_string()),
                None => {
                    report.channels_skipped.push((
                        step.name.clone(),
                        format!(
                            "parent (ref '{parent_ref}') failed to create -- skipped to avoid \
                             silently flattening it to top-level"
                        ),
                    ));
                    continue;
                }
            },
            None => None,
        };

        match hub_client::create_channel(
            client,
            hub_url,
            token,
            &step.name,
            parent_id.as_deref(),
            step.kind,
        )
        .await
        {
            Ok(id) => {
                resolver.insert(&step.ref_id, &id);
                report.channels_created.push((step.name.clone(), id));
            }
            Err(e) => {
                report
                    .channels_failed
                    .push((step.name.clone(), e.to_string()));
            }
        }
    }
}

async fn apply_overwrites(
    client: &Client,
    hub_url: &str,
    token: &str,
    plan: &Plan,
    resolver: &plan::RefResolver,
    report: &mut ApplyReport,
) {
    let channel_names: HashMap<&str, &str> = plan
        .channel_steps
        .iter()
        .map(|c| (c.ref_id.as_str(), c.name.as_str()))
        .collect();

    for ow in &plan.overwrite_steps {
        let display_name = channel_names
            .get(ow.channel_ref.as_str())
            .copied()
            .unwrap_or(ow.channel_ref.as_str())
            .to_string();

        let channel_id = match resolver.resolve(&ow.channel_ref) {
            Some(id) => id.to_string(),
            None => {
                report.overwrites_skipped.push((
                    display_name,
                    ow.role_ref.clone(),
                    "channel failed to create".to_string(),
                ));
                continue;
            }
        };
        let role_id = match resolver.resolve(&ow.role_ref) {
            Some(id) => id.to_string(),
            None => {
                report.overwrites_skipped.push((
                    display_name,
                    ow.role_ref.clone(),
                    "role failed to create".to_string(),
                ));
                continue;
            }
        };

        match hub_client::put_channel_permissions(
            client,
            hub_url,
            token,
            &channel_id,
            &role_id,
            &ow.allow,
            &ow.deny,
        )
        .await
        {
            Ok(()) => report.overwrites_applied += 1,
            Err(e) => {
                report
                    .overwrites_failed
                    .push((display_name, ow.role_ref.clone(), e.to_string()));
            }
        }
    }
}
