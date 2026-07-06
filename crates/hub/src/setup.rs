//! `wavvon-hub setup` — the offline install wizard.
//!
//! This is the CLI counterpart to the discovery web wizard described in
//! `docs/docs/hub-creation-wizard.md` §3 (the "CLI-only setup wizard"
//! alternative, listed there as a deferred stretch goal). It targets the
//! operator who has a box (bare metal, a VPS, a home server) and Docker, but
//! doesn't want to hand-author `docker-compose.yml` and generate a database
//! password themselves.
//!
//! The wizard only ever *writes files*. It never talks to Docker unless the
//! operator opts in with `--start`, and it never talks to the network at
//! all — this is the no-catalog, no-discovery-dependency path (mirrors the
//! built-in `bootstrap::presets` fallback already used at hub first-run).
//!
//! Flow:
//! 1. [`parse_cli_args`] turns `argv` into a [`SetupInputs`] (all fields
//!    optional at this stage).
//! 2. [`merge_env`] fills any still-missing fields from `WAVVON_SETUP_*`
//!    environment variables (flags always win).
//! 3. If stdin is a TTY and `--non-interactive` wasn't passed, `prompt_missing`
//!    interactively fills whatever [`merge_env`] didn't.
//! 4. [`validate`] turns the now-hopefully-complete [`SetupInputs`] into a
//!    validated [`SetupConfig`], rejecting bad preset names and
//!    domain/LAN-mode combinations that don't make sense.
//! 5. [`generate_files`] writes `docker-compose.yml` + `.env` (with a freshly
//!    generated database password) into the target directory.
//! 6. [`print_next_steps`] explains the invite-first ownership model:
//!    `docker compose up -d`, then redeem the one-time owner invite the hub
//!    mints and logs on its first boot (see `routes::invites`,
//!    `maybe_mint_first_boot_owner_invite`) from a client to claim ownership.
//!
//! Steps 1-5 are pure functions with no I/O side effects beyond
//! [`generate_files`] itself, which is what the tests in
//! `hub/tests/hub_wizard_flow.rs` exercise directly with fixed,
//! non-interactive input — no TTY involved. (That integration test file is
//! deliberately not named `setup_*.rs`: Windows' installer-detection
//! heuristic requires elevation to run any unmanifested `.exe` whose
//! filename contains "setup", which would otherwise fail every test run on
//! Windows CI with `ERROR_ELEVATION_REQUIRED`.)

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use rand::RngCore;

use crate::bootstrap::presets::PRESET_NAMES;

const USAGE: &str = "\
Usage: wavvon-hub setup [OPTIONS]

Interactively (or non-interactively) generates a docker-compose.yml + .env
pair for a new Wavvon hub. Writes files only — run `docker compose up -d`
yourself afterwards, or pass --start to have the wizard do it for you.

OPTIONS:
  --name <NAME>            Hub display name (default: \"My Wavvon Hub\")
  --template <PRESET>      Starting template: gaming | community | minimal
  --mode <MODE>            Deployment mode: public | lan
  --domain <DOMAIN>        Public domain (required when --mode public)
  --out <DIR>              Output directory (default: ./wavvon-hub)
  --start                  Run `docker compose up -d` after generating files
  --non-interactive, --yes Never prompt, even on a TTY; fail on missing fields
  -h, --help                Print this help message

Every flag has a matching environment variable, so the wizard is fully
scriptable with no TTY: WAVVON_SETUP_NAME, WAVVON_SETUP_TEMPLATE,
WAVVON_SETUP_MODE, WAVVON_SETUP_DOMAIN, WAVVON_SETUP_OUT,
WAVVON_SETUP_START (true/1), WAVVON_SETUP_NON_INTERACTIVE (true/1).
Flags take precedence over environment variables. When stdin is not a TTY,
the wizard behaves as if --non-interactive were passed.
";

/// Raw inputs gathered from CLI flags and environment variables, before
/// interactive prompting fills any gaps and [`validate`] runs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SetupInputs {
    pub name: Option<String>,
    pub template: Option<String>,
    pub mode: Option<String>,
    pub domain: Option<String>,
    pub out_dir: Option<String>,
    pub start: bool,
    pub non_interactive: bool,
}

/// Deployment mode chosen by the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentMode {
    /// Public, internet-facing hub reachable at `domain`. A reverse proxy
    /// (nginx/Caddy) is expected to terminate TLS in front of the HTTP port
    /// — the generated compose file only publishes it on loopback.
    Public { domain: String },
    /// LAN-only hub (`WAVVON_LAN_MODE=true`). No domain: the hub self-signs
    /// its own certificate and refuses to start on a non-private address
    /// (see `crate::lan` and `docs/docs/lan-mode.md`).
    Lan,
}

/// Fully resolved, validated wizard configuration, ready for file generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupConfig {
    pub name: String,
    pub template: String,
    pub mode: DeploymentMode,
    pub out_dir: PathBuf,
    pub start: bool,
}

/// Paths and secrets produced by [`generate_files`].
#[derive(Debug, Clone)]
pub struct GeneratedFiles {
    pub compose_path: PathBuf,
    pub env_path: PathBuf,
    pub db_password: String,
}

/// Entry point called from `main.rs` for `wavvon-hub setup <args...>`.
/// `args` excludes the leading `setup` token itself.
pub fn run(args: &[String]) -> Result<(), String> {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return Ok(());
    }

    let mut inputs = parse_cli_args(args)?;
    merge_env(&mut inputs);

    let interactive = !inputs.non_interactive && std::io::stdin().is_terminal();
    if interactive {
        prompt_missing(&mut inputs)?;
    }

    let cfg = validate(inputs)?;
    let generated = generate_files(&cfg)?;
    print_next_steps(&cfg, &generated);

    if cfg.start {
        start_compose(&cfg.out_dir)?;
    }

    Ok(())
}

/// Parses `setup` subcommand flags. Pure and TTY-independent — used directly
/// by tests.
pub fn parse_cli_args(args: &[String]) -> Result<SetupInputs, String> {
    let mut inputs = SetupInputs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => inputs.name = Some(next_value(args, &mut i, "--name")?),
            "--template" => inputs.template = Some(next_value(args, &mut i, "--template")?),
            "--mode" => inputs.mode = Some(next_value(args, &mut i, "--mode")?),
            "--domain" => inputs.domain = Some(next_value(args, &mut i, "--domain")?),
            "--out" => inputs.out_dir = Some(next_value(args, &mut i, "--out")?),
            "--start" => {
                inputs.start = true;
                i += 1;
            }
            "--non-interactive" | "--yes" => {
                inputs.non_interactive = true;
                i += 1;
            }
            other => {
                return Err(format!("Unknown flag '{other}' for setup.\n\n{USAGE}"));
            }
        }
    }
    Ok(inputs)
}

/// Consumes the flag at `args[*i]` plus its value at `args[*i + 1]`, advancing
/// `*i` past both.
fn next_value(args: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    let value = args
        .get(*i + 1)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("{flag} requires a value"))?
        .clone();
    *i += 2;
    Ok(value)
}

/// Fills any field still unset after CLI parsing from `WAVVON_SETUP_*`
/// environment variables. Flags always win over environment variables.
pub fn merge_env(inputs: &mut SetupInputs) {
    if inputs.name.is_none() {
        inputs.name = std::env::var("WAVVON_SETUP_NAME").ok();
    }
    if inputs.template.is_none() {
        inputs.template = std::env::var("WAVVON_SETUP_TEMPLATE").ok();
    }
    if inputs.mode.is_none() {
        inputs.mode = std::env::var("WAVVON_SETUP_MODE").ok();
    }
    if inputs.domain.is_none() {
        inputs.domain = std::env::var("WAVVON_SETUP_DOMAIN").ok();
    }
    if inputs.out_dir.is_none() {
        inputs.out_dir = std::env::var("WAVVON_SETUP_OUT").ok();
    }
    if !inputs.start {
        inputs.start = env_flag("WAVVON_SETUP_START");
    }
    if !inputs.non_interactive {
        inputs.non_interactive = env_flag("WAVVON_SETUP_NON_INTERACTIVE");
    }
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).ok().as_deref(),
        Some("true") | Some("1")
    )
}

/// Interactively prompts for any field [`merge_env`] left unset. Only ever
/// reached when stdin is a real TTY (see [`run`]) — not exercised by the
/// automated tests, which always supply every field non-interactively.
fn prompt_missing(inputs: &mut SetupInputs) -> Result<(), String> {
    use dialoguer::theme::ColorfulTheme;
    use dialoguer::{Input, Select};

    let theme = ColorfulTheme::default();
    let prompt_err = |e: dialoguer::Error| format!("prompt failed: {e}");

    if inputs.name.is_none() {
        let name: String = Input::with_theme(&theme)
            .with_prompt("Hub name")
            .default("My Wavvon Hub".to_string())
            .interact_text()
            .map_err(prompt_err)?;
        inputs.name = Some(name);
    }

    if inputs.template.is_none() {
        let default_idx = PRESET_NAMES
            .iter()
            .position(|p| *p == "community")
            .unwrap_or(0);
        let selection = Select::with_theme(&theme)
            .with_prompt("Starting template")
            .items(PRESET_NAMES)
            .default(default_idx)
            .interact()
            .map_err(prompt_err)?;
        inputs.template = Some(PRESET_NAMES[selection].to_string());
    }

    if inputs.mode.is_none() {
        let options = [
            "public (has a domain, reachable from the internet)",
            "lan (local network only, no domain)",
        ];
        let selection = Select::with_theme(&theme)
            .with_prompt("Deployment mode")
            .items(&options)
            .default(0)
            .interact()
            .map_err(prompt_err)?;
        inputs.mode = Some(if selection == 0 { "public" } else { "lan" }.to_string());
    }

    if inputs.mode.as_deref() == Some("public") && inputs.domain.is_none() {
        let domain: String = Input::with_theme(&theme)
            .with_prompt("Domain (e.g. hub.example.com)")
            .interact_text()
            .map_err(prompt_err)?;
        inputs.domain = Some(domain);
    }

    if inputs.out_dir.is_none() {
        let out: String = Input::with_theme(&theme)
            .with_prompt("Output directory")
            .default("./wavvon-hub".to_string())
            .interact_text()
            .map_err(prompt_err)?;
        inputs.out_dir = Some(out);
    }

    Ok(())
}

/// Validates and resolves [`SetupInputs`] into a [`SetupConfig`]. Pure — no
/// I/O, no environment reads. This is what the "bad preset name rejected"
/// and "domain vs LAN mutually sensible" unit tests exercise directly.
pub fn validate(inputs: SetupInputs) -> Result<SetupConfig, String> {
    let name = inputs
        .name
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "My Wavvon Hub".to_string());

    let template = inputs.template.ok_or_else(|| {
        format!(
            "Missing template preset: pass --template <{}> or set WAVVON_SETUP_TEMPLATE",
            PRESET_NAMES.join("|")
        )
    })?;
    if !PRESET_NAMES.contains(&template.as_str()) {
        return Err(format!(
            "Unknown template preset '{template}'; valid presets are: {}",
            PRESET_NAMES.join(", ")
        ));
    }

    let mode_str = inputs.mode.ok_or_else(|| {
        "Missing deployment mode: pass --mode <public|lan> or set WAVVON_SETUP_MODE".to_string()
    })?;

    let domain = inputs.domain.filter(|d| !d.trim().is_empty());

    let mode = match mode_str.to_lowercase().as_str() {
        "public" => {
            let domain = domain.ok_or_else(|| {
                "public mode requires a domain: pass --domain <domain> or set \
                 WAVVON_SETUP_DOMAIN"
                    .to_string()
            })?;
            DeploymentMode::Public { domain }
        }
        "lan" => {
            if let Some(domain) = domain {
                return Err(format!(
                    "--domain '{domain}' was given but --mode lan doesn't use one — LAN hubs \
                     self-sign their own certificate for their private address instead of \
                     using a domain (see docs/docs/lan-mode.md). Drop --domain, or switch to \
                     --mode public."
                ));
            }
            DeploymentMode::Lan
        }
        other => {
            return Err(format!(
                "Unknown deployment mode '{other}'; expected 'public' or 'lan'"
            ))
        }
    };

    let out_dir = PathBuf::from(inputs.out_dir.unwrap_or_else(|| "./wavvon-hub".to_string()));

    Ok(SetupConfig {
        name,
        template,
        mode,
        out_dir,
        start: inputs.start,
    })
}

/// Writes `docker-compose.yml` and `.env` into `cfg.out_dir`, generating a
/// fresh random database password each call. Creates the output directory
/// if it doesn't already exist.
pub fn generate_files(cfg: &SetupConfig) -> Result<GeneratedFiles, String> {
    std::fs::create_dir_all(&cfg.out_dir).map_err(|e| {
        format!(
            "Could not create output directory {}: {e}",
            cfg.out_dir.display()
        )
    })?;

    let db_password = generate_password();

    let env_path = cfg.out_dir.join(".env");
    let compose_path = cfg.out_dir.join("docker-compose.yml");

    std::fs::write(&env_path, render_env(cfg, &db_password))
        .map_err(|e| format!("Could not write {}: {e}", env_path.display()))?;
    std::fs::write(&compose_path, render_compose(cfg))
        .map_err(|e| format!("Could not write {}: {e}", compose_path.display()))?;

    Ok(GeneratedFiles {
        compose_path,
        env_path,
        db_password,
    })
}

/// 24 random bytes, hex-encoded (48 hex chars) — long enough to be a solid
/// database password, and hex is always URL-safe inside the
/// `postgres://user:PASSWORD@host/db` connection string (no `:`, `@`, `/`,
/// or other characters that would need escaping).
fn generate_password() -> String {
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn render_env(cfg: &SetupConfig, db_password: &str) -> String {
    let mut out = String::new();
    out.push_str("# Generated by `wavvon-hub setup`. Do not commit this file — it contains\n");
    out.push_str(&format!("# the database password for \"{}\".\n", cfg.name));
    out.push_str(&format!("WAVVON_DB_PASSWORD={db_password}\n"));
    out.push_str(&format!(
        "WAVVON_DATABASE_URL=postgres://wavvon:{db_password}@db:5432/wavvon\n"
    ));
    out.push_str(&format!("WAVVON_TEMPLATE={}\n", cfg.template));
    out.push_str("WAVVON_LOG_FORMAT=text\n");
    match &cfg.mode {
        DeploymentMode::Public { domain } => {
            out.push_str(&format!("WAVVON_PUBLIC_URL=https://{domain}\n"));
            out.push_str(
                "# A reverse proxy (nginx/Caddy) on this host terminates TLS and forwards to\n",
            );
            out.push_str("# the hub's loopback-only port below; this tells the rate limiter to\n");
            out.push_str("# trust the proxy's X-Forwarded-For header instead of its own IP.\n");
            out.push_str("WAVVON_TRUSTED_PROXY=true\n");
        }
        DeploymentMode::Lan => {
            out.push_str("# LAN mode: self-signed trust, private-address guard, mDNS advert.\n");
            out.push_str("# See docs/docs/lan-mode.md.\n");
            out.push_str("WAVVON_LAN_MODE=true\n");
        }
    }
    out.push('\n');
    out.push_str("# Optional: seed a specific owner instead of using the first-boot invite\n");
    out.push_str("# printed in `docker compose logs hub` (the recommended path — see the\n");
    out.push_str("# wizard's printed next steps). Uncomment only if you already know the\n");
    out.push_str("# operator's public key (Settings -> Identity in a Wavvon client):\n");
    out.push_str("# WAVVON_OWNER_PUBKEY=<64-hex-char-public-key>\n");
    out
}

fn render_compose(cfg: &SetupConfig) -> String {
    let slug = slugify(&cfg.name);
    let hub_container = format!("{slug}-hub");
    let db_container = format!("{slug}-db");

    let (hub_port_line, hub_port_comment) = match &cfg.mode {
        DeploymentMode::Public { .. } => (
            "127.0.0.1:3000:3000".to_string(),
            "      # Loopback only — a reverse proxy on this host terminates TLS and\n      # forwards here. Never publish 3000 directly on a public-domain deployment.",
        ),
        DeploymentMode::Lan => (
            "3000:3000".to_string(),
            "      # LAN-only: WAVVON_LAN_MODE guards this to a private address, so\n      # exposing it on every interface is safe here.",
        ),
    };

    format!(
        "# Generated by `wavvon-hub setup` for \"{name}\" ({mode_label}).\n\
         # Review before deploying, then from this directory:\n\
         #   docker compose up -d\n\
         # Secrets live in .env, not here — do not commit .env.\n\
         \n\
         services:\n\
         \x20\x20hub:\n\
         \x20\x20\x20\x20image: ghcr.io/wavvon/hub:latest\n\
         \x20\x20\x20\x20container_name: {hub_container}\n\
         \x20\x20\x20\x20restart: unless-stopped\n\
         \x20\x20\x20\x20depends_on:\n\
         \x20\x20\x20\x20\x20\x20db:\n\
         \x20\x20\x20\x20\x20\x20\x20\x20condition: service_healthy\n\
         \x20\x20\x20\x20env_file:\n\
         \x20\x20\x20\x20\x20\x20- .env\n\
         \x20\x20\x20\x20volumes:\n\
         \x20\x20\x20\x20\x20\x20- hub-data:/data\n\
         \x20\x20\x20\x20ports:\n\
{hub_port_comment}\n\
         \x20\x20\x20\x20\x20\x20- \"{hub_port_line}\"\n\
         \x20\x20\x20\x20\x20\x20# Voice relay — must stay reachable from wherever clients connect.\n\
         \x20\x20\x20\x20\x20\x20- \"3001:3001/udp\"\n\
         \n\
         \x20\x20db:\n\
         \x20\x20\x20\x20image: postgres:16-alpine\n\
         \x20\x20\x20\x20container_name: {db_container}\n\
         \x20\x20\x20\x20restart: unless-stopped\n\
         \x20\x20\x20\x20environment:\n\
         \x20\x20\x20\x20\x20\x20POSTGRES_USER: wavvon\n\
         \x20\x20\x20\x20\x20\x20POSTGRES_PASSWORD: ${{WAVVON_DB_PASSWORD}}\n\
         \x20\x20\x20\x20\x20\x20POSTGRES_DB: wavvon\n\
         \x20\x20\x20\x20volumes:\n\
         \x20\x20\x20\x20\x20\x20- db-data:/var/lib/postgresql/data\n\
         \x20\x20\x20\x20healthcheck:\n\
         \x20\x20\x20\x20\x20\x20test: [\"CMD-SHELL\", \"pg_isready -U wavvon -d wavvon\"]\n\
         \x20\x20\x20\x20\x20\x20interval: 5s\n\
         \x20\x20\x20\x20\x20\x20timeout: 3s\n\
         \x20\x20\x20\x20\x20\x20retries: 10\n\
         \x20\x20\x20\x20# No host port published on purpose — reachable only on the compose\n\
         \x20\x20\x20\x20# network, never the internet.\n\
         \n\
         volumes:\n\
         \x20\x20hub-data:\n\
         \x20\x20db-data:\n",
        name = cfg.name,
        mode_label = match &cfg.mode {
            DeploymentMode::Public { domain } => format!("public, domain={domain}"),
            DeploymentMode::Lan => "LAN".to_string(),
        },
    )
}

/// Lowercases `name`, replaces runs of non-alphanumeric characters with a
/// single hyphen, and trims leading/trailing hyphens. Falls back to
/// `"wavvon-hub"` if that leaves nothing usable (e.g. an all-emoji name).
fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut last_was_dash = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "wavvon-hub".to_string()
    } else {
        trimmed.to_string()
    }
}

fn print_next_steps(cfg: &SetupConfig, generated: &GeneratedFiles) {
    println!();
    println!("Wrote:");
    println!("  {}", generated.compose_path.display());
    println!("  {}", generated.env_path.display());
    println!();
    println!("Generated a random database password (in .env — do not commit it).");
    println!();
    println!("Next steps:");
    println!("  1. Review the generated files, especially docker-compose.yml's ports.");
    if let DeploymentMode::Public { domain } = &cfg.mode {
        println!(
            "     Point a reverse proxy (nginx/Caddy) at 127.0.0.1:3000 for {domain}, \
             terminating TLS there."
        );
    }
    println!("  2. cd {} && docker compose up -d", cfg.out_dir.display());
    println!("  3. This hub starts with no owner and invite_only=true, so it mints a");
    println!("     one-time owner invite on first boot and logs it. Find it with:");
    println!("       docker compose logs hub | grep -i invite");
    println!("     (or: docker compose exec hub /usr/local/bin/wavvon-hub --doctor)");
    println!("     The log line looks like:");
    println!("       First-boot owner invite: wavvon://<host>/i/<hub-pubkey>/<code>");
    println!("     The exact code only exists after first boot, so it can't be pre-rendered");
    println!("     here — open the link (or paste it into a client's join flow) to claim");
    println!("     ownership of \"{}\".", cfg.name);
    println!("  4. Once you're the owner, invite others from the client as usual.");
    println!();
}

fn start_compose(out_dir: &Path) -> Result<(), String> {
    println!("Running `docker compose up -d` in {}...", out_dir.display());
    let status = std::process::Command::new("docker")
        .args(["compose", "up", "-d"])
        .current_dir(out_dir)
        .status()
        .map_err(|e| {
            format!(
                "Could not run `docker compose up -d` ({e}). Is Docker installed and on PATH? \
                 Run it manually: cd {} && docker compose up -d",
                out_dir.display()
            )
        })?;
    if !status.success() {
        return Err(format!(
            "`docker compose up -d` exited with {status}. Check the output above, then retry \
             manually from {}.",
            out_dir.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flag_inputs(name: &str, template: &str, mode: &str, domain: Option<&str>) -> SetupInputs {
        SetupInputs {
            name: Some(name.to_string()),
            template: Some(template.to_string()),
            mode: Some(mode.to_string()),
            domain: domain.map(|d| d.to_string()),
            out_dir: None,
            start: false,
            non_interactive: true,
        }
    }

    // ── parse_cli_args ────────────────────────────────────────────────────

    #[test]
    fn parses_all_flags() {
        let args: Vec<String> = [
            "--name",
            "My Community",
            "--template",
            "gaming",
            "--mode",
            "public",
            "--domain",
            "hub.example.com",
            "--out",
            "/tmp/out",
            "--start",
            "--non-interactive",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let inputs = parse_cli_args(&args).unwrap();
        assert_eq!(inputs.name.as_deref(), Some("My Community"));
        assert_eq!(inputs.template.as_deref(), Some("gaming"));
        assert_eq!(inputs.mode.as_deref(), Some("public"));
        assert_eq!(inputs.domain.as_deref(), Some("hub.example.com"));
        assert_eq!(inputs.out_dir.as_deref(), Some("/tmp/out"));
        assert!(inputs.start);
        assert!(inputs.non_interactive);
    }

    #[test]
    fn unknown_flag_is_rejected() {
        let args: Vec<String> = vec!["--bogus".to_string(), "value".to_string()];
        let err = parse_cli_args(&args).unwrap_err();
        assert!(err.contains("--bogus"));
    }

    #[test]
    fn flag_missing_value_is_rejected() {
        let args: Vec<String> = vec!["--name".to_string()];
        let err = parse_cli_args(&args).unwrap_err();
        assert!(err.contains("--name"));
    }

    // ── merge_env ─────────────────────────────────────────────────────────
    // Environment variable mutation makes this test order-sensitive against
    // any other test touching the same vars; scope it to a single test with
    // its own unique var values and clean up afterwards.

    #[test]
    fn env_fills_gaps_but_flags_win() {
        std::env::set_var("WAVVON_SETUP_NAME", "From Env");
        std::env::set_var("WAVVON_SETUP_TEMPLATE", "minimal");
        let mut inputs = SetupInputs {
            name: None,
            template: Some("gaming".to_string()), // flag already set — env must not override
            mode: None,
            domain: None,
            out_dir: None,
            start: false,
            non_interactive: false,
        };
        merge_env(&mut inputs);
        assert_eq!(inputs.name.as_deref(), Some("From Env"));
        assert_eq!(inputs.template.as_deref(), Some("gaming"));
        std::env::remove_var("WAVVON_SETUP_NAME");
        std::env::remove_var("WAVVON_SETUP_TEMPLATE");
    }

    // ── validate ──────────────────────────────────────────────────────────

    #[test]
    fn bad_preset_name_is_rejected() {
        let inputs = flag_inputs("Test Hub", "not-a-real-preset", "public", Some("x.example"));
        let err = validate(inputs).unwrap_err();
        assert!(err.contains("not-a-real-preset"));
        assert!(err.contains("gaming"));
    }

    #[test]
    fn missing_template_is_rejected() {
        let mut inputs = flag_inputs("Test Hub", "gaming", "public", Some("x.example"));
        inputs.template = None;
        let err = validate(inputs).unwrap_err();
        assert!(err.contains("template"));
    }

    #[test]
    fn public_mode_without_domain_is_rejected() {
        let inputs = flag_inputs("Test Hub", "community", "public", None);
        let err = validate(inputs).unwrap_err();
        assert!(err.contains("domain"));
    }

    #[test]
    fn lan_mode_with_domain_is_rejected() {
        let inputs = flag_inputs("Test Hub", "community", "lan", Some("x.example"));
        let err = validate(inputs).unwrap_err();
        assert!(err.contains("lan"));
    }

    #[test]
    fn unknown_mode_is_rejected() {
        let inputs = flag_inputs("Test Hub", "community", "orbital", None);
        let err = validate(inputs).unwrap_err();
        assert!(err.contains("orbital"));
    }

    #[test]
    fn missing_mode_is_rejected() {
        let mut inputs = flag_inputs("Test Hub", "community", "public", Some("x.example"));
        inputs.mode = None;
        let err = validate(inputs).unwrap_err();
        assert!(err.contains("mode"));
    }

    #[test]
    fn public_mode_resolves_with_domain() {
        let inputs = flag_inputs("Test Hub", "gaming", "public", Some("hub.example.com"));
        let cfg = validate(inputs).unwrap();
        assert_eq!(cfg.name, "Test Hub");
        assert_eq!(cfg.template, "gaming");
        match cfg.mode {
            DeploymentMode::Public { domain } => assert_eq!(domain, "hub.example.com"),
            DeploymentMode::Lan => panic!("expected Public mode"),
        }
        assert_eq!(cfg.out_dir, PathBuf::from("./wavvon-hub"));
    }

    #[test]
    fn lan_mode_resolves_without_domain() {
        let inputs = flag_inputs("Test Hub", "minimal", "lan", None);
        let cfg = validate(inputs).unwrap();
        assert_eq!(cfg.mode, DeploymentMode::Lan);
    }

    #[test]
    fn mode_is_case_insensitive() {
        let inputs = flag_inputs("Test Hub", "minimal", "LAN", None);
        let cfg = validate(inputs).unwrap();
        assert_eq!(cfg.mode, DeploymentMode::Lan);
    }

    #[test]
    fn blank_name_falls_back_to_default() {
        let mut inputs = flag_inputs("", "minimal", "lan", None);
        inputs.name = Some("   ".to_string());
        let cfg = validate(inputs).unwrap();
        assert_eq!(cfg.name, "My Wavvon Hub");
    }

    // ── slugify ───────────────────────────────────────────────────────────

    #[test]
    fn slugify_handles_spaces_and_punctuation() {
        assert_eq!(slugify("My Cool Hub!"), "my-cool-hub");
        assert_eq!(slugify("  leading/trailing  "), "leading-trailing");
    }

    #[test]
    fn slugify_falls_back_when_nothing_usable() {
        assert_eq!(slugify("!!!"), "wavvon-hub");
    }

    // ── generate_password ─────────────────────────────────────────────────

    #[test]
    fn generated_passwords_are_hex_and_differ() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), 48);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "two calls should not produce the same password");
    }
}
