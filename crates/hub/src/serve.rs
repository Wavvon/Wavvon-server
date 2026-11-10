use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use tokio::sync::{broadcast, RwLock};
use url::Url;
use wavvon_hub::cert_worker;
use wavvon_hub::db;
use wavvon_hub::dm_worker;
use wavvon_hub::federation::client::FederationClient;
use wavvon_hub::server;
use wavvon_hub::state::AppState;
use wavvon_identity::Identity;
use webauthn_rs::WebauthnBuilder;

/// Start the hub server and run until it fails or a stop signal arrives.
pub async fn run(
    mut settings: wavvon_hub::settings::Settings,
    otlp_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
) -> Result<()> {
    let http_port = settings.http_port;
    let voice_udp_port = settings.voice_udp_port;

    let (hub_identity, is_new) = Identity::load_or_create(Path::new("hub_identity.json"))?;

    // Where we are reachable from outside. Resolved here, after the identity
    // exists, because a farm-hosted hub derives it from its farm's URL plus
    // its own pubkey — the farm cannot pass it at spawn, since the key in it
    // is generated on this very line. Everything downstream that needs a
    // public address reads this, not `settings.public_url`.
    let public_url = wavvon_hub::settings::effective_public_url(
        settings.public_url.as_deref(),
        settings.farm_url.as_deref(),
        Some(&hub_identity.public_key_hex()),
    );
    if public_url.is_none() {
        tracing::warn!(
            "No public URL: {} is unset and this hub is not farm-managed. Voice, \
             invite links and passkeys all need one and will be unavailable.",
            wavvon_hub_env::PUBLIC_URL,
        );
    }

    // ---- LAN mode resolution ----
    // Must run before the TLS banner below: LAN mode can supply its own
    // self-signed cert/key when no CA cert is already configured, and it
    // always applies the hard private-address guard first (lan-mode.md §4)
    // — this is what makes it structurally impossible for a self-signed or
    // plaintext LAN hub to end up reachable from the public internet.
    let has_ca_cert = settings.tls_cert.is_some() && settings.tls_key.is_some();
    let mut effective_tls_cert = settings.tls_cert.clone();
    let mut effective_tls_key = settings.tls_key.clone();
    // "self" | "none", mirrors AppState::lan_tls_mode. None when LAN mode is
    // off, or when a CA cert is already configured (see has_ca_cert below).
    let mut lan_tls_tier: Option<String> = None;
    let mut lan_fingerprint: Option<String> = None;
    let mut lan_advertise_ip: Option<std::net::IpAddr> = None;

    if settings.lan_mode {
        match wavvon_hub::lan::resolve_lan_address(settings.lan_advertise_addr.as_deref()) {
            Ok(ip) => lan_advertise_ip = Some(ip),
            Err(e) => {
                eprintln!("LAN mode configuration error: {e}");
                std::process::exit(1);
            }
        }
        let ip = lan_advertise_ip.expect("set immediately above");
        match wavvon_hub::lan::lan_bind_addr(settings.bind_addr) {
            Ok(addr) => settings.bind_addr = addr,
            Err(e) => {
                eprintln!("LAN mode configuration error: {e}");
                std::process::exit(1);
            }
        }

        if has_ca_cert {
            tracing::info!(
                "LAN mode: WAVVON_TLS_CERT/WAVVON_TLS_KEY are already configured; the \
                 private-address guard stays active but self-signed/plaintext trust bootstrap \
                 and mDNS advertisement are skipped (a CA-issued cert is the 'everyone' tier \
                 from lan-mode.md and doesn't need LAN mode's help)."
            );
        } else if settings.lan_tls_mode == "none" {
            lan_tls_tier = Some("none".to_string());
            lan_fingerprint = Some(hub_identity.public_key_hex());
        } else {
            match wavvon_hub::lan::load_or_create_self_signed(
                Path::new("lan_cert.pem"),
                Path::new("lan_cert.key"),
                ip,
            ) {
                Ok(cert) => {
                    effective_tls_cert = Some("lan_cert.pem".to_string());
                    effective_tls_key = Some("lan_cert.key".to_string());
                    lan_tls_tier = Some("self".to_string());
                    lan_fingerprint = Some(cert.fingerprint_hex);
                }
                Err(e) => {
                    eprintln!("LAN mode: failed to generate self-signed cert: {e}");
                    std::process::exit(1);
                }
            }
        }
    }

    // ---- Startup summary banner ----
    let tls_enabled = effective_tls_cert.is_some() && effective_tls_key.is_some();
    let scheme = if tls_enabled { "https" } else { "http" };
    let cwd = std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".into());

    tracing::info!(
        "wavvon-hub {} starting  port={} ({scheme})  voice_udp={}  tls={}  cors={}",
        env!("CARGO_PKG_VERSION"),
        http_port,
        voice_udp_port,
        if tls_enabled { "enabled" } else { "disabled" },
        settings.cors_origins,
    );
    tracing::info!("data: identity={cwd}/hub_identity.json  database=PostgreSQL");

    if settings.allow_private_webhooks {
        tracing::warn!(
            "WAVVON_ALLOW_PRIVATE_WEBHOOKS is enabled: outgoing webhooks and app webhook URLs              may use plain http and private/loopback hosts (SSRF guard off)."
        );
    }

    // The generic mixed-content warning doesn't apply to LAN plaintext mode
    // (that tier is documented and gated, not an oversight) — the LAN MODE
    // banner below covers it instead.
    if !tls_enabled && lan_tls_tier.as_deref() != Some("none") {
        tracing::warn!(
            "TLS is disabled — browser clients served over HTTPS cannot connect to an http:// hub \
             (mixed-content blocked). Set WAVVON_TLS_CERT and WAVVON_TLS_KEY or terminate TLS at a reverse proxy."
        );
    }
    tracing::info!(
        "Reminder: the voice UDP port {} must be open in any cloud firewall / security group — \
         voice fails silently when the port is blocked.",
        voice_udp_port
    );
    match settings.web_client_dir.as_deref() {
        Some(dir) => tracing::info!("web client: serving from {dir}"),
        None => tracing::info!("web client: disabled (set WAVVON_WEB_CLIENT_DIR to enable)"),
    }

    if is_new {
        let cwd = std::env::current_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_default();
        tracing::warn!(
            "Generated a NEW hub identity: {hub_identity}. It is {cwd}/hub_identity.json; back it \
             up with the database. Every client knows this hub by that key: losing the file makes \
             this a different hub to all of them. If you reinstalled and kept the old file, \
             `wavvon-hub rotate-key --endorse-from <old file>` lets clients follow."
        );
    } else {
        tracing::info!("Loaded hub identity: {}", hub_identity);
    }

    if let (Some(ip), Some(tier)) = (lan_advertise_ip, lan_tls_tier.as_deref()) {
        let trust_desc = if tier == "self" {
            format!(
                "fingerprint {}",
                lan_fingerprint.as_deref().unwrap_or("(unknown)")
            )
        } else {
            "plaintext".to_string()
        };
        tracing::warn!(
            "LAN MODE — serving {scheme} on {ip}:{http_port}; NOT reachable from the internet; \
             trust bootstrapped via {trust_desc}"
        );
    }

    // Mode is chosen by the absence of configuration (decisions.md, "The hub
    // bundles PostgreSQL, and never touches one it did not create"): no URL
    // means the hub starts and supervises its own server, a URL means it is a
    // plain client that runs migrations and manages nothing.
    //
    // Held for the life of the process: dropping the handle does not stop the
    // server, but keeping it is what lets shutdown stop it deliberately.
    let embedded = match settings.database_url.as_deref() {
        Some(_) => None,
        None => {
            let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            match wavvon_hub::embedded_pg::start(&root).await {
                Ok(pg) => {
                    tracing::info!(
                        "database: embedded PostgreSQL, data in {}",
                        pg.data_dir().display()
                    );
                    Some(pg)
                }
                Err(e) => {
                    // Never a fallback to the old localhost guess: connecting
                    // to whatever answers on 5432 is how a hub came to operate
                    // on a database nobody meant.
                    eprintln!("FATAL could not start the built-in PostgreSQL: {e:#}");
                    std::process::exit(1);
                }
            }
        }
    };
    let db_url = match (&embedded, settings.database_url.as_deref()) {
        (Some(pg), _) => pg.url().to_string(),
        (None, Some(url)) => {
            tracing::info!("database: external, as configured");
            url.to_string()
        }
        // Unreachable: no URL took the embedded branch above, which either
        // produced a handle or exited.
        (None, None) => unreachable!("no database URL and no embedded server"),
    };

    let write_pool = PgPoolOptions::new()
        .max_connections(settings.db_max_connections)
        .connect(&db_url)
        .await
        .expect("Failed to connect to database");

    let db = write_pool;

    // Before migrations: a server below the floor otherwise fails partway
    // through applying the schema, and the operator sees a CREATE TABLE
    // syntax error instead of "your PostgreSQL is too old".
    if let Err(e) = db::version::ensure_supported(&db).await {
        eprintln!("FATAL {e}");
        std::process::exit(1);
    }

    db::migrations::run(&db).await?;

    // First-run bootstrap: applies a template (from a wizard-issued bootstrap
    // token, a template URL, a local template file, or a built-in preset)
    // when the hub has no channels and no users yet. Runs before owner_pubkey
    // seeding below so a template's channels/roles exist by the time the
    // owner is assigned. Non-fatal for network/file issues — a bad template,
    // unreachable URL, or missing file never blocks startup, the hub just
    // starts blank. An unrecognized WAVVON_TEMPLATE preset name is a
    // configuration mistake and does fail startup (see bootstrap::presets).
    {
        let bootstrap_client = reqwest::Client::new();
        wavvon_hub::bootstrap::maybe_bootstrap(
            &db,
            &bootstrap_client,
            &wavvon_hub::bootstrap::BootstrapConfig {
                template_url: settings.template_url.clone(),
                template_file: settings.template_file.clone(),
                preset: settings.template.clone(),
            },
        )
        .await?;
    }

    // If owner_pubkey is configured, seed that key as the hub owner before
    // serving any traffic. Idempotent: skipped if the key is already owner.
    // The farm sets this when spawning a hub created by a specific user.
    if let Some(owner_pk) = settings.owner_pubkey.as_deref() {
        let owner_pk = owner_pk.trim().to_lowercase();
        if owner_pk.len() == 64 && owner_pk.chars().all(|c| c.is_ascii_hexdigit()) {
            let current: Option<String> = sqlx::query_scalar(
                "SELECT user_public_key FROM user_roles WHERE role_id = 'builtin-owner' LIMIT 1",
            )
            .fetch_optional(&db)
            .await
            .unwrap_or(None);

            if current.as_deref() != Some(&owner_pk) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                sqlx::query(
                    "INSERT INTO users (public_key, first_seen_at, is_member) VALUES ($1, $2, TRUE)
                         ON CONFLICT (public_key) DO UPDATE SET is_member = TRUE",
                )
                .bind(&owner_pk)
                .bind(now)
                .execute(&db)
                .await
                .ok();
                sqlx::query("DELETE FROM user_roles WHERE role_id = 'builtin-owner'")
                    .execute(&db)
                    .await
                    .ok();
                sqlx::query(
                    "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ($1, 'builtin-owner', $2)
                     ON CONFLICT (user_public_key, role_id) DO UPDATE SET assigned_at = excluded.assigned_at",
                )
                .bind(&owner_pk)
                .bind(now)
                .execute(&db)
                .await
                .ok();
                tracing::info!(
                    "Hub owner seeded from owner_pubkey: {}…",
                    &owner_pk[..16.min(owner_pk.len())]
                );
            }
        } else {
            tracing::warn!("owner_pubkey is set but not a valid 64-char hex key; ignoring");
        }
    }

    if settings.owner_pubkey.is_none() {
        // An owner seated through the first-boot invite holds the role with no
        // env var behind it, which is the default path, so ask the database.
        let has_owner: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM user_roles WHERE role_id = 'builtin-owner')",
        )
        .fetch_one(&db)
        .await
        .unwrap_or(false);
        if !has_owner {
            tracing::warn!(
                "No WAVVON_OWNER_PUBKEY configured and nobody holds the owner role. \
                 Redeem the owner invite below, set WAVVON_OWNER_PUBKEY and restart, \
                 or run `wavvon-hub admin users set-owner <pubkey>`."
            );
        }

        // Fresh hubs default to invite_only=true (task #31), which would
        // otherwise leave no invite-free path for anyone to become owner.
        // Mint (or reuse) the one-time owner-granting invite and print the
        // plain /join link so the operator has a concrete way in. No-op once
        // the hub already has a real user — see maybe_mint_first_boot_owner_invite.
        match wavvon_hub::routes::invites::maybe_mint_first_boot_owner_invite(&db).await {
            Ok(Some(code)) => {
                // The /join link must be copy-pasteable: an explicit scheme in
                // public_url wins; a bare public host is assumed TLS-fronted;
                // the localhost fallback matches this process's own TLS state.
                let join_scheme = match public_url.as_deref() {
                    Some(u) if u.starts_with("http://") => "http",
                    Some(_) => "https",
                    None => scheme,
                };
                // `public_url` may carry a path (a farm-hosted hub lives under
                // /hub/<pubkey>), so this is the whole base, not just a host —
                // stripping the scheme and appending /join gives the right
                // link either way.
                let raw_host = public_url
                    .clone()
                    .unwrap_or_else(|| format!("localhost:{}", settings.http_port));
                let host = raw_host
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_end_matches('/');
                tracing::warn!("First-boot owner invite: {join_scheme}://{host}/join/{code}");
            }
            Ok(None) => {}
            Err((_, e)) => {
                tracing::warn!("Could not mint first-boot owner invite: {e}");
            }
        }
    }

    let search_path = std::path::Path::new("hub.search");
    let search: Arc<dyn wavvon_hub::search::MessageSearch> =
        if settings.search_backend.as_deref() == Some("none") {
            Arc::new(wavvon_hub::search::null_search::NullSearch)
        } else {
            Arc::new(
                wavvon_hub::search::tantivy_search::TantivySearch::open(search_path)
                    .expect("Failed to open Tantivy search index"),
            )
        };

    let (chat_tx, _) = broadcast::channel::<(
        wavvon_hub::routes::chat_models::ChatEvent,
        std::sync::Arc<str>,
    )>(4096);
    let (voice_event_tx, _) = broadcast::channel(1024);
    let (dm_tx, _) = broadcast::channel(1024);
    let (screen_share_tx, _) = broadcast::channel(1024);

    // Farm integration: fetch the farm pubkey from farm_url if set.
    let farm_url = settings.farm_url.clone();
    let http_client = reqwest::Client::new();
    let cached_farm_pubkey: Arc<tokio::sync::RwLock<Option<String>>> =
        Arc::new(tokio::sync::RwLock::new(None));
    let last_farm_pubkey_fetch: Arc<tokio::sync::RwLock<i64>> =
        Arc::new(tokio::sync::RwLock::new(0));

    if let Some(ref url) = farm_url {
        match http_client
            .get(format!("{url}/farm/info"))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(body) => {
                        if let Some(pk) = body.get("public_key").and_then(|v| v.as_str()) {
                            *cached_farm_pubkey.write().await = Some(pk.to_string());
                            tracing::info!(
                                "Cached farm pubkey from {url}: {}",
                                &pk[..16.min(pk.len())]
                            );
                        } else {
                            tracing::warn!("Farm /farm/info response missing public_key field");
                        }
                    }
                    Err(e) => tracing::warn!("Failed to parse farm /farm/info response: {e}"),
                }
            }
            Ok(resp) => tracing::warn!(
                "Farm /farm/info returned non-success status: {}",
                resp.status()
            ),
            Err(e) => tracing::warn!(
                "Could not reach farm at {url} on startup: {e} — hub will work with hub-issued tokens only"
            ),
        }
    }

    // Publicly-reachable host for the voice WebTransport endpoint
    // (voice-transport-v2.md). Voice is dialled directly, never through the
    // farm's HTTP proxy — a datagram carries no path to route on — so only
    // the *host* is taken here, and the port is this hub's own allocated one.
    // WAVVON_VOICE_PUBLIC_HOST wins: a public host behind a proxy that drops
    // UDP needs voice on a DNS-only name. The certificate is pinned by hash
    // from /info, so that name needs no CA certificate of its own.
    let voice_udp_host: Option<String> = settings
        .voice_public_host
        .clone()
        .filter(|h| !h.trim().is_empty())
        .or_else(|| {
            public_url
                .as_deref()
                .and_then(|u| Url::parse(u).ok())
                .and_then(|parsed| parsed.host_str().map(|h| h.to_string()))
        })
        .or_else(|| lan_advertise_ip.map(|ip| ip.to_string()));
    let voice_wt_url: Option<String> =
        voice_udp_host.map(|host| format!("https://{host}:{voice_udp_port}/voice"));

    // ---- WebAuthn / passkey setup ----
    let rp_id: String = settings
        .webauthn_rp_id
        .clone()
        .or_else(|| {
            public_url.as_deref().and_then(|u| {
                Url::parse(u)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(|h| h.to_string()))
            })
        })
        .unwrap_or_else(|| "localhost".to_string());

    // Origin only — scheme, host and port, never the path. WebAuthn compares
    // the browser's origin, and a hub behind a farm (or any path-prefixing
    // proxy) has a public URL with a path on the end; passing that whole URL
    // would build a relying party nothing ever matches.
    let rp_origin: Url = public_url
        .as_deref()
        .and_then(|u| Url::parse(u).ok())
        .and_then(|parsed| Url::parse(&parsed.origin().ascii_serialization()).ok())
        .unwrap_or_else(|| {
            Url::parse(&format!("http://localhost:{}", settings.http_port)).unwrap()
        });

    let hub_display_name = "Wavvon Hub";

    // A relying party the browser will refuse must not take the hub down with
    // it. This used to `.expect()`, and the first farm-hosted hub to boot found
    // out why that was wrong: a farm reached at an IP derives an rp_id of
    // `127.0.0.1`, WebAuthn requires an effective *domain*, and the whole
    // process died at startup. Losing passkeys on a hub that could never have
    // offered them is the correct outcome; refusing to start is not — and on a
    // farm it takes out a community per misconfigured address.
    let webauthn = Arc::new(
        WebauthnBuilder::new(&rp_id, &rp_origin)
            .and_then(|b| b.rp_name(hub_display_name).build())
            .unwrap_or_else(|e| {
                tracing::warn!(
                    rp_id,
                    rp_origin = %rp_origin,
                    error = %e,
                    "WebAuthn is unavailable on this hub: passkey registration and \
                     sign-in will fail. A relying-party id must be a domain — an IP \
                     address or a bare host cannot be one. Set WAVVON_WEBAUTHN_RP_ID, \
                     or reach this hub by hostname."
                );
                let fallback = Url::parse("http://localhost").expect("static URL");
                WebauthnBuilder::new("localhost", &fallback)
                    .and_then(|b| b.rp_name(hub_display_name).build())
                    .expect("the localhost relying party is always valid")
            }),
    );

    if rp_id != "localhost" && settings.tls_cert.is_none() {
        tracing::warn!(
            "WebAuthn requires HTTPS for non-localhost rp_id '{rp_id}'; \
             passkey registration/assertion will fail on plain HTTP"
        );
    }

    let state = Arc::new(AppState {
        hub_name: "my-hub".to_string(),
        hub_identity,
        db,
        pending_challenges: RwLock::new(HashMap::new()),
        ws_tickets: std::sync::Mutex::new(HashMap::new()),
        cert_portfolio_cache: RwLock::new(HashMap::new()),
        chat_tx,
        federation_client: FederationClient::new(),
        peer_tokens: RwLock::new(HashMap::new()),
        http_client,
        voice_channels: RwLock::new(HashMap::new()),
        voice_last_active: RwLock::new(HashMap::new()),
        voice_sender_ids: RwLock::new(HashMap::new()),
        voice_next_sender_id: RwLock::new(HashMap::new()),
        voice_udp_port,
        voice_wt_url,
        // Seeded with what we can work out ourselves; a farm-managed hub has
        // this replaced by the farm's answer on the first heartbeat, which is
        // also how a later rename reaches it.
        canonical_url: Arc::new(RwLock::new(public_url.clone())),
        voice_cert_hash: RwLock::new(None),
        voice_event_tx,
        dm_tx,
        online_users: RwLock::new(HashMap::new()),
        screen_shares: RwLock::new(HashMap::new()),
        federated_masters: RwLock::new(HashMap::new()),
        screen_share_tx,
        app_sessions: RwLock::new(HashMap::new()),
        farm_url,
        cached_farm_pubkey,
        last_farm_pubkey_fetch,
        farm_session_checks: std::sync::Mutex::new(HashMap::new()),
        voice_zones: RwLock::new(HashMap::new()),
        video_channels: RwLock::new(HashMap::new()),
        started_at: std::time::Instant::now(),
        whisper_target_defs: RwLock::new(HashMap::new()),
        whisper_optouts: RwLock::new(std::collections::HashSet::new()),
        whisper_target_pubkeys: RwLock::new(HashMap::new()),
        voice_relay_active: RwLock::new(std::collections::HashSet::new()),
        voice_outbound_loss: RwLock::new(HashMap::new()),
        staging_voice_grants: RwLock::new(HashMap::new()),
        voice_talk_blocked: RwLock::new(std::collections::HashSet::new()),
        voice_pending_binds: RwLock::new(HashMap::new()),
        ws_key_senders: RwLock::new(HashMap::new()),
        rate_limiters: Default::default(),
        preview_cache: std::sync::Mutex::new(std::collections::HashMap::new()),
        search,
        reindex_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        owner_pubkey: settings.owner_pubkey.clone(),
        apps_allow_camera: settings.apps_allow_camera,
        allow_private_webhooks: settings.allow_private_webhooks,
        accept_unbound_auth: false,
        metrics_enabled: settings.metrics,
        http_video_stream_budget: settings.http_video_stream_budget as usize,
        webauthn,
        webauthn_reg_challenges: RwLock::new(HashMap::new()),
        webauthn_auth_challenges: RwLock::new(HashMap::new()),
        webhook_circuit: Arc::new(tokio::sync::Mutex::new(
            wavvon_hub::state::WebhookCircuit::default(),
        )),
        lan_mode: settings.lan_mode,
        lan_tls_mode: lan_tls_tier.clone(),
        lan_fingerprint: lan_fingerprint.clone(),
    });

    // LAN mode: advertise via mDNS/DNS-SD (`_wavvon._tcp.local`), when
    // enabled and when a no-CA trust tier is actually in play (see the
    // has_ca_cert skip above). Kept alive for the process lifetime by
    // holding the returned daemon in this binding — dropping it would
    // unregister the service. Failure here is non-fatal: mDNS is a
    // discovery convenience, not part of the safety invariant, and boxes
    // without multicast (containers, some CI) must not fail to start.
    let _lan_mdns_daemon = if settings.lan_mode && settings.lan_mdns {
        match (lan_advertise_ip, lan_tls_tier.as_deref()) {
            (Some(ip), Some(tier)) => {
                let hub_name_for_mdns = wavvon_hub::routes::hub::current_hub_name(&state).await;
                let fp_or_pubkey = lan_fingerprint
                    .clone()
                    .unwrap_or_else(|| state.hub_identity.public_key_hex());
                let params = wavvon_hub::lan::MdnsAnnounceParams {
                    hub_name: &hub_name_for_mdns,
                    advertise_ip: ip,
                    port: http_port,
                    tls_mode: tier,
                    fingerprint_or_pubkey: &fp_or_pubkey,
                };
                match wavvon_hub::lan::start_mdns_advertiser(&params) {
                    Ok(daemon) => {
                        tracing::info!(
                            "LAN mode: advertising via mDNS as _wavvon._tcp.local (name={hub_name_for_mdns})"
                        );
                        Some(daemon)
                    }
                    Err(e) => {
                        tracing::warn!("LAN mode: mDNS advertisement failed (non-fatal): {e}");
                        None
                    }
                }
            }
            _ => None,
        }
    } else {
        None
    };

    // Start the WebTransport voice relay (voice-transport-v2.md). Uses the
    // *raw* WAVVON_TLS_CERT/WAVVON_TLS_KEY, not `effective_tls_cert`/`_key`
    // — a LAN-mode self-signed cert has no rotation story and isn't bounded
    // to the 14-day validity `serverCertificateHashes` requires, so voice
    // always manages its own identity independently of LAN mode.
    let bound_voice_port = wavvon_hub::voice_wt::start(
        state.clone(),
        voice_udp_port,
        settings.tls_cert.as_deref(),
        settings.tls_key.as_deref(),
    )
    .await
    .context("Failed to start voice WebTransport relay")?;
    tracing::info!("Voice WebTransport listening on port {bound_voice_port}");

    // Retry undelivered federated DMs in the background.
    dm_worker::spawn(state.clone());

    // Issue certifications to eligible members daily.
    cert_worker::spawn(state.clone());

    // Sweep messages and forum posts past their channel retention deadline.
    wavvon_hub::retention_worker::spawn(state.clone());
    wavvon_hub::routes::stickers::spawn_gc(state.clone());

    // Auto-move idle voice participants into the configured AFK channel.
    wavvon_hub::afk_worker::spawn(state.clone());

    // Sync federated ban lists from subscribed sources every 6 hours.
    wavvon_hub::banlist_worker::spawn(state.clone());

    // Poll known cert issuers for revocations every 6 hours.
    wavvon_hub::cert_revocation_worker::spawn(state.clone());

    // Poll known subkey issuers for revocations every 6 hours.
    wavvon_hub::subkey_revocation_worker::spawn(state.clone());

    // Post event reminder cards a configured number of minutes before start.
    wavvon_hub::reminder_worker::spawn(state.clone());

    // Sweep join-to-create temp voice channels past their empty-grace period.
    wavvon_hub::temp_channel_worker::spawn(state.clone());

    // Farm heartbeat: POST /farm/heartbeat every 60 seconds when WAVVON_FARM_URL is set.
    if let Some(ref farm_url_for_hb) = state.farm_url {
        let hb_state = state.clone();
        let hb_url = farm_url_for_hb.clone();
        // The farm allocated our row before this process existed, so it does
        // not know our pubkey — it is generated on first boot. Reporting the
        // id it gave us is how it binds the two. Without it the farm has a hub
        // it can manage but cannot route to, because the proxy keys on
        // `hubs.hub_pubkey`.
        let hb_farm_hub_id = settings.farm_hub_id.clone();
        let hb_credential = settings.farm_hub_credential.clone();
        if hb_farm_hub_id.is_none() {
            tracing::warn!(
                "{} is set but {} is not — the farm cannot bind this hub to its row, \
                 so it will never be able to route traffic to us",
                wavvon_hub_env::FARM_URL,
                wavvon_hub_env::FARM_HUB_ID,
            );
        }
        tokio::spawn(async move {
            // The first tick fires immediately, on purpose. This used to be
            // skipped, which meant a freshly spawned hub said nothing for a
            // full minute — and the first heartbeat is what claims its serial,
            // so for that minute the farm had a hub it could not route to and
            // its monitor had no evidence it was alive. Announce on boot, then
            // every 60s.
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let online = hb_state.online_users.read().await.len() as u64;
                // Not measured yet: the farm shows 0 for every hub. The database lives in
                // PostgreSQL, so the figure would need a size query, not a file stat.
                let db_size = 0u64;
                let uptime = hb_state.started_at.elapsed().as_secs();
                let payload = serde_json::json!({
                    "hub_id": hb_farm_hub_id,
                    "hub_credential": hb_credential,
                    "hub_pubkey": hb_state.hub_identity.public_key_hex(),
                    "online_users": online,
                    "storage_bytes": db_size,
                    "uptime_seconds": uptime,
                });
                // The reply carries the address the farm currently publishes
                // for us. Adopting it here is what makes a rename propagate to
                // every connected client within one interval, without a
                // restart — clients re-read /info on connect and on
                // hub_updated, and take the new URL from there.
                if let Ok(resp) = hb_state
                    .http_client
                    .post(format!("{hb_url}/farm/heartbeat"))
                    .json(&payload)
                    .send()
                    .await
                {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        if let Ok(siblings) =
                            serde_json::from_value::<Vec<wavvon_hub::farm_siblings::Sibling>>(
                                body.get("siblings")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null),
                            )
                        {
                            wavvon_hub::farm_siblings::reconcile(&hb_state.db, &siblings).await;
                        }
                        if let Some(url) = body.get("canonical_url").and_then(|v| v.as_str()) {
                            let mut current = hb_state.canonical_url.write().await;
                            if current.as_deref() != Some(url) {
                                tracing::info!(canonical_url = url, "Farm reports our address");
                                *current = Some(url.to_string());
                            }
                        }
                    }
                }
            }
        });
    }

    if let Some(list) = settings.trusted_proxy_from.as_deref() {
        let addrs: Vec<std::net::IpAddr> = list
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .filter_map(|a| match a.parse() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    tracing::warn!(
                        "{}: ignoring {a:?}, not an IP address",
                        wavvon_hub_env::TRUSTED_PROXY_FROM
                    );
                    None
                }
            })
            .collect();
        tracing::info!("Rate limiter: X-Forwarded-For believed only from {addrs:?}");
        wavvon_hub::rate_limit::set_trusted_proxy_from(addrs);
    }

    // Log whether the rate limiter will trust X-Forwarded-For.
    if settings.trusted_proxy {
        tracing::info!(
            "Rate limiter: trusted-proxy mode ENABLED — real client IP derived from \
             X-Forwarded-For (last entry). Assumes a single reverse proxy in front."
        );
    } else {
        tracing::info!(
            "Rate limiter: direct mode (socket peer address). \
             Set WAVVON_TRUSTED_PROXY=true when a reverse proxy terminates TLS in front."
        );
    }

    // Load and validate the web client directory when configured.
    // Fail fast here so a misconfigured path doesn't silently result in a
    // running hub that 404s everything at /.
    let web_client_cfg = match settings.web_client_dir.as_deref() {
        Some(dir) => match wavvon_hub::web_client::WebClientConfig::load(dir) {
            Ok(cfg) => {
                tracing::info!(
                    "web client: loaded {} bytes for index.html from {dir}",
                    cfg.index_html.len()
                );
                Some(std::sync::Arc::new(cfg))
            }
            Err(e) => {
                tracing::error!("web client configuration error: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };

    let app = server::create_router_full(
        state,
        &settings.cors_origins,
        settings.trusted_proxy,
        web_client_cfg,
    );
    let std_listener = wavvon_hub::listen::http_listener(settings.bind_addr, http_port)
        .with_context(|| format!("Failed to bind {}:{http_port}", settings.bind_addr))?;
    let bound = std_listener.local_addr()?;

    let serve = async {
        let tls = if let (Some(cert), Some(key)) =
            (effective_tls_cert.as_deref(), effective_tls_key.as_deref())
        {
            let cert_path = PathBuf::from(cert);
            let key_path = PathBuf::from(key);
            let rustls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .with_context(|| {
                        format!("Failed to load TLS cert/key from {cert:?} / {key:?}")
                    })?;
            tracing::info!("Hub server listening on https://{bound} (TLS enabled)");
            Some(rustls_config)
        } else {
            tracing::info!(
                "Hub server listening on http://{bound} (plaintext — set WAVVON_TLS_CERT and WAVVON_TLS_KEY to enable TLS)"
            );
            None
        };
        wavvon_hub::listen::serve(std_listener, tls, app).await?;
        Ok::<(), anyhow::Error>(())
    };

    // Whichever comes first — the listener giving up, or the operator asking
    // us to stop. The signal arm is what makes `stop_embedded` reachable at
    // all; see its doc comment for why an orphaned postmaster matters.
    let result = tokio::select! {
        r = serve => r,
        reason = shutdown_signal() => {
            tracing::info!("Shutdown requested ({reason})");
            Ok(())
        }
    };

    stop_embedded(embedded).await;

    if let Some(provider) = otlp_provider {
        let _ = provider.shutdown();
    }

    result
}

/// Resolve when the operator asks this process to stop, naming which signal
/// did it.
///
/// `tokio::signal::ctrl_c()` is SIGINT alone on Unix, and SIGINT is the
/// interactive stop. Every documented production deployment uses SIGTERM —
/// `systemctl stop`, `docker stop` and a plain `kill` all send it — so waiting
/// on SIGINT only meant the process was terminated without ever reaching
/// `stop_embedded`, leaving a postmaster holding the data directory on a
/// normal, documented stop. See `stop_embedded` for why that matters on the
/// upgrade path.
///
/// A force kill (SIGKILL, `Stop-Process -Force`) stays uncatchable here and
/// everywhere; adopting the orphan on the next start is what covers it.
async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        // Failing to install a handler is not worth refusing to serve over —
        // the other signal still works, and the worst case is the behaviour
        // this function was written to fix.
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Could not listen for SIGTERM: {e}");
                let _ = tokio::signal::ctrl_c().await;
                return "SIGINT";
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "SIGINT",
            _ = term.recv() => "SIGTERM",
        }
    }
    #[cfg(not(unix))]
    {
        // The Windows equivalents of a service stop. `ctrl_close` is the
        // console window closing and `ctrl_shutdown` is the machine going
        // down; both give a short grace period, which is enough to stop a
        // postmaster.
        use tokio::signal::windows;
        let mut close = match windows::ctrl_close() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Could not listen for CTRL_CLOSE: {e}");
                let _ = tokio::signal::ctrl_c().await;
                return "Ctrl-C";
            }
        };
        let mut shutdown = match windows::ctrl_shutdown() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("Could not listen for CTRL_SHUTDOWN: {e}");
                let _ = tokio::signal::ctrl_c().await;
                return "Ctrl-C";
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "Ctrl-C",
            _ = close.recv() => "CTRL_CLOSE",
            _ = shutdown.recv() => "CTRL_SHUTDOWN",
        }
    }
}

/// Stop the PostgreSQL this process started, if it started one.
///
/// The handle above says it is held so "shutdown can stop it deliberately",
/// and until now nothing did: the serve future never returned, so an
/// operator's Ctrl-C left the postmaster running with the data directory
/// open. Adopting an orphan on the next start is handled (embedded_pg
/// `already_running`) — the hazard is the *upgrade* path, where the hub's own
/// refusal tells the operator to move `pgdata` aside. On Windows that fails
/// while a postmaster holds it; on Linux it succeeds and the live postmaster
/// keeps writing to the moved directory, which is the half-migration the
/// version check exists to prevent.
async fn stop_embedded(embedded: Option<wavvon_hub::embedded_pg::EmbeddedPostgres>) {
    let Some(pg) = embedded else { return };
    match pg.stop().await {
        Ok(()) => tracing::info!("Stopped the embedded PostgreSQL"),
        // Worth a line and not a failure: the process is going away either
        // way, and the next start adopts a server that is still up.
        Err(e) => tracing::warn!("Could not stop the embedded PostgreSQL: {e:#}"),
    }
}
