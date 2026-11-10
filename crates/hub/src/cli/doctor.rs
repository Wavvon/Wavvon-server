use std::path::{Path, PathBuf};

use sqlx::postgres::PgPoolOptions;
use url::Url;
use wavvon_identity::Identity;

/// Run --doctor pre-flight checks. Returns true if all checks pass.
pub async fn run_doctor() -> bool {
    use tokio::net::UdpSocket;

    let settings = match wavvon_hub::settings::load() {
        Ok(s) => s,
        Err(e) => {
            println!("FAIL  settings: {e}");
            return false;
        }
    };
    println!("PASS  settings: loaded");

    let mut all_pass = true;

    // Check TCP port
    match wavvon_hub::listen::http_listener(settings.bind_addr, settings.http_port) {
        Ok(l) => println!(
            "PASS  HTTP port {}: bindable on {}",
            settings.http_port,
            l.local_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_default()
        ),
        Err(e) => {
            println!("FAIL  HTTP port {}: {e}", settings.http_port);
            all_pass = false;
        }
    }

    // Check UDP port
    match UdpSocket::bind(format!("0.0.0.0:{}", settings.voice_udp_port)).await {
        Ok(_) => println!("PASS  Voice UDP port {}: bindable", settings.voice_udp_port),
        Err(e) => {
            println!("FAIL  Voice UDP port {}: {e}", settings.voice_udp_port);
            all_pass = false;
        }
    }

    // Voice is UDP and dialled at the public host unless told otherwise; an
    // HTTP proxy in front of that host (Cloudflare's orange cloud) passes the
    // site and the WebSocket and silently drops every voice datagram.
    if settings.voice_public_host.is_none() {
        let host = settings
            .public_url
            .as_deref()
            .and_then(|u| Url::parse(u).ok())
            .and_then(|u| u.host_str().map(str::to_string));
        if let Some(host) = host {
            if let Ok(addrs) = tokio::net::lookup_host((host.as_str(), 443)).await {
                if addrs
                    .into_iter()
                    .any(|a| wavvon_hub::udp_dropping_proxy(a.ip()))
                {
                    println!(
                        "WARN  Voice: {host} resolves into Cloudflare's proxy, which drops UDP, so \
                         voice will not connect. Make the record DNS-only, or set {} to a DNS-only \
                         name for voice",
                        wavvon_hub_env::VOICE_PUBLIC_HOST
                    );
                }
            }
        }
    }

    // Check TLS files if configured
    match (settings.tls_cert.as_deref(), settings.tls_key.as_deref()) {
        (Some(cert), Some(key)) => {
            for (label, path) in [("TLS cert", cert), ("TLS key", key)] {
                match std::fs::read(path) {
                    Ok(bytes) => {
                        // Minimal PEM sanity: file must contain "-----BEGIN"
                        if bytes.windows(11).any(|w| w == b"-----BEGIN ") {
                            println!("PASS  {label} ({path}): readable PEM");
                        } else {
                            println!(
                                "FAIL  {label} ({path}): file exists but does not look like PEM"
                            );
                            all_pass = false;
                        }
                    }
                    Err(e) => {
                        println!("FAIL  {label} ({path}): {e}");
                        all_pass = false;
                    }
                }
            }
        }
        (None, None) => {
            println!("INFO  TLS: not configured (plaintext HTTP)");
        }
        _ => {
            println!(
                "FAIL  TLS: WAVVON_TLS_CERT and WAVVON_TLS_KEY must both be set or both unset"
            );
            all_pass = false;
        }
    }

    // Check working directory writable
    let probe = ".wavvon-doctor-probe";
    match std::fs::write(probe, b"ok") {
        Ok(_) => {
            let _ = std::fs::remove_file(probe);
            println!(
                "PASS  working directory ({}): writable",
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "?".into())
            );
        }
        Err(e) => {
            println!(
                "FAIL  working directory ({}): {e}",
                std::env::current_dir()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "?".into())
            );
            all_pass = false;
        }
    }

    // Check web client directory when configured
    match settings.web_client_dir.as_deref() {
        None => {
            println!("INFO  web client: disabled (WAVVON_WEB_CLIENT_DIR not set)");
        }
        Some(dir) => {
            let dir_path = std::path::Path::new(dir);
            if !dir_path.exists() {
                println!("FAIL  web client dir '{dir}': directory does not exist");
                all_pass = false;
            } else {
                let index = dir_path.join("index.html");
                match std::fs::read(&index) {
                    Ok(bytes) if !bytes.is_empty() => {
                        println!("PASS  web client dir '{dir}': directory exists, index.html readable ({} bytes)", bytes.len());
                    }
                    Ok(_) => {
                        println!("FAIL  web client dir '{dir}': index.html exists but is empty");
                        all_pass = false;
                    }
                    Err(e) => {
                        println!("FAIL  web client dir '{dir}': cannot read index.html: {e}");
                        all_pass = false;
                    }
                }
            }
        }
    }

    // LAN mode: confirm the advertise address is private, and — for the
    // self-signed tier — generate/load the cert and print the fingerprint
    // and join URL an operator would put on an invite/QR (lan-mode.md §4).
    if settings.lan_mode {
        println!("\nLAN mode:");
        match wavvon_hub::lan::resolve_lan_address(settings.lan_advertise_addr.as_deref()) {
            Ok(ip) => {
                println!("PASS  LAN advertise address: {ip} (private/loopback/link-local)");
                let has_ca_cert = settings.tls_cert.is_some() && settings.tls_key.is_some();
                if has_ca_cert {
                    println!(
                        "INFO  trust: CA cert already configured (WAVVON_TLS_CERT/_KEY) — \
                         LAN self-signed/plaintext bootstrap and mDNS advertisement are skipped"
                    );
                } else if settings.lan_tls_mode == "none" {
                    println!(
                        "INFO  trust: plaintext (WAVVON_LAN_TLS_MODE=none) — gated to the \
                         private address above by the LAN-mode guard"
                    );
                    println!("INFO  Join URL: http://{ip}:{}", settings.http_port);
                } else {
                    match wavvon_hub::lan::load_or_create_self_signed(
                        std::path::Path::new("lan_cert.pem"),
                        std::path::Path::new("lan_cert.key"),
                        ip,
                    ) {
                        Ok(cert) => {
                            println!(
                                "PASS  self-signed cert: fingerprint {}",
                                cert.fingerprint_hex
                            );
                            println!(
                                "INFO  Join URL: https://{ip}:{} (client pins fingerprint {} out of band)",
                                settings.http_port, cert.fingerprint_hex
                            );
                        }
                        Err(e) => {
                            println!("FAIL  self-signed cert: {e}");
                            all_pass = false;
                        }
                    }
                }
                println!(
                    "INFO  mDNS advertisement: {}",
                    if settings.lan_mdns {
                        "enabled"
                    } else {
                        "disabled (WAVVON_LAN_MDNS=false)"
                    }
                );
            }
            Err(e) => {
                println!("FAIL  LAN advertise address: {e}");
                all_pass = false;
            }
        }
    }

    // Owner / first-boot invite status. Best-effort only: this needs a live
    // database connection that the rest of doctor doesn't otherwise require,
    // so an unreachable DB (or a hub that has never run migrate/start yet)
    // is reported as INFO, not FAIL — it doesn't block a normal doctor run.
    // Reuses the same idempotent mint used at real startup, so running
    // `--doctor` before the hub's first real launch is enough to get the
    // link — it's safe to call repeatedly and a no-op once a user exists.
    println!();
    // Which database this hub would use, in the words an operator needs: the
    // embedded one is invisible otherwise — no port they chose, no directory
    // they named — and "where is my data" is the first question a backup
    // raises.
    let embedded_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let db_url = match settings.database_url.clone() {
        Some(url) => {
            println!(
                "INFO  database: external, from {}",
                wavvon_hub_env::DATABASE_URL
            );
            url
        }
        None => {
            let data_dir = embedded_root.join("pgdata");
            // Say it here rather than letting the operator find out at first
            // boot: with no WAVVON_DATABASE_URL this build has no database it
            // can reach, and doctor exists precisely to answer that before
            // anything runs.
            if !wavvon_hub::embedded_pg::BUNDLED_AVAILABLE {
                println!(
                    "FAIL  database: none — {} is unset and {}",
                    wavvon_hub_env::DATABASE_URL,
                    wavvon_hub::embedded_pg::unavailable_reason()
                );
                all_pass = false;
            }
            match wavvon_hub::embedded_pg::bundled_major() {
                Some(major) => println!(
                    "INFO  database: built-in PostgreSQL {major}, data in {}",
                    data_dir.display()
                ),
                None => println!(
                    "INFO  database: built-in PostgreSQL, data in {}",
                    data_dir.display()
                ),
            }
            match wavvon_hub::embedded_pg::compatibility(
                wavvon_hub::embedded_pg::data_dir_major(&data_dir),
                wavvon_hub::embedded_pg::bundled_major(),
            ) {
                wavvon_hub::embedded_pg::Compatibility::Start => {}
                wavvon_hub::embedded_pg::Compatibility::NeedsUpgrade { from, to } => println!(
                    "WARN  the data directory was written by PostgreSQL {from} and this hub \
                     carries {to} — back up with the previous binary and restore with this one"
                ),
                wavvon_hub::embedded_pg::Compatibility::Downgraded { from, to } => println!(
                    "FAIL  the data directory was written by PostgreSQL {from} and this hub \
                     carries {to} — an older server cannot read it; run the newer hub"
                ),
            }
            // doctor does not start a server: it reports. Whatever is already
            // running answers the connection below; a hub that has never
            // booted has nothing to connect to yet, which is reported as INFO
            // like every other pre-first-boot state here.
            wavvon_hub::embedded_pg::running_url(&embedded_root)
                .unwrap_or_else(|| wavvon_hub::settings::DEFAULT_DATABASE_URL.to_string())
        }
    };
    match PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
    {
        Ok(pool) => {
            match wavvon_hub::routes::invites::maybe_mint_first_boot_owner_invite(&pool).await {
                Ok(Some(code)) => {
                    // Read the identity rather than create one: on a
                    // farm-hosted hub the public URL contains its pubkey, and
                    // doctor printing a localhost link for a hub that is
                    // actually reachable at https://farm/hub/<key> would be
                    // worse than useless. Absent (hub never started) → falls
                    // back to whatever is configured.
                    let pubkey = Identity::load(Path::new("hub_identity.json"))
                        .ok()
                        .map(|i| i.public_key_hex());
                    let raw_host = wavvon_hub::settings::effective_public_url(
                        settings.public_url.as_deref(),
                        settings.farm_url.as_deref(),
                        pubkey.as_deref(),
                    )
                    .unwrap_or_else(|| format!("localhost:{}", settings.http_port));
                    let host = raw_host
                        .trim_start_matches("https://")
                        .trim_start_matches("http://")
                        .trim_end_matches('/');
                    let scheme = if host.starts_with("localhost") || host.starts_with("127.") {
                        "http"
                    } else {
                        "https"
                    };
                    println!(
                        "INFO  hub owner: none yet — first-boot invite {scheme}://{host}/join/{code}"
                    );
                }
                Ok(None) => {
                    println!("PASS  hub owner: already assigned");
                }
                Err((_, e)) => {
                    println!("INFO  hub owner check skipped: {e}");
                }
            }
        }
        Err(e) => {
            let (shown, _) = wavvon_hub::db::dump::split_password(&db_url);
            println!("INFO  database ({shown}) unreachable, skipping owner check: {e}");
        }
    }

    if all_pass {
        println!("\nAll checks passed.");
    } else {
        println!("\nOne or more checks failed.");
    }
    all_pass
}
