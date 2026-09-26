/// Hub process lifecycle manager.
///
/// Owns the map of running hub child processes and exposes spawn/stop/restart
/// operations. On farm startup `spawn_all_from_db` re-spawns every non-suspended,
/// non-deleted hub found in the `hubs` table.
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::PgPool;
use tokio::process::Child;
use tokio::sync::RwLock;

/// First number at or above `base` that nobody holds.
fn first_gap(base: u16, occupied: &HashSet<u16>) -> u16 {
    let mut port = base;
    while occupied.contains(&port) {
        port += 1;
    }
    port
}

struct HubProcess {
    port: u16,
    voice_port: u16,
    child: Child,
}

pub struct HubManager {
    hubs: RwLock<HashMap<String, HubProcess>>,
    /// Absolute path (or name on PATH) of the `wavvon-hub` binary.
    hub_bin: String,
    /// Externally reachable farm URL — passed to hub processes as `WAVVON_FARM_URL`.
    farm_url: String,
    /// Base port for allocating new hub process HTTP ports.
    base_port: u16,
    /// Base port for allocating new hub voice (WebTransport/QUIC over UDP) ports.
    /// Separate range from `base_port` so the two never collide.
    voice_base_port: u16,
    /// The farm's own PostgreSQL URL. Each hub's database is created on this
    /// server and derived from this URL (db/provision.rs).
    db_base_url: String,
    /// Parent directory for per-hub working directories. Each hub runs in
    /// `<hubs_dir>/<hub_id>` so they cannot share an identity file.
    hubs_dir: String,
}

impl HubManager {
    pub fn new(
        hub_bin: String,
        farm_url: String,
        base_port: u16,
        voice_base_port: u16,
        db_base_url: String,
        hubs_dir: String,
    ) -> Self {
        Self {
            hubs: RwLock::new(HashMap::new()),
            hub_bin,
            farm_url,
            base_port,
            voice_base_port,
            db_base_url,
            hubs_dir,
        }
    }

    /// This hub's database URL, creating the database on first use.
    ///
    /// Central because every spawn path needs it and none of them may skip it:
    /// a hub without its own database silently falls back to the shared default
    /// and starts reading another community's messages. Persisted on the row so
    /// the work happens once.
    pub async fn ensure_db_url(&self, db: &PgPool, hub_id: &str) -> Result<String> {
        let existing: Option<Option<String>> =
            sqlx::query_scalar("SELECT db_url FROM hubs WHERE id = $1")
                .bind(hub_id)
                .fetch_optional(db)
                .await
                .context("could not read the hub's database URL")?;
        if let Some(Some(url)) = existing {
            if !url.is_empty() {
                return Ok(url);
            }
        }

        let isolation: String = sqlx::query_scalar("SELECT hub_isolation FROM farms WHERE id = 1")
            .fetch_optional(db)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "database".to_string());
        let isolation = crate::db::provision::Isolation::from_setting(&isolation);

        let url = crate::db::provision::provision_hub(db, &self.db_base_url, hub_id, isolation)
            .await
            .with_context(|| format!("could not give hub {hub_id} a place of its own"))?;

        // A place of its own is not the same as credentials of its own: with
        // `hub_db_role = 'shared'` every hub still connects as the farm, so a
        // compromised one can reach its siblings under either layout. Failure
        // refuses the hub for the same reason provisioning does — falling back
        // to the shared role would silently hand out the access the setting
        // was turned on to remove.
        let role_mode: String = sqlx::query_scalar("SELECT hub_db_role FROM farms WHERE id = 1")
            .fetch_optional(db)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "shared".to_string());
        let url = match crate::db::provision::RoleMode::from_setting(&role_mode) {
            crate::db::provision::RoleMode::Shared => url,
            crate::db::provision::RoleMode::PerHub => crate::db::provision::provision_hub_role(
                db,
                &self.db_base_url,
                &url,
                hub_id,
                isolation,
            )
            .await
            .with_context(|| format!("could not give hub {hub_id} a role of its own"))?,
        };

        sqlx::query("UPDATE hubs SET db_url = $1 WHERE id = $2")
            .bind(&url)
            .bind(hub_id)
            .execute(db)
            .await
            .context("could not record the hub's database URL")?;
        Ok(url)
    }

    /// Every port already handed out: the children this process is running,
    /// plus every port persisted on a hub row that still exists.
    ///
    /// The persisted half is the half that matters. `self.hubs` only ever
    /// holds hubs this farm spawned successfully, so a hub whose spawn failed
    /// and every agent-hosted hub — which runs on another node and never
    /// enters the map at all — reserved nothing, and the next allocation
    /// handed out the same number again. `process_port` is what the proxy
    /// routes on, so two rows sharing one is two hubs at one address.
    ///
    /// Suspended hubs keep their ports: they are resumable, and resuming onto
    /// a port someone else took is the same collision, later.
    async fn occupied_ports(&self, db: &PgPool) -> (HashSet<u16>, HashSet<u16>) {
        let hubs = self.hubs.read().await;
        let mut http: HashSet<u16> = hubs.values().map(|h| h.port).collect();
        let mut voice: HashSet<u16> = hubs.values().map(|h| h.voice_port).collect();
        drop(hubs);

        match sqlx::query_as::<_, (Option<i32>, Option<i32>)>(
            "SELECT process_port, voice_port FROM hubs WHERE deleted_at IS NULL",
        )
        .fetch_all(db)
        .await
        {
            Ok(rows) => {
                for (port, voice_port) in rows {
                    if let Some(p) = port {
                        http.insert(p as u16);
                    }
                    if let Some(vp) = voice_port {
                        voice.insert(vp as u16);
                    }
                }
            }
            // Falling back to the in-memory view silently is how this bug
            // worked in the first place — say so, loudly.
            Err(e) => tracing::error!(
                error = %e,
                "Could not read allocated ports; allocating from running hubs only,                  which may hand out a port another hub already holds"
            ),
        }
        (http, voice)
    }

    /// Allocate the next free HTTP port for a new hub process.
    /// Returns `base_port + N` where N is the first gap.
    // ponytail: read-then-write, so two concurrent creates can still pick the
    // same port. A partial unique index on process_port would make that loud
    // if hub creation ever runs concurrently enough to matter.
    pub async fn allocate_port(&self, db: &PgPool) -> u16 {
        let (occupied, _) = self.occupied_ports(db).await;
        first_gap(self.base_port, &occupied)
    }

    /// Allocate the next free voice port for a new hub process. Same first-gap
    /// strategy as `allocate_port`, over the separate `voice_base_port` range.
    pub async fn allocate_voice_port(&self, db: &PgPool) -> u16 {
        let (_, occupied) = self.occupied_ports(db).await;
        first_gap(self.voice_base_port, &occupied)
    }

    /// Spawn a hub child process.
    ///
    /// The hub binary is resolved from `WAVVON_HUB_BIN` env var, falling back to
    /// the path stored in `self.hub_bin`.
    ///
    /// `owner_pubkey` is passed as `WAVVON_OWNER_PUBKEY` so the hub seeds that key
    /// as the builtin-owner role on first boot. `voice_port` is passed as
    /// `WAVVON_VOICE_UDP_PORT` so multiple farm-spawned hubs on one box don't
    /// collide on the default 3001.
    pub async fn spawn_hub(
        &self,
        hub_id: &str,
        db_url: &str,
        port: u16,
        voice_port: u16,
        owner_pubkey: Option<&str>,
    ) -> Result<()> {
        let bin = std::env::var(wavvon_hub_env::HUB_BIN).unwrap_or_else(|_| self.hub_bin.clone());

        // Names come from `wavvon_hub_env` rather than string literals. This
        // call used to set WAVVON_HUB_HTTP_PORT, a name the hub never reads —
        // so every spawned hub ignored its carefully allocated port and bound
        // the default 3000, and the proxy routed to a port nothing listened
        // on. Nothing failed loudly, which is why it survived.
        // Each hub gets its own working directory, and that is not tidiness.
        // A hub resolves `hub_identity.json` and its search index relative to
        // the process cwd, and children inherit the farm's — so every hub on a
        // farm loaded the SAME identity file. The first to boot created it and
        // every other one adopted its key: one pubkey across the whole farm,
        // which is the hub's whole identity in federation, in serial routing,
        // and in every signature it makes. They fought over the search index
        // lock too, which is how this surfaced.
        let work_dir = std::path::Path::new(&self.hubs_dir).join(hub_id);
        std::fs::create_dir_all(&work_dir)
            .with_context(|| format!("Cannot create working directory {work_dir:?}"))?;

        let mut cmd = tokio::process::Command::new(&bin);
        cmd.current_dir(&work_dir);
        // Tokio detaches a child on drop rather than killing it — see the same
        // note in agent/src/hub_manager.rs. Without this, dropping the manager
        // without calling `stop_hub` orphans a hub that keeps its port and
        // keeps writing to the shared default database, supervised by nobody.
        cmd.kill_on_drop(true)
            .env(wavvon_hub_env::HTTP_PORT, port.to_string())
            .env(wavvon_hub_env::VOICE_UDP_PORT, voice_port.to_string())
            .env(wavvon_hub_env::FARM_URL, &self.farm_url)
            // Our row id for this hub. It reports this back on its first
            // heartbeat, which is the only way we learn its pubkey and can
            // start routing `/hub/<serial>` to it.
            .env(wavvon_hub_env::FARM_HUB_ID, hub_id)
            // This hub's own database (db/provision.rs). Passing nothing here
            // is what made every farm-spawned hub fall back to the same default
            // URL and share one database with all the others — invisibly, since
            // the farm was setting WAVVON_HUB_DB, a name the hub never read.
            .env(wavvon_hub_env::DATABASE_URL, db_url);
        if let Some(pk) = owner_pubkey {
            cmd.env(wavvon_hub_env::OWNER_PUBKEY, pk);
        }
        let child = cmd.spawn().with_context(|| {
            format!("Failed to spawn hub process for {hub_id} (binary: {bin:?})")
        })?;

        let mut hubs = self.hubs.write().await;
        hubs.insert(
            hub_id.to_string(),
            HubProcess {
                port,
                voice_port,
                child,
            },
        );
        tracing::info!(hub_id, port, voice_port, "Hub process spawned");
        Ok(())
    }

    /// Stop a running hub process (SIGTERM on Unix, TerminateProcess on Windows).
    pub async fn stop_hub(&self, hub_id: &str) -> Result<()> {
        let mut hubs = self.hubs.write().await;
        if let Some(mut proc) = hubs.remove(hub_id) {
            proc.child
                .kill()
                .await
                .with_context(|| format!("Failed to kill hub process {hub_id}"))?;
            tracing::info!(hub_id, "Hub process stopped");
        }
        Ok(())
    }

    /// Restart a hub process: stop it then re-spawn with the same db_url, port
    /// and voice_port.
    pub async fn restart_hub(
        &self,
        hub_id: &str,
        db_url: &str,
        port: u16,
        voice_port: u16,
    ) -> Result<()> {
        self.stop_hub(hub_id).await?;
        self.spawn_hub(hub_id, db_url, port, voice_port, None).await
    }

    /// Whether a hub process is currently tracked as running.
    pub async fn is_running(&self, hub_id: &str) -> bool {
        self.hubs.read().await.contains_key(hub_id)
    }

    /// Return the port the named hub process is listening on, if running.
    pub async fn port_of(&self, hub_id: &str) -> Option<u16> {
        self.hubs.read().await.get(hub_id).map(|h| h.port)
    }

    /// Re-spawn all non-suspended, non-deleted hubs from the DB.
    /// Called once at farm startup.
    ///
    /// Hubs created before `voice_port` existed have it NULL — allocate and
    /// persist one now rather than falling back to the fatal-collision default.
    pub async fn spawn_all_from_db(&self, db: &PgPool) -> Result<()> {
        // process_port/voice_port are INTEGER (i32) — decoding as i64 fails sqlx's
        // type check at runtime (same latent bug the proxy had; see proxy.rs).
        #[allow(clippy::type_complexity)]
        let rows: Vec<(String, i32, Option<i32>, Option<String>)> = sqlx::query_as(
            "SELECT id, process_port, voice_port, owner_pubkey FROM hubs
             WHERE suspended_at IS NULL AND deleted_at IS NULL AND process_port IS NOT NULL",
        )
        .fetch_all(db)
        .await
        .context("Failed to query hubs for startup spawn")?;

        for (hub_id, port, voice_port, owner_pubkey) in rows {
            // Hubs that predate per-hub databases have no `db_url`; this
            // provisions one on the spot. A failure here skips the hub rather
            // than starting it against the shared default, which is the
            // condition this whole mechanism exists to end.
            let db_url = match self.ensure_db_url(db, &hub_id).await {
                Ok(url) => url,
                Err(e) => {
                    tracing::error!(
                        hub_id,
                        error = %e,
                        "No database for this hub — not starting it. Starting it anyway would \
                         put it back on the database every other hub shares."
                    );
                    continue;
                }
            };
            let port = port as u16;
            let voice_port = match voice_port {
                Some(vp) => vp as u16,
                None => {
                    let vp = self.allocate_voice_port(db).await;
                    let _ = sqlx::query("UPDATE hubs SET voice_port = $1 WHERE id = $2")
                        .bind(vp as i32)
                        .bind(&hub_id)
                        .execute(db)
                        .await;
                    vp
                }
            };
            if let Err(e) = self
                .spawn_hub(&hub_id, &db_url, port, voice_port, owner_pubkey.as_deref())
                .await
            {
                tracing::warn!(hub_id, error = %e, "Failed to spawn hub on startup (skipping)");
            }
        }

        Ok(())
    }

    /// Allocate an HTTP port and a voice port and persist both to the `hubs`
    /// row, then spawn. Returns the allocated `(port, voice_port)`.
    pub async fn allocate_and_spawn(
        self: &Arc<Self>,
        db: &PgPool,
        hub_id: &str,
        db_url: &str,
        owner_pubkey: Option<&str>,
    ) -> Result<(u16, u16)> {
        let port = self.allocate_port(db).await;
        let voice_port = self.allocate_voice_port(db).await;

        // Persist ports before spawning so a restart can re-use them.
        sqlx::query("UPDATE hubs SET process_port = $1, voice_port = $2 WHERE id = $3")
            .bind(port as i64)
            .bind(voice_port as i64)
            .bind(hub_id)
            .execute(db)
            .await
            .context("Failed to persist hub ports")?;

        self.spawn_hub(hub_id, db_url, port, voice_port, owner_pubkey)
            .await?;
        Ok((port, voice_port))
    }
}
