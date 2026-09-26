//! The PostgreSQL the hub carries with it.
//!
//! `WAVVON_DATABASE_URL` unset means *"start and manage your own PostgreSQL"*
//! — download a binary, run it, you have a hub (decisions.md, "The hub bundles
//! PostgreSQL, and never touches one it did not create"). Set, and the hub is
//! a plain client: it runs migrations and touches nothing else, because a
//! database the operator built is theirs.
//!
//! The archive is compiled in, not fetched at runtime, so first start works on
//! a machine with no network and no package manager.
//!
//! **Layout, and why it is shaped this way.** SQL does not change between
//! PostgreSQL majors; the *on-disk data directory* does, and a newer server
//! refuses to read an older one by design. Reading the old directory at all
//! needs that major's own binaries, so installations are version-scoped and the
//! previous one is never deleted:
//!
//! ```text
//! <data_root>/pg/18.4.0/   binaries (kept — they are what can read old data)
//! <data_root>/pg/19.1.0/   binaries (new)
//! <data_root>/pgdata/      data, carrying its own PG_VERSION
//! <data_root>/pg/embedded.json  the port and password this hub chose
//! ```
//!
//! On a major mismatch the hub **refuses with instructions** rather than
//! starting. Half-migrating a data directory is unrecoverable, and guessing is
//! how it happens.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use postgresql_embedded::{PostgreSQL, Settings};
use serde::{Deserialize, Serialize};

/// The database the hub uses inside its own server.
const DATABASE_NAME: &str = "wavvon";

/// What survives a restart: the port this instance listens on and the password
/// it was initialised with.
///
/// Regenerating either would strand the data directory — initdb set that
/// password once — so they are written down the first time and read every time
/// after. The file sits beside the data it belongs to, not in a user's home:
/// two hubs in two directories are two hubs.
#[derive(Serialize, Deserialize)]
struct Persisted {
    port: u16,
    password: String,
}

pub struct EmbeddedPostgres {
    /// Held for the lifetime of the process. Dropping it does not stop the
    /// server (it is not a temporary instance) — `stop` is explicit.
    postgres: PostgreSQL,
    url: String,
    data_dir: PathBuf,
}

impl EmbeddedPostgres {
    /// The connection URL for the hub's own database.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Where the data lives, for anything that has to tell an operator.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// The `bin` directory of the PostgreSQL this hub is running.
    ///
    /// `pg_dump` and `pg_restore` live here and nowhere else on a machine
    /// whose whole selling point is that PostgreSQL was never installed — so
    /// backup has to be pointed at them, or the one install story that needs
    /// bundled binaries is the one where backup fails.
    pub fn bin_dir(&self) -> PathBuf {
        resolve_bin_dir(&self.postgres.settings().installation_dir)
    }

    pub async fn stop(&self) -> Result<()> {
        self.postgres
            .stop()
            .await
            .context("stopping embedded PostgreSQL")
    }

    /// Create another database inside this server and return its URL.
    ///
    /// The hub itself needs exactly one, but a `db move` has two ends, and
    /// pointing both at the bundled server is what lets that path be tested on
    /// a machine with no PostgreSQL installed — with the client tools and the
    /// server guaranteed to be the same version, which is the one thing a
    /// dump/restore is most sensitive to.
    pub async fn create_database(&self, name: &str) -> Result<String> {
        if !self.postgres.database_exists(name).await? {
            self.postgres
                .create_database(name)
                .await
                .with_context(|| format!("creating database {name}"))?;
        }
        Ok(self.postgres.settings().url(name))
    }
}

/// The major version of the PostgreSQL compiled into this binary.
pub fn bundled_major() -> Option<u64> {
    major_of_requirement(&Settings::default().version.to_string())
}

/// Pull the major out of a version requirement like `=18.4.0`.
fn major_of_requirement(req: &str) -> Option<u64> {
    req.trim()
        .trim_start_matches(['=', '^', '~', '>', '<', ' '])
        .split('.')
        .next()?
        .trim()
        .parse()
        .ok()
}

/// The major a data directory was created by, or `None` when there is no data
/// directory yet.
pub fn data_dir_major(data_dir: &Path) -> Option<u64> {
    std::fs::read_to_string(data_dir.join("PG_VERSION"))
        .ok()?
        .trim()
        .split('.')
        .next()?
        .parse()
        .ok()
}

/// What to do about an existing data directory, given what this binary carries.
#[derive(Debug, PartialEq, Eq)]
pub enum Compatibility {
    /// No data yet, or the same major: start normally.
    Start,
    /// The data was written by an older major. It cannot be read by this
    /// server, and the fix is a dump with the old binaries and a restore into
    /// the new ones — never an in-place guess.
    NeedsUpgrade { from: u64, to: u64 },
    /// The data was written by a *newer* major than this binary carries, which
    /// means someone downgraded the hub. Refusing is the only safe answer:
    /// there is no way to read it here, and trying would be the half-migration
    /// this design exists to avoid.
    Downgraded { from: u64, to: u64 },
}

pub fn compatibility(data_major: Option<u64>, bundled_major: Option<u64>) -> Compatibility {
    match (data_major, bundled_major) {
        (Some(data), Some(bundled)) if data < bundled => Compatibility::NeedsUpgrade {
            from: data,
            to: bundled,
        },
        (Some(data), Some(bundled)) if data > bundled => Compatibility::Downgraded {
            from: data,
            to: bundled,
        },
        _ => Compatibility::Start,
    }
}

/// The `bin` directory under an installation root.
///
/// Which of two shapes it is depends on when you ask. On a first run the
/// crate's `installation_dir` is still the root we handed it and the archive
/// lands in a version-named directory beneath; on later runs it has resolved
/// to that directory itself. Guessing one of the two is how `pg_dump` comes
/// out "not found" on a machine that is carrying it.
fn resolve_bin_dir(installation_dir: &Path) -> PathBuf {
    let direct = installation_dir.join("bin");
    if direct.is_dir() {
        return direct;
    }
    std::fs::read_dir(installation_dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path().join("bin"))
        .find(|candidate| candidate.is_dir())
        .unwrap_or(direct)
}

fn read_persisted(path: &Path) -> Option<Persisted> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn write_persisted(path: &Path, state: &Persisted) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string(state)?)
        .with_context(|| format!("writing {}", path.display()))?;
    // The password is in here. On Unix the file is the only thing standing
    // between another local user and the hub's database.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Find a free TCP port for the first start.
///
/// Recorded afterwards rather than re-picked: a hub that moved port on every
/// restart would leave `pg_dump` and every other tool pointed at the wrong one.
fn pick_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .context("no free local port for the embedded PostgreSQL")?;
    Ok(listener.local_addr()?.port())
}

/// Say what a dynamic-link failure from the bundled binaries actually means.
///
/// The archive is chosen by build target, and the **musl** one is the odd one
/// out: measured 2026-09-05, its `initdb` declares `libicuuc.so.74` as a
/// dynamic dependency (the glibc build links ICU statically and needs nothing
/// but libc), and no current Alpine ships that soname — 3.24 has ICU 78, so
/// even `apk add icu-libs` does not satisfy it. `libpq.so.5` there also wants
/// `libgssapi_krb5.so.2`.
///
/// Left alone, the operator gets a wall of `symbol not found` relocations from
/// a program they never ran, on the one path advertised as needing no
/// prerequisites. This turns that into a sentence and a way out.
fn explain_dynamic_link_failure(e: impl std::fmt::Display) -> anyhow::Error {
    let message = e.to_string();
    let looks_dynamic = message.contains("Error loading shared library")
        || message.contains("Error relocating")
        || message.contains("cannot open shared object file");
    if !looks_dynamic {
        return anyhow::anyhow!(message);
    }
    anyhow::anyhow!(
        "{message}\n\nThe bundled PostgreSQL binaries could not be loaded by this system. \
         The musl build of them is not self-contained: it needs ICU 74 (libicuuc.so.74) \
         and krb5, which musl distributions do not ship at that version. Either run the \
         glibc build of the hub, or point WAVVON_DATABASE_URL at a PostgreSQL you provide \
         — a database you built is never touched by the bundled mode."
    )
}

fn random_password() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Point backup/restore at the bundled client tools, unless the operator
/// already said where they are.
///
/// On the install story bundling exists for, PostgreSQL was never installed:
/// `pg_dump` is not on PATH and never will be, so it has to be found inside
/// our own version-scoped install directory. `start` has always done this at
/// the end — and that was the whole coverage, because the one test that
/// checked it started a server first. The path an operator actually takes does
/// not: a hub that is *running* (or one that was killed, leaving its
/// postmaster up) is adopted rather than started, and adoption skipped this —
/// so `wavvon-hub backup` on a live bundled hub failed with "pg_dump not
/// found. Install the PostgreSQL client tools", on the one setup that is
/// carrying them.
pub fn point_tools_at_bundled(data_root: &Path) {
    if std::env::var_os(crate::db::dump::PG_BIN_DIR_ENV).is_some() {
        return; // an operator who set it themselves is left alone
    }
    let bin = resolve_bin_dir(&data_root.join("pg"));
    if !bin.is_dir() {
        return; // nothing unpacked here yet; the caller will start one
    }
    // SAFETY-ish: single-threaded startup, before any worker is spawned.
    std::env::set_var(crate::db::dump::PG_BIN_DIR_ENV, &bin);
}

/// The URL of an embedded server that is **already** running under
/// `data_root`, without starting anything.
///
/// For the paths that report rather than act — `doctor`, and any CLI that
/// wants to talk to a live hub's database. Starting a second postmaster on the
/// same directory is not a thing to do by accident, so this returns `None`
/// rather than falling back to starting one.
pub fn running_url(data_root: &Path) -> Option<String> {
    let state = read_persisted(&data_root.join("pg").join("embedded.json"))?;
    if !data_root.join("pgdata").join("postmaster.pid").exists() {
        return None;
    }
    Some(format!(
        "postgres://postgres:{}@127.0.0.1:{}/{DATABASE_NAME}",
        state.password, state.port
    ))
}

/// Can this build run the bundled server at all?
///
/// False on musl, and it is a property of the build rather than of the host:
/// the archive is picked by target, and the musl one is not self-contained
/// (see `explain_dynamic_link_failure`). Deciding it at compile time means the
/// answer is available before anything is downloaded, unpacked or run — which
/// is what lets `--doctor` and `start` say so in one sentence instead of after
/// a failed `initdb`.
pub const BUNDLED_AVAILABLE: bool = !cfg!(target_env = "musl");

/// The one explanation both `start` and `--doctor` use, so they cannot drift.
pub fn unavailable_reason() -> String {
    "this is the musl build of the hub, and its bundled PostgreSQL binaries are not \
     self-contained: initdb needs ICU 74 (libicuuc.so.74) and libpq needs krb5, neither of \
     which current musl distributions ship. Point WAVVON_DATABASE_URL at a PostgreSQL you \
     provide — a database you built is never touched by the bundled mode — or run a glibc \
     build of the hub."
        .to_string()
}

/// Start (or adopt) the hub's own PostgreSQL under `data_root`, and return a
/// handle carrying the URL to connect to.
pub async fn start(data_root: &Path) -> Result<EmbeddedPostgres> {
    // Refuse before touching the filesystem. Left to run, this creates the
    // install root, downloads or unpacks an archive and only then dies inside
    // initdb — leaving half a data directory behind and a relocation dump on
    // the one path advertised as needing no prerequisites.
    if !BUNDLED_AVAILABLE {
        bail!("{}", unavailable_reason());
    }

    let install_root = data_root.join("pg");
    let data_dir = data_root.join("pgdata");
    let state_file = install_root.join("embedded.json");

    let bundled = bundled_major();
    match compatibility(data_dir_major(&data_dir), bundled) {
        Compatibility::Start => {}
        Compatibility::NeedsUpgrade { from, to } => bail!(
            "the data in {} was written by PostgreSQL {from}, and this hub carries {to}.\n\
             PostgreSQL cannot read an older data directory, so this is a migration, not a \
             restart — and it is one command:\n\
             \n    wavvon-hub backup before-pg{to}.wavvon-backup   (with the previous hub binary)\n\
             \n    wavvon-hub restore before-pg{to}.wavvon-backup   (with this one, after moving \
             {} aside)\n\n\
             Nothing here has been changed.",
            data_dir.display(),
            data_dir.display(),
        ),
        Compatibility::Downgraded { from, to } => bail!(
            "the data in {} was written by PostgreSQL {from} and this hub carries {to} — an older \
             server cannot read a newer data directory.\n\
             This is a downgraded hub binary, not a broken database: run the newer hub again, or \
             restore a backup taken with it. Nothing here has been changed.",
            data_dir.display(),
        ),
    }

    let (port, password, first_run) = match read_persisted(&state_file) {
        Some(state) => (state.port, state.password, false),
        None => (pick_port()?, random_password(), true),
    };

    let mut settings = Settings {
        // Version-scoped, and the previous major's binaries stay: they are the
        // only thing that can read the data they wrote.
        installation_dir: install_root.clone(),
        data_dir: data_dir.clone(),
        password_file: install_root.join(".pgpass"),
        port,
        username: "postgres".to_string(),
        password: password.clone(),
        // Not temporary: the whole point is that the data outlives the process.
        temporary: false,
        // The crate's default deadline covers starting a server, not the
        // first run — which extracts a whole PostgreSQL and runs initdb, and
        // on a cold filesystem took longer than that here. A hub that times
        // out on its very first boot is the worst possible first impression
        // of "download a binary and run it".
        timeout: Some(std::time::Duration::from_secs(300)),
        ..Settings::default()
    };
    // musl's locale support is minimal, and initdb inherits whatever the
    // environment claims. `C` is available everywhere and is what a server
    // wants anyway — collation that depends on the host's locale is how two
    // machines disagree about ORDER BY.
    settings
        .configuration
        .insert("lc_messages".to_string(), "C".to_string());

    let mut postgres = PostgreSQL::new(settings);

    // Adopt a server that is already up rather than starting a second one.
    // A hub that was killed leaves its postmaster running, and `pg_ctl start`
    // against a live data directory fails — so without this, one crash means
    // the hub cannot restart until somebody finds and kills a process they did
    // not know existed.
    let already_running = match running_url(data_root) {
        Some(url) => sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&url)
            .await
            .map(|pool| {
                drop(pool);
                true
            })
            .unwrap_or(false),
        None => false,
    };

    if !already_running {
        postgres
            .setup()
            .await
            .map_err(explain_dynamic_link_failure)
            .context("installing or initialising the embedded PostgreSQL")?;
        postgres
            .start()
            .await
            .map_err(explain_dynamic_link_failure)
            .context("starting the embedded PostgreSQL")?;
    } else {
        tracing::info!("Adopted the embedded PostgreSQL already running on port {port}");
    }

    if first_run {
        write_persisted(&state_file, &Persisted { port, password })?;
    }

    if !postgres.database_exists(DATABASE_NAME).await? {
        postgres
            .create_database(DATABASE_NAME)
            .await
            .with_context(|| format!("creating the {DATABASE_NAME} database"))?;
    }

    // Point backup/restore at the binaries we are actually running — see
    // `point_tools_at_bundled`, which the adopt path calls for the same
    // reason. Resolved from the settings here because they name the exact
    // install this process is running.
    if std::env::var_os(crate::db::dump::PG_BIN_DIR_ENV).is_none() {
        let bin = resolve_bin_dir(&postgres.settings().installation_dir);
        // SAFETY-ish: single-threaded startup, before any worker is spawned.
        std::env::set_var(crate::db::dump::PG_BIN_DIR_ENV, &bin);
    }

    let url = postgres.settings().url(DATABASE_NAME);
    Ok(EmbeddedPostgres {
        postgres,
        url,
        data_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_requirement_yields_its_major() {
        assert_eq!(major_of_requirement("=18.4.0"), Some(18));
        assert_eq!(major_of_requirement("^17.2.1"), Some(17));
        assert_eq!(major_of_requirement("19"), Some(19));
        assert_eq!(major_of_requirement("not a version"), None);
    }

    /// The whole reason the layout is version-scoped: what the hub does about
    /// an existing data directory is decided *before* anything is touched.
    #[test]
    fn compatibility_is_decided_by_the_major_alone() {
        assert_eq!(compatibility(None, Some(18)), Compatibility::Start);
        assert_eq!(compatibility(Some(18), Some(18)), Compatibility::Start);
        assert_eq!(
            compatibility(Some(17), Some(18)),
            Compatibility::NeedsUpgrade { from: 17, to: 18 }
        );
        // A downgraded binary must refuse rather than "try": there is no
        // reading a newer data directory with an older server.
        assert_eq!(
            compatibility(Some(19), Some(18)),
            Compatibility::Downgraded { from: 19, to: 18 }
        );
    }

    /// A minor difference is not a migration — 18.4 and 18.7 share a data
    /// directory format, and refusing there would turn a routine upgrade into
    /// an outage.
    #[test]
    fn a_minor_upgrade_just_starts() {
        assert_eq!(data_dir_major(Path::new("nonexistent")), None);
        assert_eq!(compatibility(Some(18), Some(18)), Compatibility::Start);
    }

    #[test]
    fn the_bundled_archive_reports_a_major() {
        // If this ever returns None the version-compat check silently degrades
        // to "always start", which is the half-migration this guards against.
        assert!(
            bundled_major().is_some(),
            "the bundled archive must name its version"
        );
    }

    #[test]
    fn a_loader_failure_gets_an_explanation_and_nothing_else_does() {
        // The real thing, from a musl container: initdb from the bundled
        // archive against Alpine 3.24 (ICU 78).
        let musl = explain_dynamic_link_failure(
            "Command error: stdout=; stderr=Error loading shared library \
             libicuuc.so.74: No such file or directory (needed by .../bin/initdb)",
        )
        .to_string();
        assert!(
            musl.contains("libicuuc.so.74"),
            "keeps the original message"
        );
        assert!(
            musl.contains("WAVVON_DATABASE_URL"),
            "names the way out: {musl}"
        );

        // Everything else must pass through: a port clash or a corrupt data
        // directory has nothing to do with dynamic linking, and dressing it up
        // as an ICU problem would send the operator the wrong way.
        let other = explain_dynamic_link_failure("could not bind to port 5432").to_string();
        assert_eq!(other, "could not bind to port 5432");
    }
}
