//! Logical dump and restore — the one mechanism that moves a hub's data.
//!
//! Everything that moves a database goes through here: `wavvon-hub backup` /
//! `restore` today, and embedded↔external moves and embedded major upgrades
//! once PostgreSQL is bundled. See decisions.md, "One mechanism moves the
//! data: logical dump/restore" — three features that looked separate share one
//! implementation, so it is built once and guarded once.
//!
//! **Every path refuses rather than half-writes.** A restore that stops with a
//! sentence leaves the operator where they started; one that gets halfway
//! leaves them somewhere nobody has ever tested.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use sqlx::PgPool;

/// Overrides where the PostgreSQL client binaries are found.
///
/// Unset (the normal case) means PATH. It exists for the operator whose
/// `pg_dump` is not on PATH, and as the hook for bundled PostgreSQL: the
/// binaries then live in our own version-scoped install directory, and an
/// operator will not have them on PATH at all. Whichever binaries the hub is
/// using are the ones that must do the dump.
pub const PG_BIN_DIR_ENV: &str = "WAVVON_PG_BIN_DIR";

fn pg_binary(name: &str) -> PathBuf {
    match std::env::var(PG_BIN_DIR_ENV) {
        Ok(dir) if !dir.is_empty() => Path::new(&dir).join(name),
        _ => PathBuf::from(name),
    }
}

/// Turns "the tool is missing" into the one sentence that fixes it, rather
/// than a bare `NotFound` from the OS. Worth the lines: an operator running
/// the official image hits this before they hit anything else.
fn run(bin: &str, args: &[&str], what: &str) -> Result<()> {
    let path = pg_binary(bin);
    let output = Command::new(&path).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            anyhow::anyhow!(
                "{bin} not found. Install the PostgreSQL client tools \
                 (Debian/Ubuntu: `apt install postgresql-client`), or set {} to \
                 the directory holding them.",
                PG_BIN_DIR_ENV,
            )
        } else {
            anyhow::anyhow!("could not run {}: {e}", path.display())
        }
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{what} failed ({}):\n{}", output.status, stderr.trim());
    }
    Ok(())
}

/// `server_version_num` of the server behind `pool`, e.g. `160004`.
pub async fn server_version_num(pool: &PgPool) -> Result<i32> {
    let raw: String = sqlx::query_scalar("SHOW server_version_num")
        .fetch_one(pool)
        .await
        .context("could not read the PostgreSQL server version")?;
    raw.trim()
        .parse()
        .with_context(|| format!("PostgreSQL reported an unparseable version: {raw:?}"))
}

/// The schema this hub's tables actually live in.
///
/// Normally `public`. A farm using schema isolation hands each hub a
/// `search_path` instead, so its tables are in `hub_<id>` — and everything
/// here that once said `schemaname = 'public'` would have found nothing,
/// reported zero tables, and called the backup a success.
pub async fn current_schema(pool: &PgPool) -> Result<String> {
    sqlx::query_scalar::<_, Option<String>>("SELECT current_schema()")
        .fetch_one(pool)
        .await
        .context("could not read the current schema")?
        .context("this connection has no schema on its search_path")
}

/// Exact row count per table in this hub's schema, keyed by table name.
///
/// Deliberately `COUNT(*)` and not `pg_stat_user_tables.n_live_tup`: the
/// planner's estimate is close enough for query planning and useless for
/// "did all my data arrive". This runs once at dump time and once after a
/// restore, and a community hub has neither the table count nor the row count
/// for that to be slow.
pub async fn row_counts(pool: &PgPool) -> Result<std::collections::BTreeMap<String, i64>> {
    let schema = current_schema(pool).await?;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname = $1 ORDER BY tablename",
    )
    .bind(&schema)
    .fetch_all(pool)
    .await
    .context("could not list tables")?;

    let mut counts = std::collections::BTreeMap::new();
    for table in tables {
        // The name comes from pg_tables, not from a caller, so it cannot be
        // hostile — but it still has to be quoted to survive a table named
        // like a keyword.
        let sql = format!("SELECT COUNT(*) FROM \"{}\"", table.replace('"', "\"\""));
        let n: i64 = sqlx::query_scalar(&sql)
            .fetch_one(pool)
            .await
            .with_context(|| format!("could not count rows in {table}"))?;
        counts.insert(table, n);
    }
    Ok(counts)
}

/// True when the target database has no tables of its own yet.
pub async fn is_empty(pool: &PgPool) -> Result<bool> {
    let schema = current_schema(pool).await?;
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pg_tables WHERE schemaname = $1")
        .bind(&schema)
        .fetch_one(pool)
        .await
        .context("could not inspect the destination database")?;
    Ok(n == 0)
}

/// Dump `db_url` to `out` in PostgreSQL's custom format.
///
/// `--no-owner --no-acl` so the archive restores under whatever role the
/// destination uses. A hub's data does not depend on role names, and carrying
/// them turns "restore onto a fresh server" into "first recreate my roles".
///
/// `--schema` is explicit rather than implied by the connection's
/// `search_path`: a farm using schema isolation puts this hub's tables in
/// `hub_<id>` and its siblings' in the same database, so a dump that trusted
/// the default would either miss everything or take everyone's.
///
/// A schema-mode archive names its schema inside, so it restores into a
/// database where that schema is free. Restoring one hub's dump *as* another
/// hub is not something this does.
pub fn dump(db_url: &str, out: &Path, schema: &str) -> Result<()> {
    run(
        "pg_dump",
        &[
            "--format=custom",
            "--no-owner",
            "--no-acl",
            &format!("--schema={schema}"),
            "--file",
            &out.to_string_lossy(),
            db_url,
        ],
        "pg_dump",
    )
}

/// Restore `archive` into `db_url`.
///
/// `--exit-on-error` is the point: without it `pg_restore` reports every
/// failure and still exits 0, so a restore that dropped half the schema looks
/// exactly like one that worked.
///
/// `--clean --if-exists` is what makes that survivable on a `public`-schema
/// hub. pg_dump 14 and older write `CREATE SCHEMA public` into the archive,
/// and every destination database already has `public` — so the first TOC
/// entry failed and `--exit-on-error` turned that into a failed restore, on
/// every PostgreSQL 14 client. 14 is the declared floor, so this was the
/// low end of the supported range, not an exotic setup. pg_dump 15+ stopped
/// emitting the line, which is why it only ever failed in CI.
///
/// The drops are guarded by `--if-exists`, so into the empty database a
/// restore normally targets they are all no-ops. With `--force` into a
/// populated one they now replace what the archive covers instead of merging
/// rows into it — which is what "restore over this hub" should mean.
pub fn restore(db_url: &str, archive: &Path) -> Result<()> {
    run(
        "pg_restore",
        &[
            "--no-owner",
            "--no-acl",
            "--exit-on-error",
            "--clean",
            "--if-exists",
            "--dbname",
            db_url,
            &archive.to_string_lossy(),
        ],
        "pg_restore",
    )
}

/// A dump restores into an equal or newer major, never an older one — a newer
/// server's dump may contain syntax an older one cannot parse.
///
/// Counter-intuitive once PostgreSQL is bundled: the embedded instance follows
/// upstream and is usually the *newer* side, so "move my data to my own
/// PostgreSQL" is the direction most likely to be refused, because
/// distributions ship older majors.
pub fn check_direction(source_version_num: i32, target_version_num: i32) -> Result<()> {
    let (source_major, target_major) = (source_version_num / 10_000, target_version_num / 10_000);
    if target_major >= source_major {
        return Ok(());
    }
    bail!(
        "this backup came from PostgreSQL {source_major} and the destination is \
         PostgreSQL {target_major}. A dump restores into an equal or newer major \
         only — a newer server's dump can contain syntax an older one cannot \
         parse. Restore onto PostgreSQL {source_major} or newer."
    )
}

/// Names every table whose row count differs, so a partial restore is reported
/// as a partial restore instead of "Restore complete".
pub fn compare_row_counts(
    before: &std::collections::BTreeMap<String, i64>,
    after: &std::collections::BTreeMap<String, i64>,
) -> Result<()> {
    let mut problems = Vec::new();
    for (table, expected) in before {
        match after.get(table) {
            Some(got) if got == expected => {}
            Some(got) => problems.push(format!("  {table}: expected {expected}, found {got}")),
            None => problems.push(format!("  {table}: missing (expected {expected} rows)")),
        }
    }
    if problems.is_empty() {
        return Ok(());
    }
    bail!(
        "the restored database does not match the backup:\n{}\n\
         The database is in an unknown state — do not start the hub against it.",
        problems.join("\n")
    )
}

/// What a completed move carried.
pub struct MoveReport {
    pub rows: i64,
    pub tables: usize,
}

/// Copy a hub's database from one PostgreSQL to another.
///
/// The third user of this one dump/restore path (decisions.md, "One mechanism
/// moves the data"), and the reason it waited for bundled PostgreSQL: with no
/// embedded side, moving was `backup` then `restore` against another URL,
/// which both commands already did. With one, "adopt my own PostgreSQL" and
/// "give it up again" are operations an operator actually has — and neither
/// should require a `pg_dump` incantation they cannot run, because the
/// binaries live inside our install directory.
///
/// **Copies, and stops.** Nothing switches mode here: the operator sets or
/// unsets `WAVVON_DATABASE_URL` and restarts. The source is left intact, so a
/// destination that misbehaves is undone by changing one variable back.
///
/// Database only. The identity file and the uploads directory are files on
/// one machine and do not move with a database; `backup` is the command that
/// takes all three.
pub async fn move_database(source_url: &str, target_url: &str, force: bool) -> Result<MoveReport> {
    if source_url == target_url {
        bail!("the source and the destination are the same database");
    }

    let source = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(source_url)
        .await
        .context("cannot open the source database")?;
    let target = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(target_url)
        .await
        .context("cannot open the destination database")?;

    // Direction first, before a single byte is written. A dump restores into
    // an equal or newer major and not into an older one — and that cuts
    // against intuition now that the bundled PostgreSQL follows upstream: the
    // embedded side is usually the *newer* one, so "move my data to my own
    // PostgreSQL" is the direction most likely to be refused.
    let source_version = server_version_num(&source).await?;
    let target_version = server_version_num(&target).await?;
    check_direction(source_version, target_version)?;

    if !is_empty(&target).await? && !force {
        bail!(
            "the destination already has tables. Writing into it would merge two hubs into one. \
             Point at an empty database, or pass --force if you meant this one."
        );
    }

    let schema = current_schema(&source).await?;
    let expected = row_counts(&source).await?;

    let staging = tempfile::tempdir()?;
    let dump_path = staging.path().join("database.dump");
    dump(source_url, &dump_path, &schema)?;
    restore(target_url, &dump_path)?;

    // The source's counts are the contract, exactly as an archive's are for a
    // restore: a partial move is reported as partial rather than as done.
    let actual = row_counts(&target).await?;
    compare_row_counts(&expected, &actual)?;

    Ok(MoveReport {
        rows: expected.values().sum(),
        tables: expected.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn direction_allows_same_and_newer() {
        assert!(check_direction(140_000, 140_004).is_ok(), "same major");
        assert!(check_direction(140_000, 160_002).is_ok(), "newer major");
    }

    #[test]
    fn direction_refuses_older_and_says_which_way() {
        let err = check_direction(160_002, 140_000).unwrap_err().to_string();
        assert!(err.contains("PostgreSQL 16"), "source, got: {err}");
        assert!(err.contains("PostgreSQL 14"), "target, got: {err}");
    }

    /// A minor-version difference is not a direction problem — 16.4 → 16.1 is
    /// the same major and restores fine.
    #[test]
    fn direction_ignores_minor_versions() {
        assert!(check_direction(160_004, 160_001).is_ok());
    }

    fn counts(pairs: &[(&str, i64)]) -> BTreeMap<String, i64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    #[test]
    fn row_counts_match() {
        let c = counts(&[("users", 3), ("messages", 90)]);
        assert!(compare_row_counts(&c, &c).is_ok());
    }

    #[test]
    fn short_table_is_reported_by_name() {
        let before = counts(&[("users", 3), ("messages", 90)]);
        let after = counts(&[("users", 3), ("messages", 12)]);
        let err = compare_row_counts(&before, &after).unwrap_err().to_string();
        assert!(err.contains("messages"), "names the table, got: {err}");
        assert!(err.contains("90"), "expected count, got: {err}");
        assert!(
            !err.contains("users"),
            "should not flag a table that matched"
        );
    }

    #[test]
    fn missing_table_is_reported() {
        let before = counts(&[("users", 3)]);
        let err = compare_row_counts(&before, &counts(&[]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing"), "got: {err}");
    }

    /// Tables the destination has and the backup does not are not an error:
    /// migrations run on startup and a newer binary legitimately adds tables.
    #[test]
    fn extra_tables_in_the_destination_are_fine() {
        let before = counts(&[("users", 3)]);
        let after = counts(&[("users", 3), ("new_feature", 0)]);
        assert!(compare_row_counts(&before, &after).is_ok());
    }
}
