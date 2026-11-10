use anyhow::Context;
use anyhow::Result;
use sqlx::postgres::PgPoolOptions;
use std::path::PathBuf;
use wavvon_hub::db;

/// Default archive name for `backup` / `admin backup` when no path is given.
/// `arg_index` is where the optional path sits in argv.
pub fn backup_out_path(arg_index: usize) -> String {
    std::env::args().nth(arg_index).unwrap_or_else(|| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("hub-backup-{ts}.tar.gz")
    })
}

/// Source path and `--force` for `restore` / `admin restore`. `usage` is the
/// error text when the path is missing.
pub fn restore_args(arg_index: usize, usage: &str) -> Result<(String, bool)> {
    let src = std::env::args()
        .nth(arg_index)
        .filter(|a| !a.starts_with("--"))
        .ok_or_else(|| anyhow::anyhow!("{usage}"))?;
    let force = std::env::args().any(|a| a == "--force");
    Ok((src, force))
}

/// `wavvon-hub migrate`.
pub async fn migrate() -> Result<()> {
    let (db_url, started) = cli_database_url().await;
    let db = PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await?;
    db::version::ensure_supported(&db)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    db::migrations::run(&db).await?;
    println!("Migrations applied");
    db.close().await;
    if let Some(pg) = started {
        pg.stop().await?;
    }
    Ok(())
}

/// `wavvon-hub backup [out]`.
pub async fn backup_cmd() -> Result<()> {
    let out_path = backup_out_path(2);
    let (db_url, started) = cli_database_url().await;
    backup(&out_path, &db_url).await?;
    println!("Backup written to {out_path}");
    if let Some(pg) = started {
        pg.stop().await?;
    }
    Ok(())
}

/// `wavvon-hub restore <backup.tar.gz> [--force]`.
pub async fn restore_cmd() -> Result<()> {
    let (src, force) = restore_args(2, "Usage: wavvon-hub restore <backup.tar.gz> [--force]")?;
    let (db_url, started) = cli_database_url().await;
    restore(&src, &db_url, force).await?;
    if let Some(pg) = started {
        pg.stop().await?;
    }
    println!("Restore complete. Restart the hub to apply.");
    Ok(())
}

/// `wavvon-hub db move --to <url> | --from <url> [--force]`.
pub async fn move_cmd() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let value_after = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .filter(|v| !v.starts_with("--"))
            .cloned()
    };
    let to = value_after("--to");
    let from = value_after("--from");
    let force = args.iter().any(|a| a == "--force");

    // One direction per invocation. "Both" has no meaning and "neither"
    // would silently do nothing, so both are refused rather than guessed.
    let (source_label, target_label, other) = match (&to, &from) {
        (Some(url), None) => ("this hub", "the other database", url.clone()),
        (None, Some(url)) => ("the other database", "this hub", url.clone()),
        _ => anyhow::bail!(
            "Usage: wavvon-hub db move --to <url> | --from <url> [--force]\n\
             Exactly one direction, and the URL is the *other* database — this hub's own \
             comes from {} (or the built-in PostgreSQL when that is unset).",
            wavvon_hub_env::DATABASE_URL
        ),
    };

    let (mine, started) = cli_database_url().await;
    let (source_url, target_url) = if to.is_some() {
        (mine, other)
    } else {
        (other, mine)
    };

    db_move(&source_url, &target_url, source_label, target_label, force).await?;
    if let Some(pg) = started {
        pg.stop().await?;
    }
    Ok(())
}

/// The database URL for CLI subcommands that run before `Settings` is loaded
/// (`migrate`, `admin`).
///
/// These used to resolve it independently and disagreed: `migrate` read
/// `WAVVON_DATABASE_URL` while `admin` read only the unprefixed
/// `DATABASE_URL`, so `admin users set-owner` — the ownership bootstrap —
/// silently hit the built-in default on any hub configured the documented
/// way. `WAVVON_DATABASE_URL` is the documented variable (the one `Settings`
/// resolves for the server path); the unprefixed name stays as a fallback.
///
/// Falling back to the built-in default is *announced*. These subcommands
/// mutate ownership and schema, and "it said OK" against a database the
/// operator did not mean is the failure this whole function exists to stop.
pub async fn cli_database_url() -> (String, Option<wavvon_hub::embedded_pg::EmbeddedPostgres>) {
    if let Ok(url) =
        std::env::var(wavvon_hub_env::DATABASE_URL).or_else(|_| std::env::var("DATABASE_URL"))
    {
        return (url, None);
    }

    // No URL means the hub's own PostgreSQL (decisions.md), and a CLI command
    // has to reach the same one the server would — `backup` against a
    // different database is a backup of nothing, reported as success.
    let root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if let Some(url) = wavvon_hub::embedded_pg::running_url(&root) {
        // Adopting, not starting — so nothing has pointed the dump tools at
        // the bundled install yet, and `pg_dump` is not on PATH on the setup
        // that owns this branch.
        wavvon_hub::embedded_pg::point_tools_at_bundled(&root);
        return (url, None);
    }
    // Not running: start it for the length of this command. It is the hub's
    // own server in the hub's own directory, so this is not "managing a
    // database we did not create" — it is opening the one we did.
    match wavvon_hub::embedded_pg::start(&root).await {
        Ok(pg) => {
            let url = pg.url().to_string();
            (url, Some(pg))
        }
        Err(e) => {
            eprintln!("FATAL could not open the hub's built-in PostgreSQL: {e:#}");
            std::process::exit(1);
        }
    }
}

/// Everything a hub is, in one file: the database, the identity key, and the
/// uploaded files.
///
/// It used to be the identity file and a metadata stub, with a comment saying
/// to run `pg_dump` separately — so "take a backup first" in the upgrade docs
/// pointed at a tool that did not take one. Uploads were missing too, which
/// meant a restored hub came back with every attachment a broken link.
///
/// The Tantivy search index is deliberately absent: it is derived from the
/// messages table and rebuilt by `POST /admin/search/reindex`, so carrying it
/// would inflate every archive with data the hub can regenerate.
pub async fn backup(out_path: &str, db_url: &str) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(db_url)
        .await
        .context("Cannot open the database to back it up")?;

    let server_version_num = db::dump::server_version_num(&pool).await?;
    // Whatever schema this hub actually lives in: `public` normally, or one of
    // its own when a farm separates hubs by schema rather than by database.
    // Recorded in the archive so a restore knows what it is holding.
    let schema = db::dump::current_schema(&pool).await?;
    let row_counts = db::dump::row_counts(&pool).await?;

    // Dumped to a temp file first: the tar is written last, so a pg_dump that
    // fails leaves no archive at all rather than a plausible-looking one that
    // is missing the database.
    let staging = tempfile::tempdir()?;
    let dump_path = staging.path().join("database.dump");
    println!("Dumping the database…");
    db::dump::dump(db_url, &dump_path, &schema)?;

    // The archive carries the hub's secret key and the whole database.
    let file = wavvon_identity::create_secret(out_path)?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);

    tar.append_path_with_name(&dump_path, "database.dump")?;

    if std::path::Path::new("hub_identity.json").exists() {
        tar.append_path("hub_identity.json")?;
    }

    let uploads = wavvon_hub::routes::uploads::uploads_dir();
    let uploads_included = std::path::Path::new(&uploads).is_dir();
    if uploads_included {
        tar.append_dir_all("uploads", &uploads)?;
    }

    let meta = serde_json::json!({
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        "wavvon_version": env!("CARGO_PKG_VERSION"),
        // Read back at restore time to refuse a restore into an older major
        // before anything is written.
        "pg_server_version_num": server_version_num,
        // Compared after the restore, so a partial one is reported as partial.
        "row_counts": row_counts,
        "schema": schema,
        "uploads_included": uploads_included,
    });
    let meta_bytes = serde_json::to_vec_pretty(&meta)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(meta_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "backup_meta.json", meta_bytes.as_slice())?;
    tar.finish()?;

    let tables = row_counts.len();
    let rows: i64 = row_counts.values().sum();
    println!(
        "Backed up {rows} rows across {tables} tables from PostgreSQL {}.{}.",
        server_version_num / 10_000,
        server_version_num % 10_000
    );
    if !uploads_included {
        println!("No uploads directory at {uploads} — nothing to include.");
    }
    Ok(())
}

/// Restore a backup archive over the configured database.
///
/// Refuses rather than half-writes, in this order: the destination must be
/// empty, and its major must be at least the source's. `--force` waives only
/// the emptiness check — the version rule is not the operator's to overrule,
/// because past it `pg_restore` simply cannot parse the archive.
/// Printing wrapper over [`db::dump::move_database`] — the mechanism lives in
/// the library so it can be tested against two real databases.
pub async fn db_move(
    source_url: &str,
    target_url: &str,
    source_label: &str,
    target_label: &str,
    force: bool,
) -> anyhow::Result<()> {
    println!("Moving from {source_label} to {target_label}…");
    let report = db::dump::move_database(source_url, target_url, force).await?;
    println!(
        "Moved {} rows across {} tables. {source_label} is untouched.",
        report.rows, report.tables
    );
    println!(
        "Nothing has switched over: set (or unset) {} and restart the hub when you are ready.",
        wavvon_hub_env::DATABASE_URL
    );
    Ok(())
}

pub async fn restore(src_path: &str, db_url: &str, force: bool) -> anyhow::Result<()> {
    let file = std::fs::File::open(src_path)
        .with_context(|| format!("Cannot open backup archive {src_path}"))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    let staging = tempfile::tempdir()?;
    archive
        .unpack(staging.path())
        .context("Cannot unpack the backup archive")?;

    let meta: serde_json::Value = std::fs::read(staging.path().join("backup_meta.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    let dump_path = staging.path().join("database.dump");
    if dump_path.exists() {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(db_url)
            .await
            .context("Cannot open the destination database")?;

        // Direction first: it is the check that cannot be waived, so failing
        // it should cost nothing.
        if let Some(source) = meta["pg_server_version_num"].as_i64() {
            let target = db::dump::server_version_num(&pool).await?;
            db::dump::check_direction(source as i32, target)?;
        }

        if !db::dump::is_empty(&pool).await? && !force {
            anyhow::bail!(
                "the destination database already has tables. Restoring over them \
                 would merge two hubs into one. Restore into an empty database, or \
                 pass --force if you meant to write into this one."
            );
        }

        println!("Restoring the database…");
        db::dump::restore(db_url, &dump_path)?;

        // The archive's counts are the contract: every table it carried must
        // come back with the same number of rows.
        if let Ok(expected) = serde_json::from_value::<std::collections::BTreeMap<String, i64>>(
            meta["row_counts"].clone(),
        ) {
            let actual = db::dump::row_counts(&pool).await?;
            db::dump::compare_row_counts(&expected, &actual)?;
            let rows: i64 = expected.values().sum();
            println!("Verified {rows} rows across {} tables.", expected.len());
        }
    } else {
        println!(
            "WARN  This archive has no database dump — it was written by a hub from \
             when `backup` only captured the identity file. The database is NOT being \
             restored."
        );
    }

    let src = staging.path().join("hub_identity.json");
    if src.exists() {
        std::fs::copy(&src, "hub_identity.json")?;
        println!("Restored hub_identity.json.");
    }

    let uploads_src = staging.path().join("uploads");
    if uploads_src.is_dir() {
        let dest = wavvon_hub::routes::uploads::uploads_dir();
        copy_dir_all(&uploads_src, std::path::Path::new(&dest))?;
        println!("Restored uploads into {dest}.");
    }

    Ok(())
}

/// Recursive copy, merging into whatever is already there. Files present in
/// the archive win; files only in the destination are left alone — a restore
/// should not delete an attachment the archive simply predates.
fn copy_dir_all(src: &std::path::Path, dest: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let to = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}
