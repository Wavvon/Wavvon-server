use wavvon_hub::db;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn migrations_idempotent_on_fresh_db() {
    let (pool, _guard) = common::create_test_db().await;

    // Running migrations again on an already-migrated database must not fail.
    // (create_test_db already ran migrations once; running them again exercises
    // the IF NOT EXISTS / DO NOTHING guards.)
    db::migrations::run(&pool).await.unwrap();

    // All expected columns exist on channels — query information_schema
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = 'channels'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();

    assert!(names.contains(&"id".to_string()));
    assert!(names.contains(&"name".to_string()));
    assert!(names.contains(&"created_by".to_string()));
    assert!(names.contains(&"parent_id".to_string()));
    assert!(names.contains(&"is_category".to_string()));
    assert!(names.contains(&"created_at".to_string()));
}

#[tokio::test]
async fn migrations_data_survives_rerun() {
    let (pool, _guard) = common::create_test_db().await;

    // Insert a user so the FK on channels.created_by is satisfied
    sqlx::query(
        "INSERT INTO users (public_key, first_seen_at, last_seen_at) VALUES ('user-anon', 1000000, 1000000)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Insert a channel row to represent existing data
    sqlx::query(
        "INSERT INTO channels (id, name, created_by, created_at) VALUES ('ch-survives', 'general', 'user-anon', 1000000)",
    )
    .execute(&pool)
    .await
    .unwrap();

    // Running migrations again must not destroy existing data
    db::migrations::run(&pool).await.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM channels WHERE id = 'ch-survives'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "channel row must survive migration rerun");
}

#[tokio::test]
async fn migrations_create_all_core_tables() {
    let (pool, _guard) = common::create_test_db().await;

    // Every table we expect to exist
    let expected = [
        "users",
        "sessions",
        "channels",
        "messages",
        "peers",
        "federated_channels",
        "federated_messages",
        "roles",
        "role_permissions",
        "user_roles",
        "bans",
        "mutes",
        "invites",
        "hub_settings",
        "alliances",
        "alliance_members",
        "alliance_shared_channels",
        "channel_bans",
        "voice_mutes",
        "channel_settings",
        "conversations",
        "conversation_members",
        "friends",
    ];

    for table in expected {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = $1",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(count, 1, "Table '{table}' should exist after migrations");
    }
}

/// The real server the suite runs against must satisfy the declared floor —
/// otherwise the floor is a claim nobody checks. Pairs with the unit tests in
/// `db::version`, which cover the comparison and the message.
#[tokio::test]
async fn test_database_meets_the_declared_minimum_version() {
    let (db, _guard) = common::create_test_db().await;
    wavvon_hub::db::version::ensure_supported(&db)
        .await
        .expect("CI/dev PostgreSQL is below the declared minimum");
}

/// Every `ADD COLUMN ... NOT NULL` must carry a `DEFAULT`.
///
/// This is what makes downgrading a hub survivable at the schema level. An
/// older binary does not know the columns a newer one added, so its INSERTs
/// omit them; a `NOT NULL` column with no default rejects every one of those
/// inserts and the old binary cannot write at all. With a default, the column
/// fills itself and the old binary keeps working against the newer schema.
///
/// Source-level on purpose: `information_schema` cannot tell a column added by
/// `ALTER TABLE` from one that was in the original `CREATE TABLE`, and the
/// latter are legitimately `NOT NULL` without a default (primary keys, and
/// every column a binary of that vintage already supplies).
///
/// It holds today by luck, not by rule. This is the rule.
#[test]
fn added_columns_never_require_a_value_an_older_binary_cannot_supply() {
    const SRC: &str = include_str!("../src/db/migrations.rs");

    let mut offenders = Vec::new();
    for (i, chunk) in SRC.split("ADD COLUMN").enumerate().skip(1) {
        // The column definition runs to the end of the statement or the next
        // column in the list — whichever comes first.
        let end = chunk
            .find([',', ';', '"'])
            .unwrap_or_else(|| chunk.len().min(200));
        let def = chunk[..end].to_uppercase();
        if def.contains("NOT NULL") && !def.contains("DEFAULT") {
            offenders.push(format!("#{i}: ADD COLUMN{}", &chunk[..end]));
        }
    }

    assert!(
        offenders.is_empty(),
        "these added columns are NOT NULL with no DEFAULT, which stops an older \
         binary inserting at all after an upgrade:\n{}",
        offenders.join("\n")
    );
}

#[tokio::test]
async fn membership_column_backfills_from_roles_and_drops_explicit_everyone_rows() {
    let (pool, _guard) = common::create_test_db().await;

    // Put the database back in its pre-`is_member` shape.
    for sql in [
        "DROP VIEW member_roles",
        "ALTER TABLE users DROP COLUMN is_member",
        "INSERT INTO users (public_key, first_seen_at) VALUES ('old-member', 1), ('old-granted', 1), ('old-stranger', 1)",
        "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ('old-member', 'builtin-everyone', 1), ('old-granted', 'builtin-owner', 1)",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }

    db::migrations::run(&pool).await.unwrap();

    let members: Vec<String> =
        sqlx::query_scalar("SELECT public_key FROM users WHERE is_member ORDER BY public_key")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(members, vec!["old-granted", "old-member"]);

    let everyone_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM user_roles WHERE role_id = 'builtin-everyone'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(everyone_rows, 0, "the floor is implicit now");

    // A stranger handed a role later is not promoted by a restart.
    sqlx::query("INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ('old-stranger', 'builtin-owner', 2)")
        .execute(&pool)
        .await
        .unwrap();
    db::migrations::run(&pool).await.unwrap();
    let promoted: bool =
        sqlx::query_scalar("SELECT is_member FROM users WHERE public_key = 'old-stranger'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!promoted);
}

#[tokio::test]
async fn peers_admitted_as_members_are_demoted_once_and_people_are_spared() {
    let (pool, _guard) = common::create_test_db().await;

    for sql in [
        "INSERT INTO users (public_key, first_seen_at, is_member, display_name) VALUES
            ('hub-only', 1, TRUE, NULL), ('hub-person', 1, TRUE, 'Alice'), ('hub-owner', 1, TRUE, NULL),
            ('plain-member', 1, TRUE, NULL)",
        "INSERT INTO peers (public_key, name, url, added_at) VALUES
            ('hub-only', 'x', '', 1), ('hub-person', 'y', '', 1), ('hub-owner', 'z', '', 1)",
        "INSERT INTO user_roles (user_public_key, role_id, assigned_at) VALUES ('hub-owner', 'builtin-owner', 1)",
        "INSERT INTO sessions (token, public_key, created_at, scope) VALUES ('t1', 'hub-only', 1, 'member')",
        "DELETE FROM hub_settings WHERE key = 'peer_membership_cleanup_v1'",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }

    db::migrations::run(&pool).await.unwrap();

    let members: Vec<String> =
        sqlx::query_scalar("SELECT public_key FROM users WHERE is_member ORDER BY public_key")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(members, vec!["hub-owner", "hub-person", "plain-member"]);
    let scope: String = sqlx::query_scalar("SELECT scope FROM sessions WHERE token = 't1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(scope, "peer");

    // Once only: a later admission is not undone by a restart.
    sqlx::query("UPDATE users SET is_member = TRUE WHERE public_key = 'hub-only'")
        .execute(&pool)
        .await
        .unwrap();
    db::migrations::run(&pool).await.unwrap();
    let again: bool =
        sqlx::query_scalar("SELECT is_member FROM users WHERE public_key = 'hub-only'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(again);
}
