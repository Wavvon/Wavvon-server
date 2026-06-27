use wavvon_hub::db;

#[path = "common.rs"]
mod common;

#[tokio::test]
async fn migrations_idempotent_on_fresh_db() {
    let pool = common::create_test_db().await;

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
    let pool = common::create_test_db().await;

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
    let pool = common::create_test_db().await;

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
