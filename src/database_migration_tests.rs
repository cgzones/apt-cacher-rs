use super::*;
use sqlx::migrate::Migrator;

const PRELUDE: i64 = 20_251_204_161_856;

fn migrations(keep: impl Fn(i64) -> bool) -> Migrator {
    Migrator::with_migrations(
        sqlx::migrate!()
            .iter()
            .filter(|migration| keep(migration.version))
            .cloned()
            .collect(),
    )
}

async fn legacy_database() -> (tempfile::TempDir, Database) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Database::connect(&dir.path().join("legacy.db"), Duration::from_secs(5))
        .await
        .expect("connect");
    db.create_legacy_tables().await.expect("legacy schema");
    // A normal conflict consumes an AUTOINCREMENT value, leaving ids 1 and 3.
    sqlx::raw_sql(
        "INSERT INTO mirrors (host, path, first_seen, last_seen, last_cleanup)
         VALUES ('first.example', 'debian', 10, 20, 30);
         INSERT INTO mirrors (host, path) VALUES ('first.example', 'debian')
         ON CONFLICT (host, path) DO UPDATE SET last_seen = 20;
         INSERT INTO mirrors (host, path, first_seen, last_seen, last_cleanup)
         VALUES ('second.example', 'debian', 40, 50, 60);
         INSERT INTO origins (mirror_id, distribution, component, architecture)
         VALUES (3, 'sid', 'main', 'amd64');
         INSERT INTO downloads (mirror_id, debname, size, duration, client_ip)
         VALUES (3, 'package.deb', 1, 1, x'00');
         INSERT INTO deliveries (mirror_id, debname, size, duration, partial, client_ip)
         VALUES (3, 'package.deb', 1, 1, 0, x'00');",
    )
    .execute(&db.conn)
    .await
    .expect("legacy rows");
    (dir, db)
}

async fn assert_preserved(db: &Database) {
    let rows: Vec<(i64, String, i64, i64, i64)> = query_as(
        "SELECT id, host, first_seen, last_seen, last_cleanup FROM mirrors_v2 ORDER BY id",
    )
    .fetch_all(&db.conn)
    .await
    .expect("mirrors");
    assert_eq!(
        rows,
        [
            (1, "first.example".into(), 10, 20, 30),
            (3, "second.example".into(), 40, 50, 60)
        ]
    );
    let owners: (i64, i64, i64) = query_as(
        "SELECT (SELECT mirror_id FROM origins), (SELECT mirror_id FROM downloads),
         (SELECT mirror_id FROM deliveries)",
    )
    .fetch_one(&db.conn)
    .await
    .expect("owners");
    assert_eq!(owners, (3, 3, 3));
}

#[tokio::test]
async fn legacy_upgrade_preserves_ids_and_transfer_owners() {
    let (_dir, db) = legacy_database().await;
    db.init_tables().await.expect("upgrade");
    assert_preserved(&db).await;
    db.init_tables().await.expect("restart");
    assert_preserved(&db).await;
}

#[tokio::test]
async fn restart_between_compatibility_and_historical_migrations_is_safe() {
    let (dir, db) = legacy_database().await;
    migrations(|version| version == PRELUDE)
        .run(&db.conn)
        .await
        .expect("stage");
    assert_preserved(&db).await;
    db.conn.close().await;
    let reopened = Database::connect(&dir.path().join("legacy.db"), Duration::from_secs(5))
        .await
        .expect("reopen");
    reopened.init_tables().await.expect("finish upgrade");
    assert_preserved(&reopened).await;
}

#[tokio::test]
async fn already_migrated_database_and_checksums_are_untouched() {
    let (_dir, db) = legacy_database().await;
    migrations(|version| version != PRELUDE)
        .run(&db.conn)
        .await
        .expect("historical upgrade");
    let before: Vec<(i64, Vec<u8>)> =
        query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&db.conn)
            .await
            .expect("checksums");
    // Run directly, as the CLI would, with no legacy table at all.
    sqlx::migrate!()
        .run(&db.conn)
        .await
        .expect("compatibility upgrade");
    let after: Vec<(i64, Vec<u8>)> = query_as(
        "SELECT version, checksum FROM _sqlx_migrations WHERE version != ? ORDER BY version",
    )
    .bind(PRELUDE)
    .fetch_all(&db.conn)
    .await
    .expect("checksums");
    assert_eq!(before, after);
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM mirrors_v2 ORDER BY id")
        .fetch_all(&db.conn)
        .await
        .expect("ids");
    assert_eq!(ids, [1, 2], "do not guess how to repair historical damage");
    let owner: i64 = sqlx::query_scalar("SELECT mirror_id FROM origins")
        .fetch_one(&db.conn)
        .await
        .expect("owner");
    assert_eq!(owner, 3);
}

#[tokio::test]
async fn conflicting_staged_rows_roll_back_the_entire_migration() {
    for unexpected in [false, true] {
        let (_dir, db) = legacy_database().await;
        sqlx::raw_sql("CREATE TABLE mirrors_v2 AS SELECT id, host, 0 AS port, path, first_seen, last_seen, last_cleanup FROM mirrors WHERE id = 3;
        CREATE UNIQUE INDEX staged_ids ON mirrors_v2(id);")
        .execute(&db.conn).await.expect("conflict");
        if unexpected {
            query("UPDATE mirrors_v2 SET id = 9, host = 'unexpected.example'")
                .execute(&db.conn)
                .await
                .expect("unexpected destination");
        }
        assert!(
            migrations(|version| version == PRELUDE)
                .run(&db.conn)
                .await
                .is_err(),
            "conflicting IDs must abort"
        );
        let legacy: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mirrors")
            .fetch_one(&db.conn)
            .await
            .expect("legacy count");
        let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mirrors_v2")
            .fetch_one(&db.conn)
            .await
            .expect("staged count");
        assert_eq!(
            (legacy, staged),
            (2, 1),
            "no partial insert or legacy deletion"
        );
    }
}
