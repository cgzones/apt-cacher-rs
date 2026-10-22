-- Stage legacy rows with their original identities before the historical
-- port migration. Never reinterpret rows once that migration has run.

CREATE TABLE IF NOT EXISTS mirrors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    first_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
    last_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
    last_cleanup INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT first UNIQUE (host, path)
) STRICT;


CREATE TABLE IF NOT EXISTS mirrors_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    port INTEGER NOT NULL,
    path TEXT NOT NULL,
    first_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
    last_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
    last_cleanup INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT first UNIQUE (host, port, path)
) STRICT;

-- An unexplained partially populated destination cannot be merged safely.
-- SQLite rolls this guard and all schema/data changes back on failure.
CREATE TEMP TABLE legacy_mirror_upgrade_guard (
    existing_rows INTEGER NOT NULL CHECK (existing_rows = 0)
);
INSERT INTO legacy_mirror_upgrade_guard
SELECT COUNT(*) FROM mirrors_v2
WHERE NOT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20251204161857 AND success = 1);
DROP TABLE legacy_mirror_upgrade_guard;

INSERT INTO mirrors_v2 (id, host, port, path, first_seen, last_seen, last_cleanup)
SELECT id, host, 0, path, first_seen, last_seen, last_cleanup
FROM mirrors WHERE NOT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20251204161857 AND success = 1);

DELETE FROM mirrors WHERE NOT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = 20251204161857 AND success = 1);
