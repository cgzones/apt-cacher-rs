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

INSERT INTO mirrors_v2 (
    host, port, path, first_seen, last_seen, last_cleanup
)
SELECT host, 0, path, first_seen, last_seen, last_cleanup FROM mirrors;

DROP TABLE mirrors;
