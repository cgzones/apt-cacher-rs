CREATE TABLE IF NOT EXISTS mirrors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    first_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
    last_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
    last_cleanup INTEGER NOT NULL DEFAULT 0,
    CONSTRAINT first UNIQUE (host, path)
) STRICT;

INSERT INTO mirrors (
    host, path, first_seen, last_seen, last_cleanup
)
SELECT host, path, first_seen, last_seen, last_cleanup
FROM mirrors_v2
WHERE port = 0;

DROP TABLE mirrors_v2;
