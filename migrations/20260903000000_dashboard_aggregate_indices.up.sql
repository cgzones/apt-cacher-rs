-- Covering indexes for the dashboard's two grouped aggregates.
--
-- get_mirrors_with_stats groups both usage tables by mirror_id and sums
-- `size`; the single-column indexes replaced here still forced a table row
-- lookup for every group member. `(mirror_id, size)` serves the same
-- `WHERE mirror_id = ?` deletions (cleanup, mirror removal) on its prefix, so
-- the single-column indexes are pure write-side overhead once it exists.
DROP INDEX IF EXISTS idx_downloads_mirror_id;
DROP INDEX IF EXISTS idx_deliveries_mirror_id;
CREATE INDEX IF NOT EXISTS idx_downloads_mirror_id_size ON downloads(mirror_id, size);
CREATE INDEX IF NOT EXISTS idx_deliveries_mirror_id_size ON deliveries(mirror_id, size);

-- get_clients_with_stats groups both tables by client_ip taking
-- MAX(timestamp), SUM(size) and COUNT(*), with no index at all until now:
-- a full scan of each unbounded-growth table plus a temp b-tree for the
-- grouping. `(client_ip, timestamp, size)` makes it an index-only scan in
-- client_ip order.
CREATE INDEX IF NOT EXISTS idx_downloads_client_ip ON downloads(client_ip, timestamp, size);
CREATE INDEX IF NOT EXISTS idx_deliveries_client_ip ON deliveries(client_ip, timestamp, size);
