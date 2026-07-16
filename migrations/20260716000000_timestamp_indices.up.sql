-- get_bandwidth_since (web interface, 2x per dashboard load) and the daily
-- usage-retention DELETE filter both tables by timestamp; without an index
-- each is a full-table scan on the two unbounded-growth tables.
CREATE INDEX IF NOT EXISTS idx_downloads_timestamp ON downloads(timestamp);
CREATE INDEX IF NOT EXISTS idx_deliveries_timestamp ON deliveries(timestamp);
