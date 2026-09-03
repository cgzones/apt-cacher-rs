DROP INDEX IF EXISTS idx_deliveries_client_ip;
DROP INDEX IF EXISTS idx_downloads_client_ip;
DROP INDEX IF EXISTS idx_deliveries_mirror_id_size;
DROP INDEX IF EXISTS idx_downloads_mirror_id_size;

-- Restore what the `up` replaced.
CREATE INDEX IF NOT EXISTS idx_downloads_mirror_id ON downloads(mirror_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_mirror_id ON deliveries(mirror_id);
