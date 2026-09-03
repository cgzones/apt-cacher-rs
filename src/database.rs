#[cfg(feature = "hyper")]
use std::borrow::Cow;
use std::{
    net::{IpAddr, Ipv6Addr},
    num::{NonZero, TryFromIntError},
    path::{Path, PathBuf},
    str::FromStr as _,
    time::Duration,
};

use sqlx::{
    ConnectOptions as _, Error, Executor as _, Pool, Sqlite, SqliteConnection, SqlitePool, query,
    query_as,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous},
};
use tracing::{debug, info, trace, warn};

use crate::{
    cache_paths::MirrorSite,
    client_info::CLEANUP_CLIENT_ADDR,
    config::{Alias, ClientHost, DomainName},
    deb_mirror::{Mirror, MirrorKind},
    error::ErrorReport,
    flat_blocklist,
    humanfmt::HumanFmt,
    limits::RETENTION_TIME,
    warn_once_or_info,
};

/// Decode a `mirrors_v2.kind` column, defaulting to `Structured`.
///
/// `cleanup_invalid_rows` purges out-of-range encodings before any reader
/// observes them, so the fallback is defence in depth -- but a `Flat` row
/// silently read as `Structured` makes cleanup emit structured units and
/// reconcile against an index that does not exist, so say so. Matches the
/// `load_all_mirror_ids` reader, which already warns on the same condition.
fn decode_mirror_kind(kind: i64, path: &str) -> MirrorKind {
    if let Some(kind) = MirrorKind::from_db_int(kind) {
        kind
    } else {
        warn_once_or_info!(
            "Mirror row for `{}` has out-of-range kind value {kind}; treating the mirror as structured",
            path.escape_debug()
        );
        MirrorKind::Structured
    }
}

/// Conservative upper bound on the number of bind parameters allowed in a
/// single `SQLite` statement.
///
/// `SQLite` caps this at `SQLITE_MAX_VARIABLE_NUMBER`, whose compile-time default
/// is 999 on builds < 3.32 and 32766 on newer ones. We can't depend on the
/// runtime build so the lower historical value is hard-coded; batched
/// statements that approach the limit must chunk their inputs.
const SQLITE_MAX_BIND_PARAMETERS: usize = 999;

#[derive(Debug, Clone)]
pub(crate) struct Database {
    conn: Pool<Sqlite>,
}

#[derive(Clone, Debug)]
pub(crate) struct MirrorEntry {
    pub(crate) host: ClientHost,
    /// Raw port from database. `0` means no explicit port; use `port()` to get `Option<NonZero<u16>>`.
    port: u16,
    pub(crate) path: String,
    /// Raw `mirrors_v2.kind` (INTEGER) value.  `cleanup_invalid_rows`
    /// purges rows whose encoding falls outside the [`MirrorKind`]
    /// invariant before any code reads `MirrorEntry`s, so the
    /// `From<MirrorEntry> for Mirror` conversion's `unwrap_or` fallback
    /// is pure defense-in-depth.
    kind: i64,
}

impl MirrorEntry {
    #[must_use]
    pub(crate) const fn port(&self) -> Option<NonZero<u16>> {
        NonZero::new(self.port)
    }

    /// Decoded layout kind. `cleanup_invalid_rows` purges out-of-range
    /// encodings before any reader observes them, so the `unwrap_or`
    /// fallback to `Structured` is purely defensive — mirrors the same
    /// fallback used by `From<MirrorEntry> for Mirror`.
    #[must_use]
    pub(crate) fn kind(&self) -> MirrorKind {
        decode_mirror_kind(self.kind, &self.path)
    }

    #[cfg(feature = "hyper")]
    #[must_use]
    pub(crate) fn format_authority(&self) -> Cow<'_, str> {
        self.host.format_authority(self.port())
    }

    /// The on-disk identity of this mirror, for every `CachePaths`
    /// derivation (`mirror_dir`, `entry_dir`, `tmp_dir`, ...).  Rows store
    /// the canonical (alias-resolved) host -- `decide_request` resolves
    /// aliases before any row is minted and `merge_alias_rows` folds legacy
    /// alias rows at startup -- so this is the same projection as
    /// `ConnectionDetails::site`.
    #[must_use]
    pub(crate) fn site(&self) -> MirrorSite<'_> {
        MirrorSite {
            host: self.host.as_cache_host(),
            port: self.port(),
            path: &self.path,
        }
    }
}

#[cfg(test)]
impl MirrorEntry {
    /// Test-only constructor: production code only builds a `MirrorEntry`
    /// from a SQL row, but `cleanup::model::classify_mirror`'s pure unit
    /// tests need to build one directly.
    pub(crate) fn new_for_test(
        host: ClientHost,
        port: Option<NonZero<u16>>,
        path: String,
        kind: MirrorKind,
    ) -> Self {
        Self {
            host,
            port: port.map_or(0, NonZero::get),
            path,
            kind: kind.as_db_int(),
        }
    }
}

impl From<MirrorEntry> for Mirror {
    fn from(entry: MirrorEntry) -> Self {
        let port = entry.port();
        let MirrorEntry {
            host,
            port: _,
            path,
            kind,
        } = entry;
        let kind = decode_mirror_kind(kind, &path);
        Self::new(host, port, path, kind)
    }
}

#[derive(Debug)]
pub(crate) struct MirrorStatEntry {
    pub(crate) host: ClientHost,
    /// Raw port from database. `0` means no explicit port; use `port()` to get `Option<NonZero<u16>>`.
    port: u16,
    pub(crate) path: String,
    pub(crate) first_seen: i64,
    pub(crate) last_seen: i64,
    pub(crate) last_cleanup: i64,
    pub(crate) total_download_size: i64,
    pub(crate) total_delivery_size: i64,
    pub(crate) download_count: i64,
    pub(crate) delivery_count: i64,
}

impl MirrorStatEntry {
    #[must_use]
    pub(crate) const fn port(&self) -> Option<NonZero<u16>> {
        NonZero::new(self.port)
    }

    /// Render `host[:port]/path` directly into a `Formatter` without
    /// allocating an intermediate `String`.
    #[must_use]
    pub(crate) fn uri(&self) -> impl std::fmt::Display + '_ {
        struct W<'a> {
            host: &'a ClientHost,
            port: Option<NonZero<u16>>,
            path: &'a str,
        }
        impl std::fmt::Display for W<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}/{}", self.host.format_authority(self.port), self.path)
            }
        }
        W {
            host: &self.host,
            port: self.port(),
            path: &self.path,
        }
    }

    /// The on-disk identity of this mirror; the same projection as
    /// [`MirrorEntry::site`] (rows are canonical).
    #[must_use]
    pub(crate) fn site(&self) -> MirrorSite<'_> {
        MirrorSite {
            host: self.host.as_cache_host(),
            port: self.port(),
            path: &self.path,
        }
    }
}

#[derive(Debug)]
pub(crate) struct OriginEntry {
    pub(crate) host: ClientHost,
    /// Raw port from database. `0` means no explicit port; use `port()` to get `Option<NonZero<u16>>`.
    port: u16,
    pub(crate) mirror_path: String,
    pub(crate) distribution: String,
    pub(crate) component: String,
    pub(crate) architecture: String,
    pub(crate) last_seen: i64,
}

impl OriginEntry {
    #[must_use]
    pub(crate) const fn port(&self) -> Option<NonZero<u16>> {
        NonZero::new(self.port)
    }

    /// Whether this origin was seen within [`RETENTION_TIME`] of `now` (seconds
    /// since the epoch). Cleanup reconciles only against active origins: a stale
    /// one's `Packages` index no longer describes what the mirror still serves.
    #[must_use]
    pub(crate) fn is_active(&self, now: Duration) -> bool {
        Duration::from_secs(
            u64::try_from(self.last_seen).expect("Database should never store negative timestamp"),
        ) + RETENTION_TIME
            > now
    }

    /// Render `host[:port]/mirror_path` directly into a `Formatter` without
    /// allocating an intermediate `String`.
    #[must_use]
    pub(crate) fn mirror_uri(&self) -> impl std::fmt::Display + '_ {
        struct W<'a> {
            host: &'a ClientHost,
            port: Option<NonZero<u16>>,
            mirror_path: &'a str,
        }
        impl std::fmt::Display for W<'_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}/{}",
                    self.host.format_authority(self.port),
                    self.mirror_path
                )
            }
        }
        W {
            host: &self.host,
            port: self.port(),
            mirror_path: &self.mirror_path,
        }
    }
}

#[cfg(test)]
impl OriginEntry {
    /// Test-only constructor: production code only builds an `OriginEntry` from
    /// a SQL row, but `cleanup::refs`' pure unit tests need to build one
    /// directly.
    pub(crate) fn new_for_test(
        host: ClientHost,
        mirror_path: String,
        distribution: String,
        last_seen: i64,
    ) -> Self {
        Self {
            host,
            port: 0,
            mirror_path,
            distribution,
            component: "main".to_owned(),
            architecture: "amd64".to_owned(),
            last_seen,
        }
    }
}

#[derive(Debug)]
pub(crate) struct ClientStatEntry {
    pub(crate) client_ip: IpAddr,
    pub(crate) last_seen: i64,
    pub(crate) total_downloaded: i64,
    pub(crate) total_delivered: i64,
    pub(crate) request_count: i64,
}

#[derive(Debug)]
pub(crate) struct TopPackageEntry {
    pub(crate) debname: String,
    pub(crate) delivery_count: i64,
    pub(crate) total_delivered: i64,
    pub(crate) package_size: i64,
}

/// The dashboard's two Top-Packages rankings, from one aggregate pass.
///
/// The two tables rank the same `GROUP BY debname` aggregate differently, so
/// they used to be two statements scanning `deliveries` end to end for the
/// same numbers. [`Database::get_top_packages`] ranks both ways in one query
/// and splits the result here.
#[derive(Debug)]
pub(crate) struct TopPackages {
    /// Most deliveries first.
    pub(crate) by_count: Vec<TopPackageEntry>,
    /// Most bytes delivered first.
    pub(crate) by_size: Vec<TopPackageEntry>,
}

/// Bytes downloaded from upstream and delivered to clients over the
/// dashboard's two reporting windows, from one statement.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BandwidthWindows {
    /// `(downloaded, delivered)` over the last 24 hours.
    pub(crate) day: (i64, i64),
    /// `(downloaded, delivered)` over the last 7 days.
    pub(crate) week: (i64, i64),
}

/// Pre-converted SQL-ready row for a `deliveries` insert. Constructed once by
/// the producer side of the batch pipeline so the per-event hot path stays
/// out of `i64::try_from` and IPv6-mapping conversions.
#[derive(Debug)]
pub(crate) struct DeliveryRow {
    pub(crate) mirror_id: i64,
    pub(crate) debname: String,
    pub(crate) size: i64,
    pub(crate) duration: i64,
    pub(crate) partial: u8,
    pub(crate) client_ip: [u8; 16],
}

/// Pre-converted SQL-ready row for a `downloads` insert.
#[derive(Debug)]
pub(crate) struct DownloadRow {
    pub(crate) mirror_id: i64,
    pub(crate) debname: String,
    pub(crate) size: i64,
    pub(crate) duration: i64,
    pub(crate) client_ip: [u8; 16],
}

/// Pre-converted SQL-ready row for an `origins` upsert.
///
/// `PartialEq` supports batch-level dedup in the DB task: every Packages
/// request for an origin enqueues the same upsert.
/// A mirror row without origins, as returned by
/// [`Database::get_mirrors_without_origins`].
#[derive(Debug)]
pub(crate) struct OrphanMirror {
    pub(crate) id: i64,
    pub(crate) entry: MirrorEntry,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct OriginRow {
    pub(crate) mirror_id: i64,
    pub(crate) distribution: String,
    pub(crate) component: String,
    pub(crate) architecture: String,
}

/// Upsert a mirror row and return `(id, was_inserted)` in a single round
/// trip via `RETURNING`. `was_inserted` is `first_seen = last_seen`: equal
/// on a fresh INSERT, since ON CONFLICT rewrites `last_seen` (and
/// conditionally `kind`) but never `first_seen`. An ON-CONFLICT update
/// landing in the same unixepoch second as the original INSERT also
/// compares equal - a harmless false positive (a repeated "Encountered
/// new mirror" debug line at worst).
///
/// The `kind` column on ON-CONFLICT latches to `Structured` (0) whenever
/// any structured request arrives for an existing row, so the blocklist
/// seed at next startup cannot lose a collision that surfaced only after
/// a flat row already existed for the same `(host, port, path)`.
async fn upsert_mirror_get_id(
    tx: &mut SqliteConnection,
    mirror: &Mirror,
) -> Result<(i64, bool), Error> {
    let host = mirror.host();
    let port = mirror.port().map_or(0, NonZero::get);
    let path = mirror.path();
    let kind = mirror.kind().as_db_int();
    let row = query!(
        r#"
            INSERT INTO mirrors_v2
            (host, port, path, kind)
            VALUES
            (?, ?, ?, ?)
            ON CONFLICT
            DO UPDATE SET
              last_seen = unixepoch(CURRENT_TIMESTAMP),
              kind = CASE
                WHEN excluded.kind = 0 THEN 0
                ELSE mirrors_v2.kind
              END
            RETURNING id, kind AS "kind!: i64", (first_seen = last_seen) AS "was_inserted!: bool";
        "#,
        host,
        port,
        path,
        kind,
    )
    .fetch_one(&mut *tx)
    .await?;
    // Newly-registered structured mirrors at `path = "flat"` (or
    // `flat/<anything>`) would have their files written into the same
    // `<host>/flat/` tree the host-level flat layout reserves.  Record
    // the host in the blocklist so subsequent flat URLs for it fall
    // through to passthrough uncached.
    //
    // Gate on the post-upsert `kind` column rather than `was_inserted`:
    // a structured request can latch a previously-flat row to structured
    // (was_inserted=false), and that transition must still be observed
    // by the blocklist.  `record_mirror`'s `path_collides_with_flat_layout`
    // check is the cheap pre-filter; the HashSet insert is idempotent.
    if MirrorKind::from_db_int(row.kind) == Some(MirrorKind::Structured) {
        // `mirror` is canonical (alias-resolved at dispatch), so its host is
        // the on-disk host directory the blocklist keys on.
        flat_blocklist::record_mirror(mirror.host().as_cache_host(), mirror.port(), mirror.path());
    }
    Ok((row.id, row.was_inserted))
}

/// On-disk footprint of the `SQLite` database: the main file plus its `-wal`
/// sidecar, which in WAL mode can hold a sizeable share of the rows (an
/// unclean shutdown leaves it uncheckpointed). `None` when the main file
/// cannot be stat'ed; a missing/unreadable WAL simply contributes zero.
async fn database_file_size(path: &Path) -> Option<u64> {
    let main = tokio::fs::metadata(path)
        .await
        .inspect_err(|err| {
            warn!(
                "Failed to stat database `{}`; reporting its on-disk size as unknown:  {}",
                path.display(),
                ErrorReport(err)
            );
        })
        .ok()?
        .len();

    let mut wal = path.as_os_str().to_os_string();
    wal.push("-wal");
    let wal = tokio::fs::metadata(PathBuf::from(wal))
        .await
        .map_or(0, |md| md.len());

    Some(main.saturating_add(wal))
}

impl Database {
    pub(crate) async fn connect(path: &Path, slow_timeout: Duration) -> Result<Self, Error> {
        let url = format!("sqlite://{}", path.display());

        debug!("Opening database `{url}` with slow timeout of {slow_timeout:?}...");

        // WAL lets readers (web interface, cleanup) run concurrently with
        // the batch-flush writer instead of excluding it across pool
        // connections, and keeps synchronous=NORMAL corruption-safe: an
        // OS/power crash can only lose the last uncheckpointed transactions,
        // never corrupt the file. That loss is fine for reconstructible cache
        // metadata, and it avoids the DELETE-journal churn plus per-flush
        // fsyncs of sqlx's FULL default.
        let opts = SqliteConnectOptions::from_str(&url)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            // These two take `log::LevelFilter`, the crate's only remaining
            // `log` use — don't drop the `log` dep to "modernize" onto tracing.
            .log_statements(log::LevelFilter::Trace)
            .log_slow_statements(log::LevelFilter::Warn, slow_timeout);
        let conn = SqlitePool::connect_with(opts).await?;

        if let Some(size) = database_file_size(path).await {
            info!(
                "Database `{}` opened (size: {})",
                path.display(),
                HumanFmt::Size(size)
            );
        } else {
            info!("Database `{}` opened", path.display());
        }

        Ok(Self { conn })
    }

    /// Create the four legacy tables (mirrors, origins, downloads, deliveries)
    /// inside a transaction.  These are the pre-migration tables that all
    /// subsequent `sqlx::migrate!` migrations assume already exist.
    async fn create_legacy_tables(&self) -> Result<(), Error> {
        let mut tx = self.conn.begin().await?;

        tx.execute(
            r"
            CREATE TABLE IF NOT EXISTS mirrors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                path TEXT NOT NULL,
                first_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
                last_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
                last_cleanup INTEGER NOT NULL DEFAULT 0,
                CONSTRAINT first UNIQUE (host, path)
            ) STRICT;
            ",
        )
        .await?;

        tx.execute(
            r"
            CREATE TABLE IF NOT EXISTS origins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mirror_id INTEGER NOT NULL,
                distribution TEXT NOT NULL,
                component TEXT NOT NULL,
                architecture TEXT NOT NULL,
                first_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
                last_seen INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP)),
                CONSTRAINT first UNIQUE (mirror_id, distribution, component, architecture)
            ) STRICT;
            ",
        )
        .await?;

        tx.execute(
            r"
            CREATE TABLE IF NOT EXISTS downloads (
                mirror_id INTEGER NOT NULL,
                debname TEXT NOT NULL,
                size INTEGER NOT NULL,
                duration INTEGER NOT NULL,
                client_ip BLOB NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP))
            ) STRICT;
            ",
        )
        .await?;

        tx.execute(
            r"
            CREATE TABLE IF NOT EXISTS deliveries (
                mirror_id INTEGER NOT NULL,
                debname TEXT NOT NULL,
                size INTEGER NOT NULL,
                duration INTEGER NOT NULL,
                partial INTEGER NOT NULL,
                client_ip BLOB NOT NULL,
                timestamp INTEGER NOT NULL DEFAULT (unixepoch(CURRENT_TIMESTAMP))
            ) STRICT;
            ",
        )
        .await?;

        tx.commit().await
    }

    /// Run all pending `sqlx::migrate!` migrations against the pool.
    async fn run_migrations(&self) -> Result<(), Error> {
        trace!("Performing database migrations...");
        sqlx::migrate!().run(&self.conn).await?;
        Ok(())
    }

    pub(crate) async fn init_tables(&self) -> Result<(), Error> {
        trace!("Initializing database tables...");
        self.create_legacy_tables().await?;
        self.run_migrations().await
    }

    pub(crate) async fn get_mirrors(&self) -> Result<Vec<MirrorEntry>, Error> {
        query_as!(
            MirrorEntry,
            r#"
              SELECT host AS "host: ClientHost", port AS "port: u16", path, kind AS "kind!: i64"
              FROM mirrors_v2;
        "#,
        )
        .fetch_all(&self.conn)
        .await
    }

    /// Returns mirrors whose `last_seen` is within the `active` range from the current time.
    #[cfg(feature = "hyper")]
    pub(crate) async fn get_recent_mirrors(
        &self,
        active: Duration,
    ) -> Result<Vec<MirrorEntry>, Error> {
        let max_age_secs: i64 = active
            .as_secs()
            .try_into()
            .map_err(|err: TryFromIntError| Error::InvalidArgument(err.to_string()))?;

        query_as!(
            MirrorEntry,
            r#"
              SELECT host AS "host: ClientHost", port AS "port: u16", path, kind AS "kind!: i64"
              FROM mirrors_v2
              WHERE last_seen >= unixepoch() - ?;
        "#,
            max_age_secs,
        )
        .fetch_all(&self.conn)
        .await
    }

    /// Return every mirror row whose `path` collides with the host-level
    /// `flat/` anchor used by the new flat-repository layout — i.e. a
    /// structured mirror at `path = 'flat'` or `path` starting with
    /// `'flat/'`.  Used at startup to seed the
    /// [`crate::flat_blocklist`].
    pub(crate) async fn load_flat_collision_mirrors(&self) -> Result<Vec<MirrorEntry>, Error> {
        query_as!(
            MirrorEntry,
            r#"
              SELECT host AS "host: ClientHost", port AS "port: u16", path, kind AS "kind!: i64"
              FROM mirrors_v2
              WHERE kind = 0 AND (path = 'flat' OR path LIKE 'flat/%');
            "#,
        )
        .fetch_all(&self.conn)
        .await
    }

    pub(crate) async fn get_mirrors_with_stats(&self) -> Result<Vec<MirrorStatEntry>, Error> {
        query_as!(MirrorStatEntry,
            r#"
            SELECT
                mirrors_v2.host AS "host: ClientHost",
                mirrors_v2.port AS "port: u16",
                mirrors_v2.path,
                mirrors_v2.first_seen,
                mirrors_v2.last_seen,
                mirrors_v2.last_cleanup,
                COALESCE(downloads.total_size, 0) AS "total_download_size: i64",
                COALESCE(deliveries.total_size, 0) AS "total_delivery_size: i64",
                COALESCE(downloads.cnt, 0) AS "download_count: i64",
                COALESCE(deliveries.cnt, 0) AS "delivery_count: i64"
            FROM mirrors_v2
            LEFT JOIN
                (SELECT mirror_id, SUM(size) AS total_size, COUNT(*) AS cnt FROM downloads GROUP BY mirror_id) AS downloads
            ON mirrors_v2.id = downloads.mirror_id
            LEFT JOIN
                (SELECT mirror_id, SUM(size) AS total_size, COUNT(*) AS cnt FROM deliveries GROUP BY mirror_id) AS deliveries
            ON mirrors_v2.id = deliveries.mirror_id
            ;
        "#).fetch_all(&self.conn).await
    }

    pub(crate) async fn get_origins(&self) -> Result<Vec<OriginEntry>, Error> {
        query_as!(
            OriginEntry,
            r#"
              SELECT
                mirrors_v2.host AS "host: ClientHost",
                mirrors_v2.port AS "port: u16",
                mirrors_v2.path AS mirror_path,
                origins.distribution,
                origins.component,
                origins.architecture,
                origins.last_seen
              FROM origins
              JOIN mirrors_v2 ON mirrors_v2.id = origins.mirror_id;
        "#,
        )
        .fetch_all(&self.conn)
        .await
    }

    pub(crate) async fn get_origins_by_mirror(
        &self,
        host: &ClientHost,
        port: Option<NonZero<u16>>,
        path: &str,
    ) -> Result<Vec<OriginEntry>, Error> {
        let port = port.map_or(0, NonZero::get);

        query_as!(
            OriginEntry,
            r#"
              SELECT
                mirrors_v2.host AS "host: ClientHost",
                mirrors_v2.port AS "port: u16",
                mirrors_v2.path AS mirror_path,
                origins.distribution,
                origins.component,
                origins.architecture,
                origins.last_seen
              FROM origins
              JOIN mirrors_v2 ON mirrors_v2.id = origins.mirror_id
              WHERE mirrors_v2.host = ? AND mirrors_v2.port = ? AND mirrors_v2.path = ?;
        "#,
            host,
            port,
            path
        )
        .fetch_all(&self.conn)
        .await
    }

    /// `true` iff a `mirrors_v2` row exists for the given identity tuple.
    /// Used by `task_cleanup` to gate the flat-cleanup root fallback: a
    /// mint-and-fetch path that would otherwise insert a fresh row on
    /// miss.  Reusing only pre-existing rows keeps the DB free of
    /// cleanup-synthesised mirror entries.
    pub(crate) async fn mirror_exists(
        &self,
        host: &ClientHost,
        port: Option<NonZero<u16>>,
        path: &str,
    ) -> Result<bool, Error> {
        let port = port.map_or(0, NonZero::get);
        let row = query!(
            r#"SELECT id AS "id!: i64" FROM mirrors_v2 WHERE host = ? AND port = ? AND path = ? LIMIT 1;"#,
            host,
            port,
            path
        )
        .fetch_optional(&self.conn)
        .await?;
        Ok(row.is_some())
    }

    pub(crate) async fn mirror_cleanup(&self, mirror: &Mirror) -> Result<(), Error> {
        let host = mirror.host();
        let port = mirror.port().map_or(0, NonZero::get);
        let path = mirror.path();

        query!(
            r"
                UPDATE mirrors_v2
                SET last_cleanup = unixepoch(CURRENT_TIMESTAMP)
                WHERE host = ? AND port = ? AND path = ?;
        ",
            host,
            port,
            path
        )
        .execute(&self.conn)
        .await?;

        Ok(())
    }

    pub(crate) async fn get_clients_with_stats(&self) -> Result<Vec<ClientStatEntry>, Error> {
        struct RawClientStat {
            client_ip: Vec<u8>,
            last_seen: i64,
            total_downloaded: i64,
            total_delivered: i64,
            request_count: i64,
        }

        let rows = query_as!(
            RawClientStat,
            r#"
            SELECT
                client_ip AS "client_ip!: Vec<u8>",
                MAX(last_seen) AS "last_seen!: i64",
                SUM(dl_size) AS "total_downloaded!: i64",
                SUM(del_size) AS "total_delivered!: i64",
                SUM(del_count) AS "request_count!: i64"
            FROM (
                SELECT client_ip, MAX(timestamp) AS last_seen, SUM(size) AS dl_size, 0 AS del_size, 0 AS del_count
                FROM downloads GROUP BY client_ip
                UNION ALL
                SELECT client_ip, MAX(timestamp) AS last_seen, 0 AS dl_size, SUM(size) AS del_size, COUNT(*) AS del_count
                FROM deliveries GROUP BY client_ip
            )
            GROUP BY client_ip;
            "#
        )
        .fetch_all(&self.conn)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let octets: [u8; 16] = match r.client_ip.try_into() {
                    Ok(o) => o,
                    Err(blob) => {
                        // One line per bad row per dashboard render otherwise.
                        warn_once_or_info!(
                            "Dropping clients-stats row with malformed client_ip blob ({} bytes) from the dashboard; restart the daemon to purge it from the database",
                            blob.len()
                        );
                        return None;
                    }
                };
                let ip: Ipv6Addr = octets.into();
                // The cleanup-synthetic sentinel has download rows but never
                // delivery rows, so its entry would render as "0 requests
                // with bytes downloaded". Cleanup is excluded from
                // client-facing metrics; keep the per-client table
                // consistent with that.
                if ip.to_canonical() == CLEANUP_CLIENT_ADDR.ip() {
                    return None;
                }
                Some(ClientStatEntry {
                    client_ip: ip.to_canonical(),
                    last_seen: r.last_seen,
                    total_downloaded: r.total_downloaded,
                    total_delivered: r.total_delivered,
                    request_count: r.request_count,
                })
            })
            .collect())
    }

    /// Bytes downloaded from upstream and delivered to clients over both of
    /// the dashboard's reporting windows.
    ///
    /// One statement rather than two calls of a single-window query: the four
    /// scalar subselects each ride `idx_{downloads,deliveries}_timestamp`, and
    /// issuing them together costs one round trip through the pool instead of
    /// two. Both windows consequently degrade together on error, which is what
    /// the single "N/A" fallback in the Cache Statistics section expects.
    pub(crate) async fn get_bandwidth_windows(
        &self,
        day_epoch: i64,
        week_epoch: i64,
    ) -> Result<BandwidthWindows, Error> {
        struct Row {
            day_downloaded: i64,
            day_delivered: i64,
            week_downloaded: i64,
            week_delivered: i64,
        }

        let row = query_as!(
            Row,
            r#"
            SELECT
                COALESCE((SELECT SUM(size) FROM downloads  WHERE timestamp >= ?1), 0) AS "day_downloaded!: i64",
                COALESCE((SELECT SUM(size) FROM deliveries WHERE timestamp >= ?1), 0) AS "day_delivered!: i64",
                COALESCE((SELECT SUM(size) FROM downloads  WHERE timestamp >= ?2), 0) AS "week_downloaded!: i64",
                COALESCE((SELECT SUM(size) FROM deliveries WHERE timestamp >= ?2), 0) AS "week_delivered!: i64";
            "#,
            day_epoch,
            week_epoch
        )
        .fetch_one(&self.conn)
        .await?;

        Ok(BandwidthWindows {
            day: (row.day_downloaded, row.day_delivered),
            week: (row.week_downloaded, row.week_delivered),
        })
    }

    /// Trivial liveness query backing the `/healthcheck` database check.
    /// Uses the non-macro `query()` so no offline `.sqlx` snapshot is needed.
    pub(crate) async fn ping(&self) -> Result<(), Error> {
        query("SELECT 1;").fetch_one(&self.conn).await?;
        Ok(())
    }

    /// Both Top-Packages rankings from one pass over `deliveries`.
    ///
    /// The two tables the dashboard renders differ only in their ordering, so
    /// this ranks the aggregate both ways with `ROW_NUMBER()` and returns the
    /// union of the two top-`limit` sets -- at most `2 * limit` rows -- rather
    /// than scanning the table twice. The aggregate CTE is referenced exactly
    /// once, so there is no CTE-materialisation question.
    pub(crate) async fn get_top_packages(&self, limit: u32) -> Result<TopPackages, Error> {
        struct RankedPackage {
            debname: String,
            delivery_count: i64,
            total_delivered: i64,
            package_size: i64,
            rank_by_count: i64,
            rank_by_size: i64,
        }

        // Exclude volatile resources (Release/Packages/Translation/...) — their
        // filename does not change, so they would otherwise dominate by count,
        // and their repeated re-delivery would dominate the by-size table too.
        // Permanent .deb packages always end in `.deb`, `.udeb`, or `.ddeb`
        // (see `deb_mirror::VALID_DEB_EXTENSIONS`).
        //
        // `debname` as the secondary sort key is a tie-break the two separate
        // queries never had: without it equal counts order arbitrarily, which
        // is untestable and makes consecutive dashboard loads reshuffle rows.
        let rows = query_as!(
            RankedPackage,
            r#"
            WITH agg AS (
                SELECT
                    debname,
                    COUNT(*) AS delivery_count,
                    SUM(size) AS total_delivered,
                    MAX(size) AS package_size
                FROM deliveries
                WHERE debname LIKE '%.deb'
                   OR debname LIKE '%.udeb'
                   OR debname LIKE '%.ddeb'
                GROUP BY debname
            ),
            ranked AS (
                SELECT
                    debname,
                    delivery_count,
                    total_delivered,
                    package_size,
                    ROW_NUMBER() OVER (ORDER BY delivery_count DESC, debname ASC) AS rank_by_count,
                    ROW_NUMBER() OVER (ORDER BY total_delivered DESC, debname ASC) AS rank_by_size
                FROM agg
            )
            SELECT
                debname AS "debname!: String",
                delivery_count AS "delivery_count!: i64",
                total_delivered AS "total_delivered!: i64",
                package_size AS "package_size!: i64",
                rank_by_count AS "rank_by_count!: i64",
                rank_by_size AS "rank_by_size!: i64"
            FROM ranked
            WHERE rank_by_count <= ?1 OR rank_by_size <= ?1
            ORDER BY rank_by_count;
            "#,
            limit
        )
        .fetch_all(&self.conn)
        .await?;

        let capacity = usize::try_from(limit).unwrap_or(usize::MAX);
        let limit = i64::from(limit);
        let mut by_count = Vec::with_capacity(rows.len().min(capacity));
        // (rank, entry) so the by-size ranking can be restored without
        // re-deriving it from the totals — the tie-break lives in SQL.
        let mut by_size: Vec<(i64, TopPackageEntry)> = Vec::new();
        for row in rows {
            let entry = || TopPackageEntry {
                debname: row.debname.clone(),
                delivery_count: row.delivery_count,
                total_delivered: row.total_delivered,
                package_size: row.package_size,
            };
            if row.rank_by_size <= limit {
                by_size.push((row.rank_by_size, entry()));
            }
            if row.rank_by_count <= limit {
                by_count.push(entry());
            }
        }
        // `ORDER BY rank_by_count` already ordered `by_count`; `by_size` holds
        // at most `limit` elements, so this sort is on 5 items by default.
        by_size.sort_unstable_by_key(|&(rank, _)| rank);

        Ok(TopPackages {
            by_count,
            by_size: by_size.into_iter().map(|(_rank, entry)| entry).collect(),
        })
    }

    /// Hydrate the in-memory mirror-id cache at startup.
    ///
    /// Returns one entry per row in `mirrors_v2`. Used by the batched
    /// `db_loop` so subsequent delivery/download/origin events resolve the
    /// `mirror_id` from memory instead of upserting on every event.
    pub(crate) async fn load_all_mirror_ids(&self) -> Result<Vec<(i64, Mirror)>, Error> {
        struct Row {
            id: i64,
            host: String,
            port: u16,
            path: String,
            kind: i64,
        }

        let rows = query_as!(
            Row,
            r#"
              SELECT id AS "id!: i64", host, port AS "port!: u16", path, kind AS "kind!: i64"
              FROM mirrors_v2;
            "#,
        )
        .fetch_all(&self.conn)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                // Reconstruct DomainName via its parser so an Ipv4/Ipv6 row
                // round-trips to the right enum variant. cleanup_invalid_rows
                // ran at startup and rejects exactly the same hosts (via
                // DomainName::new) plus any out-of-range kind values, so a
                // hit on either guard below would mean on-disk corruption
                // that bypassed cleanup.
                let row_id = r.id;
                let host = match DomainName::new(r.host) {
                    Ok(h) => h,
                    Err(invalid) => {
                        warn_once_or_info!(
                            "Dropping mirror row id={row_id} with invalid host `{}` while hydrating the mirror-id cache",
                            invalid.escape_debug()
                        );
                        return None;
                    }
                };
                let Some(kind) = MirrorKind::from_db_int(r.kind) else {
                    warn_once_or_info!(
                        "Dropping mirror row id={row_id} with out-of-range kind value {} while hydrating the mirror-id cache",
                        r.kind
                    );
                    return None;
                };
                Some((
                    row_id,
                    Mirror::new(ClientHost::from(host), NonZero::new(r.port), r.path, kind),
                ))
            })
            .collect())
    }

    /// Pool-based variant of the private `upsert_mirror_get_id`. Issued on a
    /// mirror-id cache miss in the batched `db_loop`. Returns the row `id`
    /// and `was_inserted = true` when the mirror was inserted for the first
    /// time (no prior row in `mirrors_v2`; same-second caveat on
    /// `upsert_mirror_get_id` applies).
    pub(crate) async fn upsert_mirror_id(&self, mirror: &Mirror) -> Result<(i64, bool), Error> {
        let mut tx = self.conn.begin().await?;
        let result = upsert_mirror_get_id(&mut tx, mirror).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Bulk-update `mirrors_v2.last_seen` for a set of (id, `last_seen`) pairs.
    ///
    /// Issues one UPDATE per chunk: a CTE injects all pairs as a single
    /// `VALUES` clause, then the UPDATE joins on it and uses `MAX(existing, new)`
    /// so flushes are idempotent even if a stale timestamp arrives after a
    /// fresh one. Chunked by [`SQLITE_MAX_BIND_PARAMETERS`]; all chunks share
    /// one transaction. Returns the total rows affected.
    pub(crate) async fn batch_update_mirror_last_seen(
        &self,
        pairs: &[(i64, i64)],
    ) -> Result<u64, Error> {
        const BINDS_PER_ROW: usize = 2;
        const CHUNK_SIZE: usize = SQLITE_MAX_BIND_PARAMETERS / BINDS_PER_ROW;

        if pairs.is_empty() {
            return Ok(0);
        }

        let mut tx = self.conn.begin().await?;
        let mut affected = 0u64;
        for chunk in pairs.chunks(CHUNK_SIZE) {
            let mut qb: sqlx::QueryBuilder<Sqlite> =
                sqlx::QueryBuilder::new("WITH new_seen(id, ts) AS (");
            qb.push_values(chunk, |mut b, &(id, ts)| {
                b.push_bind(id).push_bind(ts);
            });
            qb.push(
                ") UPDATE mirrors_v2 \
                  SET last_seen = MAX(last_seen, \
                      (SELECT ts FROM new_seen WHERE new_seen.id = mirrors_v2.id)) \
                  WHERE id IN (SELECT id FROM new_seen)",
            );
            let res = qb.build().execute(&mut *tx).await?;
            affected = affected.saturating_add(res.rows_affected());
        }
        tx.commit().await?;
        Ok(affected)
    }

    /// Insert a batch of delivery rows in a single transaction.
    ///
    /// Chunks the input so no single statement exceeds
    /// [`SQLITE_MAX_BIND_PARAMETERS`]. All chunks share one transaction so the
    /// flush remains atomic from the caller's perspective.
    pub(crate) async fn batch_insert_deliveries(&self, rows: &[DeliveryRow]) -> Result<(), Error> {
        const BINDS_PER_ROW: usize = 6;
        const CHUNK_SIZE: usize = SQLITE_MAX_BIND_PARAMETERS / BINDS_PER_ROW;

        if rows.is_empty() {
            return Ok(());
        }

        let mut tx = self.conn.begin().await?;
        for chunk in rows.chunks(CHUNK_SIZE) {
            let mut qb: sqlx::QueryBuilder<Sqlite> = sqlx::QueryBuilder::new(
                "INSERT INTO deliveries (mirror_id, debname, size, duration, partial, client_ip) ",
            );
            qb.push_values(chunk, |mut b, row| {
                b.push_bind(row.mirror_id)
                    .push_bind(&row.debname)
                    .push_bind(row.size)
                    .push_bind(row.duration)
                    .push_bind(row.partial)
                    .push_bind(&row.client_ip[..]);
            });
            qb.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Insert a batch of download rows in a single transaction.
    ///
    /// Chunks the input so no single statement exceeds
    /// [`SQLITE_MAX_BIND_PARAMETERS`]. All chunks share one transaction so the
    /// flush remains atomic from the caller's perspective.
    pub(crate) async fn batch_insert_downloads(&self, rows: &[DownloadRow]) -> Result<(), Error> {
        const BINDS_PER_ROW: usize = 5;
        const CHUNK_SIZE: usize = SQLITE_MAX_BIND_PARAMETERS / BINDS_PER_ROW;

        if rows.is_empty() {
            return Ok(());
        }

        let mut tx = self.conn.begin().await?;
        for chunk in rows.chunks(CHUNK_SIZE) {
            let mut qb: sqlx::QueryBuilder<Sqlite> = sqlx::QueryBuilder::new(
                "INSERT INTO downloads (mirror_id, debname, size, duration, client_ip) ",
            );
            qb.push_values(chunk, |mut b, row| {
                b.push_bind(row.mirror_id)
                    .push_bind(&row.debname)
                    .push_bind(row.size)
                    .push_bind(row.duration)
                    .push_bind(&row.client_ip[..]);
            });
            qb.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// UPSERT a batch of origin rows in a single transaction. The per-row
    /// `ON CONFLICT DO UPDATE last_seen` clause prevents a true multi-row
    /// VALUES form, but transaction grouping still amortises the commit.
    pub(crate) async fn batch_upsert_origins(&self, rows: &[OriginRow]) -> Result<(), Error> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut tx = self.conn.begin().await?;
        for row in rows {
            query!(
                r"
                    INSERT INTO origins
                    (mirror_id, distribution, component, architecture)
                    VALUES
                    (?, ?, ?, ?)
                    ON CONFLICT (mirror_id, distribution, component, architecture)
                    DO UPDATE SET last_seen = unixepoch(CURRENT_TIMESTAMP);
                ",
                row.mirror_id,
                row.distribution,
                row.component,
                row.architecture,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Repair usage rows an older version or a manual edit could have left
    /// with a `client_ip` that is not a 16-byte encoded address.
    ///
    /// Startup only. The daemon has never written such a row, and the DELETE
    /// holds the write lock for a full scan of both usage tables — during
    /// which the batch flusher stalls and the request path can block in
    /// `send_db_command`. Paying that once at startup is a repair; paying it
    /// daily is a tax on a condition that cannot arise.
    pub(crate) async fn cleanup_invalid_usage_rows(&self) -> Result<(), Error> {
        let downloads_deleted = query!(r"DELETE FROM downloads WHERE length(client_ip) != 16;")
            .execute(&self.conn)
            .await?;

        if downloads_deleted.rows_affected() > 0 {
            warn!(
                "Removed {} download rows with invalid client_ip",
                downloads_deleted.rows_affected()
            );
        }

        let deliveries_deleted = query!(r"DELETE FROM deliveries WHERE length(client_ip) != 16;")
            .execute(&self.conn)
            .await?;

        if deliveries_deleted.rows_affected() > 0 {
            warn!(
                "Removed {} delivery rows with invalid client_ip",
                deliveries_deleted.rows_affected()
            );
        }

        Ok(())
    }

    /// Remove mirrors whose `host` no longer parses through
    /// `DomainName::new` or whose `kind` is outside the [`MirrorKind`]
    /// invariant.  Cascade to origins/downloads/deliveries.
    ///
    /// The host check uses `DomainName::new` (not `is_valid_config_domain`) so
    /// the row set this function purges is exactly the set of rows
    /// downstream code — notably `flat_blocklist::init` — relies on
    /// being absent.  Any future tightening of `DomainName::new` then
    /// automatically also tightens cleanup, instead of opening a
    /// panic gap between the two validators.
    ///
    /// Runs at startup and on every cleanup cycle: unlike the usage-row
    /// scrub, `mirrors_v2` is bounded by the mirror count, so the scan stays
    /// cheap, and `flat_blocklist::init` needs the invariant it guarantees
    /// to hold continuously, not just after a restart.
    pub(crate) async fn cleanup_invalid_rows(&self) -> Result<(), Error> {
        {
            struct MirrorRow {
                id: i64,
                host: String,
                kind: i64,
            }

            let mut tx = self.conn.begin().await?;

            let mirrors = query_as!(
                MirrorRow,
                r#"SELECT id AS "id!: i64", host, kind AS "kind!: i64" FROM mirrors_v2;"#
            )
            .fetch_all(&mut *tx)
            .await?;

            for mirror in mirrors {
                let bad_host = DomainName::new(mirror.host.clone()).is_err();
                let bad_kind = MirrorKind::from_db_int(mirror.kind).is_none();

                if !bad_host && !bad_kind {
                    continue;
                }

                if bad_host {
                    warn!(
                        "Removing mirror id={} with invalid host `{}`",
                        mirror.id,
                        mirror.host.escape_debug()
                    );
                }
                if bad_kind {
                    warn!(
                        "Removing mirror id={} (host `{}`) with out-of-range kind={}",
                        mirror.id,
                        mirror.host.escape_debug(),
                        mirror.kind
                    );
                }

                query!(r"DELETE FROM origins WHERE mirror_id = ?;", mirror.id)
                    .execute(&mut *tx)
                    .await?;
                query!(r"DELETE FROM downloads WHERE mirror_id = ?;", mirror.id)
                    .execute(&mut *tx)
                    .await?;
                query!(r"DELETE FROM deliveries WHERE mirror_id = ?;", mirror.id)
                    .execute(&mut *tx)
                    .await?;
                query!(r"DELETE FROM mirrors_v2 WHERE id = ?;", mirror.id)
                    .execute(&mut *tx)
                    .await?;
            }

            tx.commit().await?;
        }

        Ok(())
    }

    /// Fold mirror rows written under a configured alias host into the row of
    /// the alias' main host: origins, downloads and deliveries are re-pointed
    /// (an origin the main row already has is dropped), and an alias row with
    /// no main counterpart is simply renamed.  Rows are canonical from
    /// `decide_request` on; this runs at startup for rows an earlier version
    /// wrote, and after an alias is added to the configuration.  Without it
    /// two rows would each reconcile the one shared tree against only their
    /// own indices and grace-sweep each other's debs.  Returns the number of
    /// rows folded or renamed.
    pub(crate) async fn merge_alias_rows(&self, aliases: &[Alias]) -> Result<usize, Error> {
        let mut merged = 0usize;
        let mut tx = self.conn.begin().await?;

        for group in aliases {
            let main_host = group.main.to_client_host();
            for alias in &group.aliases {
                let alias_rows = query!(
                    r"SELECT id, port, path FROM mirrors_v2 WHERE host = ?;",
                    alias
                )
                .fetch_all(&mut *tx)
                .await?;
                for alias_row in alias_rows {
                    let main_row = query!(
                        r"SELECT id FROM mirrors_v2 WHERE host = ? AND port = ? AND path = ?;",
                        main_host,
                        alias_row.port,
                        alias_row.path
                    )
                    .fetch_optional(&mut *tx)
                    .await?;
                    match main_row {
                        None => {
                            query!(
                                r"UPDATE mirrors_v2 SET host = ? WHERE id = ?;",
                                main_host,
                                alias_row.id
                            )
                            .execute(&mut *tx)
                            .await?;
                            info!(
                                "Renamed mirror row {alias}/{} to alias main host {main_host}",
                                alias_row.path
                            );
                        }
                        Some(main_row) => {
                            query!(
                                r"UPDATE OR IGNORE origins SET mirror_id = ? WHERE mirror_id = ?;",
                                main_row.id,
                                alias_row.id
                            )
                            .execute(&mut *tx)
                            .await?;
                            query!(r"DELETE FROM origins WHERE mirror_id = ?;", alias_row.id)
                                .execute(&mut *tx)
                                .await?;
                            query!(
                                r"UPDATE downloads SET mirror_id = ? WHERE mirror_id = ?;",
                                main_row.id,
                                alias_row.id
                            )
                            .execute(&mut *tx)
                            .await?;
                            query!(
                                r"UPDATE deliveries SET mirror_id = ? WHERE mirror_id = ?;",
                                main_row.id,
                                alias_row.id
                            )
                            .execute(&mut *tx)
                            .await?;
                            query!(r"DELETE FROM mirrors_v2 WHERE id = ?;", alias_row.id)
                                .execute(&mut *tx)
                                .await?;
                            info!(
                                "Merged mirror row {alias}/{} into alias main host {main_host}",
                                alias_row.path
                            );
                        }
                    }
                    merged += 1;
                }
            }
        }

        tx.commit().await?;
        Ok(merged)
    }

    /// Drop `origins` rows last seen before `cutoff` (seconds since the
    /// epoch): an origin no client asked for within the retention window
    /// would otherwise cost a `Packages` fetch cascade on every cleanup run
    /// and a dashboard row forever.
    pub(crate) async fn delete_stale_origins(&self, cutoff: Duration) -> Result<u64, Error> {
        let cutoff_epoch = i64::try_from(cutoff.as_secs())
            .map_err(|err: TryFromIntError| Error::InvalidArgument(err.to_string()))?;

        let result = query!(r"DELETE FROM origins WHERE last_seen < ?;", cutoff_epoch)
            .execute(&self.conn)
            .await?;

        Ok(result.rows_affected())
    }

    /// Mirror rows no `origins` row references any more.  Cleanup drops the
    /// ones whose cache tree is gone as well (see
    /// [`Self::delete_mirrors`]); the row id travels along for that.
    pub(crate) async fn get_mirrors_without_origins(&self) -> Result<Vec<OrphanMirror>, Error> {
        struct Row {
            id: i64,
            host: ClientHost,
            port: u16,
            path: String,
            kind: i64,
        }

        let rows = query_as!(
            Row,
            r#"
              SELECT id, host AS "host: ClientHost", port AS "port: u16", path, kind AS "kind!: i64"
              FROM mirrors_v2
              WHERE NOT EXISTS (SELECT 1 FROM origins WHERE origins.mirror_id = mirrors_v2.id);
            "#,
        )
        .fetch_all(&self.conn)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| OrphanMirror {
                id: row.id,
                entry: MirrorEntry {
                    host: row.host,
                    port: row.port,
                    path: row.path,
                    kind: row.kind,
                },
            })
            .collect())
    }

    /// Delete mirror rows by id together with every row referencing them.
    pub(crate) async fn delete_mirrors(&self, ids: &[i64]) -> Result<(), Error> {
        let mut tx = self.conn.begin().await?;

        for id in ids {
            query!(r"DELETE FROM origins WHERE mirror_id = ?;", id)
                .execute(&mut *tx)
                .await?;
            query!(r"DELETE FROM downloads WHERE mirror_id = ?;", id)
                .execute(&mut *tx)
                .await?;
            query!(r"DELETE FROM deliveries WHERE mirror_id = ?;", id)
                .execute(&mut *tx)
                .await?;
            query!(r"DELETE FROM mirrors_v2 WHERE id = ?;", id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;

        Ok(())
    }

    pub(crate) async fn delete_usage_logs(&self, keep_date: Duration) -> Result<(), Error> {
        let keep_epoch = i64::try_from(keep_date.as_secs())
            .map_err(|err: TryFromIntError| Error::InvalidArgument(err.to_string()))?;

        let mut tx = self.conn.begin().await?;

        query!(
            r"
                DELETE FROM downloads
                WHERE timestamp < ?;
            ",
            keep_epoch
        )
        .execute(&mut *tx)
        .await?;

        query!(
            r"
                DELETE FROM deliveries
                WHERE timestamp < ?;
            ",
            keep_epoch
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    async fn temp_db() -> (tempfile::TempDir, Database) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = Database::connect(&dir.path().join("t.db"), Duration::from_secs(5))
            .await
            .expect("connect");
        db.init_tables().await.expect("schema");
        (dir, db)
    }

    async fn count(db: &Database) -> i64 {
        let row = query("SELECT COUNT(*) FROM downloads")
            .fetch_one(&db.conn)
            .await
            .expect("count");
        sqlx::Row::get(&row, 0)
    }

    /// Insert a mirror row directly: `upsert_mirror_id` resolves aliases
    /// through `global_config()`, which no unit test can initialise.
    async fn insert_mirror(db: &Database, path: &str) -> i64 {
        let row = query(
            "INSERT INTO mirrors_v2 (host, port, path, kind) VALUES ('deb.example.org', 0, ?, 0) RETURNING id",
        )
        .bind(path)
        .fetch_one(&db.conn)
        .await
        .expect("insert mirror");
        sqlx::Row::get(&row, 0)
    }

    #[tokio::test]
    async fn delete_stale_origins_keeps_recent_rows() {
        let (_dir, db) = temp_db().await;
        let fresh_id = insert_mirror(&db, "fresh").await;
        let stale_id = insert_mirror(&db, "stale").await;
        let row = |mirror_id| OriginRow {
            mirror_id,
            distribution: "sid".to_owned(),
            component: "main".to_owned(),
            architecture: "amd64".to_owned(),
        };
        db.batch_upsert_origins(&[row(fresh_id), row(stale_id)])
            .await
            .expect("upsert origins");
        query("UPDATE origins SET last_seen = 1000 WHERE mirror_id = ?")
            .bind(stale_id)
            .execute(&db.conn)
            .await
            .expect("backdate");

        db.delete_stale_origins(Duration::from_secs(2000))
            .await
            .expect("delete stale");

        let left = db.get_origins().await.expect("get origins");
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].mirror_path, "fresh");
    }

    async fn insert_mirror_host(db: &Database, host: &str, path: &str) -> i64 {
        let row = query(
            "INSERT INTO mirrors_v2 (host, port, path, kind) VALUES (?, 0, ?, 0) RETURNING id",
        )
        .bind(host)
        .bind(path)
        .fetch_one(&db.conn)
        .await
        .expect("insert mirror");
        sqlx::Row::get(&row, 0)
    }

    fn origin(mirror_id: i64, distribution: &str) -> OriginRow {
        OriginRow {
            mirror_id,
            distribution: distribution.to_owned(),
            component: "main".to_owned(),
            architecture: "amd64".to_owned(),
        }
    }

    #[tokio::test]
    async fn merge_alias_rows_folds_alias_rows_into_the_main_row() {
        use crate::config::Alias;
        let (_dir, db) = temp_db().await;
        let main_id = insert_mirror_host(&db, "deb.example.org", "debian").await;
        let alias_id = insert_mirror_host(&db, "ftp.example.org", "debian").await;
        // An alias row with no main counterpart is renamed, not merged.
        let lone_alias_id = insert_mirror_host(&db, "ftp.example.org", "ubuntu").await;
        db.batch_upsert_origins(&[
            origin(main_id, "sid"),
            origin(alias_id, "sid"),
            origin(alias_id, "bookworm"),
            origin(lone_alias_id, "noble"),
        ])
        .await
        .expect("upsert origins");

        let aliases = [Alias {
            main: ClientHost::new("deb.example.org".to_owned())
                .expect("host")
                .into_cache_host(),
            aliases: vec![ClientHost::new("ftp.example.org".to_owned()).expect("host")],
        }];
        let merged = db.merge_alias_rows(&aliases).await.expect("merge");
        assert_eq!(merged, 2);

        let mut mirrors: Vec<(String, String)> = db
            .get_mirrors()
            .await
            .expect("mirrors")
            .into_iter()
            .map(|m| (m.host.to_string(), m.path))
            .collect();
        mirrors.sort();
        assert_eq!(
            mirrors,
            vec![
                ("deb.example.org".to_owned(), "debian".to_owned()),
                ("deb.example.org".to_owned(), "ubuntu".to_owned()),
            ]
        );
        let mut dists: Vec<(String, String)> = db
            .get_origins()
            .await
            .expect("origins")
            .into_iter()
            .map(|o| (o.mirror_path, o.distribution))
            .collect();
        dists.sort();
        assert_eq!(
            dists,
            vec![
                ("debian".to_owned(), "bookworm".to_owned()),
                ("debian".to_owned(), "sid".to_owned()),
                ("ubuntu".to_owned(), "noble".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn mirrors_without_origins_lists_only_orphans() {
        let (_dir, db) = temp_db().await;
        let with_id = insert_mirror(&db, "with").await;
        let without_id = insert_mirror(&db, "without").await;
        db.batch_upsert_origins(&[OriginRow {
            mirror_id: with_id,
            distribution: "sid".to_owned(),
            component: "main".to_owned(),
            architecture: "amd64".to_owned(),
        }])
        .await
        .expect("upsert origins");

        let orphans = db.get_mirrors_without_origins().await.expect("query");
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].id, without_id);
        assert_eq!(orphans[0].entry.path, "without");

        db.delete_mirrors(&[without_id]).await.expect("delete");
        assert!(
            db.get_mirrors_without_origins()
                .await
                .expect("query")
                .is_empty()
        );
        assert_eq!(db.get_mirrors().await.expect("mirrors").len(), 1);
    }

    #[tokio::test]
    async fn usage_row_scrub_is_startup_only() {
        let (_dir, db) = temp_db().await;
        let mirror_id = insert_mirror(&db, "scrub").await;

        // A row an older version could have written: client_ip is not 16 bytes.
        query(
            "INSERT INTO downloads (mirror_id, debname, size, duration, client_ip, timestamp) \
             VALUES (?, 'a.deb', 1, 1, ?, 1)",
        )
        .bind(mirror_id)
        .bind(vec![0u8; 4])
        .execute(&db.conn)
        .await
        .expect("insert short client_ip");

        // The periodic path must not scan the usage tables.
        db.cleanup_invalid_rows().await.expect("periodic cleanup");
        assert_eq!(
            count(&db).await,
            1,
            "the daily cycle must not scan the usage tables"
        );

        // The startup path still repairs it.
        db.cleanup_invalid_usage_rows()
            .await
            .expect("startup scrub");
        assert_eq!(count(&db).await, 0, "startup must still repair legacy rows");
    }

    /// Insert a `deliveries` row for the dashboard aggregate tests.
    async fn insert_delivery(db: &Database, mirror_id: i64, debname: &str, size: i64, ts: i64) {
        query(
            "INSERT INTO deliveries (mirror_id, debname, size, duration, partial, client_ip, timestamp) \
             VALUES (?, ?, ?, 1, 0, X'00000000000000000000ffff7f000001', ?)",
        )
        .bind(mirror_id)
        .bind(debname)
        .bind(size)
        .bind(ts)
        .execute(&db.conn)
        .await
        .expect("insert delivery");
    }

    async fn insert_download(db: &Database, mirror_id: i64, debname: &str, size: i64, ts: i64) {
        query(
            "INSERT INTO downloads (mirror_id, debname, size, duration, client_ip, timestamp) \
             VALUES (?, ?, ?, 1, X'00000000000000000000ffff7f000001', ?)",
        )
        .bind(mirror_id)
        .bind(debname)
        .bind(size)
        .bind(ts)
        .execute(&db.conn)
        .await
        .expect("insert download");
    }

    fn names(entries: &[TopPackageEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.debname.as_str()).collect()
    }

    /// The two rankings come from one pass, so they must still disagree where
    /// the old pair of queries disagreed: `many.deb` wins by count, `big.deb`
    /// by bytes.
    #[tokio::test]
    async fn top_packages_ranks_by_count_and_by_size_independently() {
        let (_dir, db) = temp_db().await;
        let mirror = insert_mirror(&db, "debian").await;

        for _ in 0..5 {
            insert_delivery(&db, mirror, "many.deb", 10, 1_000).await;
        }
        insert_delivery(&db, mirror, "big.deb", 5_000, 1_000).await;
        insert_delivery(&db, mirror, "mid.udeb", 100, 1_000).await;
        insert_delivery(&db, mirror, "mid.udeb", 100, 1_000).await;

        let top = db.get_top_packages(3).await.expect("top packages");

        assert_eq!(names(&top.by_count), ["many.deb", "mid.udeb", "big.deb"]);
        assert_eq!(names(&top.by_size), ["big.deb", "mid.udeb", "many.deb"]);

        let many = &top.by_count[0];
        assert_eq!(many.delivery_count, 5);
        assert_eq!(many.total_delivered, 50);
        assert_eq!(many.package_size, 10, "package_size is MAX(size), one copy");
    }

    /// Volatile index files are re-delivered constantly and would dominate
    /// both rankings; only `.deb`/`.udeb`/`.ddeb` may appear.
    #[tokio::test]
    async fn top_packages_excludes_non_package_deliveries() {
        let (_dir, db) = temp_db().await;
        let mirror = insert_mirror(&db, "debian").await;

        for _ in 0..20 {
            insert_delivery(&db, mirror, "Packages.xz", 9_999, 1_000).await;
        }
        insert_delivery(&db, mirror, "only.ddeb", 1, 1_000).await;

        let top = db.get_top_packages(5).await.expect("top packages");

        assert_eq!(names(&top.by_count), ["only.ddeb"]);
        assert_eq!(names(&top.by_size), ["only.ddeb"]);
    }

    /// Equal counts used to order arbitrarily; the SQL tie-break makes the
    /// order deterministic, which is what keeps the dashboard from
    /// reshuffling rows between loads.
    #[tokio::test]
    async fn top_packages_breaks_ties_by_name() {
        let (_dir, db) = temp_db().await;
        let mirror = insert_mirror(&db, "debian").await;

        for name in ["c.deb", "a.deb", "b.deb"] {
            insert_delivery(&db, mirror, name, 100, 1_000).await;
        }

        let top = db.get_top_packages(2).await.expect("top packages");

        assert_eq!(names(&top.by_count), ["a.deb", "b.deb"]);
        assert_eq!(names(&top.by_size), ["a.deb", "b.deb"]);
    }

    /// Both windows come from one statement now; each must still filter on
    /// its own cutoff.
    #[tokio::test]
    async fn bandwidth_windows_filter_each_cutoff_separately() {
        let (_dir, db) = temp_db().await;
        let mirror = insert_mirror(&db, "debian").await;

        // Timestamps: 100 is inside both windows, 50 only inside the week
        // window, 10 outside both.
        insert_download(&db, mirror, "a.deb", 1, 100).await;
        insert_download(&db, mirror, "b.deb", 2, 50).await;
        insert_download(&db, mirror, "c.deb", 4, 10).await;
        insert_delivery(&db, mirror, "a.deb", 8, 100).await;
        insert_delivery(&db, mirror, "b.deb", 16, 50).await;
        insert_delivery(&db, mirror, "c.deb", 32, 10).await;

        let windows = db
            .get_bandwidth_windows(100, 50)
            .await
            .expect("bandwidth windows");

        assert_eq!(windows.day, (1, 8), "day window covers timestamp >= 100");
        assert_eq!(
            windows.week,
            (1 + 2, 8 + 16),
            "week window covers timestamp >= 50"
        );
    }

    /// An empty database must report zeroes, not an error or a missing row.
    #[tokio::test]
    async fn bandwidth_windows_report_zero_on_an_empty_database() {
        let (_dir, db) = temp_db().await;

        let windows = db.get_bandwidth_windows(0, 0).await.expect("bandwidth");

        assert_eq!(windows.day, (0, 0));
        assert_eq!(windows.week, (0, 0));
    }
}
