//! The dashboard's row tables (Mirrors, Origins, Clients, Top Packages,
//! Uncacheables), each returned as a [`Section`], plus the cached per-mirror
//! directory walk that feeds the Mirrors table.

use std::{
    cmp::Reverse,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::SystemTime,
};

use coarsetime::Instant;
use hashbrown::HashMap;
use tracing::error;

use crate::{
    cache_paths::{CachePaths, SUBDIR_FLAT_BYHASH},
    cache_walk::{DirFailure, EntryKind, OnMissing, WalkContext, Walker},
    database::{Database, MirrorStatEntry},
    deb_mirror::is_deb_package,
    error::ErrorReport,
    humanfmt::HumanFmt,
    metrics,
    uncacheables::get_uncacheables,
};

use super::{
    fmt::{FmtLastSeenHealth, FmtTimestamp, Freshness, HtmlEscape, HtmlEscaped, as_size},
    table::{Table, tr, write_section_error},
};

/// A rendered dashboard table together with its row count, which the page
/// shows next to the section heading and uses to decide whether the
/// section starts expanded.
pub(super) struct Section {
    pub(super) html: String,
    pub(super) rows: usize,
}

impl Section {
    /// No rows: the section renders collapsed with an empty body.
    pub(super) const EMPTY: Self = Self {
        html: String::new(),
        rows: 0,
    };
}

// Per-mirror directory scan
// ---------------------------------------------------------------------------

/// TTL for cached per-mirror directory-scan results.
const DIR_STATS_TTL_SECS: u64 = 60;

/// Maximum number of mirror directory walks running concurrently when the
/// `DIR_STATS_CACHE` is cold. Bounds disk fan-out and FD usage.
const DIR_SCAN_CONCURRENCY: usize = 8;

#[derive(Clone, Copy, Default)]
pub(super) struct DirStats {
    pub(super) files: usize,
    pub(super) size: u64,
    pub(super) byhash_files: usize,
    /// Files whose extension is `.deb`. Disjoint from `metadata_files`,
    /// orthogonal to `byhash_files`.
    pub(super) deb_files: usize,
    /// Files whose extension is anything other than `.deb` — Packages,
    /// Release, by-hash entries, etc. Disjoint from `deb_files`. Together
    /// they sum to `files`.
    pub(super) metadata_files: usize,
    pub(super) max_file_size: u64,
    pub(super) oldest_mtime: Option<SystemTime>,
    pub(super) newest_mtime: Option<SystemTime>,
}

impl DirStats {
    fn merge(&mut self, other: Self) {
        let Self {
            files,
            size,
            byhash_files,
            deb_files,
            metadata_files,
            max_file_size,
            oldest_mtime,
            newest_mtime,
        } = other;

        self.files += files;
        self.size += size;
        self.byhash_files += byhash_files;
        self.deb_files += deb_files;
        self.metadata_files += metadata_files;
        self.max_file_size = self.max_file_size.max(max_file_size);
        self.oldest_mtime = merge_min(self.oldest_mtime, oldest_mtime);
        self.newest_mtime = merge_max(self.newest_mtime, newest_mtime);
    }
}

fn merge_min(a: Option<SystemTime>, b: Option<SystemTime>) -> Option<SystemTime> {
    a.into_iter().chain(b).min()
}

fn merge_max(a: Option<SystemTime>, b: Option<SystemTime>) -> Option<SystemTime> {
    a.into_iter().chain(b).max()
}

type DirStatsCache = parking_lot::Mutex<HashMap<PathBuf, (Instant, DirStats)>>;

static DIR_STATS_CACHE: LazyLock<DirStatsCache> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

async fn cached_mirror_directory_size(path: &Path) -> DirStats {
    // Bind the lookup to a local so the `MutexGuard` drops at this `;`,
    // before any `.await` below — `parking_lot::Mutex` held across an
    // await is a deadlock waiting for someone to extend the body.
    let cached = DIR_STATS_CACHE.lock().get(path).copied();
    if let Some((ts, stats)) = cached
        && ts.elapsed().as_secs() < DIR_STATS_TTL_SECS
    {
        return stats;
    }
    let stats = mirror_directory_size(path).await;
    DIR_STATS_CACHE
        .lock()
        .insert(path.to_path_buf(), (Instant::now(), stats));
    stats
}

static DASHBOARD_WALK: WalkContext = WalkContext {
    what: "a mirror directory",
    dir_failure: DirFailure::Continue("excluding its unread entries from the reported cache size"),
    entry_failure: "excluding it from the reported cache size",
    non_regular: "excluding it from the reported cache size",
};

/// Tally every regular file below `path` for the dashboard's Mirrors table.
///
/// Unlike the startup scan this walk knows nothing about the layout: every
/// directory is descended into (`tmp/` and nested mirrors included), and
/// every regular file counts.  The walker's tag remembers whether the
/// directory sits under a `by-hash/` subtree.  Anomalies (a symlink, a stat
/// failure, an unreadable subdirectory) are logged and counted by the walker
/// like everywhere else and the walk carries on, so one bad entry no longer
/// drops the whole mirror from the table.
async fn mirror_directory_size(path: &Path) -> DirStats {
    let mut stats = DirStats::default();
    let mut walker = Walker::new(path, &DASHBOARD_WALK, OnMissing::Tolerate, false);

    while let Some(mut entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => {}
            EntryKind::File => {
                let Some(mdata) = entry.metadata().await else {
                    continue;
                };
                let len = mdata.len();
                stats.size += len;
                stats.files += 1;
                stats.max_file_size = stats.max_file_size.max(len);
                if entry.tag() {
                    stats.byhash_files += 1;
                }
                if entry.name().to_str().is_some_and(is_deb_package) {
                    stats.deb_files += 1;
                } else {
                    stats.metadata_files += 1;
                }
                if let Ok(mtime) = mdata.modified() {
                    stats.oldest_mtime = merge_min(stats.oldest_mtime, Some(mtime));
                    stats.newest_mtime = merge_max(stats.newest_mtime, Some(mtime));
                }
            }
            EntryKind::Dir => {
                let in_byhash = entry.tag() || entry.name() == SUBDIR_FLAT_BYHASH;
                entry.descend(in_byhash);
            }
        }
    }

    stats
}

// ---------------------------------------------------------------------------
// Table builders
// ---------------------------------------------------------------------------

/// `Display` wrappers used exclusively by the Mirrors table. Pulled out of
/// `build_mirror_table` so the function body stays focused on data flow rather
/// than on per-cell rendering details.
mod mirror_cells {
    use std::fmt::{self, Display, Formatter};

    use crate::humanfmt::HumanFmt;

    use super::super::fmt::Meter;

    pub(super) struct DirSizeCell {
        pub size: u64,
        pub total: u64,
    }
    impl Display for DirSizeCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            Display::fmt(&HumanFmt::Size(self.size), f)?;
            if self.total > 0 {
                #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
                let pct = self.size as f64 / self.total as f64 * 100.0;
                write!(f, " ({pct:.1}%)")?;
                Display::fmt(
                    &Meter {
                        value: self.size,
                        max: self.total,
                    },
                    f,
                )?;
            }
            Ok(())
        }
    }

    pub(super) struct AvgMaxCell {
        pub files: usize,
        pub size: u64,
        pub max_file: u64,
    }
    impl Display for AvgMaxCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.files == 0 {
                f.write_str("N/A")
            } else {
                let avg = self.size / self.files as u64;
                write!(
                    f,
                    "{} / {}",
                    HumanFmt::Size(avg),
                    HumanFmt::Size(self.max_file)
                )
            }
        }
    }

    pub(super) struct EfficiencyCell {
        pub downloaded: i64,
        pub delivered: i64,
    }
    impl Display for EfficiencyCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.delivered == 0 {
                f.write_str("N/A")
            } else {
                #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
                let pct = (self.delivered.saturating_sub(self.downloaded)) as f64
                    / self.delivered as f64
                    * 100.0;
                write!(f, "{pct:.1}%")?;
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "clamped to the 0..=100 meter scale"
                )]
                let filled = pct.clamp(0.0, 100.0) as u64;
                Display::fmt(
                    &Meter {
                        value: filled,
                        max: 100,
                    },
                    f,
                )
            }
        }
    }
}

pub(super) async fn build_mirror_table(
    mirrors: &[MirrorStatEntry],
    now_epoch: i64,
    cache_path: &Path,
) -> (Section, DirStats) {
    use mirror_cells::{AvgMaxCell, DirSizeCell, EfficiencyCell};

    if mirrors.is_empty() {
        return (Section::EMPTY, DirStats::default());
    }

    let mut sorted: Vec<&MirrorStatEntry> = mirrors.iter().collect();
    sorted.sort_unstable_by_key(|m| Reverse(m.last_seen));

    let paths = CachePaths::new(cache_path);
    let mirror_paths: Vec<PathBuf> = sorted
        .iter()
        .map(|mirror| paths.mirror_dir(mirror.site()))
        .collect();

    // Bound disk fan-out: cold-cache rebuilds otherwise spawn one concurrent
    // recursive walk per known mirror. We process in fixed-size chunks so
    // (a) at most `DIR_SCAN_CONCURRENCY` walks run at once and (b) the
    // collected order matches `mirror_paths` (and therefore `sorted`).
    let mut dir_stats: Vec<DirStats> = Vec::with_capacity(mirror_paths.len());
    for chunk in mirror_paths.chunks(DIR_SCAN_CONCURRENCY) {
        let chunk_stats = futures_util::future::join_all(
            chunk
                .iter()
                .map(|mirror_path| cached_mirror_directory_size(mirror_path)),
        )
        .await;
        dir_stats.extend(chunk_stats);
    }

    // Drop cache entries for paths no longer attached to any known mirror.
    // Keeps `DIR_STATS_CACHE` from growing unbounded as mirrors come and go.
    {
        let mut cache = DIR_STATS_CACHE.lock();
        cache.retain(|k, _| mirror_paths.iter().any(|p| p == k));
    }

    let total_cache_size: u64 = dir_stats.iter().map(|st| st.size).sum();

    // -- Build the table ------------------------------------------------------------------
    let mut table = Table::new(&[
        "Mirror",
        "Last Seen",
        "First Seen",
        "Last Cleanup",
        "Upstream Fetches",
        "Client Deliveries",
        "Cache Efficiency",
        "Disk Space",
        "File Count",
        "Avg / Max Size",
        "Debs / Metadata",
    ]);

    for (mirror, stats) in sorted.iter().zip(&dir_stats) {
        let downloaded_bytes = as_size(mirror.total_download_size);
        let delivered_bytes = as_size(mirror.total_delivery_size);

        tr!(
            marked Freshness::of(mirror.last_seen, now_epoch).row_class(),
            table,
            HtmlEscaped(mirror.uri()),
            FmtLastSeenHealth {
                last_seen: mirror.last_seen,
                now_epoch
            },
            FmtTimestamp(mirror.first_seen),
            FmtTimestamp(mirror.last_cleanup),
            format_args!(
                "{} ({})",
                HumanFmt::Size(downloaded_bytes),
                mirror.download_count
            ),
            format_args!(
                "{} ({})",
                HumanFmt::Size(delivered_bytes),
                mirror.delivery_count
            ),
            EfficiencyCell {
                downloaded: mirror.total_download_size,
                delivered: mirror.total_delivery_size,
            },
            DirSizeCell {
                size: stats.size,
                total: total_cache_size,
            },
            stats.files,
            AvgMaxCell {
                files: stats.files,
                size: stats.size,
                max_file: stats.max_file_size,
            },
            format_args!("{} / {}", stats.deb_files, stats.metadata_files),
        );
    }

    let mut aggregate = DirStats::default();
    for stats in &dir_stats {
        aggregate.merge(*stats);
    }

    let rows = sorted.len();
    (
        Section {
            html: table.finish(),
            rows,
        },
        aggregate,
    )
}

pub(super) async fn build_origin_table(database: &Database, now_epoch: i64) -> Section {
    let mut origins = match database.get_origins().await {
        Ok(o) => o,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to query the origins for the dashboard; rendering the origin section with an error notice:  {}",
                ErrorReport(&err)
            );
            let mut buf = String::new();
            write_section_error(&mut buf, "origins", &err);
            return Section { html: buf, rows: 0 };
        }
    };

    if origins.is_empty() {
        return Section::EMPTY;
    }

    origins.sort_unstable_by_key(|o| Reverse(o.last_seen));

    let rows = origins.len();
    let mut table = Table::new(&[
        "Mirror",
        "Distribution",
        "Component",
        "Architecture",
        "Last Seen",
    ]);

    for origin in origins {
        tr!(
            marked Freshness::of(origin.last_seen, now_epoch).row_class(),
            table,
            HtmlEscaped(origin.mirror_uri()),
            HtmlEscape(&origin.distribution),
            HtmlEscape(&origin.component),
            HtmlEscape(&origin.architecture),
            FmtLastSeenHealth {
                last_seen: origin.last_seen,
                now_epoch
            },
        );
    }

    Section {
        html: table.finish(),
        rows,
    }
}

pub(super) async fn build_client_table(database: &Database, now_epoch: i64) -> Section {
    let mut clients = match database.get_clients_with_stats().await {
        Ok(o) => o,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to query the clients for the dashboard; rendering the client section with an error notice:  {}",
                ErrorReport(&err)
            );
            let mut buf = String::new();
            write_section_error(&mut buf, "clients", &err);
            return Section { html: buf, rows: 0 };
        }
    };

    if clients.is_empty() {
        return Section::EMPTY;
    }

    clients.sort_unstable_by_key(|c| Reverse(c.last_seen));

    let rows = clients.len();
    let mut table = Table::new(&[
        "IP",
        "Last Seen",
        "Upstream Fetched",
        "Served to Client",
        "Requests",
    ]);

    for client in clients {
        let downloaded = as_size(client.total_downloaded);
        let delivered = as_size(client.total_delivered);
        tr!(
            marked Freshness::of(client.last_seen, now_epoch).row_class(),
            table,
            client.client_ip,
            FmtLastSeenHealth {
                last_seen: client.last_seen,
                now_epoch
            },
            HumanFmt::Size(downloaded),
            HumanFmt::Size(delivered),
            client.request_count,
        );
    }

    Section {
        html: table.finish(),
        rows,
    }
}

#[must_use]
pub(super) fn build_uncacheable_table() -> Section {
    let uncacheables = get_uncacheables().read();

    if uncacheables.is_empty() {
        return Section::EMPTY;
    }

    let rows = uncacheables.len();
    let mut table = Table::new(&["Requested Host", "Requested Path"]);

    for (host, path) in uncacheables.iter() {
        tr!(table, HtmlEscaped(host), HtmlEscape(path));
    }
    drop(uncacheables);

    Section {
        html: table.finish(),
        rows,
    }
}

/// What a Top-Packages table renders besides the package name.
#[derive(Clone, Copy)]
pub(super) enum TopPackagesView {
    /// Columns: Package, Deliveries, Size Each.
    ByCount,
    /// Columns: Package, Delivered Total, Deliveries, Size Each.
    BySize,
}

/// Number of rows in each "Top Packages" table.
const TOP_PACKAGES_LIMIT: u32 = 5;

pub(super) async fn build_top_packages_table(
    database: &Database,
    view: TopPackagesView,
) -> Section {
    let (label, result) = match view {
        TopPackagesView::ByCount => (
            "top packages by count",
            database.get_top_packages(TOP_PACKAGES_LIMIT).await,
        ),
        TopPackagesView::BySize => (
            "top packages by size",
            database.get_top_packages_by_size(TOP_PACKAGES_LIMIT).await,
        ),
    };

    let packages = match result {
        Ok(p) => p,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to query the {label} for the dashboard; rendering that section with an error notice:  {}",
                ErrorReport(&err)
            );
            let mut buf = String::new();
            write_section_error(&mut buf, label, &err);
            return Section { html: buf, rows: 0 };
        }
    };

    if packages.is_empty() {
        return Section::EMPTY;
    }

    let rows = packages.len();
    let headers: &[&str] = match view {
        // "Package Size" meant the size of one copy in one table and the
        // cumulative bytes in the other; name each for what it counts.
        TopPackagesView::ByCount => &["Package", "Deliveries", "Size Each"],
        TopPackagesView::BySize => &["Package", "Delivered Total", "Deliveries", "Size Each"],
    };
    let mut table = Table::new(headers);

    for pkg in packages {
        let pkg_size = as_size(pkg.package_size);
        match view {
            TopPackagesView::ByCount => tr!(
                table,
                HtmlEscape(&pkg.debname),
                pkg.delivery_count,
                HumanFmt::Size(pkg_size),
            ),
            TopPackagesView::BySize => {
                let total = as_size(pkg.total_delivered);
                tr!(
                    table,
                    HtmlEscape(&pkg.debname),
                    HumanFmt::Size(total),
                    pkg.delivery_count,
                    HumanFmt::Size(pkg_size),
                );
            }
        }
    }

    Section {
        html: table.finish(),
        rows,
    }
}
