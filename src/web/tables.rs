//! The dashboard's row tables (Mirrors, Origins, Clients, Top Packages,
//! Uncacheables), each returned as a [`Section`], plus the cached per-mirror
//! directory walk that feeds the Mirrors table.

use std::{
    cmp::Reverse,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
    time::SystemTime,
};

use coarsetime::Instant;
use hashbrown::HashMap;
use tracing::error;

use crate::{
    cache_paths::{CachePaths, SUBDIR_FLAT_BYHASH},
    cache_walk::{AnomalyLevel, DirFailure, EntryKind, OnMissing, WalkContext, Walker},
    client_trouble::ClientTrouble,
    config::{ClientHost, Config},
    database::{ClientStatEntry, MirrorStatEntry, OriginEntry, TopPackageEntry},
    deb_mirror::is_deb_package,
    error::ErrorReport,
    humanfmt::HumanFmt,
    metrics,
    mirror_health::MirrorHealth,
    mirror_indexes::{self, MirrorIndexes},
    mirror_perf::MirrorPerf,
    scheme_cache::{self, SchemeKeyRef, SchemeVerdict},
    swrite,
    uncacheables::get_uncacheables,
};

use super::{
    fmt::{
        Count, FmtLastSeenHealth, Freshness, HtmlEscape, HtmlEscaped, Level, Nonzero, RelTime,
        as_size,
    },
    table::{Table, tr, when, write_section_error},
};

/// A rendered dashboard table together with its row count, which the page
/// shows next to the section heading and uses to decide whether the
/// section starts expanded.
#[derive(Clone)]
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
    fn files(self) -> usize {
        self.deb_files + self.metadata_files
    }

    fn merge(&mut self, other: Self) {
        let Self {
            size,
            byhash_files,
            deb_files,
            metadata_files,
            max_file_size,
            oldest_mtime,
            newest_mtime,
        } = other;

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

/// One mirror directory's cached walk result. The async lock is held for the
/// whole refresh, so concurrent dashboard loads that find the entry stale wait
/// for the one walk in flight and read its result instead of each walking
/// the tree again.
type DirStatsSlot = Arc<tokio::sync::Mutex<Option<(Instant, DirStats)>>>;

type DirStatsCache = parking_lot::Mutex<HashMap<PathBuf, DirStatsSlot>>;

static DIR_STATS_CACHE: LazyLock<DirStatsCache> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

async fn cached_mirror_directory_size(path: &Path) -> DirStats {
    cached_dir_stats(
        path,
        |path| async move { mirror_directory_size(&path).await },
    )
    .await
}

/// The slot's result while it is younger than [`DIR_STATS_TTL_SECS`].
fn fresh_dir_stats(cached: Option<(Instant, DirStats)>) -> Option<DirStats> {
    cached
        .filter(|(ts, _)| ts.elapsed().as_secs() < DIR_STATS_TTL_SECS)
        .map(|(_, stats)| stats)
}

/// [`cached_mirror_directory_size`] with the walk passed in, so the
/// single-flight refresh is testable without a mirror tree.
///
/// A refresh runs as its own task holding the slot, so a dashboard load
/// cancelled mid-walk (the browser went away) does not throw the walk away:
/// it completes and publishes, and the next load reads its result.
async fn cached_dir_stats<F>(
    path: &Path,
    walk: impl FnOnce(PathBuf) -> F + Send + 'static,
) -> DirStats
where
    F: Future<Output = DirStats> + Send + 'static,
{
    // Bind the slot to a local so the `MutexGuard` drops at this `;`,
    // before any `.await` below — `parking_lot::Mutex` held across an
    // await is a deadlock waiting for someone to extend the body.
    // `entry_ref` looks up by the borrowed `&Path`; only a first visit
    // materialises the owned `PathBuf` key.
    let slot = Arc::clone(DIR_STATS_CACHE.lock().entry_ref(path).or_default());
    // Waits for a refresh in flight, which holds the lock.
    let cached = *slot.lock().await;
    if let Some(stats) = fresh_dir_stats(cached) {
        return stats;
    }
    let owned = path.to_path_buf();
    let refresh = tokio::spawn(async move {
        let mut cached = slot.lock_owned().await;
        // Another load may have refreshed the slot since the check above.
        if let Some(stats) = fresh_dir_stats(*cached) {
            return stats;
        }
        let stats = walk(owned).await;
        *cached = Some((Instant::now(), stats));
        stats
    });
    match refresh.await {
        Ok(stats) => stats,
        Err(err) => {
            error!(
                "Failed to walk mirror directory `{}` for the dashboard; reporting it as empty:  {}",
                path.display(),
                ErrorReport(&err)
            );
            DirStats::default()
        }
    }
}

static DASHBOARD_WALK: WalkContext = WalkContext {
    what: "a mirror directory",
    dir_failure: DirFailure::Continue("excluding its unread entries from the reported cache size"),
    entry_failure: "excluding it from the reported cache size",
    non_regular: "excluding it from the reported cache size",
    anomalies: AnomalyLevel::Debug,
};

/// Tally every regular file below `path` for the dashboard's Mirrors table.
///
/// Unlike the startup scan this walk knows nothing about the layout: every
/// directory is descended into (`tmp/` and nested mirrors included), and
/// every regular file counts.  The walker's tag remembers whether the
/// directory sits under a `by-hash/` subtree.  Failures (a stat failure, an
/// unreadable subdirectory) are logged and counted by the walker like
/// everywhere else and the walk carries on, so one bad entry no longer drops
/// the whole mirror from the table.  A symlink or other non-regular entry is
/// counted but logged at `debug` only ([`AnomalyLevel::Debug`]): a viewer's
/// refresh re-runs this walk, and the startup scan and cleanup already warn
/// about the same entry.
async fn mirror_directory_size(path: &Path) -> DirStats {
    let mut stats = DirStats::default();
    let mut walker = Walker::new(path, &DASHBOARD_WALK, OnMissing::Tolerate, false).stat_files();

    while let Some(mut entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => {}
            EntryKind::File => {
                let Some(mdata) = entry.metadata().await else {
                    continue;
                };
                let len = mdata.len();
                stats.size += len;
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

    use std::time::Duration;

    use crate::{
        config::ClientHost,
        mirror_health::MirrorHealth,
        mirror_indexes::{self, IndexAge, IndexState, MirrorIndexes},
        mirror_perf::MirrorPerf,
        scheme_cache::{Scheme, SchemeVerdict},
    };

    use super::super::fmt::{Age, HtmlEscape, HtmlEscaped, Latency, Meter, UtcText, warn_if};

    /// The coloured dot in front of a mirror's name: green without a failure
    /// since start, red once one of its files failed checksum verification
    /// (the mirror serves content its index disagrees with), amber for any
    /// other failure class. Its title spells the counts out.
    #[derive(Clone, Copy)]
    pub(super) struct HealthDot(pub MirrorHealth);
    impl Display for HealthDot {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let MirrorHealth {
                unreachable,
                protocol,
                checksum,
                slow,
            } = self.0;
            let class = if checksum > 0 {
                "alert"
            } else if unreachable + protocol + slow > 0 {
                "warn"
            } else {
                "ok"
            };
            write!(f, "<span class=\"dot {class}\" title=\"")?;
            if class == "ok" {
                f.write_str("No upstream failure since start")?;
            } else {
                f.write_str("Upstream failures since start:")?;
                let mut sep = " ";
                for (count, what) in [
                    (unreachable, "unreachable"),
                    (protocol, "protocol error"),
                    (checksum, "checksum mismatch"),
                    (slow, "timeout / slow"),
                ] {
                    if count > 0 {
                        write!(f, "{sep}{count} {what}")?;
                        sep = ", ";
                    }
                }
            }
            f.write_str("\"></span>")
        }
    }

    /// The scheme a mirror is dialled with, a chip between its health dot
    /// and its name: `https`, `http`, or `?` before the first contact
    /// decides it. The title says why, for the mirror and for every alias
    /// host that is dialled for it (each has a scheme of its own). Only a
    /// failed HTTPS probe -- of the mirror or of an alias -- warns.
    pub(super) struct SchemeChip<'a> {
        pub verdict: SchemeVerdict,
        /// Alias hosts of this mirror with their own verdicts.
        pub aliases: &'a [(&'a ClientHost, SchemeVerdict)],
    }
    impl Display for SchemeChip<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let Self { verdict, aliases } = *self;
            let (scheme, text) = match verdict.scheme() {
                Some(Scheme::Https) => ("https", "https"),
                Some(Scheme::Http) => ("http", "http"),
                None => ("unknown", "?"),
            };
            let fallback = std::iter::once(verdict)
                .chain(aliases.iter().map(|&(_, alias)| alias))
                .any(|v| matches!(v, SchemeVerdict::HttpFallback { reprobe_in: _ }));
            let warn = if fallback { " warn" } else { "" };
            write!(
                f,
                "<span class=\"scheme {scheme}{warn}\" title=\"{}",
                Why(verdict)
            )?;
            for &(host, alias) in aliases {
                write!(f, " Alias {}: {}", HtmlEscaped(host), Why(alias))?;
            }
            write!(f, "\">{text}</span>")
        }
    }

    /// One sentence on why a host is dialled as it is, for a title.
    struct Why(SchemeVerdict);
    impl Display for Why {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self.0 {
                SchemeVerdict::HttpOnlyListed => {
                    f.write_str("Plain HTTP: the host is listed in http_only_mirrors.")
                }
                SchemeVerdict::HttpNever => {
                    f.write_str("Plain HTTP: https_upgrade_mode is Never.")
                }
                SchemeVerdict::HttpsForced => {
                    f.write_str("HTTPS: https_upgrade_mode is Always.")
                }
                SchemeVerdict::HttpsUpgraded => {
                    f.write_str("HTTPS: upgraded from plain HTTP (https_upgrade_mode Auto).")
                }
                SchemeVerdict::HttpFallback { reprobe_in } => write!(
                    f,
                    "Plain HTTP: the HTTPS probe failed (port 443 unreachable, no TLS, or a certificate that did not verify). Fix the mirror's TLS, or list it in http_only_mirrors to stop probing; HTTPS is probed again in {}.",
                    Age(reprobe_in.as_secs().max(1))
                ),
                SchemeVerdict::Undecided => f.write_str(
                    "No scheme decided right now (not dialled since start, or an earlier HTTP fallback expired or was evicted): the next request probes HTTPS and falls back to plain HTTP (https_upgrade_mode Auto).",
                ),
            }
        }
    }

    /// A mirror's time to first byte: the latest, the longest since start
    /// beside it. Warns once the longest passed `warn_above`, half of
    /// `http_timeout`: the mirror came close to timing out.
    pub(super) struct TtfbCell {
        pub perf: Option<MirrorPerf>,
        pub warn_above: Duration,
    }
    impl Display for TtfbCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let Some(MirrorPerf {
                ttfb: Some(latest),
                ttfb_peak,
                rate: _,
                rate_peak: _,
            }) = self.perf
            else {
                return f.write_str("N/A");
            };
            let latency = |value| Latency {
                value,
                resolution: Latency::PRECISE,
            };
            Display::fmt(
                &warn_if(
                    format_args!(
                        "{} <span class=\"peak\">peak {}</span>",
                        latency(latest.value),
                        latency(ttfb_peak)
                    ),
                    ttfb_peak > self.warn_above,
                ),
                f,
            )
        }
    }

    /// A mirror's download throughput: the latest committed download of at
    /// least 1 MiB, the fastest since start beside it. Warns while the
    /// latest is under `warn_below`, twice `min_download_rate`: downloads
    /// from it are close to being cancelled.
    pub(super) struct ThroughputCell {
        pub perf: Option<MirrorPerf>,
        pub warn_below: Option<u64>,
    }
    impl Display for ThroughputCell {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            let Some(MirrorPerf {
                ttfb: _,
                ttfb_peak: _,
                rate: Some(latest),
                rate_peak,
            }) = self.perf
            else {
                return f.write_str("N/A");
            };
            Display::fmt(
                &warn_if(
                    format_args!(
                        "{} <span class=\"peak\">peak {}</span>",
                        HumanFmt::RatePerSec(latest.value),
                        HumanFmt::RatePerSec(rate_peak)
                    ),
                    self.warn_below.is_some_and(|floor| latest.value < floor),
                ),
                f,
            )
        }
    }

    /// A mirror's index age (`mirror_indexes`): its newest known index's
    /// age at the latest confirmation across suites, notice once that index
    /// was re-served past two weeks old (the mirror stopped syncing), marked
    /// unconfirmed when only its idle suite's age grew that far, warn once a
    /// suite was served past its `Valid-Until:`. The title lists every
    /// suite.
    pub(super) struct IndexAgeCell<'a> {
        pub indexes: Option<&'a MirrorIndexes>,
        /// `verify_checksums`, whose ingest reads the indexes.
        pub enabled: bool,
    }
    impl Display for IndexAgeCell<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if !self.enabled {
                return f.write_str("requires verify_checksums");
            }
            let Some((indexes, age)) = self
                .indexes
                .and_then(|indexes| mirror_indexes::assess(indexes).map(|age| (indexes, age)))
            else {
                return f.write_str("N/A");
            };
            let IndexAge {
                freshest_lag,
                state,
            } = age;
            let class = match state {
                IndexState::Expired => " class=\"warn\"",
                IndexState::Behind => " class=\"notice\"",
                IndexState::Unconfirmed | IndexState::Fresh => "",
            };
            write!(f, "<span{class} title=\"")?;
            let mut sep = "";
            for (suite, index) in indexes.suites() {
                write!(f, "{sep}{}: ", HtmlEscape(suite))?;
                match index.date {
                    Some(date) => write!(f, "dated {}", UtcText(date))?,
                    None => f.write_str("undated")?,
                }
                if let Some(valid_until) = index.valid_until {
                    write!(f, ", valid until {}", UtcText(valid_until))?;
                }
                write!(f, ", last served {}", UtcText(index.confirmed_at))?;
                if let Some(lag) = index.lag() {
                    write!(f, " ({} old then)", Age(lag))?;
                }
                if index.expired() {
                    f.write_str(", served expired: apt refuses it")?;
                }
                sep = "; ";
            }
            f.write_str("\">")?;
            match freshest_lag {
                Some(lag) => Display::fmt(&Age(lag), f)?,
                None => f.write_str("undated")?,
            }
            match state {
                IndexState::Expired => f.write_str(", expired")?,
                IndexState::Unconfirmed => f.write_str(", unconfirmed")?,
                IndexState::Behind | IndexState::Fresh => {}
            }
            f.write_str("</span>")
        }
    }

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

/// The Mirrors table's failure columns. In-memory counts since the daemon
/// started, unlike the persisted columns beside them, hence the scope chip.
const MIRROR_HEALTH_HEADERS: [&str; 4] = [
    "<span title=\"Downloads whose connect, or the exchange before the response head, failed: the mirror is down or unreachable from here.\">Unreachable</span> <span class=\"scope\">since start</span>",
    "<span title=\"Responses that broke the HTTP contract (malformed head, body disagreeing with its framing, unsolicited 206): a mirror bug to report.\">Protocol Errors</span> <span class=\"scope\">since start</span>",
    "<span title=\"Files whose content did not match the digest in the mirror's own index, at download or at cleanup's re-verification.\">Checksum Mismatches</span> <span class=\"scope\">since start</span>",
    "<span title=\"Downloads aborted because a body read timed out (http_timeout) or the mirror fell below min_download_rate over rate_check_timeframe.\">Timeouts / Slow</span> <span class=\"scope\">since start</span>",
];

/// The Mirrors table's index-age column (`mirror_indexes`).
const MIRROR_INDEX_HEADER: &str = "<span title=\"Age of this mirror's newest known Release/InRelease at its latest confirmation across all suites. A frozen release pocket beside a syncing -updates is fine; a suite no longer requested cannot freeze the age, and an idle mirror keeps its last reading. Over two weeks is a notice once the mirror served that newest index this old: it has likely stopped syncing; report it to the mirror's operator or switch to another mirror (a vendor repository that rarely publishes reads this way too). Over two weeks only because the suite carrying the newest index was not requested since reads unconfirmed: that suite may well have moved on. A suite served past its Valid-Until warns: apt refuses that index. Hover a cell for each suite's age when it was served. Needs verify_checksums, whose ingest reads the index.\">Newest Index</span> <span class=\"scope\">since start</span>";

/// The Mirrors table's latency and throughput columns (`mirror_perf`),
/// in-memory figures since the daemon started like the failure counts.
const MIRROR_PERF_HEADERS: [&str; 2] = [
    "<span title=\"From the start of the upstream attempt that answered (its TCP and TLS connect included when no pooled connection was reused) to its parsed response head, for cached fetches answered with a body or a 304: the latest, and the longest since start. Warns when the longest passed half of http_timeout: the mirror came close to timing out; compare mirrors and switch to a closer or less loaded one.\">Time to First Byte</span> <span class=\"scope\">since start</span>",
    "<span title=\"Body bytes per second of the latest committed download of 1 MiB or more from this mirror, and the fastest since start. A lower bound while a client is attached: splice builds pace a download to its client until it is demoted, so a slow client (see the Clients table) reads here too. Warns while the latest is under twice min_download_rate: downloads from this mirror are close to being cancelled; if no client is slow, switch to a faster mirror, or lower min_download_rate.\">Throughput</span> <span class=\"scope\">since start</span>",
];

/// One failure-count cell of the Mirrors table.
fn health_cell(value: u64, level: Level) -> Nonzero {
    Nonzero { value, level }
}

/// The Mirrors table's name column: what the dot and the chip in front of
/// each name mean.
const MIRROR_HEADER: &str = "<span title=\"The dot is the mirror's upstream health since start (hover it for the failures); the chip is the scheme it is dialled with now (hover it for why).\">Mirror</span>";

/// The [`mirror_cells::SchemeChip`] parts of `mirror`: its own verdict and
/// one per alias host configured for it, each looked up on the mirror's port.
fn scheme_verdicts<'a>(
    mirror: &MirrorStatEntry,
    config: &'a Config,
) -> (SchemeVerdict, Vec<(&'a ClientHost, SchemeVerdict)>) {
    let port = mirror.port().map(std::num::NonZero::get);
    let verdict = scheme_cache::verdict_for(
        SchemeKeyRef {
            host: mirror.host.as_str(),
            port,
        },
        config,
    );
    let aliases = config
        .aliases
        .iter()
        .filter(|alias| alias.main.as_str() == mirror.host.as_str())
        .flat_map(|alias| &alias.aliases)
        .map(|host| {
            let key = SchemeKeyRef {
                host: host.as_str(),
                port,
            };
            (host, scheme_cache::verdict_for(key, config))
        })
        .collect();
    (verdict, aliases)
}

/// The in-memory per-mirror figures the Mirrors table joins onto the
/// persisted rows, each keyed by the `MirrorUri` rendering.
pub(super) struct MirrorSnapshots {
    pub(super) health: HashMap<Box<str>, MirrorHealth>,
    pub(super) perf: HashMap<Box<str>, MirrorPerf>,
    pub(super) indexes: HashMap<Box<str>, MirrorIndexes>,
}

pub(super) async fn build_mirror_table(
    mirrors: &[MirrorStatEntry],
    snapshots: &MirrorSnapshots,
    now_epoch: i64,
    config: &Config,
) -> (Section, DirStats) {
    use mirror_cells::{
        AvgMaxCell, DirSizeCell, EfficiencyCell, HealthDot, IndexAgeCell, SchemeChip,
        ThroughputCell, TtfbCell,
    };

    let MirrorSnapshots {
        health,
        perf,
        indexes,
    } = snapshots;
    let ttfb_warn_above = config.http_timeout / 2;
    let rate_warn_below = config
        .min_download_rate
        .map(|rate| (rate.get() as u64).saturating_mul(2));

    if mirrors.is_empty() && health.is_empty() {
        return (Section::EMPTY, DirStats::default());
    }

    let mut sorted: Vec<&MirrorStatEntry> = mirrors.iter().collect();
    sorted.sort_unstable_by_key(|m| Reverse(m.last_seen));

    let paths = CachePaths::new(&config.cache_directory);
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

    // Complete before the first row is rendered: the Disk Space cell shows
    // each mirror's share of `aggregate.size`.
    let mut aggregate = DirStats::default();
    for stats in &dir_stats {
        aggregate.merge(*stats);
    }

    let mut table = Table::numeric(
        "mirrors",
        &[
            MIRROR_HEADER,
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
            MIRROR_HEALTH_HEADERS[0],
            MIRROR_HEALTH_HEADERS[1],
            MIRROR_HEALTH_HEADERS[2],
            MIRROR_HEALTH_HEADERS[3],
            MIRROR_PERF_HEADERS[0],
            MIRROR_PERF_HEADERS[1],
            MIRROR_INDEX_HEADER,
        ],
        &[4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
    );

    // The per-mirror failure counts join by the `MirrorUri` rendering
    // (`mirror_registry`'s snapshot key); a failing mirror without a row of
    // its own is appended below the persisted ones.
    let mut unmatched: Vec<(&str, &MirrorHealth)> =
        health.iter().map(|(key, h)| (key.as_ref(), h)).collect();
    let mut key = String::new();
    for (mirror, stats) in sorted.iter().zip(&dir_stats) {
        let downloaded_bytes = as_size(mirror.total_download_size);
        let delivered_bytes = as_size(mirror.total_delivery_size);
        key.clear();
        swrite!(key, "{}", mirror.uri());
        let mirror_health = health.get(key.as_str()).copied().unwrap_or_default();
        unmatched.retain(|(k, _)| *k != key);
        let (verdict, aliases) = scheme_verdicts(mirror, config);
        let mirror_perf = perf.get(key.as_str()).copied();
        let suites = indexes.get(key.as_str());
        let index_lag = suites
            .filter(|_| config.verify_checksums)
            .and_then(mirror_indexes::assess)
            .and_then(|age| age.freshest_lag);

        tr!(
            marked Freshness::of(mirror.last_seen, now_epoch).row_class(),
            table,
            // The dot makes the cell markup, which `Table::cell` never titles,
            // so the name carries its own title for when it is cut off. The
            // name stays last in the cell.
            format_args!(
                "{}{}<span title=\"{uri}\">{uri}</span>",
                HealthDot(mirror_health),
                SchemeChip {
                    verdict,
                    aliases: &aliases,
                },
                uri = HtmlEscaped(mirror.uri())
            ) => Some(key.as_str()),
            FmtLastSeenHealth {
                last_seen: mirror.last_seen,
                now_epoch
            } => when(mirror.last_seen),
            RelTime {
                epoch: mirror.first_seen,
                now: now_epoch
            } => when(mirror.first_seen),
            RelTime {
                epoch: mirror.last_cleanup,
                now: now_epoch
            } => when(mirror.last_cleanup),
            format_args!(
                "{} ({})",
                HumanFmt::Size(downloaded_bytes),
                Count::db(mirror.download_count)
            ) => Some(downloaded_bytes),
            format_args!(
                "{} ({})",
                HumanFmt::Size(delivered_bytes),
                Count::db(mirror.delivery_count)
            ) => Some(delivered_bytes),
            EfficiencyCell {
                downloaded: mirror.total_download_size,
                delivered: mirror.total_delivery_size,
            } => efficiency_key(downloaded_bytes, delivered_bytes),
            DirSizeCell {
                size: stats.size,
                total: aggregate.size,
            } => Some(stats.size),
            Count::len(stats.files()) => Some(stats.files()),
            AvgMaxCell {
                files: stats.files(),
                size: stats.size,
                max_file: stats.max_file_size,
            } => (stats.files() > 0).then(|| stats.size / stats.files() as u64),
            format_args!(
                "{} / {}",
                Count::len(stats.deb_files),
                Count::len(stats.metadata_files)
            ) => Some(stats.deb_files),
            health_cell(mirror_health.unreachable, Level::Warn) => Some(mirror_health.unreachable),
            health_cell(mirror_health.protocol, Level::Warn) => Some(mirror_health.protocol),
            health_cell(mirror_health.checksum, Level::Alert) => Some(mirror_health.checksum),
            health_cell(mirror_health.slow, Level::Warn) => Some(mirror_health.slow),
            TtfbCell {
                perf: mirror_perf,
                warn_above: ttfb_warn_above,
            } => mirror_perf.and_then(|p| p.ttfb).map(|latest| latest.value.as_micros()),
            ThroughputCell {
                perf: mirror_perf,
                warn_below: rate_warn_below,
            } => mirror_perf.and_then(|p| p.rate).map(|latest| latest.value),
            IndexAgeCell {
                indexes: suites,
                enabled: config.verify_checksums,
            } => index_lag,
        );
    }

    // A mirror that failed before it ever answered has no persisted row:
    // everything but its failure counts is unknown, its scheme chip
    // included (the row has only the rendered name to go by).
    unmatched.sort_unstable_by_key(|(key, _)| *key);
    for (key, mirror_health) in &unmatched {
        tr!(
            table,
            format_args!(
                "{}<span title=\"{key}\">{key}</span>",
                HealthDot(**mirror_health),
                key = HtmlEscape(key)
            ) => Some(*key),
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            health_cell(mirror_health.unreachable, Level::Warn) => Some(mirror_health.unreachable),
            health_cell(mirror_health.protocol, Level::Warn) => Some(mirror_health.protocol),
            health_cell(mirror_health.checksum, Level::Alert) => Some(mirror_health.checksum),
            health_cell(mirror_health.slow, Level::Warn) => Some(mirror_health.slow),
            // Never answered, so never measured.
            "N/A",
            "N/A",
            "N/A",
        );
    }

    let rows = sorted.len() + unmatched.len();
    (
        Section {
            html: table.finish(),
            rows,
        },
        aggregate,
    )
}

/// The Cache Efficiency column's sort key: the saved share in tenths of a
/// percent (negative when more was fetched than delivered), `None` before
/// anything was delivered, as the cell's `N/A`.
fn efficiency_key(downloaded: u64, delivered: u64) -> Option<i128> {
    (delivered > 0)
        .then(|| (i128::from(delivered) - i128::from(downloaded)) * 1000 / i128::from(delivered))
}

/// Log a failed dashboard query and render its section's error notice.
///
/// One place so every section reports a DB failure identically: the
/// `DB_OPERATION_FAILED` bump, an ERROR naming the section, and the notice
/// the reader sees in place of the table.
pub(super) fn db_error_section(label: &'static str, err: &sqlx::Error) -> Section {
    metrics::DB_OPERATION_FAILED.increment();
    error!(
        "Failed to query the {label} for the dashboard; rendering that section with an error notice:  {}",
        ErrorReport(err)
    );
    let mut buf = String::new();
    write_section_error(&mut buf, label, err);
    Section { html: buf, rows: 0 }
}

/// The Origins table's index-date column (`mirror_indexes`).
const ORIGIN_INDEX_HEADER: &str = "<span title=\"The Date of the newest Release/InRelease of this distribution the mirror served since start: how current the index behind this origin is. Needs verify_checksums, whose ingest reads the index.\">Index Date</span> <span class=\"scope\">since start</span>";

/// Renders borrowed rows (like [`build_mirror_table`]) rather than owning
/// them: the rows come from the memoized aggregate block, which several
/// concurrent renders share. `indexes` is the `mirror_indexes` snapshot,
/// joined on the mirror and the distribution (the suite).
pub(super) fn render_origin_table(
    origins: &[OriginEntry],
    indexes: &HashMap<Box<str>, MirrorIndexes>,
    now_epoch: i64,
) -> Section {
    if origins.is_empty() {
        return Section::EMPTY;
    }

    let mut sorted: Vec<&OriginEntry> = origins.iter().collect();
    sorted.sort_unstable_by_key(|o| Reverse(o.last_seen));

    let rows = sorted.len();
    let mut table = Table::new(
        "origins",
        &[
            "Mirror",
            "Distribution",
            "Component",
            "Architecture",
            "Last Seen",
            ORIGIN_INDEX_HEADER,
        ],
    );

    let mut key = String::new();
    for origin in sorted {
        key.clear();
        swrite!(key, "{}", origin.mirror_uri());
        let index_date = indexes
            .get(key.as_str())
            .and_then(|indexes| indexes.suite(&origin.distribution))
            .and_then(|index| index.date);
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
            } => when(origin.last_seen),
            RelTime {
                epoch: index_date.unwrap_or(0),
                now: now_epoch
            } => index_date.and_then(when),
        );
    }

    Section {
        html: table.finish(),
        rows,
    }
}

/// The Clients table's address column. A row is one address, which an IPv6
/// host using temporary (privacy) addresses changes daily or so: the tooltip
/// says why one machine can fill several rows.
const CLIENT_IP_HEADER: &str = "<span title=\"One row per client address; an IPv4 client of the dual-stack listener shows as IPv4. An IPv6 host using temporary (privacy) addresses gets a row for every address it used, and the per-client caps count each address on its own unless client_ipv6_prefix_len groups them by network.\">IP</span>";

/// The Clients table's trouble columns: in-memory counts since the daemon
/// started for the heaviest offenders (`client_trouble`), unlike the
/// persisted columns beside them, hence the scope chip.
const CLIENT_TROUBLE_HEADERS: [&str; 5] = [
    "<span title=\"Deliveries aborted because this client read below min_download_rate over rate_check_timeframe, or stalled a body write for http_timeout.\">Slow / Timed Out</span> <span class=\"scope\">since start</span>",
    "<span title=\"Deliveries this client hung up on before the body was complete.\">Disconnects</span> <span class=\"scope\">since start</span>",
    "<span title=\"Connections refused by max_connections_per_client_ip and CONNECT tunnels refused by https_tunnel_max_connections_per_client.\">Cap Refusals</span> <span class=\"scope\">since start</span>",
    "<span title=\"Connections and requests refused because of who sent them: allowed_proxy_clients, allowed_webif_clients or webif_hostnames. A stray or hostile host, or an ACL set too tight.\">Refused (client ACL)</span> <span class=\"scope\">since start</span>",
    "<span title=\"Requests and CONNECT tunnels for a mirror outside allowed_mirrors or https_tunnel_allowed_mirrors: usually a repository in this client's sources that this proxy does not serve. Add the mirror, or remove it from the client. Not highlighted: a client with such an entry is refused on every update.\">Refused (mirror)</span> <span class=\"scope\">since start</span>",
];

/// See [`render_origin_table`] on why the rows are borrowed. `trouble` is
/// the heavy-hitter snapshot; a tracked client without a persisted row (one
/// that was only ever refused, say) is appended with N/A in the persisted
/// columns.
pub(super) fn render_client_table(
    clients: &[ClientStatEntry],
    trouble: &[ClientTrouble],
    now_epoch: i64,
) -> Section {
    if clients.is_empty() && trouble.is_empty() {
        return Section::EMPTY;
    }

    let mut sorted: Vec<&ClientStatEntry> = clients.iter().collect();
    sorted.sort_unstable_by_key(|c| Reverse(c.last_seen));

    let mut table = Table::numeric(
        "clients",
        &[
            CLIENT_IP_HEADER,
            "Last Seen",
            "Upstream Fetched",
            "Served to Client",
            "Requests",
            CLIENT_TROUBLE_HEADERS[0],
            CLIENT_TROUBLE_HEADERS[1],
            CLIENT_TROUBLE_HEADERS[2],
            CLIENT_TROUBLE_HEADERS[3],
            CLIENT_TROUBLE_HEADERS[4],
        ],
        &[2, 3, 4, 5, 6, 7, 8, 9],
    );

    let warn = |value| Nonzero {
        value,
        level: Level::Warn,
    };
    let mut unmatched: Vec<&ClientTrouble> = trouble.iter().collect();
    for client in &sorted {
        let downloaded = as_size(client.total_downloaded);
        let delivered = as_size(client.total_delivered);
        let counts = trouble
            .iter()
            .find(|t| t.ip == client.client_ip)
            .copied()
            .unwrap_or_else(|| ClientTrouble::none(client.client_ip));
        unmatched.retain(|t| t.ip != client.client_ip);
        tr!(
            marked Freshness::of(client.last_seen, now_epoch).row_class(),
            table,
            // Unkeyed: the address sorts as its text.
            client.client_ip,
            FmtLastSeenHealth {
                last_seen: client.last_seen,
                now_epoch
            } => when(client.last_seen),
            HumanFmt::Size(downloaded) => Some(downloaded),
            HumanFmt::Size(delivered) => Some(delivered),
            Count::db(client.request_count) => Some(as_size(client.request_count)),
            warn(counts.slow) => Some(counts.slow),
            Count(counts.disconnect) => Some(counts.disconnect),
            warn(counts.cap_refused) => Some(counts.cap_refused),
            warn(counts.unauthorized) => Some(counts.unauthorized),
            Count(counts.mirror_refused) => Some(counts.mirror_refused),
        );
    }
    // Heaviest first, as the snapshot came.
    for counts in &unmatched {
        tr!(
            table,
            counts.ip,
            "N/A",
            "N/A",
            "N/A",
            "N/A",
            warn(counts.slow) => Some(counts.slow),
            Count(counts.disconnect) => Some(counts.disconnect),
            warn(counts.cap_refused) => Some(counts.cap_refused),
            warn(counts.unauthorized) => Some(counts.unauthorized),
            Count(counts.mirror_refused) => Some(counts.mirror_refused),
        );
    }

    Section {
        html: table.finish(),
        rows: sorted.len() + unmatched.len(),
    }
}

#[must_use]
pub(super) fn build_uncacheable_table() -> Section {
    let uncacheables = get_uncacheables();

    if uncacheables.is_empty() {
        return Section::EMPTY;
    }

    let rows = uncacheables.len();
    let mut table = Table::new("uncacheables", &["Requested Host", "Requested Path"]);

    for entry in uncacheables.iter() {
        tr!(
            table,
            HtmlEscape(&entry.authority()),
            HtmlEscape(&entry.path)
        );
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
pub(super) const TOP_PACKAGES_LIMIT: u32 = 5;

/// See [`render_origin_table`] on why the rows are borrowed. Both views are
/// rendered from one aggregate pass (`Database::get_top_packages`), so the
/// caller hands the same `TopPackages` to this function twice.
pub(super) fn render_top_packages_table(
    packages: &[TopPackageEntry],
    view: TopPackagesView,
) -> Section {
    if packages.is_empty() {
        return Section::EMPTY;
    }

    let rows = packages.len();
    let (key, headers, numeric): (&str, &[&str], &[usize]) = match view {
        // "Package Size" meant the size of one copy in one table and the
        // cumulative bytes in the other; name each for what it counts.
        TopPackagesView::ByCount => (
            "packages-count",
            &["Package", "Deliveries", "Size Each"],
            &[1, 2],
        ),
        TopPackagesView::BySize => (
            "packages-size",
            &["Package", "Delivered Total", "Deliveries", "Size Each"],
            &[1, 2, 3],
        ),
    };
    let mut table = Table::numeric(key, headers, numeric);

    for pkg in packages {
        let pkg_size = as_size(pkg.package_size);
        match view {
            TopPackagesView::ByCount => tr!(
                table,
                HtmlEscape(&pkg.debname),
                Count::db(pkg.delivery_count) => Some(as_size(pkg.delivery_count)),
                HumanFmt::Size(pkg_size) => Some(pkg_size),
            ),
            TopPackagesView::BySize => {
                let total = as_size(pkg.total_delivered);
                tr!(
                    table,
                    HtmlEscape(&pkg.debname),
                    HumanFmt::Size(total) => Some(total),
                    Count::db(pkg.delivery_count) => Some(as_size(pkg.delivery_count)),
                    HumanFmt::Size(pkg_size) => Some(pkg_size),
                );
            }
        }
    }

    Section {
        html: table.finish(),
        rows,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// Counts its calls; each takes 50 ms and reports seven files.
    fn counted_walk(
        walks: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> impl FnOnce(PathBuf) -> std::pin::Pin<Box<dyn Future<Output = DirStats> + Send>> + Send + 'static
    {
        let walks = Arc::clone(walks);
        move |_path| {
            Box::pin(async move {
                walks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                DirStats {
                    deb_files: 7,
                    ..DirStats::default()
                }
            })
        }
    }

    /// Dashboard loads that find the same entry stale share one walk: the
    /// others wait for it and read its result.
    #[tokio::test]
    async fn concurrent_refreshes_of_one_directory_walk_it_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().expect("tempdir");
        let walks = Arc::new(AtomicUsize::new(0));
        let results = futures_util::future::join_all(
            std::iter::repeat_with(|| cached_dir_stats(dir.path(), counted_walk(&walks))).take(5),
        )
        .await;
        assert!(results.iter().all(|stats| stats.files() == 7));
        assert_eq!(walks.load(Ordering::SeqCst), 1);
        DIR_STATS_CACHE.lock().remove(dir.path());
    }

    /// A load cancelled mid-walk leaves the walk running: the next load
    /// reads its result instead of walking again.
    #[tokio::test]
    async fn a_cancelled_refresh_still_publishes_its_walk() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().expect("tempdir");
        let walks = Arc::new(AtomicUsize::new(0));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                cached_dir_stats(dir.path(), counted_walk(&walks)),
            )
            .await
            .is_err(),
            "the first load is cancelled before its 50 ms walk ends"
        );
        let stats = cached_dir_stats(dir.path(), counted_walk(&walks)).await;
        assert_eq!(stats.files(), 7);
        assert_eq!(
            walks.load(Ordering::SeqCst),
            1,
            "the cancelled walk was kept"
        );
        DIR_STATS_CACHE.lock().remove(dir.path());
    }

    #[test]
    fn efficiency_sorts_by_the_saved_share() {
        assert_eq!(efficiency_key(0, 0), None);
        assert_eq!(efficiency_key(100, 1000), Some(900));
        assert_eq!(efficiency_key(1000, 1000), Some(0));
        assert_eq!(efficiency_key(1500, 1000), Some(-500));
        assert_eq!(efficiency_key(0, u64::MAX), Some(1000));
    }

    #[test]
    fn merge_min_and_max_treat_none_as_absent() {
        assert_eq!(merge_min(None, None), None);
        assert_eq!(merge_max(None, None), None);

        assert_eq!(merge_min(Some(at(5)), None), Some(at(5)));
        assert_eq!(merge_min(None, Some(at(5))), Some(at(5)));
        assert_eq!(merge_max(Some(at(5)), None), Some(at(5)));
        assert_eq!(merge_max(None, Some(at(5))), Some(at(5)));

        assert_eq!(merge_min(Some(at(5)), Some(at(9))), Some(at(5)));
        assert_eq!(merge_min(Some(at(9)), Some(at(5))), Some(at(5)));
        assert_eq!(merge_max(Some(at(5)), Some(at(9))), Some(at(9)));
        assert_eq!(merge_max(Some(at(9)), Some(at(5))), Some(at(9)));
    }

    #[test]
    fn dir_stats_merge_sums_counts_and_folds_extremes() {
        let mut acc = DirStats::default();
        acc.merge(DirStats {
            size: 300,
            byhash_files: 1,
            deb_files: 2,
            metadata_files: 1,
            max_file_size: 200,
            oldest_mtime: Some(at(50)),
            newest_mtime: Some(at(80)),
        });
        // A mirror whose walk saw no mtimes leaves the extremes untouched.
        acc.merge(DirStats {
            size: 10,
            byhash_files: 0,
            deb_files: 0,
            metadata_files: 1,
            max_file_size: 10,
            oldest_mtime: None,
            newest_mtime: None,
        });
        acc.merge(DirStats {
            size: 1000,
            byhash_files: 2,
            deb_files: 0,
            metadata_files: 2,
            max_file_size: 900,
            oldest_mtime: Some(at(20)),
            newest_mtime: Some(at(70)),
        });

        assert_eq!(acc.files(), 6);
        assert_eq!(acc.size, 1310);
        assert_eq!(acc.byhash_files, 3);
        assert_eq!(acc.deb_files, 2);
        assert_eq!(acc.metadata_files, 4);
        assert_eq!(acc.deb_files + acc.metadata_files, acc.files());
        assert_eq!(acc.max_file_size, 900);
        assert_eq!(acc.oldest_mtime, Some(at(20)));
        assert_eq!(acc.newest_mtime, Some(at(80)));
    }

    #[test]
    fn dir_stats_merge_into_default_is_identity() {
        let stats = DirStats {
            size: 2,
            byhash_files: 3,
            deb_files: 4,
            metadata_files: 5,
            max_file_size: 6,
            oldest_mtime: Some(at(7)),
            newest_mtime: Some(at(8)),
        };
        let mut acc = DirStats::default();
        acc.merge(stats);
        assert_eq!(acc.files(), 9);
        assert_eq!(acc.size, 2);
        assert_eq!(acc.byhash_files, 3);
        assert_eq!(acc.deb_files, 4);
        assert_eq!(acc.metadata_files, 5);
        assert_eq!(acc.max_file_size, 6);
        assert_eq!(acc.oldest_mtime, Some(at(7)));
        assert_eq!(acc.newest_mtime, Some(at(8)));
    }
}
