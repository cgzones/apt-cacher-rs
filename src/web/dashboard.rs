//! The dashboard page (`/`): gathers every section concurrently into
//! [`DashboardData`] and assembles the page from it. The details sections
//! (Daemon Status, Configuration, Maintenance, Cache Statistics) are built
//! here; the row tables come from [`super::tables`] and the Metrics section
//! from [`super::metrics_page`].

use std::{
    fmt::{self, Display, Formatter},
    net::SocketAddr,
    path::Path,
    sync::Arc,
};

use coarsetime::Instant;
use tracing::error;

use crate::{
    AppState, LOGSTORE, RUNTIMEDETAILS, RuntimeDetails,
    active_downloads::ActiveDownloads,
    build_info::{APP_VERSION, FEATURES_ONE_LINE},
    cache_metadata,
    cleanup::{CLEANUP_INTERVAL_SECS, next_cleanup_epoch},
    client_counter::{active_client_downloads, busiest_client_connections, connected_clients},
    client_trouble,
    config::HttpsUpgradeMode,
    database::{
        BandwidthWindows, ClientStatEntry, Database, MirrorStatEntry, OriginEntry, TopPackages,
    },
    database_task::DB_TASK_QUEUE_SENDER,
    error::ErrorReport,
    fd_usage, global_cache_quota, global_checksum_registry, global_config, global_verify_throttle,
    healthcheck::{CHECK_TIMEOUT, ProbeSlot, ProbedSpace, probe_filesystem_space},
    humanfmt::HumanFmt,
    integrity,
    main_loop::LISTEN_ADDR,
    mem_usage::{self, Footprint, ProcessMemory},
    metrics, mirror_health, mirror_indexes, mirror_perf,
    passthrough_limiter::active_relays,
    permitted_host_cache, scheme_cache, swrite,
    tunnel_limiter::{active_tunnels, busiest_client_tunnels},
    uncacheables::{UNCACHEABLES_MAX, get_uncacheables},
    verify_throttle, warn_once_or_debug,
};

use super::{
    fmt::{
        CacheHitRatio, Colorize, Count, DiskUsage, EnabledDisabled, FmtMTimeAge, Gauge, HtmlEscape,
        MinRate, OptOrUnlimited, OptSize, Pct, RatioClass, RelTime, Saturation, Utc, Window, YesNo,
        as_size, now_epoch, warn_if,
    },
    metrics_page::build_metrics_html,
    page::{
        Heading, Page, PageTitle, PinLink, QueryOptions, SetupHint, build_nav_html, build_page,
    },
    response::WebResponse,
    table::{
        DetailsList, Highlights, Kind, Rows, write_collapsible_details,
        write_collapsible_details_badged, write_collapsible_section, write_section,
    },
    tables::{
        DirStats, MirrorSnapshots, Section, TOP_PACKAGES_LIMIT, TopPackagesView,
        build_mirror_table, build_uncacheable_table, db_error_section, render_client_table,
        render_origin_table, render_top_packages_table,
    },
};

// ---------------------------------------------------------------------------
// Data gathering
// ---------------------------------------------------------------------------

struct DashboardData {
    mirror: Section,
    origin: Section,
    client: Section,
    uncacheable: Section,
    top_packages_by_count: Section,
    top_packages_by_size: Section,
    daemon_status_html: String,
    /// One gauge per limiter; see [`build_capacity_html`].
    capacity_html: String,
    /// The process's memory and each store's share; see [`build_memory_html`].
    memory_html: String,
    configuration_html: String,
    maintenance_html: String,
    cache_stats_html: String,
    metrics_html: String,
    /// Highlighted rows in the collapsed Metrics section, shown on its
    /// header so an alert is not hidden behind the fold.
    metrics_highlights: Highlights,
    hero_html: String,
    /// Whether any mirror has ever been contacted. A dashboard of zeroes on
    /// a fresh install needs the setup hint more than it needs the tables.
    /// A failed mirror query counts as traffic: see `gather_dashboard_data`.
    seen_traffic: bool,
    generation_start: Instant,
    /// Wall-clock time spent on the parallel DB-query block (mirrors,
    /// origins, clients, top packages, bandwidth) — excluding the FS work
    /// tracked separately in `fs_elapsed`.
    db_elapsed: std::time::Duration,
    /// Wall-clock time the mirror-section branch spent on FS work after
    /// the initial `get_mirrors_with_stats` query: the per-mirror directory
    /// walks, the (small) `DIR_STATS_CACHE` prune and the `statvfs` probe.
    /// Subtracted from the total parallel time to produce `db_elapsed`.
    fs_elapsed: std::time::Duration,
}

/// Every dashboard query that scans the whole `downloads` / `deliveries`
/// history, fetched as one unit so the memo below can cover all of them.
struct DashboardAggregates {
    /// Also feeds the Maintenance and Cache Statistics sections. A *failed*
    /// mirror query must not reach them as an empty list: "no mirror is
    /// known" and "no mirror has ever been seen" lead to opposite pages, so
    /// the failure stays an `Err` in [`AggregateResults`] instead.
    mirrors: Vec<MirrorStatEntry>,
    origins: Vec<OriginEntry>,
    clients: Vec<ClientStatEntry>,
    top_packages: TopPackages,
    bandwidth: BandwidthWindows,
}

/// The same five results before the all-or-nothing check, so a partial
/// failure still renders four good sections and one error notice.
struct AggregateResults {
    mirrors: Result<Vec<MirrorStatEntry>, sqlx::Error>,
    origins: Result<Vec<OriginEntry>, sqlx::Error>,
    clients: Result<Vec<ClientStatEntry>, sqlx::Error>,
    top_packages: Result<TopPackages, sqlx::Error>,
    bandwidth: Result<BandwidthWindows, sqlx::Error>,
}

/// Memoized aggregate block. A `tokio::sync::Mutex` held *across* the
/// refresh gives single-flight semantics, as `healthcheck::HEALTH_CACHE`
/// does: concurrent dashboard loads queue behind one pass over the usage
/// tables instead of each issuing its own.
static AGGREGATE_CACHE: tokio::sync::Mutex<Option<(Instant, Arc<DashboardAggregates>)>> =
    tokio::sync::Mutex::const_new(None);

/// Memoization window. Deliberately short: the page's auto-refresh defaults
/// to 30 s and goes down to 1 s (`page::QueryOptions`), so a longer window
/// would render identical numbers on consecutive refreshes. This slot exists
/// to collapse a burst — concurrent loads, a rapid manual reload — not to
/// serve a stale page.
const AGGREGATES_TTL: coarsetime::Duration = coarsetime::Duration::from_secs(5);

/// Serve the memoized aggregates, refreshing them when older than
/// [`AGGREGATES_TTL`].
///
/// The slot is populated only when every query succeeded. `sqlx::Error` is
/// not `Clone`, so a failure could not be stored anyway, and returning the
/// raw per-query results on a partial failure keeps today's behaviour: each
/// section renders its own error notice and the next load retries at once.
async fn cached_aggregates(
    database: &Database,
    now_epoch: i64,
) -> Result<Arc<DashboardAggregates>, Box<AggregateResults>> {
    let mut cache = AGGREGATE_CACHE.lock().await;
    if let Some((at, aggregates)) = cache.as_ref()
        && at.elapsed() < AGGREGATES_TTL
    {
        return Ok(Arc::clone(aggregates));
    }

    let day_cutoff = now_epoch.saturating_sub(24 * 60 * 60);
    let week_cutoff = now_epoch.saturating_sub(7 * 24 * 60 * 60);

    // The five queries run concurrently on this one task; the lock is held
    // across them so concurrent loads queue behind this single flight.
    let results = tokio::join!(
        database.get_mirrors_with_stats(),
        database.get_origins(),
        database.get_clients_with_stats(),
        database.get_top_packages(TOP_PACKAGES_LIMIT),
        database.get_bandwidth_windows(day_cutoff, week_cutoff),
    );

    match results {
        (Ok(mirrors), Ok(origins), Ok(clients), Ok(top_packages), Ok(bandwidth)) => {
            let aggregates = Arc::new(DashboardAggregates {
                mirrors,
                origins,
                clients,
                top_packages,
                bandwidth,
            });
            // Timestamp taken after the queries complete, not before, so a
            // slow pass does not pre-expire its own entry.
            *cache = Some((Instant::now(), Arc::clone(&aggregates)));
            drop(cache);
            Ok(aggregates)
        }
        (mirrors, origins, clients, top_packages, bandwidth) => {
            drop(cache);
            Err(Box::new(AggregateResults {
                mirrors,
                origins,
                clients,
                top_packages,
                bandwidth,
            }))
        }
    }
}

/// Drop the memoized aggregates so the next dashboard load re-queries.
///
/// Called by the cleanup task: cleanup is the only thing that *removes* rows
/// (orphan mirror rows, stale origins, expired usage logs), and an operator
/// who has just run a cleanup reloads the page precisely to see it took
/// effect. Row *insertions* need no invalidation — a count a few seconds
/// behind is what [`AGGREGATES_TTL`] already accepts.
pub(crate) async fn invalidate_aggregates() {
    *AGGREGATE_CACHE.lock().await = None;
}

/// Walk each mirror's cache directory for the Mirrors table and probe the
/// filesystem for free space. The DB half of what used to be one
/// `build_mirror_section` now rides the memoized aggregate block; what is
/// left is the FS work the dashboard footer reports as `disk`.
///
/// This is a free async fn rather than an inline `tokio::join!` branch so
/// rustc can prove `Send` for the future without tripping over higher-rank
/// lifetime auto-trait inference at the spawn site.
async fn build_mirror_fs_section(
    mirrors: &[MirrorStatEntry],
    snapshots: &MirrorSnapshots,
    now_epoch: i64,
) -> (Section, DirStats, Option<u64>) {
    let config = global_config();

    let ((section, aggregate), free_disk_bytes) = tokio::join!(
        build_mirror_table(mirrors, snapshots, now_epoch, config),
        free_disk_bytes(&config.cache_directory),
    );

    (section, aggregate, free_disk_bytes)
}

/// The dashboard's own `statvfs(3)` slot (see [`probe_filesystem_space`]).
static DISK_FREE_PROBE: ProbeSlot = ProbeSlot::new();

/// The last free-space figure and when it was taken. The lock is held across
/// the probe, so concurrent loads wait for the one in flight and read its
/// result rather than finding the slot busy: `StillBlocked` then only means
/// a probe that outran its deadline, or one a cancelled load left running.
static DISK_FREE_MEMO: tokio::sync::Mutex<Option<(Instant, Option<u64>)>> =
    tokio::sync::Mutex::const_new(None);

/// How long a free-space figure is reused.
const DISK_FREE_TTL: coarsetime::Duration = coarsetime::Duration::from_secs(1);

/// Free bytes on the cache filesystem for the footer, `None` (shown as
/// unknown) when they could not be measured. `statvfs(3)` can hang on a
/// stuck network filesystem or a failing disk, and a timeout only stops the
/// waiting, so the call goes through [`DISK_FREE_PROBE`]: one stuck probe
/// holds one blocking-pool thread, not one per dashboard load.
async fn free_disk_bytes(cache_dir: &Path) -> Option<u64> {
    memoized_free_bytes(&DISK_FREE_MEMO, cache_dir, || {
        probe_filesystem_space(&DISK_FREE_PROBE, CHECK_TIMEOUT, cache_dir)
    })
    .await
}

/// [`free_disk_bytes`] with the memo and the probe passed in, so the
/// coalescing is testable without a filesystem to hang.
async fn memoized_free_bytes<F>(
    memo: &tokio::sync::Mutex<Option<(Instant, Option<u64>)>>,
    cache_dir: &Path,
    probe: impl FnOnce() -> F,
) -> Option<u64>
where
    F: Future<Output = ProbedSpace>,
{
    let mut memo = memo.lock().await;
    if let Some((at, free)) = *memo
        && at.elapsed() < DISK_FREE_TTL
    {
        return free;
    }
    let free = match probe().await {
        ProbedSpace::Measured(space) => space.map(|space| space.free_bytes),
        ProbedSpace::TimedOut => {
            warn_once_or_debug!(
                "Failed to measure the free space of the filesystem holding `{}` within {}; showing it as unknown on the dashboard",
                cache_dir.display(),
                HumanFmt::Time(CHECK_TIMEOUT)
            );
            None
        }
        ProbedSpace::StillBlocked => {
            warn_once_or_debug!(
                "Failed to measure the free space of the filesystem holding `{}`: an earlier statvfs(3) of it has not returned; showing it as unknown on the dashboard",
                cache_dir.display()
            );
            None
        }
    };
    *memo = Some((Instant::now(), free));
    free
}

async fn gather_dashboard_data(appstate: &AppState) -> DashboardData {
    let start = Instant::now();

    let now = Utc::now();
    let now_epoch = now.inner().unix_timestamp();

    // The whole aggregate block, memoized: one pass over the usage tables
    // per `AGGREGATES_TTL` no matter how many loads arrive. Timed directly
    // rather than derived by subtracting the FS work, so the footer's `db`
    // figure is exact — and reads ~0 on a memo hit, which is accurate: this
    // render did no database work.
    let db_start = Instant::now();
    let aggregates = cached_aggregates(&appstate.database, now_epoch).await;
    let db_elapsed: std::time::Duration = db_start.elapsed().into();

    // Normalize the memo hit and the partial-failure path into one set of
    // per-section results, so each section below is rendered exactly once.
    let (mirrors, origins, clients, top_packages, bandwidth) = match &aggregates {
        Ok(agg) => (
            Ok(agg.mirrors.as_slice()),
            Ok(agg.origins.as_slice()),
            Ok(agg.clients.as_slice()),
            Ok(&agg.top_packages),
            Ok(agg.bandwidth),
        ),
        Err(results) => (
            results.mirrors.as_deref(),
            results.origins.as_deref(),
            results.clients.as_deref(),
            results.top_packages.as_ref(),
            results.bandwidth.as_ref().copied(),
        ),
    };

    // One snapshot of the in-memory per-mirror figures for both tables.
    let snapshots = MirrorSnapshots {
        health: mirror_health::snapshot(),
        perf: mirror_perf::snapshot(),
        indexes: mirror_indexes::snapshot(),
    };
    let origin = match origins {
        Ok(rows) => render_origin_table(rows, &snapshots.indexes, now_epoch),
        Err(err) => db_error_section("origins", err),
    };
    let client = match clients {
        Ok(rows) => render_client_table(rows, &client_trouble::snapshot(), now_epoch),
        Err(err) => db_error_section("clients", err),
    };
    // Both tables come from one query, so one failure is one log line and one
    // notice text shown twice — not two independent section failures.
    let (top_packages_by_count, top_packages_by_size) = match top_packages {
        Ok(pkgs) => (
            render_top_packages_table(&pkgs.by_count, TopPackagesView::ByCount),
            render_top_packages_table(&pkgs.by_size, TopPackagesView::BySize),
        ),
        Err(err) => {
            let notice = db_error_section("top packages", err);
            (notice.clone(), notice)
        }
    };

    // A failed mirror query is not evidence of a fresh install. Suppress the
    // setup hint in that case: pairing "No mirror has been contacted yet.
    // Point apt at this proxy" with a Mirrors section already showing a
    // database error tells an established operator to reinstall.
    let mirror_rows = mirrors.unwrap_or_default();
    let seen_traffic = mirrors.is_err() || !mirror_rows.is_empty();

    // The FS half of the Mirrors section: the per-mirror directory walks and
    // the `statvfs` probe, reported as `disk` in the footer.
    //
    // This runs *after* the aggregate block rather than beside it, because
    // the mirror rows it walks come from that block. The walk used to start
    // as soon as `get_mirrors_with_stats` resolved and overlap the remaining
    // queries, so a load missing both memos (the 5s one here, the 60s
    // `DIR_STATS_TTL_SECS` in the walk -- a 30s auto-refresh misses this one
    // every time and that one every other time) now pays `db + disk` where
    // it used to pay roughly the larger of the two. The penalty is bounded
    // by the aggregate block's own duration, and folding the duplicate scans
    // away cut that from 726ms to 201ms on a ~400k-row `deliveries` table:
    // below a ~525ms cold walk the sequential path is still the faster of
    // the two, and above it the gap asymptotes to ~200ms of a multi-second
    // load. Restoring the overlap costs a second memo slot for the mirror
    // query alone; measure a large cache before paying for it, and note
    // that the walk's own per-file blocking-pool hop (R4 in
    // `docs/perf-review-2026-09-02.md`) is the bigger lever there.
    let fs_start = Instant::now();
    let (mirror_table, aggregate_dir_stats, free_disk_bytes) =
        build_mirror_fs_section(mirror_rows, &snapshots, now_epoch).await;
    let fs_elapsed: std::time::Duration = fs_start.elapsed().into();
    let mirror = match mirrors {
        Ok(_rows) => mirror_table,
        Err(err) => db_error_section("mirrors", err),
    };

    let uncacheable = build_uncacheable_table();

    let rd = RUNTIMEDETAILS.get().expect("initialized in main()");
    let database_size = match tokio::fs::metadata(&rd.config.database_path).await {
        Ok(data) => Some(data.len()),
        Err(err) => {
            error!(
                "Failed to stat the database file `{}`; reporting its size as unknown on the dashboard:  {}",
                rd.config.database_path.display(),
                ErrorReport(&err)
            );
            None
        }
    };

    // Slots, not entries: the row shows this beside the cap and the peak,
    // which both count `UpstreamSlot`s, so the three share a unit. A download
    // whose upstream connection is back in the pool but whose commit is still
    // running counts in `len()` (the shutdown summary), not here.
    let active_mirror_downloads = appstate.active_downloads.upstream_slots();
    let process_memory = mem_usage::process_memory();

    // Sample utilization so the peak metric reflects long idle stretches.
    let cache_size = global_cache_quota().current_size();
    global_cache_quota().sample_utilization_peak_with(cache_size);

    let next_cleanup_epoch = next_cleanup_epoch();

    let daemon_status_html = build_daemon_status_html(rd, now, process_memory, database_size);
    let capacity_html = build_capacity_html(rd, active_mirror_downloads);
    let memory_html = build_memory_html(rd, process_memory, &appstate.active_downloads);

    let configuration_html = build_configuration_html(rd);
    let maintenance_html = build_maintenance_html(mirror_rows, now_epoch, next_cleanup_epoch);

    let cache_stats_html = build_cache_stats_html(
        mirror_rows,
        bandwidth,
        &aggregate_dir_stats,
        cache_size,
        free_disk_bytes,
        rd,
    );

    let (metrics_html, metrics_highlights) = build_metrics_html(rd.start_time.unix_timestamp());
    let hero_html = build_hero_html(
        mirror_rows,
        cache_size,
        rd.config.disk_quota.map(std::num::NonZero::get),
    );

    DashboardData {
        mirror,
        origin,
        client,
        uncacheable,
        top_packages_by_count,
        top_packages_by_size,
        daemon_status_html,
        capacity_html,
        memory_html,
        configuration_html,
        maintenance_html,
        cache_stats_html,
        metrics_html,
        metrics_highlights,
        hero_html,
        seen_traffic,
        generation_start: start,
        db_elapsed,
        fs_elapsed,
    }
}

/// A duration in milliseconds, fixed unit and fixed precision.
///
/// The footer's three figures are read against each other, so they have to
/// share a unit: `HumanFmt::Time` picks one per value and mixes "30.0ms"
/// with "412us" on one line. Rounding to whole milliseconds first shares the
/// unit but renders every sub-millisecond figure as "0ns", which is how the
/// disk timing read on an idle daemon.
struct Millis(std::time::Duration);

impl Display for Millis {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:.2}ms", self.0.as_secs_f64() * 1000.0)
    }
}

/// The share of what clients asked for that never left the cache, as a
/// parenthesised suffix; nothing at all before anything has been served.
///
/// `saved` is the figure the hero prints beside it, not a second derivation
/// of it: the two have to agree, and a percentage computed from unclamped
/// totals reads `-8.3%` next to a `0B` headline whenever more has been
/// fetched than delivered.
struct SavedShare {
    saved: u64,
    delivered: i64,
}

impl Display for SavedShare {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.delivered <= 0 {
            return Ok(());
        }
        write!(
            f,
            " ({})",
            Pct {
                num: i64::try_from(self.saved).unwrap_or(i64::MAX),
                den: self.delivered,
            }
        )
    }
}

/// The one thing the daemon exists to do, at the top of the page: bytes in
/// from upstream, bytes out to clients, and the difference it kept. That
/// difference was previously the third cell of the fourth card, in the same
/// weight as the buffer size.
fn build_hero_html(mirrors: &[MirrorStatEntry], cache_size: u64, quota: Option<u64>) -> String {
    let downloaded_raw: i64 = mirrors.iter().map(|m| m.total_download_size).sum();
    let delivered_raw: i64 = mirrors.iter().map(|m| m.total_delivery_size).sum();
    let downloaded = as_size(downloaded_raw);
    let delivered = as_size(delivered_raw);
    // Floors at zero. A mirror can have fetched more than it has delivered
    // (bodies still in flight, clients gone mid-download), and "-4.2GB of
    // bandwidth saved" is not a thing the cache can have done.
    let saved = delivered.saturating_sub(downloaded);

    let mut html = String::with_capacity(1024);
    swrite!(
        html,
        "<div class=\"hero\" data-section=\"hero\">\
         <div class=\"flow\">\
         <span><span class=\"k\">fetched upstream</span><span class=\"v\">{}</span></span>\
         <span class=\"arrow\">\u{2192}</span>\
         <span><span class=\"k\">served to clients</span><span class=\"v\">{}</span></span>\
         </div>\
         <div class=\"saved\"><span class=\"k\">bandwidth saved{} <span class=\"scope\" title=\"Totals from the database: they survive restarts.\">persisted</span></span>\
         <span class=\"big\">{}</span></div>",
        HumanFmt::Size(downloaded),
        HumanFmt::Size(delivered),
        // Suppressed until something has been served: "(N/A)" beside a 0B
        // figure is the first thing a new install reads.
        SavedShare {
            saved,
            delivered: delivered_raw,
        },
        HumanFmt::Size(saved),
    );

    swrite!(
        html,
        "<div class=\"right\"><span class=\"k\">cache</span>\
         <span class=\"v\">{}</span></div></div>",
        DiskUsage { cache_size, quota },
    );
    html
}

fn build_daemon_status_html(
    rd: &RuntimeDetails,
    now: Utc,
    process_memory: Option<ProcessMemory>,
    database_size: Option<u64>,
) -> String {
    let mut t = DetailsList::new();
    t.row("Version", APP_VERSION);
    t.row("Features", FEATURES_ONE_LINE);
    t.row(
        "Start Time",
        format_args!(
            "{} (up {})",
            RelTime {
                epoch: rd.start_time.unix_timestamp(),
                now: now.inner().unix_timestamp(),
            },
            HumanFmt::Time((now.inner() - rd.start_time).unsigned_abs())
        ),
    );
    t.entry("Memory Usage")
        .kind(Kind::Live)
        .tip("The process's resident set; the Memory section says what holds it.")
        .value(format_args!(
            "{} ({} virtual)",
            OptSize {
                bytes: process_memory.map(|m| m.resident),
                fallback: "N/A",
            },
            OptSize {
                bytes: process_memory.map(|m| m.virtual_size),
                fallback: "N/A",
            },
        ));
    t.entry("Database Size").kind(Kind::Live).value(OptSize {
        bytes: database_size,
        fallback: "N/A",
    });
    t.entry("Active Client Downloads")
        .kind(Kind::Live)
        .value(format_args!(
            "{} <span class=\"peak\">peak {}</span>",
            Count::len(active_client_downloads()),
            Count(metrics::ACTIVE_CLIENT_DOWNLOADS_PEAK.get()),
        ));
    t.finish()
}

/// A store's row value: its estimated heap, with the entry count against
/// the cap beside it, e.g. `~83.2MB 385 396 / 500 000 entries`. The tilde
/// marks the estimate (see `mem_usage`); the process figures above the
/// stores carry none.
struct StoreUsage {
    footprint: Footprint,
    cap: Option<usize>,
}

impl Display for StoreUsage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { footprint, cap } = self;
        write!(
            f,
            "~{} <span class=\"peak\">{}",
            HumanFmt::Size(footprint.bytes as u64),
            Count::len(footprint.entries)
        )?;
        if let Some(cap) = cap {
            write!(f, " / {}", Count::len(*cap))?;
        }
        f.write_str(" entries</span>")
    }
}

/// The SQLite row's tip; the allocator row it refers to is glibc-only.
const SQLITE_TIP: &str = if cfg!(target_env = "gnu") {
    "What the database engine holds: the page cache of each pool connection (up to 2 MiB each by default), prepared statements and schema copies. Part of the allocator heap above."
} else {
    "What the database engine holds: the page cache of each pool connection (up to 2 MiB each by default), prepared statements and schema copies."
};

/// The Memory section: what the kernel and the allocator measure, then the
/// daemon's own stores with their estimated share, so an operator reading
/// a large resident set can tell a registry sized to its cap from allocator
/// slack or an index ingest in flight.
fn build_memory_html(
    rd: &RuntimeDetails,
    process_memory: Option<ProcessMemory>,
    active_downloads: &ActiveDownloads,
) -> String {
    let config = &rd.config;
    let mut html = String::with_capacity(8192);
    html.push_str(
        "<p class=\"scope-note\">Measured figures first, then the daemon's stores that grow with the cache's content, with their estimated heap. Left out, holding an entry per mirror or one in all: the database task's mirror ids, the dashboard's directory sizes and its memoized aggregates. What the stores leave unaccounted for is transfer buffers (buffer_size per connection), TLS sessions, index decoding in flight, the runtime and the allocator's own overhead.</p>",
    );
    let mut t = DetailsList::new();

    let resident = t
        .entry("Resident")
        .kind(Kind::Live)
        .tip("Pages of this process in RAM, as top and systemd report it. Anonymous pages are the heap and the thread stacks; file-backed ones are the binary, its libraries and SQLite's WAL index, shared with every process mapping them; shared pages are tmpfs or System V shared memory, normally none.");
    match process_memory {
        Some(memory) => {
            let ProcessMemory {
                resident: total,
                anonymous,
                file_backed,
                shared,
                peak_resident,
                virtual_size,
            } = memory;
            resident
                .parts(|parts| {
                    parts.row("Anonymous", HumanFmt::Size(anonymous));
                    parts.row("File-backed", HumanFmt::Size(file_backed));
                    parts.row("Shared", HumanFmt::Size(shared));
                })
                .note(format_args!(
                    "peak {} since start; {} virtual",
                    HumanFmt::Size(peak_resident),
                    HumanFmt::Size(virtual_size)
                ))
                .value(HumanFmt::Size(total));
        }
        None => resident.value("N/A"),
    }

    #[cfg(target_env = "gnu")]
    {
        let stats = mem_usage::allocator_stats();
        t.entry("Allocator Heap")
            .kind(Kind::Live)
            .tip("glibc malloc's account of the heap: the bytes handed out and still held, and the bytes free inside its arenas, mostly blocks freed since and kept for reuse (those stay resident; an arena's untouched top does not). The allocator gives memory back by itself only from an arena's top, so a burst (an index decode, a large dashboard query) can leave the retained figure high for good; it is not a leak.")
            .note(format_args!(
                "{} freed but retained; {} of the in-use bytes mapped directly",
                HumanFmt::Size(stats.retained),
                HumanFmt::Size(stats.mmapped)
            ))
            .value(format_args!("{} in use", HumanFmt::Size(stats.in_use)));
    }

    let sqlite = mem_usage::sqlite_memory();
    t.entry("SQLite")
        .kind(Kind::Live)
        .tip(SQLITE_TIP)
        .note(format_args!(
            "peak {} since start",
            HumanFmt::Size(sqlite.peak)
        ))
        .value(HumanFmt::Size(sqlite.used));

    let mut total = Footprint::default();
    let mut store = |t: &mut DetailsList,
                     label: &'static str,
                     tip: &'static str,
                     footprint: Footprint,
                     cap: Option<usize>| {
        total += footprint;
        t.entry(label)
            .kind(Kind::Live)
            .tip(tip)
            .value(StoreUsage { footprint, cap });
    };

    store(
        &mut t,
        "Checksum Registry",
        "Expected SHA-256 digests parsed from Packages and Release indexes, against verify_checksums_max_entries: each file's digest, keyed by its name, in eviction order. The largest store by far once a few indexes are ingested; lower the cap to trade memory for re-ingests (Metrics: Integrity, Re-ingests).",
        global_checksum_registry().footprint(),
        Some(config.verify_checksums_max_entries.get()),
    );
    store(
        &mut t,
        "Metadata Cache",
        "Per-file ETag and Last-Modified validators read from xattrs once, so a conditional request on a cached file costs no fgetxattr(2); the entries of one mirror share a single copy of it. Cleared and refilled past its cap; rebuilt lazily after a restart.",
        cache_metadata::store().footprint(),
        Some(cache_metadata::CACHE_METADATA_MAX_ENTRIES),
    );
    let (ledger, ledger_cap) = integrity::ingest_ledger_footprint();
    store(
        &mut t,
        "Ingest Ledger",
        "The cached index files whose digests the registry holds, by path, so an index served from cache is only re-decoded when its digests are missing.",
        ledger,
        Some(ledger_cap),
    );
    store(
        &mut t,
        "Active Downloads",
        "Downloads in flight, one entry per resource, shared by every client waiting on it; gone once the file is committed.",
        active_downloads.footprint(),
        None,
    );
    store(
        &mut t,
        "Verify Throttle",
        "Resources in checksum-failure backoff (Metrics: Integrity, Mismatch); empty unless a mirror serves content its own index disagrees with.",
        global_verify_throttle().footprint(),
        Some(verify_throttle::MAX_THROTTLE_ENTRIES),
    );
    store(
        &mut t,
        "Permitted Hosts",
        "Host headers and redirect targets already checked against allowed_mirrors, by their raw spelling, so a repeat costs no re-validation.",
        permitted_host_cache::footprint(),
        Some(permitted_host_cache::PERMITTED_HOST_CACHE_MAX_ENTRIES),
    );
    store(
        &mut t,
        "Scheme Cache",
        "The scheme (HTTP or HTTPS) last known good for each upstream host, which https_upgrade_mode consults.",
        scheme_cache::footprint(),
        None,
    );
    store(
        &mut t,
        "Mirror Tables",
        "Per-mirror performance, health and index-age records behind the Mirrors table, one of each per mirror seen.",
        mirror_perf::footprint() + mirror_health::footprint() + mirror_indexes::footprint(),
        None,
    );
    store(
        &mut t,
        "Log Store",
        "The warnings and errors the Logs page shows: logstore_capacity entries of up to 4 KiB each, the ring reserved up front.",
        LOGSTORE.get().expect("initialized in main()").footprint(),
        Some(config.logstore_capacity.get()),
    );
    t.entry("Stores Total")
        .kind(Kind::Live)
        .tip("The estimated heap of every store above together; compare with the allocator's in-use figure.")
        .value(StoreUsage {
            footprint: total,
            cap: None,
        });

    html.push_str(&t.finish());
    html
}

/// A configured `usize` cap as the `u64` every gauge renders.
fn cap_of(cap: Option<std::num::NonZero<usize>>) -> Option<u64> {
    cap.map(|cap| cap.get() as u64)
}

/// The Capacity section: one gauge per limiter -- live count against its
/// cap, peak since start -- with how long the limiter spent at its cap and
/// the share of admissions it refused, so an operator can tell a cap sized
/// too low (long at cap, a real refusal share) from a burst.
fn build_capacity_html(rd: &RuntimeDetails, active_mirror_downloads: usize) -> String {
    let config = &rd.config;
    let mut t = DetailsList::new();
    let mut html = String::with_capacity(4096);
    swrite!(
        html,
        "<p class=\"scope-note\">Live values against their caps. Peaks, time at cap and refusal shares count since the daemon started, {}.</p>",
        RelTime {
            epoch: rd.start_time.unix_timestamp(),
            now: Utc::now().inner().unix_timestamp(),
        }
    );

    let open_fds = t
        .entry("Open File Descriptors")
        .kind(Kind::Live)
        .tip("Sockets, cache files, splice pipes and the database this process holds, against its soft RLIMIT_NOFILE. At the cap accept(2) fails with EMFILE (Metrics: Descriptor Exhaustion) and new downloads cannot open their files. Raise LimitNOFILE= in the service unit, or lower max_connections, which by default takes three quarters of the limit.");
    // Sampled now too, so the peak is never below the figure beside it.
    match fd_usage::sample() {
        Some(current) => {
            let (soft, hard) = fd_usage::nofile_limit();
            open_fds
                .note(format_args!(
                    "hard limit {}; peak sampled every {} s",
                    OptOrUnlimited(hard.map(Count)),
                    fd_usage::SAMPLE_INTERVAL.as_secs()
                ))
                .value(Gauge {
                    current,
                    cap: soft,
                    peak: Some(metrics::OPEN_FDS_PEAK.get()),
                });
        }
        None => open_fds.value("N/A"),
    }

    let refused = metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP.get();
    let mut slots = t.entry("Upstream Download Slots")
        .kind(Kind::Live)
        .tip("Downloads with an upstream connection open, against max_upstream_downloads; a new download past it is refused with 503. Long at cap with a real refusal share means the cap is below the load (or a slow mirror holds slots: see the Mirrors table).");
    // No cap, nothing to saturate.
    if config.max_upstream_downloads.is_some() {
        slots = slots.note(Saturation {
            at_cap: metrics::UPSTREAM_DOWNLOAD_CAP_CLOCK.total(),
            refused,
            attempts: metrics::UPSTREAM_DOWNLOADS_ADMITTED.get() + refused,
            verb: "refused",
        });
    }
    slots.value(Gauge {
        current: active_mirror_downloads as u64,
        cap: cap_of(config.max_upstream_downloads),
        peak: Some(metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.get()),
    });

    let refused = metrics::PASSTHROUGH_REJECTED_CAP.get();
    let mut relays = t.entry("Passthrough Relays")
        .kind(Kind::Live)
        .tip("Uncached requests currently relayed to an upstream, against max_passthrough_relays; a relay past it is refused with 503.");
    if config.max_passthrough_relays.is_some() {
        relays = relays.note(Saturation {
            at_cap: metrics::PASSTHROUGH_CAP_CLOCK.total(),
            refused,
            attempts: metrics::PASSTHROUGH_ADMITTED.get() + refused,
            verb: "refused",
        });
    }
    relays.value(Gauge {
        current: active_relays() as u64,
        cap: cap_of(config.max_passthrough_relays),
        peak: Some(metrics::PASSTHROUGH_ACTIVE_PEAK.get()),
    });

    let accepted = metrics::CONNECTIONS_ACCEPTED.get();
    let mut connected = t
        .entry("Connected Clients")
        .kind(Kind::Live)
        .tip("Open client connections, against max_connections (by default three quarters of the soft RLIMIT_NOFILE); a connection past it is closed at accept time. Raise max_connections and LimitNOFILE together.");
    if config.max_connections.is_some() {
        let refused = metrics::CONNECTION_REJECTED_GLOBAL_CAP.get();
        connected = connected.note(format_args!(
            "refused {} of {} accepted connections",
            Count(refused),
            Count(accepted)
        ));
    }
    connected.value(Gauge {
        current: connected_clients() as u64,
        cap: cap_of(config.max_connections),
        peak: Some(metrics::CONNECTED_CLIENTS_PEAK.get()),
    });

    if let Some(cap) = config.max_connections_per_client_ip {
        t.entry("Connections per Client IP")
        .kind(Kind::Live)
            .tip("Connections held by the busiest single source IP (IPv6 by client_ipv6_prefix_len network when below 128), against max_connections_per_client_ip; its next connection is closed at accept time. The peak is the most any IP held since start: deploy generously, watch it settle, then lower the cap to a margin above it. The Clients table names refused clients.")
            .note(Saturation {
                at_cap: metrics::CONNECTION_PER_IP_CAP_CLOCK.total(),
                refused: metrics::CONNECTION_REJECTED_PER_IP_CAP.get(),
                attempts: accepted,
                verb: "refused",
            })
            .value(Gauge {
                current: busiest_client_connections() as u64,
                cap: Some(cap.get() as u64),
                peak: Some(metrics::PER_CLIENT_IP_PEAK.get()),
            });
    }

    if config.https_tunnel_enabled {
        t.entry("HTTPS Tunnels")
        .kind(Kind::Live)
            .tip("CONNECT tunnels open across all clients. There is no global tunnel cap; the per-client one is the row beside it.")
            .value(format_args!(
                "{} <span class=\"peak\">peak {}</span>",
                Count::len(active_tunnels()),
                Count(metrics::CONNECT_TUNNEL_ACTIVE_PEAK.get())
            ));
        if let Some(cap) = config.https_tunnel_max_connections_per_client {
            let refused = metrics::TUNNEL_REJECTED_CAPACITY.get();
            t.entry("HTTPS Tunnels per Client")
        .kind(Kind::Live)
                .tip("Tunnels held by the busiest single source IP, against https_tunnel_max_connections_per_client; its next CONNECT is refused with 429. The Clients table names refused clients.")
                .note(Saturation {
                    at_cap: metrics::TUNNEL_PER_CLIENT_CAP_CLOCK.total(),
                    refused,
                    attempts: metrics::TUNNEL_CONNECTS_TOTAL.get() + refused,
                    verb: "refused",
                })
                .value(Gauge {
                    current: busiest_client_tunnels() as u64,
                    cap: Some(cap.get() as u64),
                    peak: None,
                });
        }
    }

    let database_tx = DB_TASK_QUEUE_SENDER
        .get()
        .expect("Sender initialized in main_loop()");
    let channel_max = database_tx.max_capacity();
    t.entry("DB Command Queue")
        .kind(Kind::Live)
        .tip("Commands and reserved slots against db_channel_capacity. Time at cap is sampled at send and receive boundaries; brief transitions between samples can be missed. While it is full, request paths wait on database writes: raise db_channel_capacity, or flush sooner with db_batch_flush_max_count / db_batch_flush_interval_secs.")
        .note(Saturation {
            at_cap: metrics::DB_QUEUE_CAP_CLOCK.total(),
            refused: metrics::DB_QUEUE_FULL_WAITS.get(),
            attempts: metrics::DB_COMMANDS_SENT.get(),
            verb: "found full",
        })
        .value(Gauge {
            current: channel_max.saturating_sub(database_tx.capacity()) as u64,
            cap: Some(channel_max as u64),
            peak: Some(metrics::DB_QUEUE_DEPTH_PEAK.get()),
        });

    let logstore = LOGSTORE.get().expect("initialized in main()");
    t.entry("Log Ring")
        .kind(Kind::Live)
        .tip("Entries held for the /logs page, against logstore_capacity. A full ring is normal: the oldest entry makes room for the newest. Raise logstore_capacity to reach further back.")
        .note(format_args!(
            "{} evicted since start",
            Count(metrics::LOGSTORE_EVICTIONS.get())
        ))
        .value(Gauge {
            current: logstore.len() as u64,
            cap: Some(config.logstore_capacity.get() as u64),
            peak: None,
        });

    html.push_str(&t.finish());
    html
}

/// A retention window in days, or `"forever"` when it is unlimited.
struct Retention(Option<std::num::NonZero<u64>>);

impl Display for Retention {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(days) => write!(f, "{days} days"),
            None => f.write_str("forever"),
        }
    }
}

fn build_configuration_html(rd: &RuntimeDetails) -> String {
    let https_mode = match rd.config.https_upgrade_mode {
        HttpsUpgradeMode::Auto => "Auto",
        HttpsUpgradeMode::Always => "Always",
        HttpsUpgradeMode::Never => "Never",
    };

    // The address actually bound, which differs from the configured `::`
    // after the IPv4 fallback; `SocketAddr` brackets an IPv6 address.
    let configured = SocketAddr::from((rd.config.bind_addr, rd.config.bind_port.get()));
    let listening = LISTEN_ADDR.get().copied().unwrap_or(configured);
    let fallback_note = if listening == configured {
        ""
    } else {
        " (IPv4 only: this host has no IPv6)"
    };

    let mut t = DetailsList::new();
    t.row("Listening On", format_args!("{listening}{fallback_note}"));
    t.row(
        "Cache Directory",
        HtmlEscape(&rd.config.cache_directory.to_string_lossy()),
    );
    t.row(
        "Database Path",
        HtmlEscape(&rd.config.database_path.to_string_lossy()),
    );
    t.row(
        "HTTP Timeout",
        format_args!("{:.0}s", rd.config.http_timeout.as_secs_f64()),
    );
    t.row("HTTPS Upgrade Mode", https_mode);
    t.row(
        "HTTPS Tunnel",
        EnabledDisabled(rd.config.https_tunnel_enabled),
    );
    t.row("Min Download Rate", MinRate(rd.config.min_download_rate));
    t.row(
        "Rate Check Timeframe",
        format_args!("{}s", rd.config.rate_check_timeframe),
    );
    t.row(
        "Max Upstream Downloads",
        OptOrUnlimited(rd.config.max_upstream_downloads),
    );
    t.row(
        "Disk Quota",
        OptSize {
            bytes: rd.config.disk_quota.map(std::num::NonZero::get),
            fallback: "None",
        },
    );
    t.row(
        "Buffer Size",
        HumanFmt::BinarySize(rd.config.buffer_size as u64),
    );
    t.row(
        "Reject pdiff Requests",
        YesNo(rd.config.reject_pdiff_requests),
    );
    t.row("Usage Retention", Retention(rd.config.usage_retention_days));
    t.row(
        "ByHash Retention",
        format_args!("{} days", rd.config.byhash_retention_days),
    );
    t.row("Log Buffer Capacity", rd.config.logstore_capacity);
    t.row("Allowed Mirrors", rd.config.allowed_mirrors.len());
    t.row("Allowed Mirror Ports", rd.config.allowed_mirror_ports.len());
    t.row("HTTP-Only Mirrors", rd.config.http_only_mirrors.len());
    t.row(
        "Allowed Tunnel Ports",
        rd.config.https_tunnel_allowed_ports.len(),
    );
    t.row(
        "Allowed Tunnel Mirrors",
        rd.config.https_tunnel_allowed_mirrors.len(),
    );
    t.row("Aliases", rd.config.aliases.len());
    t.row("Allowed Clients", rd.config.allowed_proxy_clients.len());
    t.finish()
}

fn build_maintenance_html(
    mirrors: &[MirrorStatEntry],
    now_epoch: i64,
    next_cleanup_epoch: i64,
) -> String {
    let last_cleanup_epoch = mirrors.iter().map(|m| m.last_cleanup).max().unwrap_or(0);

    let mut t = DetailsList::new();
    t.entry("Last Cleanup")
        .kind(Kind::Persisted)
        .tip("The newest cleanup recorded for any mirror in the database, so it survives restarts. The Metrics section's Cleanup rows cover this process's own runs.")
        .value(RelTime {
            epoch: last_cleanup_epoch,
            now: now_epoch,
        });
    t.row(
        "Cleanup Interval",
        HumanFmt::Time(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS)),
    );
    t.row(
        "Next Cleanup",
        RelTime {
            epoch: next_cleanup_epoch,
            now: now_epoch,
        },
    );
    t.finish()
}

fn build_cache_stats_html(
    mirrors: &[MirrorStatEntry],
    bandwidth_result: Result<BandwidthWindows, &sqlx::Error>,
    aggregate: &DirStats,
    cache_size: u64,
    free_disk_bytes: Option<u64>,
    rd: &RuntimeDetails,
) -> String {
    let now = now_epoch();
    let total_download_count: i64 = mirrors.iter().map(|m| m.download_count).sum();
    let total_delivery_count: i64 = mirrors.iter().map(|m| m.delivery_count).sum();
    // Floored at 0: the two counts are pruned independently, so more
    // downloads than deliveries can be on record.
    let cache_hits = total_delivery_count
        .saturating_sub(total_download_count)
        .max(0);

    let uncacheable_count = get_uncacheables().len();

    // One statement covers both windows, so they succeed or fail together.
    let (bandwidth_day, bandwidth_week) = match bandwidth_result {
        Ok(windows) => (Some(windows.day), Some(windows.week)),
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to query the bandwidth windows; the dashboard reports both as N/A:  {}",
                ErrorReport(err)
            );
            (None, None)
        }
    };

    // The lifetime fetched/served/saved triple lives in the hero; repeating
    // it here would be the same three numbers twice on one screen.
    let mut t = DetailsList::new();
    t.entry("Cache Hit Ratio")
        .kind(Kind::Persisted)
        .tip("Client deliveries not preceded by an upstream fetch, over all deliveries: from the database, so it spans restarts (and usage_retention_days).")
        .value(CacheHitRatio {
            hits: cache_hits,
            total: total_delivery_count,
        },
    );
    t.entry("Bandwidth (last 24h)")
        .kind(Kind::Persisted)
        .value(Window(bandwidth_day));
    t.entry("Bandwidth (last 7d)")
        .kind(Kind::Persisted)
        .value(Window(bandwidth_week));
    t.entry("Uncacheable Resources")
        .kind(Kind::Live)
        .tip("Recently seen uncacheable (host, path) resources the Uncacheables section lists, against the fixed number it keeps; the oldest makes room for the newest.")
        .value(Gauge {
            current: uncacheable_count as u64,
            cap: Some(UNCACHEABLES_MAX.get() as u64),
            peak: None,
        });
    t.entry("Cached Files")
        .kind(Kind::Live)
        .tip("From a walk of the mirror directories, cached for up to a minute.")
        .value(format_args!(
            "{} debs / {} metadata / {} by-hash",
            Count::len(aggregate.deb_files),
            Count::len(aggregate.metadata_files),
            Count::len(aggregate.byhash_files)
        ));
    t.entry("Oldest Cached File")
        .kind(Kind::Live)
        .value(FmtMTimeAge {
            mtime: aggregate.oldest_mtime,
            now,
        });
    t.entry("Newest Cached File")
        .kind(Kind::Live)
        .value(FmtMTimeAge {
            mtime: aggregate.newest_mtime,
            now,
        });

    let quota = rd.config.disk_quota.map(std::num::NonZero::get);
    t.entry("Total Disk Usage")
        .kind(Kind::Live)
        .value(DiskUsage { cache_size, quota });

    // The timestamp first: it is set after the pair, so finding it set
    // means the pair is that scan's.
    let scanned_at = metrics::ORPHANED_PARTIALS_SCANNED_AT.get();
    let orphans = t
        .entry("Orphaned Partials")
        .tip("Kept .partial downloads no running download holds, found by the last cache scan (at startup and after every cleanup): the resume state of downloads that failed or were abandoned, counted against disk_quota until cleanup removes them after 24 h. Warns above a tenth of disk_quota. A large figure means downloads keep dying mid-body: see Downloads Aborted and the Mirrors table for the mirror.");
    if scanned_at == 0 {
        orphans.value("no cache scan yet");
    } else {
        let files = metrics::ORPHANED_PARTIAL_FILES.get();
        let bytes = metrics::ORPHANED_PARTIAL_BYTES.get();
        orphans
            .note(format_args!(
                "at the last cache scan, {}",
                RelTime {
                    epoch: i64::try_from(scanned_at).unwrap_or(i64::MAX),
                    now,
                }
            ))
            .value(warn_if(
                format_args!(
                    "{} file{}, {}",
                    Count(files),
                    if files == 1 { "" } else { "s" },
                    HumanFmt::Size(bytes)
                ),
                orphans_over_quota_share(bytes, quota),
            ));
    }

    let free_disk_space = if let Some(free) = free_disk_bytes {
        let remaining_quota = quota.map(|q| q.saturating_sub(cache_size));
        let class = match remaining_quota {
            Some(rq) if free < rq => RatioClass::Warn,
            _ => RatioClass::Normal,
        };
        Colorize {
            inner: format_args!("{}", HumanFmt::Size(free)),
            class,
        }
    } else {
        Colorize {
            inner: format_args!("N/A"),
            class: RatioClass::Alert,
        }
    };

    t.entry("Free Disk Space")
        .kind(Kind::Live)
        .value(free_disk_space);

    t.finish()
}

/// Whether orphaned partials take more than a tenth of `disk_quota`: a
/// share of the cache that failed downloads, not packages, occupy. Without
/// a quota there is no share to exceed.
fn orphans_over_quota_share(orphaned_bytes: u64, quota: Option<u64>) -> bool {
    quota.is_some_and(|quota| orphaned_bytes.saturating_mul(10) > quota)
}

fn build_dashboard_page(data: &DashboardData, options: QueryOptions) -> String {
    let log_count = LOGSTORE.get().expect("initialized in main()").len();
    let mut body = String::with_capacity(8 * 1024);
    let page = Page::Dashboard { log_count };
    body.push_str(&build_nav_html(page, options));
    swrite!(body, "{}", Heading);

    if !data.seen_traffic {
        let bind_port = RUNTIMEDETAILS
            .get()
            .expect("initialized in main()")
            .config
            .bind_port;
        swrite!(body, "{}", SetupHint(bind_port));
    }

    body.push_str(&data.hero_html);

    write_collapsible_section(
        &mut body,
        "Mirrors",
        "mirrors",
        Rows {
            shown: data.mirror.rows,
            total: None,
        },
        options.open.contains("mirrors"),
        "No mirror has served a request yet.",
        &data.mirror.html,
    );
    write_collapsible_section(
        &mut body,
        "Origins",
        "origins",
        Rows {
            shown: data.origin.rows,
            total: None,
        },
        options.open.contains("origins"),
        "No Packages index has been fetched yet, so no distribution, component or architecture is known.",
        &data.origin.html,
    );
    write_collapsible_section(
        &mut body,
        "Clients",
        "clients",
        Rows {
            shown: data.client.rows,
            total: None,
        },
        options.open.contains("clients"),
        "No client has fetched anything through this proxy yet.",
        &data.client.html,
    );

    let total_package_rows = data
        .top_packages_by_count
        .rows
        .max(data.top_packages_by_size.rows);
    // Left empty when neither half rendered anything, so the section falls
    // through to its empty note. Emitting the grid unconditionally would
    // make the note unreachable and leave a fresh install looking at two
    // bare sub-headings. A section error notice keeps the grid: it is
    // content, and it must not be swallowed by the note.
    let mut top_packages_body = String::new();
    if !data.top_packages_by_count.html.is_empty() || !data.top_packages_by_size.html.is_empty() {
        top_packages_body.reserve(
            data.top_packages_by_count.html.len() + data.top_packages_by_size.html.len() + 128,
        );
        swrite!(
            top_packages_body,
            "<div class=\"grid-2\">\
             <div><h3 class=\"mini\">By Delivery Count</h3>{}</div>\
             <div><h3 class=\"mini\">By Total Size</h3>{}</div>\
             </div>",
            data.top_packages_by_count.html,
            data.top_packages_by_size.html,
        );
    }
    write_collapsible_section(
        &mut body,
        "Top Packages",
        "packages",
        Rows {
            shown: total_package_rows,
            total: None,
        },
        options.open.contains("packages"),
        "No package has been delivered yet.",
        &top_packages_body,
    );

    write_collapsible_section(
        &mut body,
        "Uncacheables",
        "uncacheables",
        Rows {
            shown: data.uncacheable.rows,
            total: Some(UNCACHEABLES_MAX.get()),
        },
        options.open.contains("uncacheables"),
        "Nothing has been requested that the cache had to pass through untouched.",
        &data.uncacheable.html,
    );

    // Reference and diagnostics last: read once at setup, or when something
    // is wrong. Configuration in particular used to sit second, above the
    // figures anyone actually opens this page for.
    write_section(
        &mut body,
        "Cache Statistics",
        "cache-statistics",
        &data.cache_stats_html,
    );
    write_section(&mut body, "Capacity", "capacity", &data.capacity_html);
    write_section(&mut body, "Memory", "memory", &data.memory_html);
    write_section(
        &mut body,
        "Daemon Status",
        "daemon-status",
        &data.daemon_status_html,
    );
    // Collapsed by default, so each carries a keep-open link: without script
    // a section the reader opened would otherwise close on every
    // auto-refresh. The script hides the links; it keeps sections open
    // itself.
    let pin = |key| PinLink { key, options };
    write_collapsible_details(
        &mut body,
        "Maintenance",
        "maintenance",
        options.open.contains("maintenance"),
        pin("maintenance"),
        &data.maintenance_html,
    );
    write_collapsible_details(
        &mut body,
        "Configuration",
        "configuration",
        options.open.contains("configuration"),
        pin("configuration"),
        &data.configuration_html,
    );
    write_collapsible_details_badged(
        &mut body,
        "Metrics",
        "metrics",
        options.open.contains("metrics"),
        data.metrics_highlights,
        pin("metrics"),
        &data.metrics_html,
    );

    swrite!(
        body,
        "<footer data-section=\"footer\"><hr><p>All dates are in UTC. Page generated at {}. Generated in {} (db {}, disk {}).</p></footer>",
        Utc::now(),
        Millis(data.generation_start.elapsed().into()),
        Millis(data.db_elapsed),
        Millis(data.fs_elapsed),
    );

    build_page(PageTitle("apt-cacher-rs"), page, body, options)
}

pub(super) async fn serve_dashboard(appstate: &AppState, options: QueryOptions) -> WebResponse {
    let data = gather_dashboard_data(appstate).await;
    let html = build_dashboard_page(&data, options);
    WebResponse::html(html)
}

#[cfg(test)]
mod tests {
    /// Concurrent dashboard loads share one free-space probe and read its
    /// figure; within the memo window no probe runs at all.
    #[tokio::test(start_paused = true)]
    async fn concurrent_loads_share_one_free_space_probe() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use crate::healthcheck::FsSpace;

        static MEMO: tokio::sync::Mutex<Option<(Instant, Option<u64>)>> =
            tokio::sync::Mutex::const_new(None);
        let probes = AtomicUsize::new(0);
        let probe = || async {
            probes.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            ProbedSpace::Measured(Some(FsSpace {
                free_bytes: 42,
                inodes: None,
            }))
        };
        let dir = Path::new("/nonexistent");
        let loads = futures_util::future::join_all(
            std::iter::repeat_n(dir, 5).map(|dir| memoized_free_bytes(&MEMO, dir, probe)),
        )
        .await;
        assert_eq!(loads, [Some(42); 5]);
        assert_eq!(memoized_free_bytes(&MEMO, dir, probe).await, Some(42));
        assert_eq!(probes.load(Ordering::SeqCst), 1);
    }

    /// A probe that outran its deadline, or found the previous one still
    /// blocked, leaves the figure unknown rather than failing the page.
    #[tokio::test]
    async fn an_unmeasured_free_space_is_unknown() {
        static TIMED_OUT: tokio::sync::Mutex<Option<(Instant, Option<u64>)>> =
            tokio::sync::Mutex::const_new(None);
        static BLOCKED: tokio::sync::Mutex<Option<(Instant, Option<u64>)>> =
            tokio::sync::Mutex::const_new(None);
        let dir = Path::new("/nonexistent");
        assert_eq!(
            memoized_free_bytes(&TIMED_OUT, dir, || async { ProbedSpace::TimedOut }).await,
            None
        );
        assert_eq!(
            memoized_free_bytes(&BLOCKED, dir, || async { ProbedSpace::StillBlocked }).await,
            None
        );
    }

    use super::{Instant, Path, ProbedSpace, memoized_free_bytes, orphans_over_quota_share};

    #[test]
    fn orphans_warn_above_a_tenth_of_the_quota() {
        assert!(
            !orphans_over_quota_share(u64::MAX, None),
            "no quota, no share"
        );
        assert!(!orphans_over_quota_share(100, Some(1000)));
        assert!(orphans_over_quota_share(101, Some(1000)));
        assert!(orphans_over_quota_share(u64::MAX, Some(1)), "saturates");
    }
}
