//! The dashboard page (`/`): gathers every section concurrently into
//! [`DashboardData`] and assembles the page from it. The details sections
//! (Daemon Status, Configuration, Maintenance, Cache Statistics) are built
//! here; the row tables come from [`super::tables`] and the Metrics section
//! from [`super::metrics_page`].

use std::{
    borrow::Cow,
    fmt::{self, Display, Formatter},
};

use coarsetime::Instant;
use tracing::error;

use crate::{
    AppState, LOGSTORE, RUNTIMEDETAILS, RuntimeDetails,
    build_info::{APP_VERSION, get_features},
    cache_metadata,
    cleanup::{CLEANUP_INTERVAL_SECS, next_cleanup_epoch},
    client_counter::{active_client_downloads, connected_clients},
    config::HttpsUpgradeMode,
    database::{Database, MirrorStatEntry},
    error::ErrorReport,
    global_cache_quota, global_config,
    healthcheck::{Check, HealthReport, cached_health_report},
    humanfmt::HumanFmt,
    metrics, swrite,
    tunnel_limiter::active_tunnels,
    uncacheables::{UNCACHEABLES_MAX, get_uncacheables},
    warn_once_or_debug,
};

use super::{
    fmt::{
        CacheHitRatio, Colorize, DiskUsage, EnabledDisabled, FmtMTimeAge, FmtTimestamp, HtmlEscape,
        MinRate, OptOrUnlimited, OptSize, Pct, RatioClass, Utc, Window, YesNo, as_size,
    },
    metrics_page::build_metrics_html,
    page::{
        Page, PageTitle, QueryOptions, build_heading_html, build_nav_html, build_page,
        build_setup_hint_html,
    },
    response::WebResponse,
    table::{
        DetailsList, write_collapsible_details, write_collapsible_section, write_section,
        write_section_error,
    },
    tables::{
        DirStats, Section, TopPackagesView, build_client_table, build_mirror_table,
        build_origin_table, build_top_packages_table, build_uncacheable_table,
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
    configuration_html: String,
    maintenance_html: String,
    cache_stats_html: String,
    metrics_html: String,
    health_html: String,
    hero_html: String,
    healthy: bool,
    /// Whether any mirror has ever been contacted. A dashboard of zeroes on
    /// a fresh install needs the setup hint more than it needs the tables.
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

/// Fetch the mirror list and walk each mirror's cache directory to populate
/// the Mirrors table. Returns the loaded mirrors (used downstream for the
/// Maintenance and Cache Statistics sections), the rendered table
/// [`Section`], the aggregated `DirStats`, the free disk space reported
/// by `statvfs`, and the wall-clock time spent in the FS walks (separated
/// from `db_elapsed` for the dashboard footer).
///
/// The mirror list is `None` when the query failed, which callers must not
/// collapse into the empty list: "no mirror is known" and "no mirror has
/// ever been seen" lead to opposite pages.
///
/// This is a free async fn rather than an inline `tokio::join!` branch so
/// rustc can prove `Send` for the future without tripping over higher-rank
/// lifetime auto-trait inference at the spawn site.
async fn build_mirror_section(
    database: &Database,
    now_epoch: i64,
) -> (
    Option<Vec<MirrorStatEntry>>,
    Section,
    DirStats,
    Option<u64>,
    std::time::Duration,
) {
    let config = global_config();

    let mirrors_result = database.get_mirrors_with_stats().await;
    let fs_start = Instant::now();
    let (mirrors, section, agg) = match mirrors_result {
        Ok(m) => {
            let (section, aggregate) =
                build_mirror_table(&m, now_epoch, &config.cache_directory).await;
            (Some(m), section, aggregate)
        }
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to query the mirrors for the dashboard; rendering the mirror section with an error notice:  {}",
                ErrorReport(&err)
            );
            let mut buf = String::new();
            write_section_error(&mut buf, "mirrors", &err);
            (None, Section { html: buf, rows: 0 }, DirStats::default())
        }
    };

    // statvfs() can stall on slow/hung filesystems (NFS, FUSE, dying disks);
    // run it on the blocking pool so it cannot wedge the tokio worker.
    let free_disk_bytes = {
        let result =
            tokio::task::spawn_blocking(|| nix::sys::statvfs::statvfs(&config.cache_directory))
                .await
                .expect("task should not panic");

        let stat = result
            .inspect_err(|err| {
                warn_once_or_debug!(
                    "statvfs({}) failed:  {err}",
                    config.cache_directory.display()
                );
            })
            .ok();

        stat.and_then(|s| s.blocks_available().checked_mul(s.fragment_size()))
    };

    (
        mirrors,
        section,
        agg,
        free_disk_bytes,
        fs_start.elapsed().into(),
    )
}

async fn gather_dashboard_data(appstate: &AppState) -> DashboardData {
    let start = Instant::now();

    let now = Utc::now();
    let now_epoch = now.inner().unix_timestamp();

    let day_cutoff = now_epoch.saturating_sub(24 * 60 * 60);
    let week_cutoff = now_epoch.saturating_sub(7 * 24 * 60 * 60);

    // Run all DB queries and the (DB+FS) mirror builder concurrently. The
    // mirror branch waits on `get_mirrors_with_stats`, then drives the
    // per-mirror directory scans; the rest of the dashboard's DB queries
    // proceed in parallel with that FS work instead of blocking on it.
    let parallel_start = Instant::now();
    let (
        (mirrors, mirror, aggregate_dir_stats, free_disk_bytes, fs_elapsed),
        origin,
        client,
        top_packages_by_count,
        top_packages_by_size,
        bandwidth_day_result,
        bandwidth_week_result,
    ) = tokio::join!(
        build_mirror_section(&appstate.database, now_epoch),
        build_origin_table(&appstate.database, now_epoch),
        build_client_table(&appstate.database, now_epoch),
        build_top_packages_table(&appstate.database, TopPackagesView::ByCount),
        build_top_packages_table(&appstate.database, TopPackagesView::BySize),
        appstate.database.get_bandwidth_since(day_cutoff),
        appstate.database.get_bandwidth_since(week_cutoff),
    );
    // "DB elapsed" approximates the wall-clock cost of the parallel block
    // attributable to non-FS work — i.e. everything except the mirror
    // directory scans, which are reported separately as `fs_elapsed`.
    let total_parallel: std::time::Duration = parallel_start.elapsed().into();
    let db_elapsed = total_parallel.saturating_sub(fs_elapsed);

    // A failed mirror query is not evidence of a fresh install. Suppress the
    // setup hint in that case: pairing "No mirror has been contacted yet.
    // Point apt at this proxy" with a Mirrors section already showing a
    // database error tells an established operator to reinstall.
    let seen_traffic = match &mirrors {
        None => true,
        Some(mirrors) => !mirrors.is_empty(),
    };
    let mirrors = mirrors.unwrap_or_default();

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

    let active_mirror_downloads = appstate.active_downloads.len();
    let memory_stats = memory_stats::memory_stats();

    let https_mode = match rd.config.https_upgrade_mode {
        HttpsUpgradeMode::Auto => "Auto",
        HttpsUpgradeMode::Always => "Always",
        HttpsUpgradeMode::Never => "Never",
    };

    // Sample utilization so the peak metric reflects long idle stretches.
    let cache_size = global_cache_quota().current_size();
    global_cache_quota().sample_utilization_peak_with(cache_size);

    let next_cleanup_epoch = next_cleanup_epoch();

    let daemon_status_html = build_daemon_status_html(
        rd,
        now,
        memory_stats,
        database_size,
        active_mirror_downloads,
    );

    let configuration_html = build_configuration_html(rd, https_mode);
    let maintenance_html = build_maintenance_html(&mirrors, now_epoch, next_cleanup_epoch);

    let cache_stats_html = build_cache_stats_html(
        &mirrors,
        bandwidth_day_result,
        bandwidth_week_result,
        &aggregate_dir_stats,
        cache_size,
        free_disk_bytes,
        rd,
    );

    let metrics_html = build_metrics_html();
    let health_report = cached_health_report().await;
    let healthy = health_report.healthy();
    let health_html = build_health_html(&health_report);
    let hero_html = build_hero_html(
        &mirrors,
        cache_size,
        rd.config.disk_quota.map(std::num::NonZero::get),
        healthy,
    );

    DashboardData {
        mirror,
        origin,
        client,
        uncacheable,
        top_packages_by_count,
        top_packages_by_size,
        daemon_status_html,
        configuration_html,
        maintenance_html,
        cache_stats_html,
        metrics_html,
        health_html,
        hero_html,
        healthy,
        seen_traffic: !mirrors.is_empty(),
        generation_start: start,
        db_elapsed,
        fs_elapsed,
    }
}

/// The one thing the daemon exists to do, at the top of the page: bytes in
/// from upstream, bytes out to clients, and the difference it kept. That
/// difference was previously the third cell of the fourth card, in the same
/// weight as the mmap threshold.
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

fn build_hero_html(
    mirrors: &[MirrorStatEntry],
    cache_size: u64,
    quota: Option<u64>,
    healthy: bool,
) -> String {
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
        "<div class=\"hero\">\
         <div class=\"flow\">\
         <span><span class=\"k\">fetched upstream</span><span class=\"v\">{}</span></span>\
         <span class=\"arrow\">\u{2192}</span>\
         <span><span class=\"k\">served to clients</span><span class=\"v\">{}</span></span>\
         </div>\
         <div class=\"saved\"><span class=\"k\">bandwidth saved{}</span>\
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

    let (state_class, state_text) = if healthy {
        ("ok", "healthy")
    } else {
        ("bad", "unhealthy")
    };
    swrite!(
        html,
        "<div class=\"right\"><span class=\"k\">cache</span>\
         <span class=\"v\">{}</span>\
         <span class=\"state {state_class}\">{state_text}</span></div></div>",
        DiskUsage { cache_size, quota },
    );
    html
}

/// The five readiness checks the `/healthcheck` endpoint reports, rendered
/// on the page so an operator does not have to fetch JSON to learn whether
/// the daemon is serving.
fn build_health_html(report: &HealthReport) -> String {
    struct CheckCell<'a> {
        ok: bool,
        detail: Option<&'a str>,
    }
    impl Display for CheckCell<'_> {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            if self.ok {
                f.write_str("<span class=\"ok\">OK</span>")
            } else {
                write!(
                    f,
                    "<span class=\"alert\">{}</span>",
                    HtmlEscape(self.detail.unwrap_or("failed")),
                )
            }
        }
    }

    let mut t = DetailsList::new();
    for check in report.checks() {
        let Check {
            key: _,
            label,
            ok,
            detail,
        } = check;
        t.row(label, CheckCell { ok, detail });
    }
    t.finish()
}

fn build_daemon_status_html(
    rd: &RuntimeDetails,
    now: Utc,
    memory_stats: Option<memory_stats::MemoryStats>,
    database_size: Option<u64>,
    active_mirror_downloads: usize,
) -> String {
    let start = Utc::from_offset(rd.start_time);

    let logstore = LOGSTORE.get().expect("initialized in main()");
    let log_entries = logstore.entries().len();
    let log_cap = rd.config.logstore_capacity.get();
    let log_class = RatioClass::new(log_entries as u64, log_cap as u64);

    let mut t = DetailsList::new();
    t.row("Version", APP_VERSION);
    t.row("Features", get_features(false).replace('\n', " "));
    t.row(
        "Start Time",
        format_args!(
            "{start} (up {})",
            HumanFmt::Time((now.inner() - rd.start_time).unsigned_abs())
        ),
    );
    t.row("Current Time", now);
    {
        let phys = OptSize {
            bytes: memory_stats.map(|m| m.physical_mem as u64),
            fallback: "N/A",
        };
        let virt = OptSize {
            bytes: memory_stats.map(|m| m.virtual_mem as u64),
            fallback: "N/A",
        };
        t.row("Memory Usage", format_args!("{phys} ({virt} virtual)"));
        t.row(
            "Database Size",
            OptSize {
                bytes: database_size,
                fallback: "N/A",
            },
        );
    }
    t.row(
        "Connected Clients",
        format_args!(
            "{} (peak {})",
            connected_clients(),
            metrics::CONNECTED_CLIENTS_PEAK.get(),
        ),
    );
    if let Some(cap) = rd.config.max_connections {
        t.row_tip(
            "Connection Cap (global)",
            "`max_connections`: connections beyond it are closed at accept time. Defaults to three quarters of the soft RLIMIT_NOFILE.",
            cap,
        );
    }
    if let Some(cap) = rd.config.max_connections_per_client_ip {
        t.row_tip(
            "Per-Client-IP Connections (peak / cap)",
            "Highest concurrent connection count observed from any single source IP since startup, against the configured cap. Use to right-size `max_connections_per_client_ip`.",
            format_args!("{} / {}", metrics::PER_CLIENT_IP_PEAK.get(), cap),
        );
    }
    t.row(
        "Active Upstream Downloads",
        format_args!(
            "{active_mirror_downloads} / {} (peak {})",
            OptOrUnlimited(rd.config.max_upstream_downloads),
            metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.get(),
        ),
    );
    t.row(
        "Active Client Downloads",
        format_args!(
            "{} (peak {})",
            active_client_downloads(),
            metrics::ACTIVE_CLIENT_DOWNLOADS_PEAK.get(),
        ),
    );
    t.row("Active HTTPS Tunnels", active_tunnels());
    t.row_tip(
        "Metadata Cache Entries",
        "Process-local entries cached from per-file ETag and Last-Modified xattrs. Skips fgetxattr(2) on subsequent conditional-request hits; rebuilt lazily after restart.",
        cache_metadata::store().len(),
    );
    t.row(
        "Log Entries",
        format_args!(
            "{} / {log_cap}",
            Colorize {
                inner: log_entries,
                class: log_class,
            }
        ),
    );
    t.finish()
}

fn build_configuration_html(rd: &RuntimeDetails, https_mode: &'static str) -> String {
    let mut t = DetailsList::new();
    t.row(
        "Bind Address + Port",
        format_args!("{} : {}", rd.config.bind_addr, rd.config.bind_port),
    );
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
    t.row("Buffer Size", HumanFmt::Size(rd.config.buffer_size as u64));
    t.row(
        "Mmap Threshold",
        HumanFmt::Size(rd.config.mmap_threshold.get()),
    );
    t.row(
        "Reject pdiff Requests",
        YesNo(rd.config.reject_pdiff_requests),
    );
    t.row(
        "Usage Retention",
        match rd.config.usage_retention_days {
            Some(d) => Cow::Owned(format!("{} days", d.get())),
            None => Cow::Borrowed("forever"),
        },
    );
    t.row(
        "ByHash Retention",
        format_args!("{} days", rd.config.byhash_retention_days),
    );
    t.row("Log Buffer Capacity", rd.config.logstore_capacity);
    t.row("Allowed Mirrors", rd.config.allowed_mirrors.len());
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
    /// Renders `<timestamp> (<rel>)` if epoch > 0, otherwise just `FmtTimestamp` (= "N/A").
    struct EpochAndRel {
        epoch: i64,
        rel: std::time::Duration,
        rel_label: &'static str,
    }
    impl Display for EpochAndRel {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            Display::fmt(&FmtTimestamp(self.epoch), f)?;
            if self.epoch != 0 {
                write!(f, " ({} {})", HumanFmt::Time(self.rel), self.rel_label)?;
            }
            Ok(())
        }
    }

    let last_cleanup_epoch = mirrors.iter().map(|m| m.last_cleanup).max().unwrap_or(0);
    let cleanup_interval = HumanFmt::Time(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
    // Only meaningful when last_cleanup_epoch != 0; EpochAndRel ignores it otherwise,
    // so don't fabricate a multi-decade duration from the 0 sentinel.
    let last_rel = if last_cleanup_epoch == 0 {
        std::time::Duration::ZERO
    } else {
        std::time::Duration::from_secs(as_size(now_epoch.saturating_sub(last_cleanup_epoch)))
    };
    let next_rel =
        std::time::Duration::from_secs(as_size(next_cleanup_epoch.saturating_sub(now_epoch)));

    let mut t = DetailsList::new();
    t.row(
        "Last Cleanup",
        EpochAndRel {
            epoch: last_cleanup_epoch,
            rel: last_rel,
            rel_label: "ago",
        },
    );
    t.row("Cleanup Interval", cleanup_interval);
    t.row(
        "Next Cleanup",
        EpochAndRel {
            epoch: next_cleanup_epoch,
            rel: next_rel,
            rel_label: "from now",
        },
    );
    t.finish()
}

fn build_cache_stats_html(
    mirrors: &[MirrorStatEntry],
    bandwidth_day_result: Result<(i64, i64), sqlx::Error>,
    bandwidth_week_result: Result<(i64, i64), sqlx::Error>,
    aggregate: &DirStats,
    cache_size: u64,
    free_disk_bytes: Option<u64>,
    rd: &RuntimeDetails,
) -> String {
    let total_download_count: i64 = mirrors.iter().map(|m| m.download_count).sum();
    let total_delivery_count: i64 = mirrors.iter().map(|m| m.delivery_count).sum();
    let cache_hits = total_delivery_count.saturating_sub(total_download_count);

    let uncacheable_count = get_uncacheables().read().len();

    let bandwidth_day = match bandwidth_day_result {
        Ok(v) => Some(v),
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to query the 24h bandwidth window; the dashboard reports it as N/A:  {}",
                ErrorReport(&err)
            );
            None
        }
    };
    let bandwidth_week = match bandwidth_week_result {
        Ok(v) => Some(v),
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to query the 7d bandwidth window; the dashboard reports it as N/A:  {}",
                ErrorReport(&err)
            );
            None
        }
    };

    // The lifetime fetched/served/saved triple lives in the hero; repeating
    // it here would be the same three numbers twice on one screen.
    let mut t = DetailsList::new();
    t.row(
        "Cache Hit Ratio (persisted)",
        CacheHitRatio {
            hits: cache_hits,
            total: total_delivery_count,
        },
    );
    t.row("Bandwidth (last 24h)", Window(bandwidth_day));
    t.row("Bandwidth (last 7d)", Window(bandwidth_week));
    t.row("Uncacheable Resources", uncacheable_count);
    t.row(
        "Cached Files",
        format_args!(
            "{} debs / {} metadata / {} by-hash",
            aggregate.deb_files, aggregate.metadata_files, aggregate.byhash_files
        ),
    );
    t.row("Oldest Cached File", FmtMTimeAge(aggregate.oldest_mtime));
    t.row("Newest Cached File", FmtMTimeAge(aggregate.newest_mtime));
    t.row(
        "Total Disk Usage",
        DiskUsage {
            cache_size,
            quota: rd.config.disk_quota.map(std::num::NonZero::get),
        },
    );

    let free_disk_space = if let Some(free) = free_disk_bytes {
        let quota = rd.config.disk_quota.map(std::num::NonZero::get);
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

    t.row("Free Disk Space", free_disk_space);

    t.finish()
}

fn build_dashboard_page(data: &DashboardData, options: QueryOptions) -> String {
    let log_count = LOGSTORE
        .get()
        .expect("initialized in main()")
        .entries()
        .len();
    let nav = build_nav_html(Page::Dashboard { log_count }, options);

    let mut body = String::with_capacity(8 * 1024);
    body.push_str(&nav);
    body.push_str(&build_heading_html());

    if !data.seen_traffic {
        body.push_str(&build_setup_hint_html(
            RUNTIMEDETAILS
                .get()
                .expect("initialized in main()")
                .config
                .bind_port,
        ));
    }

    body.push_str(&data.hero_html);

    // Expanded only when something failed: healthy is already stated in the
    // hero, and a reader opening this section wants the detail, not five
    // lines of OK.
    write_collapsible_details(
        &mut body,
        "Health",
        "health-head",
        !data.healthy,
        &data.health_html,
    );

    write_collapsible_section(
        &mut body,
        "Mirrors",
        "mirrors-head",
        data.mirror.rows,
        None,
        "No mirror has served a request yet.",
        &data.mirror.html,
    );
    write_collapsible_section(
        &mut body,
        "Origins",
        "origins-head",
        data.origin.rows,
        None,
        "No Packages index has been fetched yet, so no distribution, component or architecture is known.",
        &data.origin.html,
    );
    write_collapsible_section(
        &mut body,
        "Clients",
        "clients-head",
        data.client.rows,
        None,
        "No client has fetched anything through this proxy yet.",
        &data.client.html,
    );

    let total_package_rows = data
        .top_packages_by_count
        .rows
        .max(data.top_packages_by_size.rows);
    let mut top_packages_body = String::with_capacity(
        data.top_packages_by_count.html.len() + data.top_packages_by_size.html.len() + 128,
    );
    swrite!(
        top_packages_body,
        "<div class=\"grid-2\">\
         <div><h4 class=\"mini\">By Delivery Count</h4>{}</div>\
         <div><h4 class=\"mini\">By Total Size</h4>{}</div>\
         </div>",
        data.top_packages_by_count.html,
        data.top_packages_by_size.html,
    );
    write_collapsible_section(
        &mut body,
        "Top Packages",
        "packages-head",
        total_package_rows,
        None,
        "No package has been delivered yet.",
        &top_packages_body,
    );

    write_collapsible_section(
        &mut body,
        "Uncacheables",
        "uncacheables-head",
        data.uncacheable.rows,
        Some(UNCACHEABLES_MAX.get()),
        "Nothing has been requested that the cache had to pass through untouched.",
        &data.uncacheable.html,
    );

    // Reference and diagnostics last: read once at setup, or when something
    // is wrong. Configuration in particular used to sit second, above the
    // figures anyone actually opens this page for.
    write_section(&mut body, "Cache Statistics", &data.cache_stats_html);
    write_section(&mut body, "Daemon Status", &data.daemon_status_html);
    write_collapsible_details(
        &mut body,
        "Maintenance",
        "maintenance-head",
        false,
        &data.maintenance_html,
    );
    write_collapsible_details(
        &mut body,
        "Configuration",
        "configuration-head",
        false,
        &data.configuration_html,
    );
    write_collapsible_details(
        &mut body,
        "Metrics",
        "metrics-head",
        false,
        &data.metrics_html,
    );

    // Rounded to whole milliseconds so the three figures share a unit;
    // `HumanFmt::Time` otherwise mixes "30.0ms" with "1.00ms" in one line.
    let whole_ms = |d: std::time::Duration| {
        HumanFmt::Time(std::time::Duration::from_millis(
            u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
        ))
    };
    swrite!(
        body,
        "<footer><hr><p>All dates are in UTC. Generated in {} (db {}, disk {}).</p></footer>",
        whole_ms(data.generation_start.elapsed().into()),
        whole_ms(data.db_elapsed),
        whole_ms(data.fs_elapsed),
    );

    build_page(PageTitle("apt-cacher-rs"), body, options)
}

pub(super) async fn serve_dashboard(appstate: &AppState, options: QueryOptions) -> WebResponse {
    let data = gather_dashboard_data(appstate).await;
    let html = build_dashboard_page(&data, options);
    WebResponse::html(html)
}
