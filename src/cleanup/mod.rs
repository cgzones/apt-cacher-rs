mod engine;
mod fetch;
mod model;
mod packages;
mod partials;
mod refs;
mod scan;
mod sweep;
mod verify;

use engine::{UnitStats, run_mirror_units};
// The hyper-less bridge (`splice/cleanup_bridge.rs`) answers in these.
#[cfg(not(feature = "hyper"))]
pub(crate) use fetch::{FetchFailure, IndexAnswer};
use model::classify_mirror;

use std::{
    path::Path,
    sync::atomic::{AtomicBool, AtomicI64, Ordering},
    time::Duration,
};

use coarsetime::Instant;
use futures_util::StreamExt as _;
use tracing::{debug, error, info, trace, warn};

use crate::{
    AppState,
    cache_paths::CachePaths,
    config::Config,
    database::Database,
    database_task,
    deb_mirror::{Mirror, nested_paths_per_row},
    error::ErrorReport,
    global_cache_quota, global_config,
    humanfmt::HumanFmt,
    limits::RETENTION_TIME,
    metrics,
    permitted_host_cache::mirror_permitted,
    sqlite_error::SqlxErrorReport,
    task_cache_scan::task_cache_scan,
    warn_once_or_debug, xattr_helpers,
};

/// Whether one cache tree of an origin-less mirror row still exists.
///
/// An I/O failure other than "absent" is logged, counted and answered `true`:
/// the row is the only record of where those files live, so dropping it because
/// the directory could not be read would orphan the whole tree -- no unit walk
/// would ever visit it again.
fn cache_tree_exists(path: &Path) -> bool {
    match path.try_exists() {
        Ok(exists) => exists,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            // Once-gated like `main_loop`'s sibling probe: one unreadable
            // cache root would otherwise emit two lines per origin-less
            // mirror row per cleanup run, all naming the same cause.
            warn_once_or_debug!(
                "Failed to check whether the cache directory `{}` exists; retaining its mirror row:  {}",
                path.display(),
                ErrorReport(&err)
            );
            true
        }
    }
}

/// Drop `origins` rows unseen for [`RETENTION_TIME`] and mirror rows that
/// have neither an origin left nor a cache tree on disk.  Both are minted by
/// client demand and only ever grew; without this every probed index would
/// cost a unit walk and an upstream fetch cascade per cleanup run forever.
/// A DB failure is logged and skipped -- the per-mirror work must still run.
async fn prune_stale_rows(database: &Database, config: &Config) {
    let now_secs = coarsetime::Clock::now_since_epoch().as_secs();
    let cutoff = Duration::from_secs(now_secs.saturating_sub(RETENTION_TIME.as_secs()));
    match database.delete_stale_origins(cutoff).await {
        Ok(0) => {}
        Ok(removed) => info!(
            "Removed {removed} origin rows not requested within {}",
            HumanFmt::Time(RETENTION_TIME)
        ),
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to remove stale origin rows; retaining them until the next cleanup run:  {}",
                SqlxErrorReport(&err)
            );
        }
    }

    let orphans = match database.get_mirrors_without_origins().await {
        Ok(orphans) => orphans,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to look up mirror rows without origins; retaining them until the next cleanup run:  {}",
                SqlxErrorReport(&err)
            );
            return;
        }
    };
    let paths = CachePaths::new(&config.cache_directory);
    let mut gone = Vec::new();
    for orphan in orphans {
        let site = orphan.entry.site();
        let has_tree = cache_tree_exists(&paths.mirror_dir(site))
            || cache_tree_exists(&paths.flat_root(site.host, site.port));
        if !has_tree {
            gone.push((orphan.id, Mirror::from(orphan.entry)));
        }
    }
    if gone.is_empty() {
        return;
    }
    let count = gone.len();
    let kept = match database_task::delete_mirrors(gone.iter().map(|&(id, _)| id).collect()).await {
        Ok(kept) => kept,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to remove {count} mirror rows without origins or cached files; retaining them until the next cleanup run:  {}",
                SqlxErrorReport(&err)
            );
            return;
        }
    };
    for (id, mirror) in gone {
        if kept.contains(&id) {
            info!(
                "Keeping mirror row {mirror} without origins or cached files; it was used during this cleanup run"
            );
        } else {
            info!("Removed mirror row {mirror} without origins or cached files");
        }
    }
}

/// Delay between daemon startup and the first scheduled cleanup run.
pub(crate) const FIRST_CLEANUP_DELAY_SECS: u64 = 60 * 60;

/// Interval between recurring cleanup runs.
pub(crate) const CLEANUP_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Unix-timestamp of the next scheduled cleanup. Updated by main.rs at startup,
/// after each scheduled tick, and after a SIGUSR2-triggered reset. A value of
/// `0` means "not yet initialized".
static NEXT_CLEANUP_EPOCH: AtomicI64 = AtomicI64::new(0);

pub(crate) fn set_next_cleanup_epoch(epoch: i64) {
    NEXT_CLEANUP_EPOCH.store(epoch, Ordering::Relaxed);
}

#[must_use]
pub(crate) fn next_cleanup_epoch() -> i64 {
    NEXT_CLEANUP_EPOCH.load(Ordering::Relaxed)
}

/// Whether a cleanup run is in progress; set by [`task_cleanup`], cleared by
/// its [`ActiveGuard`].
static TASK_ACTIVE: AtomicBool = AtomicBool::new(false);

/// RAII guard that releases the `task_cleanup` active flag on drop, so a
/// panic inside `task_cleanup_impl` cannot leave the flag stuck `true`
/// (which would block every subsequent scheduled run).
struct ActiveGuard;

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        let was_active = TASK_ACTIVE.swap(false, Ordering::AcqRel);
        debug_assert!(was_active, "cleanup state must be active after completion");
    }
}

pub(crate) async fn task_cleanup(appstate: &AppState) {
    if TASK_ACTIVE.swap(true, Ordering::AcqRel) {
        info!("Skipping cleanup task since already in progress");
        return;
    }
    let _guard = ActiveGuard;

    task_cleanup_impl(appstate).await;
}

/// Publish one run's `LAST_CLEANUP_*` figures for the dashboard, the finish
/// timestamp last.
fn publish_last_run(
    elapsed: coarsetime::Duration,
    files_removed: u64,
    bytes_removed: u64,
    failures: u64,
) {
    metrics::LAST_CLEANUP_DURATION_SECS.set(elapsed.as_secs());
    metrics::LAST_CLEANUP_FILES_REMOVED.set(files_removed);
    metrics::LAST_CLEANUP_BYTES_RECLAIMED.set(bytes_removed);
    metrics::LAST_CLEANUP_FAILURES.set(failures);
    metrics::LAST_CLEANUP_FINISHED_AT.set(coarsetime::Clock::now_since_epoch().as_secs());
}

async fn task_cleanup_impl(appstate: &AppState) {
    // Use buffer_unordered to limit concurrent cleanup tasks and avoid thundering herd
    const MAX_CONCURRENT_CLEANUP_TASKS: usize = 10;

    let config = global_config();

    let start = Instant::now();

    if !xattr_helpers::xattr_supported() {
        info!(
            "No extended attribute support on the cache filesystem; digest verification cannot be memoized, so every cycle re-hashes all files"
        );
    }

    if let Err(err) = appstate.database.cleanup_invalid_rows().await {
        metrics::DB_OPERATION_FAILED.increment();
        error!(
            "Failed to clean up invalid database rows; continuing with the cleanup run:  {}",
            SqlxErrorReport(&err)
        );
    }

    if let Some(usage_retention_days) = config.usage_retention_days {
        let retention_secs = usage_retention_days
            .get()
            .checked_mul(24 * 60 * 60)
            .expect("overflow check during config parsing");
        let now_secs = coarsetime::Clock::now_since_epoch().as_secs();
        let keep_date = Duration::from_secs(now_secs.saturating_sub(retention_secs));
        if let Err(err) = appstate.database.delete_usage_logs(keep_date).await {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to delete old usage logs; retaining them until the next cleanup run:  {}",
                SqlxErrorReport(&err)
            );
        }
    }

    prune_stale_rows(&appstate.database, config).await;

    // The mutating pre-pass (`cleanup_invalid_rows`, `delete_usage_logs`,
    // `prune_stale_rows`) is done, so drop the dashboard's memoized
    // aggregates now rather than only at the tail: the mirror lookup below
    // can abort the run after those deletions have landed, and every future
    // early return between here and the tail is covered too. Invalidating
    // mid-run is harmless -- a dashboard load during the per-mirror work
    // repopulates the slot with mid-run state, which the tail invalidation
    // clears again.
    crate::web::invalidate_dashboard_aggregates().await;

    let mirrors = match appstate.database.get_mirrors().await {
        Ok(m) => m,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to look up the mirrors to clean up; aborting this cleanup run:  {}",
                SqlxErrorReport(&err)
            );
            // Earlier steps in this task (cleanup_invalid_rows /
            // delete_usage_logs) may already have run, but no per-mirror
            // cleanup work was done; record the failed-run state so the
            // dashboard does not display stale prior-run values.
            publish_last_run(start.elapsed(), 0, 0, metrics::CLEANUP_ABORTED);
            return;
        }
    };

    trace!("Mirrors ({}): {mirrors:?}", mirrors.len());
    info!("Found {} mirrors for cleanup", mirrors.len());

    // Nested-mirror boundaries: for each mirror, the paths of the other mirrors
    // registered under the same alias-resolved (cache_host, port) whose path
    // lives *inside* this mirror's path (segment-aligned).  The flat cleanup
    // walks the on-disk flat subtree recursively, and these nested mirror roots
    // bound that walk so a parent mirror's cleanup does not age-evict files
    // belonging to a nested mirror (which has its own Packages index and its own
    // cleanup run).  Owned, so `mirrors` can be consumed by the per-future move
    // below.
    let nested_per_mirror = nested_paths_per_row(&mirrors);

    let cleanup_tasks = mirrors
        .into_iter()
        .zip(nested_per_mirror)
        .map(|(mirror, nested)| {
            // Every facet (partials, structured pool, flat, metadata, by-hash)
            // runs on the engine as one ordered per-mirror unit list, in the
            // order `classify_mirror` documents and emits; `nested` becomes the
            // FlatTree unit's walk boundaries.
            let mut units = classify_mirror(&mirror, nested, config);
            if !mirror_permitted(config, &mirror.host, mirror.port()) {
                info!(
                    "Mirror {} is no longer permitted by `allowed_mirrors`/`allowed_mirror_ports`; not fetching its indexes and keeping its package files",
                    mirror.site()
                );
                units.retain(|unit| !unit.fetches_indexes());
            }
            tokio::task::spawn(run_mirror_units(mirror, units, appstate.clone(), config))
        });

    let results = futures_util::stream::iter(cleanup_tasks)
        .buffer_unordered(MAX_CONCURRENT_CLEANUP_TASKS)
        .collect::<Vec<_>>()
        .await;

    let mut totals = UnitStats::default();
    // Derived per mirror (`UnitStats::retained`) before the mirrors are summed.
    let mut files_retained = 0;
    // Steps that failed (`LAST_CLEANUP_FAILURES`), each logged where it failed.
    let mut failures = 0;

    for res in results {
        // A unit's hard error is logged and swallowed inside `run_mirror_units`,
        // so the only failure that can surface here is a panicked task.
        let cleanup_result = match res {
            Ok(cr) => cr,
            Err(join_err) => {
                failures += 1;
                error!(
                    "Failed to join a mirror cleanup task; skipping that mirror's tally and cleanup timestamp:  {}",
                    ErrorReport(&join_err)
                );
                continue;
            }
        };

        if let Err(err) = appstate
            .database
            .mirror_cleanup(&cleanup_result.mirror)
            .await
        {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to record the cleanup timestamp for mirror {}; its last-cleanup time stays stale:  {}",
                cleanup_result.mirror,
                SqlxErrorReport(&err)
            );
        }

        files_retained += cleanup_result.stats.retained();
        totals.accumulate(cleanup_result.stats);
        failures += cleanup_result.failed_units;
    }

    let UnitStats {
        scanned: _,
        removed: files_removed,
        bytes_removed,
        removed_unreferenced,
        tmp_bytes_removed,
        // Per unit, already folded into `failures` by `run_mirror_units`.
        bailed: _,
        io_failures: _,
    } = totals;

    // The window snapshot must precede the scan: commits landing while the
    // scan walks are ambiguous to it, and the reconcile tolerates exactly
    // those (`CacheQuota::subtract_and_reconcile`).
    let quota = global_cache_quota();
    let window = quota.begin_reconcile_window();
    match task_cache_scan(&appstate.database).await {
        Ok(scanned) => {
            let actual_cache_size = scanned.bytes;
            // Reaped `tmp/` files were accounted like cached ones.
            let reconciled = quota.subtract_and_reconcile(
                bytes_removed.saturating_add(tmp_bytes_removed),
                actual_cache_size,
                window,
            );

            if reconciled.difference != 0 {
                warn!(
                    "Repaired cache size discrepancy of {}: actual={} ({} files) stored={} expected={} corrected={} committed during scan=+{}/-{} unwritten in-flight partials={}",
                    HumanFmt::Size(reconciled.difference),
                    HumanFmt::Size(actual_cache_size),
                    scanned.files,
                    HumanFmt::Size(reconciled.stored),
                    HumanFmt::Size(reconciled.expected),
                    HumanFmt::Size(reconciled.corrected),
                    HumanFmt::Size(reconciled.grown_during_scan),
                    HumanFmt::Size(reconciled.shrunk_during_scan),
                    HumanFmt::Size(reconciled.inflight_unwritten)
                );
            } else {
                debug!(
                    "actual cache size: {actual_cache_size} in {} files; stored cache size: {}; expected: {}; committed during scan: +{}/-{}; unwritten in-flight partials: {}",
                    scanned.files,
                    reconciled.stored,
                    reconciled.expected,
                    reconciled.grown_during_scan,
                    reconciled.shrunk_during_scan,
                    reconciled.inflight_unwritten
                );
            }
        }
        Err(err) => {
            failures += 1;
            error!(
                "Failed to rescan the cache directory after cleanup; skipping the cache-size reconciliation:  {}",
                ErrorReport(&err)
            );
        }
    }

    let elapsed = start.elapsed();
    metrics::CLEANUP_EVICTIONS.increment_by(files_removed);
    metrics::CLEANUP_BYTES_RECLAIMED.increment_by(bytes_removed);
    metrics::CLEANUP_BYHASH_UNREFERENCED.increment_by(removed_unreferenced);
    publish_last_run(elapsed, files_removed, bytes_removed, failures);

    // Second invalidation: the per-mirror units above removed rows of their
    // own, and the pre-pass one is long stale by now. Cleanup is the only
    // thing that removes rows, and an operator reloads the page precisely to
    // confirm the run took effect.
    crate::web::invalidate_dashboard_aggregates().await;

    info!(
        "Finished cleanup task in {}: retained {} files, removed {} files of size {}",
        HumanFmt::Time(elapsed.into()),
        files_retained,
        files_removed,
        HumanFmt::Size(bytes_removed)
    );
}
