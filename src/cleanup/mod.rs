mod engine;
mod model;
mod packages;
mod partials;
mod refs;
mod scan;
mod sweep;
mod verify;

use engine::run_mirror_units;
use model::classify_mirror;

use std::{
    num::NonZero,
    path::Path,
    sync::{
        LazyLock,
        atomic::{AtomicI64, Ordering},
    },
    time::Duration,
};

use coarsetime::Instant;
use futures_util::StreamExt as _;
use hashbrown::HashMap;
use tracing::{debug, error, info, trace, warn};

use crate::{
    AppState,
    cache_paths::CachePaths,
    config::{CacheHost, Config},
    database::Database,
    deb_mirror::{Mirror, derive_nested_paths},
    error::ErrorReport,
    global_cache_quota, global_config,
    humanfmt::HumanFmt,
    limits::RETENTION_TIME,
    metrics,
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
                ErrorReport(&err)
            );
        }
    }

    let orphans = match database.get_mirrors_without_origins().await {
        Ok(orphans) => orphans,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to look up mirror rows without origins; retaining them until the next cleanup run:  {}",
                ErrorReport(&err)
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
            info!(
                "Removing mirror row {} without origins or cached files",
                Mirror::from(orphan.entry)
            );
            gone.push(orphan.id);
        }
    }
    if gone.is_empty() {
        return;
    }
    if let Err(err) = database.delete_mirrors(&gone).await {
        metrics::DB_OPERATION_FAILED.increment();
        error!(
            "Failed to remove {} mirror rows without origins or cached files; retaining them until the next cleanup run:  {}",
            gone.len(),
            ErrorReport(&err)
        );
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

/// RAII guard that releases the `task_cleanup` active flag on drop, so a
/// panic inside `task_cleanup_impl` cannot leave the flag stuck `true`
/// (which would block every subsequent scheduled run).
struct ActiveGuard<'a>(&'a parking_lot::Mutex<bool>);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        let mut val = self.0.lock();
        debug_assert!(*val, "cleanup state must be active after completion");
        *val = false;
    }
}

pub(crate) async fn task_cleanup(appstate: &AppState) {
    static TASK_ACTIVE: LazyLock<parking_lot::Mutex<bool>> =
        LazyLock::new(|| parking_lot::Mutex::new(false));

    let mutex = &*TASK_ACTIVE;

    {
        let mut val = mutex.lock();
        if *val {
            info!("Skipping cleanup task since already in progress");
            return;
        }
        *val = true;
    }
    let _guard = ActiveGuard(mutex);

    task_cleanup_impl(appstate).await;
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
            ErrorReport(&err)
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
                ErrorReport(&err)
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
                ErrorReport(&err)
            );
            // Earlier steps in this task (cleanup_invalid_rows /
            // delete_usage_logs) may already have run, but no per-mirror
            // cleanup work was done; record the failed-run state so the
            // dashboard does not display stale prior-run values.
            let elapsed = start.elapsed();
            metrics::LAST_CLEANUP_DURATION_SECS.set(elapsed.as_secs());
            metrics::LAST_CLEANUP_FILES_REMOVED.set(0);
            metrics::LAST_CLEANUP_BYTES_RECLAIMED.set(0);
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
    // cleanup run).
    //
    // Paths are bucketed by (cache_host, port) and each bucket sorted once, so a
    // mirror's derivation is O(k) over its host's siblings instead of O(n) over
    // every mirror.  Rows are canonical (alias-resolved at dispatch, legacy rows
    // folded at startup), so the row host *is* the `<cache>/<host>/…` tree the
    // nesting bucket must follow.
    let host_keys: Vec<(&CacheHost, Option<NonZero<u16>>)> = mirrors
        .iter()
        .map(|entry| (entry.host.as_cache_host(), entry.port()))
        .collect();

    let mut paths_by_host: HashMap<(&CacheHost, Option<NonZero<u16>>), Vec<&str>> = HashMap::new();
    for (entry, &key) in mirrors.iter().zip(&host_keys) {
        paths_by_host
            .entry(key)
            .or_default()
            .push(entry.path.as_str());
    }
    for paths in paths_by_host.values_mut() {
        paths.sort_unstable();
    }

    // Materialise each mirror's nested-paths list to owned data so the
    // `paths_by_host` borrow on `mirrors` can end before we consume
    // `mirrors` in the per-future move below.
    let nested_per_mirror: Vec<Vec<String>> = mirrors
        .iter()
        .zip(&host_keys)
        .map(|(mirror, &key)| {
            let host_paths = paths_by_host
                .get(&key)
                .map(Vec::as_slice)
                .unwrap_or_default();
            derive_nested_paths(&mirror.path, host_paths)
        })
        .collect();
    drop(paths_by_host);

    let cleanup_tasks = mirrors
        .into_iter()
        .zip(nested_per_mirror)
        .map(|(mirror, nested)| {
            // Every facet (partials, structured pool, flat, metadata, by-hash)
            // runs on the engine as one ordered per-mirror unit list, in the
            // order `classify_mirror` documents and emits; `nested` becomes the
            // FlatTree unit's walk boundaries.
            let units = classify_mirror(&mirror, nested, config);
            tokio::task::spawn(run_mirror_units(mirror, units, appstate.clone(), config))
        });

    let results = futures_util::stream::iter(cleanup_tasks)
        .buffer_unordered(MAX_CONCURRENT_CLEANUP_TASKS)
        .collect::<Vec<_>>()
        .await;

    let mut files_retained = 0;
    let mut files_removed = 0;
    let mut bytes_removed = 0;
    let mut removed_unreferenced = 0;

    for res in results {
        // A unit's hard error is logged and swallowed inside `run_mirror_units`,
        // so the only failure that can surface here is a panicked task.
        let cleanup_result = match res {
            Ok(cr) => cr,
            Err(join_err) => {
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
                ErrorReport(&err)
            );
        }

        files_retained += cleanup_result.files_retained;
        files_removed += cleanup_result.files_removed;
        bytes_removed += cleanup_result.bytes_removed;
        removed_unreferenced += cleanup_result.removed_unreferenced;
    }

    // The window snapshot must precede the scan: commits landing while the
    // scan walks are ambiguous to it, and the reconcile tolerates exactly
    // those (`CacheQuota::subtract_and_reconcile`).
    let quota = global_cache_quota();
    let window = quota.begin_reconcile_window();
    match task_cache_scan(&appstate.database).await {
        Ok(scanned) => {
            let actual_cache_size = scanned.bytes;
            let reconciled = quota.subtract_and_reconcile(bytes_removed, actual_cache_size, window);

            if reconciled.difference != 0 {
                warn!(
                    "Repaired cache size discrepancy of {}: actual={} ({} files) stored={} expected={} corrected={} committed during scan=+{}/-{}",
                    HumanFmt::Size(reconciled.difference),
                    HumanFmt::Size(actual_cache_size),
                    scanned.files,
                    HumanFmt::Size(reconciled.stored),
                    HumanFmt::Size(reconciled.expected),
                    HumanFmt::Size(reconciled.corrected),
                    HumanFmt::Size(reconciled.grown_during_scan),
                    HumanFmt::Size(reconciled.shrunk_during_scan)
                );
            } else {
                debug!(
                    "actual cache size: {actual_cache_size} in {} files; stored cache size: {}; expected: {}; committed during scan: +{}/-{}",
                    scanned.files,
                    reconciled.stored,
                    reconciled.expected,
                    reconciled.grown_during_scan,
                    reconciled.shrunk_during_scan
                );
            }
        }
        Err(err) => {
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
    metrics::LAST_CLEANUP_DURATION_SECS.set(elapsed.as_secs());
    metrics::LAST_CLEANUP_FILES_REMOVED.set(files_removed);
    metrics::LAST_CLEANUP_BYTES_RECLAIMED.set(bytes_removed);

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
