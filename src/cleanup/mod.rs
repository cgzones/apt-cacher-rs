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
    AppState, config::CacheHost, database::resolved_cache_host, deb_mirror::derive_nested_paths,
    error::ErrorReport, global_cache_quota, global_config, humanfmt::HumanFmt, metrics,
    task_cache_scan::task_cache_scan, xattr_helpers,
};

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

    // Create a stream of futures, one per mirror, each running that
    // mirror's full ordered cleanup-unit list.
    //
    // For each mirror, collect the paths of any other mirrors registered
    // under the same alias-resolved (cache_host, port) whose path lives
    // *inside* this mirror's path (segment-aligned).  The flat-cleanup
    // walks the on-disk flat subtree recursively, and these nested mirror
    // roots must be treated as boundaries so a parent mirror's cleanup
    // does not age-evict files that belong to a nested mirror (which has
    // its own Packages index and its own cleanup run).

    // Group mirror paths by (cache_host, port) and sort each group once so
    // each mirror's nested-paths derivation is O(k) over its host's siblings
    // instead of O(n) over every mirror.  Keying on the alias-resolved
    // `CacheHost` (the same identity `MirrorEntry::cache_path` and
    // `flat_root_path_with_aliases` use to build on-disk paths) matches the cleanup
    // layout: two DB rows whose raw `ClientHost` differs but resolves to
    // the same `main` host share `<cache>/<main_host>/…` on disk, so they
    // must share a nesting bucket — otherwise a parent's flat-cleanup could
    // recurse into and age-evict files owned by a sibling alias's mirror.
    // Stored as borrows into `mirrors` and the global aliases table.
    let aliases = config.aliases.as_slice();
    // Resolve each mirror's (alias-main cache host, port) key once; the alias
    // table scan in `resolved_cache_host` is otherwise repeated in both the
    // grouping pass and the nested-paths pass below.
    let host_keys: Vec<(&CacheHost, u16)> = mirrors
        .iter()
        .map(|entry| {
            (
                resolved_cache_host(aliases, &entry.host),
                entry.port().map_or(0, std::num::NonZero::get),
            )
        })
        .collect();

    let mut paths_by_host: HashMap<(&CacheHost, u16), Vec<&str>> = HashMap::new();
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
            // runs on the engine as one ordered per-mirror unit list; the
            // classifier's emission order guarantees the two Partials units run
            // first (a stale temp file from an interrupted download shouldn't
            // linger) and each mirror's metadata sweep precedes its by-hash
            // units. `nested` feeds the FlatTree unit's walk
            // boundaries.
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

    match task_cache_scan(&appstate.database).await {
        Ok(scanned) => {
            let actual_cache_size = scanned.bytes;
            let active_downloading_size = appstate.active_downloads.download_size();

            let quota = global_cache_quota();
            let (stored, csize, difference) = quota.subtract_and_reconcile(
                bytes_removed,
                actual_cache_size,
                active_downloading_size,
            );

            if difference != 0 {
                warn!(
                    "Repaired cache size discrepancy of {}: actual={} ({} files) stored={} corrected={} active={}",
                    HumanFmt::Size(difference),
                    HumanFmt::Size(actual_cache_size),
                    scanned.files,
                    HumanFmt::Size(stored),
                    HumanFmt::Size(csize),
                    HumanFmt::Size(active_downloading_size)
                );
            } else {
                debug!(
                    "actual cache size: {actual_cache_size} in {} files; stored cache size: {stored}; active download size: {active_downloading_size}",
                    scanned.files
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

    info!(
        "Finished cleanup task in {}: retained {} files, removed {} files of size {}",
        HumanFmt::Time(elapsed.into()),
        files_retained,
        files_removed,
        HumanFmt::Size(bytes_removed)
    );
}
