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
use scan::derive_nested_paths;

use std::{
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
use log::{debug, error, info, trace, warn};

use crate::{
    AppState, cache_layout::CacheLayout, cache_metadata, config::CacheHost,
    database::resolved_cache_host, deb_mirror::Mirror, error::ProxyCacheError, global_cache_quota,
    global_config, humanfmt::HumanFmt, metrics, task_cache_scan::task_cache_scan,
};

/// Delay between daemon startup and the first scheduled cleanup run.
pub(crate) const FIRST_CLEANUP_DELAY_SECS: u64 = 60 * 60;

/// Interval between recurring cleanup runs.
pub(crate) const CLEANUP_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Grace period for unreferenced cached deb files. Apt updates that bypass
/// the proxy register their origin lazily; this delay prevents a freshly
/// cached file from being wiped before its origin row is observed.
const UNREFERENCED_KEEP_SPAN: Duration = Duration::from_hours(3 * 24);

/// Retention span for volatile index metadata (`Release`/`InRelease`/`Packages*`
/// /...) in a structured `dists/` directory. Unlike per-`.deb` files these are
/// refreshed in place (a fresh inode, hence a fresh birthtime) while a
/// distribution is in use, so aging past this span marks the distribution as
/// retired. Nothing else reclaims these files, and while a retired dist's
/// `Release` lingers, reference-mode by-hash cleanup keeps every digest it lists
/// pinned; removing the metadata bounds the growth and unblocks that reclaim.
/// See `sweep::sweep_aged_metadata`.
const METADATA_KEEP_SPAN: Duration = Duration::from_hours(90 * 24);

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

/// Drop the in-memory `cache_metadata` entry keyed by `(mirror, basename, layout)`.
/// Non-UTF-8 filenames are silently skipped: debnames are URL-decoded ASCII,
/// so any non-UTF-8 path can't be in the metadata store to begin with.
///
/// The key uses `path.file_name()` (basename) rather than a relpath because the
/// stored `cache_metadata` key already carries the on-disk directory in
/// `Mirror.path` (URL-directory-verbatim under the host-anchored flat layout),
/// so basename + the cleanup mirror is the exact key — as long as the file's
/// directory equals the cleanup mirror's registered path. That holds for every
/// deb reached through its own mirror row: each flat-deb URL directory registers
/// a row that `derive_nested_paths` turns into a walk boundary, so the handling
/// task always sees a single-segment relpath. The one gap is the recursive-scan
/// safety net: a deb nested *below* the cleanup mirror's path whose own row is
/// missing (e.g. pruned by `cleanup_invalid_rows`, or a DB reset with files left
/// behind) is keyed here under the wrong `Mirror.path` and the invalidation
/// misses. That only leaks an in-memory entry (the on-disk file is still removed
/// correctly), and the store rebuilds lazily from xattrs, so it self-heals on
/// restart.
fn invalidate_metadata_for(path: &Path, mirror: &Mirror, layout: CacheLayout) {
    if let Some(debname) = path.file_name().and_then(|n| n.to_str()) {
        cache_metadata::store().invalidate(&cache_metadata::CacheMetadataKeyRef::new(
            mirror, debname, layout,
        ));
    }
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

pub(crate) async fn task_cleanup(appstate: &AppState) -> Result<(), ProxyCacheError> {
    static TASK_ACTIVE: LazyLock<parking_lot::Mutex<bool>> =
        LazyLock::new(|| parking_lot::Mutex::new(false));

    let mutex = &*TASK_ACTIVE;

    {
        let mut val = mutex.lock();
        if *val {
            info!("Skipping cleanup task since already in progress");
            return Ok(());
        }
        *val = true;
    }
    let _guard = ActiveGuard(mutex);

    task_cleanup_impl(appstate).await
}

async fn task_cleanup_impl(appstate: &AppState) -> Result<(), ProxyCacheError> {
    // Use buffer_unordered to limit concurrent cleanup tasks and avoid thundering herd
    const MAX_CONCURRENT_CLEANUP_TASKS: usize = 10;

    let config = global_config();

    let start = Instant::now();

    if let Err(err) = appstate.database.cleanup_invalid_rows().await {
        metrics::DB_OPERATION_FAILED.increment();
        error!("Failed to clean up invalid database rows:  {err}");
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
            error!("Failed to delete old usage logs:  {err}");
        }
    }

    let mirrors = appstate.database.get_mirrors().await.inspect_err(|err| {
        metrics::DB_OPERATION_FAILED.increment();
        error!("Error looking up hosts:  {err}");
        // Earlier steps in this task (cleanup_invalid_rows /
        // delete_usage_logs) may already have run, but no per-mirror
        // cleanup work was done; record the failed-run state so the
        // dashboard does not display stale prior-run values.
        let elapsed = start.elapsed();
        metrics::LAST_CLEANUP_DURATION_SECS.set(elapsed.as_secs());
        metrics::LAST_CLEANUP_FILES_REMOVED.set(0);
        metrics::LAST_CLEANUP_BYTES_RECLAIMED.set(0);
    })?;

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
        let cleanup_result = match res {
            Ok(Ok(cr)) => cr,
            Ok(Err(err)) => {
                error!("Error in cleanup task:  {err}");
                continue;
            }
            Err(join_err) => {
                error!("Error joining cleanup task:  {join_err}");
                continue;
            }
        };

        if let Err(err) = appstate
            .database
            .mirror_cleanup(&cleanup_result.mirror)
            .await
        {
            metrics::DB_OPERATION_FAILED.increment();
            error!("Error setting cleanup timestamp:  {err}");
        }

        files_retained += cleanup_result.files_retained;
        files_removed += cleanup_result.files_removed;
        bytes_removed += cleanup_result.bytes_removed;
        removed_unreferenced += cleanup_result.removed_unreferenced;
    }

    match task_cache_scan(&appstate.database).await {
        Ok(actual_cache_size) => {
            let active_downloading_size = appstate.active_downloads.download_size();

            let quota = global_cache_quota();
            let (stored, csize, difference) = quota.subtract_and_reconcile(
                bytes_removed,
                actual_cache_size,
                active_downloading_size,
            );

            if difference != 0 {
                warn!(
                    "Repaired cache size discrepancy of {difference}: actual={actual_cache_size} stored={stored} corrected={csize} active={active_downloading_size}"
                );
            } else {
                debug!(
                    "actual cache size: {actual_cache_size}; stored cache size: {stored}; active download size: {active_downloading_size}"
                );
            }
        }
        Err(err) => {
            error!("Skipping cache-size reconciliation after cleanup:  {err}");
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

    Ok(())
}
