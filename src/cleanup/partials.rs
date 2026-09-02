use std::path::Path;
use std::time::{Duration, SystemTime};

use tracing::{debug, error};

use crate::cache_walk::{DirFailure, EntryKind, OnMissing, WalkContext, Walker};
use crate::error::ErrorReport;
use crate::metrics;

use super::scan::{remove_non_regular, remove_stray_dir};

static TMP_WALK: WalkContext = WalkContext {
    what: "a tmp directory",
    dir_failure: DirFailure::Continue("leaving its unread entries unreaped this cycle"),
    entry_failure: "retaining it this cycle",
    non_regular: "removing it once it is older than a week",
};

/// Remove stale entries from a single `tmp/` directory.
///
/// `.partial` files are deleted when zero-byte (no useful resume state) or older
/// than `partial_max_age` — the `PartialsUnit` span, so tuning it in
/// `model.rs` actually moves this threshold. Any other artifact
/// (defensive — current code only writes `.partial` here) is deleted once it has
/// aged past `FOREIGN_MAX_AGE`, the longer threshold acknowledging that we don't
/// know what produced it; a stray directory or non-regular entry is reported
/// on every cycle it is seen and reaped on the same schedule.
///
/// Called by the engine's `Partials` unit arm once per mirror per layout
/// (structured `<cache>/<cache_path>/tmp` and flat `<cache>/flat/<flat_root>/tmp`
/// — see `model::classify_mirror`'s two `Partials` units). The returned count
/// is logged only, never folded into `UnitStats::removed`/`bytes_removed`:
/// partial-download scratch files are not cached content.
pub(super) async fn cleanup_tmp_dir(
    tmp_dir: &Path,
    now: SystemTime,
    partial_max_age: Duration,
) -> u64 {
    // `TMP_WALK.non_regular` spells this out as "a week"; keep them in step.
    const FOREIGN_MAX_AGE: Duration = Duration::from_hours(7 * 24);

    let partial_cutoff = now - partial_max_age;
    let foreign_cutoff = now - FOREIGN_MAX_AGE;

    let mut removed = 0u64;

    let mut walker = Walker::new(tmp_dir, &TMP_WALK, OnMissing::Tolerate, ());

    while let Some(entry) = walker.next().await {
        let Some(mdata) = entry.metadata().await else {
            continue;
        };

        let mtime = match mdata.modified() {
            Ok(m) => m,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to read mtime of tmp entry `{}`; treating it as epoch, so it is eligible for removal:  {}",
                    entry.path().display(),
                    ErrorReport(&err)
                );
                SystemTime::UNIX_EPOCH
            }
        };
        // The tmp/ producer (`download_file`) only writes regular files, so
        // a directory here is anomalous however young it is; the walker
        // already reported a non-regular entry.
        if entry.kind() == EntryKind::Dir {
            entry.report_unexpected("removing it once it is older than a week");
        }
        // Apply the per-suffix `.partial` policy only to regular files: a
        // symlink-to-dir or a stray directory named `*.partial` should not
        // be measured by `len()` (zero for a symlink) and should be reaped
        // under the longer foreign cutoff instead.
        let is_partial = entry.kind() == EntryKind::File
            && entry
                .name()
                .to_str()
                .is_some_and(|name| name.ends_with(".partial"));
        let stale = if is_partial {
            // Zero-byte partials carry no resume state; aged partials are stale.
            mdata.len() == 0 || mtime < partial_cutoff
        } else if mtime < foreign_cutoff {
            true
        } else {
            debug!(
                "Keeping unexpected tmp entry `{}` (not yet past foreign cutoff)",
                entry.path().display()
            );
            false
        };

        if !stale {
            continue;
        }

        let path = entry.path();
        let gone = match entry.kind() {
            EntryKind::Dir => remove_stray_dir(&path).await,
            EntryKind::NonRegular => remove_non_regular(&path).await,
            EntryKind::File => match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    debug!("Removed stale tmp entry `{}`", path.display());
                    true
                }
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to remove stale tmp entry `{}`; retaining it:  {}",
                        path.display(),
                        ErrorReport(&err)
                    );
                    false
                }
            },
        };
        if gone {
            removed += 1;
        }
    }

    removed
}
