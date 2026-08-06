use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tracing::{debug, error};

use crate::error::ErrorReport;
use crate::metrics;

use super::scan::{AnomalyOutcome, DirAction, handle_anomalous_entry};

/// Remove stale entries from a single `tmp/` directory.
///
/// `.partial` files are deleted when zero-byte (no useful resume state) or older
/// than `partial_max_age` — the `PartialsUnit` span, so tuning it in
/// `model.rs` actually moves this threshold. Any other artifact
/// (defensive — current code only writes `.partial` here) is deleted once it has
/// aged past `FOREIGN_MAX_AGE`, the longer threshold acknowledging that we don't
/// know what produced it.
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
    const FOREIGN_MAX_AGE: Duration = Duration::from_hours(7 * 24);

    let partial_cutoff = now - partial_max_age;
    let foreign_cutoff = now - FOREIGN_MAX_AGE;

    let mut entries = match tokio::fs::read_dir(tmp_dir).await {
        Ok(e) => e,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return 0;
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read tmp directory `{}`; skipping this directory this cycle:  {}",
                tmp_dir.display(),
                ErrorReport(&err)
            );
            return 0;
        }
    };

    let mut removed = 0u64;

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate tmp directory `{}`; ending this directory's sweep early:  {}",
                    tmp_dir.display(),
                    ErrorReport(&err)
                );
                break;
            }
        };

        let (mdata, file_type) = match entry.metadata().await {
            Ok(m) => {
                let ft = m.file_type();
                (m, ft)
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to stat tmp entry `{}`; retaining it and skipping it this cycle:  {}",
                    entry.path().display(),
                    ErrorReport(&err)
                );
                continue;
            }
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
        // Apply the per-suffix `.partial` policy only to regular files: a
        // symlink-to-dir or a stray directory named `*.partial` should not
        // be measured by `len()` (zero for a symlink) and should be reaped
        // under the longer foreign cutoff instead.
        let is_partial = file_type.is_file()
            && entry
                .file_name()
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
        // The tmp/ producer (`download_file`) only writes regular files, so a
        // directory or non-regular entry here is anomalous. Centralized handler
        // covers both (`RemoveAll` for directories, `remove_file` for everything
        // else).
        if file_type.is_dir() || !file_type.is_file() {
            let outcome = handle_anomalous_entry(&path, file_type, DirAction::RemoveAll).await;
            if matches!(outcome, AnomalyOutcome::Removed) {
                removed += 1;
            }
        } else if let Err(err) = tokio::fs::remove_file(&path).await {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to remove stale tmp entry `{}`; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
        } else {
            debug!("Removed stale tmp entry `{}`", path.display());
            removed += 1;
        }
    }

    removed
}
