use std::{borrow::Cow, path::Path};

use hashbrown::HashMap;
use tokio::fs::DirEntry;
use tracing::{debug, error, trace, warn};

use crate::{
    cache_layout::{KNOWN_MIRROR_SUBDIRS, SUBDIR_FLAT, SUBDIR_FLAT_BYHASH, SUBDIR_TMP},
    database::{Database, MirrorEntry},
    deb_mirror::{MirrorKind, is_deb_package, is_strict_path_descendant},
    error::{ErrorReport, ProxyCacheError},
    global_config, healthcheck, metrics, task_setup,
    utils::probe_dir,
    warn_once_or_info,
};

/// Tally of one scan pass: the bytes counted towards the cache size and the
/// number of regular files they came from.  The file count is what makes an
/// `ENOSPC` from inode exhaustion legible next to a modest byte total, and it
/// is directly comparable with cleanup's `retained`/`removed` file counts.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScanTotals {
    pub(crate) bytes: u64,
    pub(crate) files: u64,
}

impl ScanTotals {
    fn add_file(&mut self, size: u64) {
        self.bytes = self.bytes.saturating_add(size);
        self.files = self.files.saturating_add(1);
    }
}

impl std::ops::AddAssign for ScanTotals {
    fn add_assign(&mut self, rhs: Self) {
        self.bytes = self.bytes.saturating_add(rhs.bytes);
        self.files = self.files.saturating_add(rhs.files);
    }
}

/// Mode that drives [`scan_sub_dir_recursive`].  The scanner is shared
/// between the structured-mirror subtree (e.g. `dists/`), the host-level
/// flat tree, and the by-hash leaves so the surrounding `read_dir` / lstat /
/// tally boilerplate is written once.
#[derive(Copy, Clone)]
enum SubDirMode {
    /// `dists/`-style: tally files, dispatch a `by-hash/` subdir to
    /// [`SubDirMode::ByHash`], warn on anything else.
    Structured,
    /// Host-level `flat/` subtree: tally files, dispatch `by-hash/`, skip
    /// `tmp/`, recurse into every other directory (URL-path verbatim).
    Flat,
    /// Content-addressed leaf: tally files only; subdirs are unexpected.
    ByHash,
}

impl SubDirMode {
    const fn purpose(self) -> &'static str {
        match self {
            Self::Structured | Self::Flat => "mirror sub-directory",
            Self::ByHash => "mirror by-hash directory",
        }
    }
}

/// Returns the size in bytes and the file count of the entire cache.
/// Files that cannot be accessed are not included; a message is logged for each.
pub(crate) async fn task_cache_scan(database: &Database) -> Result<ScanTotals, ProxyCacheError> {
    let config = global_config();

    let mirrors = match database.get_mirrors().await {
        Ok(m) => m,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to fetch the mirrors for the cache scan; abandoning the scan:  {}",
                ErrorReport(&err)
            );
            return Err(ProxyCacheError::Sqlx(err));
        }
    };

    let cache_path = &config.cache_directory;

    trace!("Scanning directory `{}`...", cache_path.display());

    let mut cache_dir = match tokio::fs::read_dir(cache_path).await {
        Ok(d) => d,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read cache directory `{}`; abandoning the cache scan:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            return Err(ProxyCacheError::Io(err));
        }
    };

    // Group mirrors by alias-resolved host directory name once, so each
    // cache entry is matched via an O(1) HashMap lookup instead of an inner
    // O(m) scan.  `paths_by_host_dir` shares the same key — every mirror
    // contributes both its `MirrorEntry` row and its `path` to the per-host
    // bucket.  Keys are owned `String`s because the `Cow` from
    // `format_cache_dir` may borrow from local data (the formatted port).
    let mut mirrors_by_dir: HashMap<String, Vec<&MirrorEntry>> =
        HashMap::with_capacity(mirrors.len());
    let mut paths_by_host_dir: HashMap<String, Vec<&str>> = HashMap::with_capacity(mirrors.len());
    for mirror in &mirrors {
        let dir_name = mirror
            .cache_host()
            .format_cache_dir(mirror.port())
            .into_owned();
        paths_by_host_dir
            .entry(dir_name.clone())
            .or_default()
            .push(mirror.path.as_str());
        mirrors_by_dir.entry(dir_name).or_default().push(mirror);
    }

    let mut totals = ScanTotals::default();

    loop {
        let entry = match cache_dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate cache directory `{}`; abandoning the cache scan:  {}",
                    cache_path.display(),
                    ErrorReport(&err)
                );
                return Err(ProxyCacheError::Io(err));
            }
        };

        match entry.metadata().await {
            Ok(mdata) if mdata.is_dir() => {}
            Ok(mdata) if mdata.file_type().is_symlink() => {
                metrics::CACHE_NON_REGULAR.increment();
                warn!(
                    "Unrecognized symlink entry `{}` in the cache directory; not counting it towards the cache size",
                    entry.path().display()
                );
                continue;
            }
            Ok(mdata) if mdata.is_file() => {
                // The healthcheck probe is created and unlinked at the
                // cache root (a scan racing that window must not flag it),
                // and the instance lock file lives there for the whole
                // process lifetime.
                if entry.file_name() == healthcheck::PROBE_FILENAME
                    || entry.file_name() == task_setup::LOCK_FILENAME
                {
                    continue;
                }
                // A regular file at the cache root is an operator
                // artefact (the cache root only ever holds host
                // directories), not a tampering signal — bucket it
                // separately from FIFO/socket/device entries.
                metrics::CACHE_UNEXPECTED_REGULAR.increment();
                warn!(
                    "Unrecognized regular file entry `{}` in the cache directory; not counting it towards the cache size",
                    entry.path().display()
                );
                continue;
            }
            Ok(_) => {
                metrics::CACHE_NON_REGULAR.increment();
                warn!(
                    "Unrecognized non-regular entry `{}` in the cache directory; not counting it towards the cache size",
                    entry.path().display()
                );
                continue;
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to get metadata of `{}`; excluding it from the cache size:  {}",
                    entry.path().display(),
                    ErrorReport(&err)
                );
                continue;
            }
        }

        let dir_name = entry.file_name();
        if dir_name == SUBDIR_TMP {
            continue;
        }

        // HashMap lookup needs a UTF-8 key.  A non-UTF-8 entry could never
        // match a registered mirror dir (mirror hosts are validated as
        // ASCII), so fall through to the unrecognized-entry warn.
        let Some(name_str) = dir_name.to_str() else {
            metrics::CACHE_DIRECTORY_UNEXPECTED.increment();
            warn!(
                "Cache directory entry `{}` has a non-UTF-8 name; skipping it and its contents",
                entry.path().display()
            );
            continue;
        };

        let Some(mirrors_here) = mirrors_by_dir.get(name_str) else {
            metrics::CACHE_DIRECTORY_UNEXPECTED.increment();
            warn!(
                "Cache directory entry `{}` matches no known mirror; skipping it and its contents",
                entry.path().display()
            );
            continue;
        };

        // `name_str` is the alias-resolved host, so any mirror rows
        // registered via alias names are silently consolidated under
        // their `main` host directory — no per-row warning needed
        // since this is the intended layout.
        //
        // Per-host mirror paths were precomputed above so `scan_mirror_dir`
        // can recognise nested mirror paths as legitimate siblings without
        // an inner O(n) scan per matching mirror row.
        let host_paths = paths_by_host_dir
            .get(name_str)
            .map(Vec::as_slice)
            .unwrap_or_default();

        for mirror in mirrors_here {
            totals += scan_mirror_dir(&entry, mirror, host_paths).await;
        }

        // The host-level `flat/` subtree is a sibling of mirror dirs.
        // Scan once per host regardless of how many mirror rows live
        // under it — flat content is owned at the host level.
        let flat_path = entry.path().join(SUBDIR_FLAT);
        match probe_dir(&flat_path, "host-level flat root").await {
            Ok(true) => {
                totals += scan_sub_dir_recursive(flat_path, SubDirMode::Flat).await;
            }
            Ok(false) => {}
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to probe host-level flat root `{}`; excluding its subtree from the cache size:  {}",
                    flat_path.display(),
                    ErrorReport(&err)
                );
            }
        }
    }

    Ok(totals)
}

#[must_use]
async fn scan_mirror_dir(
    host: &DirEntry,
    mirror: &MirrorEntry,
    other_mirror_paths: &[&str],
) -> ScanTotals {
    let mirror_path = {
        let mut p = host.path();
        let mpath = Path::new(&mirror.path);
        // `MirrorEntry::path` is validated relative by `valid_mirrorname` at
        // insertion; a debug_assert catches a corrupted DB row during
        // development without paying for a runtime check on every scan.
        debug_assert!(
            mpath.is_relative(),
            "path construction must not contain absolute components"
        );
        p.push(mpath);
        p
    };

    trace!("Scanning mirror directory `{}`...", mirror_path.display());

    let mut mirror_dir = match tokio::fs::read_dir(&mirror_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // For a `Flat`-kind row the structured-pool path is expected
            // not to exist — `kind` latches to `Structured` on the very
            // first structured request (see `upsert_mirror_get_id`), so a
            // `Flat` row has by construction never written to
            // `<host>/<mirror_path>/`. Logging above debug here would just
            // add noise on every startup / SIGUSR2 cleanup. For
            // `Structured` rows the absence is potentially a real
            // inconsistency, so it warns once there and repeats at info.
            if mirror.kind() == MirrorKind::Flat {
                debug!(
                    "Mirror directory `{}` not found (flat-kind mirror, expected)",
                    mirror_path.display()
                );
            } else {
                warn_once_or_info!(
                    "Structured mirror directory `{}` not found; counting this mirror as empty in the cache size",
                    mirror_path.display()
                );
            }
            return ScanTotals::default();
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read mirror directory `{}`; excluding this mirror from the cache size:  {}",
                mirror_path.display(),
                ErrorReport(&err)
            );
            return ScanTotals::default();
        }
    };

    let mut totals = ScanTotals::default();

    loop {
        let entry = match mirror_dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate mirror directory `{}`; ending this mirror's scan early:  {}",
                    mirror_path.display(),
                    ErrorReport(&err)
                );
                return totals;
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
                    "Failed to get metadata of `{}`; excluding it from the cache size:  {}",
                    entry.path().display(),
                    ErrorReport(&err)
                );
                continue;
            }
        };

        let name = entry.file_name();

        if file_type.is_symlink() {
            metrics::CACHE_NON_REGULAR.increment();
            warn!(
                "Unrecognized symlink entry `{}` in a mirror directory; not counting it towards the cache size",
                entry.path().display()
            );
            continue;
        }

        if file_type.is_file() {
            totals.add_file(mdata.len());

            if name.to_str().is_some_and(is_deb_package) {
                continue;
            }
            // non-deb regular file falls through to the warn below
        } else if file_type.is_dir() {
            // Recognized mirror-level layout subdir (`dists/`) gets its
            // size tallied; `tmp/` is skipped (partial-download scratch
            // space).  A subdir that is itself a registered mirror path
            // under the same host (e.g. `debian/security` when scanning
            // `debian`) is silently skipped — it'll be walked under its
            // own mirror row.  Flat repositories live under
            // `<host>/flat/` (host-level sibling of mirror dirs), not
            // below any mirror, so no `flat/` arm here.
            if KNOWN_MIRROR_SUBDIRS.iter().any(|known| name == *known) {
                totals += scan_sub_dir_recursive(entry.path(), SubDirMode::Structured).await;
                continue;
            }
            if name == SUBDIR_TMP {
                continue;
            }

            let Some(name_str) = name.to_str() else {
                metrics::CACHE_DIRECTORY_UNEXPECTED.increment();
                warn!(
                    "Unrecognized directory entry `{}` in a mirror directory; skipping it and its contents",
                    entry.path().display()
                );
                continue;
            };

            let expected = if mirror.path.is_empty() {
                Cow::Borrowed(name_str)
            } else {
                Cow::Owned(format!("{}/{}", mirror.path, name_str))
            };
            if is_registered_mirror_path(&expected, other_mirror_paths) {
                trace!(
                    "Skipping `{}` - it is a sub-mirror of `{}`",
                    entry.path().display(),
                    mirror.path
                );
                continue;
            }
            if contains_nested_mirror_path(&expected, other_mirror_paths) {
                trace!(
                    "Skipping `{}` - intermediate dir for a nested sub-mirror under `{}`",
                    entry.path().display(),
                    mirror.path
                );
                continue;
            }

            // unrecognized directory falls through to the warn below
        }

        // The regular-file arm already tallied the entry above, so its
        // consequence differs from the directory / non-regular arms.
        let (kind, consequence) = if file_type.is_dir() {
            metrics::CACHE_DIRECTORY_UNEXPECTED.increment();
            ("directory", "not counting it towards the cache size")
        } else if file_type.is_file() {
            metrics::CACHE_UNEXPECTED_REGULAR.increment();
            (
                "file",
                "counting it towards the cache size but excluding it from cleanup",
            )
        } else {
            metrics::CACHE_NON_REGULAR.increment();
            ("non-regular file", "not counting it towards the cache size")
        };
        warn!(
            "Unrecognized {kind} entry `{}` in a mirror directory; {consequence}",
            entry.path().display()
        );
    }

    trace!(
        "Size of mirror directory `{}`: {} in {} files",
        mirror_path.display(),
        totals.bytes,
        totals.files
    );

    totals
}

/// Whether `expected` (the would-be full mirror-path of a subdir found
/// inside `<host>/<mirror_path>/`, i.e. `<mirror_path>/<subdir>`) is itself
/// a registered mirror path on the same host.  Segment alignment falls out
/// of the caller's construction of `expected`: a stray byte-prefix like
/// `apt-tools` can never collide with `apt` because they differ in the
/// trailing segment.
fn is_registered_mirror_path(expected: &str, other_paths: &[&str]) -> bool {
    other_paths.contains(&expected)
}

/// Whether `expected` is the on-disk intermediate directory holding a
/// registered nested mirror — i.e. `expected` is **not** itself registered
/// but a mirror lives strictly below it (e.g. `expected = "apt/amd64"`
/// while `apt/amd64/special` is registered).  Such intermediate dirs are
/// legitimate filesystem containers and should be silently skipped during
/// scan rather than reported as "unrecognized entry".
fn contains_nested_mirror_path(expected: &str, other_paths: &[&str]) -> bool {
    other_paths
        .iter()
        .any(|p| is_strict_path_descendant(p, expected))
}

/// Walk a sub-directory tallying file sizes.  The mode determines whether
/// subdirectories are recursed into (`Flat`), dispatched to a by-hash leaf
/// (`Structured`/`Flat` on a `by-hash` name), skipped (`tmp/` under `Flat`),
/// or warned about (everything else).
#[must_use]
async fn scan_sub_dir_recursive(
    subdir_path: std::path::PathBuf,
    root_mode: SubDirMode,
) -> ScanTotals {
    // Iterative DFS using an in-place stack avoids Box::pin'ing the
    // recursive future shape (async fn recursion).
    let mut totals = ScanTotals::default();
    let mut stack: Vec<(std::path::PathBuf, SubDirMode)> = vec![(subdir_path, root_mode)];

    'outer: while let Some((current, mode)) = stack.pop() {
        trace!("Scanning {} `{}`...", mode.purpose(), current.display());

        let mut subdir_dir = match tokio::fs::read_dir(&current).await {
            Ok(d) => d,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to read {} `{}`; excluding it from the cache size:  {}",
                    mode.purpose(),
                    current.display(),
                    ErrorReport(&err)
                );
                continue;
            }
        };

        loop {
            let entry = match subdir_dir.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => continue 'outer,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to iterate {} `{}`; ending its scan early:  {}",
                        mode.purpose(),
                        current.display(),
                        ErrorReport(&err)
                    );
                    continue 'outer;
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
                        "Failed to get metadata of `{}`; excluding it from the cache size:  {}",
                        entry.path().display(),
                        ErrorReport(&err)
                    );
                    continue;
                }
            };

            if file_type.is_symlink() {
                metrics::CACHE_NON_REGULAR.increment();
                warn!(
                    "Unrecognized symlink entry `{}` in a {}; not counting it towards the cache size",
                    entry.path().display(),
                    mode.purpose()
                );
                continue;
            }

            if file_type.is_file() {
                totals.add_file(mdata.len());
                continue;
            }

            if file_type.is_dir() {
                let name = entry.file_name();
                match mode {
                    SubDirMode::Structured | SubDirMode::Flat if name == SUBDIR_FLAT_BYHASH => {
                        stack.push((entry.path(), SubDirMode::ByHash));
                        continue;
                    }
                    // Inside the host-level `flat/` subtree, any directory
                    // is a nested URL-dir under a flat repo (the URL path
                    // becomes the on-disk path verbatim) and is recursed
                    // into.  `tmp/` is the partial-download scratch space
                    // (flat partials land at
                    // `<host>/flat/<mirror_path>/tmp/`) and is owned by
                    // `cleanup_tmp_dir`, so it is skipped here to avoid
                    // inflating cache-size accounting with short-lived
                    // partials.
                    SubDirMode::Flat if name == SUBDIR_TMP => continue,
                    SubDirMode::Flat => {
                        stack.push((entry.path(), SubDirMode::Flat));
                        continue;
                    }
                    SubDirMode::Structured | SubDirMode::ByHash => {}
                }
            }

            // Only directories and non-regular entries reach here (symlinks and
            // regular files continue above, the latter after being tallied), so
            // neither arm is counted -- but a directory also goes unwalked.
            let consequence = if file_type.is_dir() {
                metrics::CACHE_DIRECTORY_UNEXPECTED.increment();
                "not counting it or its contents towards the cache size"
            } else {
                metrics::CACHE_NON_REGULAR.increment();
                "not counting it towards the cache size"
            };
            warn!(
                "Unrecognized entry `{}` in {} `{}`; {consequence}",
                entry.path().display(),
                mode.purpose(),
                current.display()
            );
        }
    }

    totals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_registered_mirror_path_exact_match() {
        let others = ["apt", "apt/amd64", "debian"];
        assert!(is_registered_mirror_path("apt/amd64", &others));
    }

    #[test]
    fn is_registered_mirror_path_segment_aligned_non_match() {
        let others = ["apt"];
        // `apt-tools` shares a byte-prefix with `apt` but is a distinct
        // segment; the caller's `<parent_path>/<subdir>` construction means
        // we only ever check whole strings here, but guard the invariant
        // explicitly anyway.
        assert!(!is_registered_mirror_path("apt-tools", &others));
    }

    #[test]
    fn is_registered_mirror_path_ancestor_does_not_match() {
        // Regression guard: a candidate that is a strict ancestor of a
        // registered nested mirror is NOT itself registered.  Pre-fix this
        // returned true via the reversed `path_starts_with_segment` call.
        let others = ["apt/amd64/special"];
        assert!(!is_registered_mirror_path("apt/amd64", &others));
    }

    #[test]
    fn contains_nested_mirror_path_ancestor_of_registered() {
        let others = ["apt/amd64/special"];
        assert!(contains_nested_mirror_path("apt/amd64", &others));
    }

    #[test]
    fn contains_nested_mirror_path_self_is_not_ancestor() {
        // `is_strict_path_descendant` is strict: equality does not count
        // as containment.  The registered-self case is handled by
        // `is_registered_mirror_path`.
        let others = ["apt/amd64"];
        assert!(!contains_nested_mirror_path("apt/amd64", &others));
    }

    #[test]
    fn contains_nested_mirror_path_unrelated() {
        let others = ["debian", "ubuntu/jammy"];
        assert!(!contains_nested_mirror_path("apt", &others));
    }
}
