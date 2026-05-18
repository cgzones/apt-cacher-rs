use std::{borrow::Cow, path::Path};

use hashbrown::HashMap;
use log::{debug, error, info, trace, warn};
use tokio::fs::DirEntry;

use crate::{
    cache_layout::{KNOWN_MIRROR_SUBDIRS, SUBDIR_FLAT, SUBDIR_FLAT_BYHASH, SUBDIR_TMP},
    database::{Database, MirrorEntry},
    deb_mirror::{MirrorKind, is_deb_package, is_strict_path_descendant},
    error::ProxyCacheError,
    global_config, metrics,
    utils::probe_dir,
};

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
            Self::Structured | Self::Flat => "mirror sub directory",
            Self::ByHash => "mirror by-hash directory",
        }
    }
}

/// Returns the size in bytes of the entire cache.
/// Files that cannot be accessed are not included, but logged about.
pub(crate) async fn task_cache_scan(database: &Database) -> Result<u64, ProxyCacheError> {
    let config = global_config();

    let mirrors = match database.get_mirrors().await {
        Ok(m) => m,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!("Error fetching mirrors:  {err}");
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
                "Failed to read cache directory `{}`:  {err}",
                cache_path.display()
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

    let mut cache_size = 0;

    loop {
        let entry = match cache_dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate cache directory `{}`:  {err}",
                    cache_path.display()
                );
                return Err(ProxyCacheError::Io(err));
            }
        };

        match entry.metadata().await {
            Ok(mdata) if mdata.is_dir() => {}
            Ok(mdata) if mdata.file_type().is_symlink() => {
                warn!(
                    "Unrecognized symlink entry in cache directory: `{}`",
                    entry.path().display()
                );
                continue;
            }
            Ok(_) => {
                metrics::CACHE_NON_REGULAR.increment();
                warn!(
                    "Unrecognized non-directory entry in cache directory: `{}`",
                    entry.path().display()
                );
                continue;
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to get metadata of `{}`:  {err}",
                    entry.path().display()
                );
                // Fall through to mirror lookup — opendir on this entry may
                // still succeed even if stat failed, and a registered mirror
                // shouldn't be skipped silently on a transient error.
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
            warn!(
                "Unrecognized directory entry in cache directory: `{}`",
                entry.path().display()
            );
            continue;
        };

        let Some(mirrors_here) = mirrors_by_dir.get(name_str) else {
            warn!(
                "Unrecognized directory entry in cache directory: `{}`",
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
            cache_size += scan_mirror_dir(&entry, mirror, host_paths).await;
        }

        // The host-level `flat/` subtree is a sibling of mirror dirs.
        // Scan once per host regardless of how many mirror rows live
        // under it — flat content is owned at the host level.
        let flat_path = entry.path().join(SUBDIR_FLAT);
        match probe_dir(&flat_path, "host-level flat root").await {
            Ok(true) => {
                cache_size += scan_sub_dir_recursive(flat_path, SubDirMode::Flat).await;
            }
            Ok(false) => {}
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Error probing host-level flat root `{}`:  {err}",
                    flat_path.display()
                );
            }
        }
    }

    Ok(cache_size)
}

#[must_use]
async fn scan_mirror_dir(
    host: &DirEntry,
    mirror: &MirrorEntry,
    other_mirror_paths: &[&str],
) -> u64 {
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
            // `<host>/<mirror_path>/`. Logging at info here just adds
            // noise on every startup / SIGUSR2 cleanup. For `Structured`
            // rows the absence is potentially a real inconsistency, so
            // keep the info-level call there.
            if mirror.kind() == MirrorKind::Flat {
                debug!("Mirror directory `{}` not found", mirror_path.display());
            } else {
                info!("Mirror directory `{}` not found", mirror_path.display());
            }
            return 0;
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read mirror directory `{}`:  {err}",
                mirror_path.display()
            );
            return 0;
        }
    };

    let mut dir_size = 0;

    loop {
        let entry = match mirror_dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate mirror directory `{}`:  {err}",
                    mirror_path.display()
                );
                return dir_size;
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
                    "Failed to get metadata of `{}`:  {err}",
                    entry.path().display()
                );
                continue;
            }
        };

        let name = entry.file_name();

        if file_type.is_symlink() {
            warn!(
                "Unrecognized symlink entry in mirror directory: `{}`",
                entry.path().display()
            );
            continue;
        }

        if file_type.is_file() {
            dir_size += mdata.len();

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
                dir_size += scan_sub_dir_recursive(entry.path(), SubDirMode::Structured).await;
                continue;
            }
            if name == SUBDIR_TMP {
                continue;
            }

            let Some(name_str) = name.to_str() else {
                warn!(
                    "Unrecognized directory entry in mirror directory: `{}`",
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

        warn!(
            "Unrecognized {} entry in mirror directory: `{}`",
            if file_type.is_dir() {
                "directory"
            } else if file_type.is_file() {
                "file"
            } else {
                "non-regular file"
            },
            entry.path().display()
        );
    }

    trace!(
        "Size of mirror directory `{}`: {}",
        mirror_path.display(),
        dir_size
    );

    dir_size
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
async fn scan_sub_dir_recursive(subdir_path: std::path::PathBuf, root_mode: SubDirMode) -> u64 {
    // Iterative DFS using an in-place stack avoids Box::pin'ing the
    // recursive future shape (async fn recursion).
    let mut dir_size = 0u64;
    let mut stack: Vec<(std::path::PathBuf, SubDirMode)> = vec![(subdir_path, root_mode)];

    'outer: while let Some((current, mode)) = stack.pop() {
        trace!("Scanning {} `{}`...", mode.purpose(), current.display());

        let mut subdir_dir = match tokio::fs::read_dir(&current).await {
            Ok(d) => d,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to read {} directory `{}`:  {err}",
                    mode.purpose(),
                    current.display()
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
                        "Failed to iterate {} directory `{}`:  {err}",
                        mode.purpose(),
                        current.display()
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
                        "Failed to get metadata of `{}`:  {err}",
                        entry.path().display()
                    );
                    continue;
                }
            };

            if file_type.is_symlink() {
                warn!(
                    "Unrecognized symlink entry in {}: `{}`",
                    mode.purpose(),
                    entry.path().display()
                );
                continue;
            }

            if file_type.is_file() {
                dir_size += mdata.len();
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

            warn!(
                "Unrecognized entry in {} `{}`: `{}`",
                mode.purpose(),
                current.display(),
                entry.path().display()
            );
        }
    }

    dir_size
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
