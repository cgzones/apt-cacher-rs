use std::ffi::OsString;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use hashbrown::HashMap;
use tracing::{debug, error, trace, warn};

use crate::cleanup::engine::SpanClass;
use crate::cleanup::model::TreeSpec;
use crate::deb_mirror::{NestedMirrorRelation, is_deb_package, nested_mirror_relation};
use crate::error::ErrorReport;
use crate::metrics;

/// Specifies how a stray directory anomaly should be handled.
#[derive(Clone, Copy)]
pub(super) enum DirAction {
    /// Log and skip; the directory is left on disk.
    Skip,
    /// Log and recursively remove via `remove_dir_all`.
    RemoveAll,
}

/// Outcome of [`handle_anomalous_entry`].
pub(super) enum AnomalyOutcome {
    /// The entry was successfully removed from disk.
    Removed,
    /// The entry was not removed (either skipped by policy or removal failed).
    Skipped,
}

/// Handle a non-regular or unexpected-directory cache entry.
///
/// - Non-directory non-regular (symlink / FIFO / socket / device): bumps
///   [`metrics::CACHE_NON_REGULAR`], logs a warning, and calls
///   `remove_file`.  Returns [`AnomalyOutcome::Removed`] on success or
///   [`AnomalyOutcome::Skipped`] on I/O error (after bumping
///   [`metrics::CACHE_IO_FAILURE`] and logging).
/// - Directory: bumps [`metrics::CACHE_DIRECTORY_UNEXPECTED`]; then either
///   skips ([`DirAction::Skip`]) or removes recursively via `remove_dir_all`
///   ([`DirAction::RemoveAll`]).
pub(super) async fn handle_anomalous_entry(
    path: &Path,
    file_type: std::fs::FileType,
    action: DirAction,
) -> AnomalyOutcome {
    if file_type.is_dir() {
        metrics::CACHE_DIRECTORY_UNEXPECTED.increment();
        match action {
            DirAction::Skip => {
                warn!(
                    "Unexpected directory `{}` in the cache; retaining it and excluding its contents from cleanup",
                    path.display()
                );
                AnomalyOutcome::Skipped
            }
            DirAction::RemoveAll => {
                warn!("Removing directory tmp entry `{}`", path.display());
                match tokio::fs::remove_dir_all(path).await {
                    Ok(()) => {
                        debug!("Removed directory tmp entry `{}`", path.display());
                        AnomalyOutcome::Removed
                    }
                    Err(err) => {
                        metrics::CACHE_IO_FAILURE.increment();
                        error!(
                            "Failed to remove directory tmp entry `{}`; retaining it:  {}",
                            path.display(),
                            ErrorReport(&err)
                        );
                        AnomalyOutcome::Skipped
                    }
                }
            }
        }
    } else {
        metrics::CACHE_NON_REGULAR.increment();
        warn!(
            "Non-regular entry `{}` in the cache; removing it",
            path.display()
        );
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                debug!("Removed non-regular entry `{}`", path.display());
                AnomalyOutcome::Removed
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to remove non-regular entry `{}`; retaining it:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
                AnomalyOutcome::Skipped
            }
        }
    }
}

/// Unified on-disk candidate scanner, driven by the unit's [`TreeSpec`].
///
/// With `tree.recurse = false` reproduces the old `scan_cached_files` exactly:
/// depth-1, basename keys, deb-named-directory warning (`CACHE_DIRECTORY_UNEXPECTED`),
/// inline removal of non-regular non-directory entries (`CACHE_NON_REGULAR`).
///
/// With `tree.recurse = true` reproduces the old `scan_flat_cached_debs` exactly:
/// stack-based recursive walk, relpath keys (forward-slash joined), skips
/// `tree.skip_subdirs` and nested-mirror boundaries, inline removal of
/// symlinks and other non-regular entries.
pub(super) async fn scan_candidates(
    tree: &TreeSpec,
    mirror_path: &str,
) -> Result<HashMap<OsString, SpanClass>, io::Error> {
    let mut ret = HashMap::new();
    let mut stack: Vec<(PathBuf, String)> = vec![(tree.root.clone(), String::new())];

    while let Some((current, rel_prefix)) = stack.pop() {
        let mut dir = match tokio::fs::read_dir(&current).await {
            Ok(d) => d,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to read directory `{}`; abandoning this cleanup unit:  {}",
                    current.display(),
                    ErrorReport(&err)
                );
                return Err(err);
            }
        };

        loop {
            let entry = match dir.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to iterate directory `{}`; abandoning this cleanup unit:  {}",
                        current.display(),
                        ErrorReport(&err)
                    );
                    return Err(err);
                }
            };
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                // Attribute the anomaly by the entry's real type instead of
                // blanket-charging `CACHE_DIRECTORY_UNEXPECTED`: a non-UTF-8
                // name can sit on a directory, a regular file, or a non-regular
                // entry. Mirror `handle_anomalous_entry`'s dir-vs-non-dir split
                // (there is no mirror-subtree "unexpected regular" counter --
                // `CACHE_UNEXPECTED_REGULAR` is cache-root-scoped).
                match entry.file_type().await {
                    Ok(ft) if ft.is_dir() => metrics::CACHE_DIRECTORY_UNEXPECTED.increment(),
                    Ok(_) => metrics::CACHE_NON_REGULAR.increment(),
                    Err(err) => {
                        metrics::CACHE_IO_FAILURE.increment();
                        error!(
                            "Failed to get file type of `{}`; the cache anomaly stays unclassified:  {}",
                            entry.path().display(),
                            ErrorReport(&err)
                        );
                    }
                }
                if tree.recurse {
                    warn!(
                        "Unrecognized entry `{}` in mirror directory; retaining it and excluding it from cleanup",
                        entry.path().display()
                    );
                } else {
                    warn!(
                        "Unrecognized entry `{}` in mirror root directory; retaining it and excluding it from cleanup",
                        entry.path().display()
                    );
                }
                continue;
            };

            // Structured (depth-1): mirror `scan_flat_cached_debs` — structured
            // Pool admits `.deb`/`.udeb`/`.ddeb`, so filter by name before
            // touching disk.  Flat (recursive): filter after all type checks.
            if !tree.recurse && !is_deb_package(name_str) {
                continue;
            }

            // Use `file_type()` (lstat semantics) so a symlink planted in
            // the cache by a hostile filesystem doesn't trick us into
            // walking outside the cache tree.
            let file_type = match entry.file_type().await {
                Ok(ft) => ft,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to get file type of `{}`; retaining the entry and excluding it from cleanup:  {}",
                        entry.path().display(),
                        ErrorReport(&err)
                    );
                    continue;
                }
            };

            if file_type.is_dir() {
                if tree.recurse {
                    // Skip the by-hash subtree (handled by the by-hash
                    // cleanup), the tmp partial-download dir, and recurse
                    // everything else.
                    if tree.skip_subdirs.contains(&name_str) {
                        continue;
                    }
                    let child_rel = if rel_prefix.is_empty() {
                        name_str.to_owned()
                    } else {
                        format!("{rel_prefix}/{name_str}")
                    };

                    // Translate the on-disk position back to a mirror-path
                    // equivalent (`<mirror_path>/<child_rel>`) so it can be
                    // compared against the registered nested mirror paths.
                    // Hits delimit a boundary: the nested mirror owns
                    // everything inside, so do not descend.
                    let owned_full;
                    let candidate_full: &str = if mirror_path.is_empty() {
                        child_rel.as_str()
                    } else {
                        owned_full = format!("{mirror_path}/{child_rel}");
                        owned_full.as_str()
                    };
                    if nested_mirror_relation(candidate_full, &tree.boundaries)
                        == NestedMirrorRelation::Boundary
                    {
                        trace!(
                            "Skipping `{}` during flat cleanup: nested mirror root for `{candidate_full}`",
                            entry.path().display(),
                        );
                        continue;
                    }

                    stack.push((entry.path(), child_rel));
                } else {
                    handle_anomalous_entry(&entry.path(), file_type, DirAction::Skip).await;
                }
                continue;
            }

            if !file_type.is_file() {
                handle_anomalous_entry(&entry.path(), file_type, DirAction::Skip).await;
                continue;
            }

            // Flat (recursive): filter by deb name after all type checks.
            if tree.recurse && !is_deb_package(name_str) {
                continue;
            }

            let key = if tree.recurse && !rel_prefix.is_empty() {
                format!("{rel_prefix}/{name_str}")
            } else {
                name_str.to_owned()
            };
            // The key is the entry's path relative to `tree.root`, which is
            // what `sweep_candidates` rejoins to reach the file -- so it must
            // stay exactly that and never, say, a basename for a nested entry.
            debug_assert_eq!(
                entry.path(),
                tree.root.join(&key),
                "candidate key must rejoin onto the tree root"
            );
            ret.insert(OsString::from(key), SpanClass::Deb);
        }
    }

    Ok(ret)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;
    use crate::cache_layout::{SUBDIR_FLAT_BYHASH, SUBDIR_TMP};
    use crate::metrics;

    #[tokio::test]
    async fn anomaly_symlink_removed_as_non_regular() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("t");
        tokio::fs::write(&target, b"x").await.expect("t");
        let link = dir.path().join("l");
        tokio::fs::symlink(&target, &link).await.expect("symlink");
        let ft = tokio::fs::symlink_metadata(&link)
            .await
            .expect("lstat")
            .file_type();
        // The counter is process-global and other unit tests in this binary
        // bump it concurrently, so assert the delta as a lower bound.
        let before = metrics::CACHE_NON_REGULAR.get();
        let out = handle_anomalous_entry(&link, ft, DirAction::Skip).await;
        assert!(matches!(out, AnomalyOutcome::Removed));
        assert!(metrics::CACHE_NON_REGULAR.get() > before);
        assert!(!link.exists());
    }

    #[tokio::test]
    async fn anomaly_stray_dir_skipped_as_unexpected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("d");
        tokio::fs::create_dir(&sub).await.expect("dir");
        let ft = tokio::fs::symlink_metadata(&sub)
            .await
            .expect("lstat")
            .file_type();
        // The counter is process-global and other unit tests in this binary
        // bump it concurrently, so assert the delta as a lower bound.
        let before = metrics::CACHE_DIRECTORY_UNEXPECTED.get();
        let out = handle_anomalous_entry(&sub, ft, DirAction::Skip).await;
        assert!(matches!(out, AnomalyOutcome::Skipped));
        assert!(metrics::CACHE_DIRECTORY_UNEXPECTED.get() > before);
        assert!(sub.exists());
    }

    #[tokio::test]
    async fn anomaly_tmp_dir_removed_with_remove_all() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("d");
        tokio::fs::create_dir(&sub).await.expect("dir");
        let ft = tokio::fs::symlink_metadata(&sub)
            .await
            .expect("lstat")
            .file_type();
        let out = handle_anomalous_entry(&sub, ft, DirAction::RemoveAll).await;
        assert!(matches!(out, AnomalyOutcome::Removed));
        assert!(!sub.exists());
    }

    #[tokio::test]
    async fn scan_candidates_structured_is_depth1_basename_keyed() {
        let dir = tempfile::tempdir().expect("tempdir");
        tokio::fs::write(dir.path().join("a_1.0_amd64.deb"), b"x")
            .await
            .expect("deb");
        tokio::fs::create_dir(dir.path().join("dists"))
            .await
            .expect("dists");
        tokio::fs::write(dir.path().join("dists/b_1.0_amd64.deb"), b"y")
            .await
            .expect("nested");
        let tree = TreeSpec {
            root: dir.path().to_path_buf(),
            recurse: false,
            skip_subdirs: &[],
            boundaries: Vec::new(),
        };
        let map = scan_candidates(&tree, "debian").await.expect("scan");
        assert!(map.contains_key(OsStr::new("a_1.0_amd64.deb")));
        assert!(
            !map.keys()
                .any(|k| k.to_string_lossy().contains("b_1.0_amd64.deb")),
            "never recurses"
        );
    }

    #[tokio::test]
    async fn scan_candidates_flat_recurses_relpath_keyed() {
        let dir = tempfile::tempdir().expect("tempdir");
        tokio::fs::create_dir(dir.path().join("amd64"))
            .await
            .expect("sub");
        tokio::fs::write(dir.path().join("amd64/c_1.0_amd64.deb"), b"z")
            .await
            .expect("deb");
        let tree = TreeSpec {
            root: dir.path().to_path_buf(),
            recurse: true,
            skip_subdirs: &[SUBDIR_FLAT_BYHASH, SUBDIR_TMP],
            boundaries: Vec::new(),
        };
        let map = scan_candidates(&tree, "apt").await.expect("scan");
        assert!(map.contains_key(OsStr::new("amd64/c_1.0_amd64.deb")));
    }
}
