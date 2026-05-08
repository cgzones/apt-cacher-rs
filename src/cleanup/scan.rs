use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use hashbrown::HashMap;
use tracing::{debug, error, trace, warn};

use crate::cleanup::engine::{Candidate, SpanClass};
use crate::deb_mirror::{is_deb_package, is_strict_path_descendant, path_starts_with_segment};
use crate::error::ProxyCacheError;
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
                    "Skipping unexpected directory in cache: `{}`",
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
                            "Failed to remove directory tmp entry `{}`:  {err}",
                            path.display()
                        );
                        AnomalyOutcome::Skipped
                    }
                }
            }
        }
    } else {
        metrics::CACHE_NON_REGULAR.increment();
        warn!("Removing non-regular entry in cache: `{}`", path.display());
        match tokio::fs::remove_file(path).await {
            Ok(()) => {
                debug!("Removed non-regular entry `{}`", path.display());
                AnomalyOutcome::Removed
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to remove non-regular entry `{}`:  {err}",
                    path.display()
                );
                AnomalyOutcome::Skipped
            }
        }
    }
}

/// Parameters controlling [`scan_candidates`]' traversal behaviour.
pub(super) struct ScanSpec {
    /// When `false`, behaves like the old `scan_cached_files`: depth-1,
    /// basename keys, deb-named-directory warning.  When `true`, behaves
    /// like the old `scan_flat_cached_debs`: recursive, relpath keys, skips
    /// `skip_subdirs` and nested-mirror boundaries.
    pub recurse: bool,
    /// Sub-directory names to skip entirely during recursive traversal
    /// (e.g. `by-hash/` and `tmp/` for flat mirrors).  Unused when
    /// `recurse` is `false`.
    pub skip_subdirs: &'static [&'static str],
    /// Mirror paths of registered siblings that live *inside* `mirror_path`.
    /// When the recursive walk reaches a directory whose mirror-path
    /// equivalent hits one of these, the subtree is skipped.  Unused when
    /// `recurse` is `false`.
    pub boundaries: Vec<String>,
}

/// Unified on-disk candidate scanner.
///
/// With `spec.recurse = false` reproduces the old `scan_cached_files` exactly:
/// depth-1, basename keys, deb-named-directory warning (`CACHE_DIRECTORY_UNEXPECTED`),
/// inline removal of non-regular non-directory entries (`CACHE_NON_REGULAR`).
///
/// With `spec.recurse = true` reproduces the old `scan_flat_cached_debs` exactly:
/// stack-based recursive walk, relpath keys (forward-slash joined), skips
/// `spec.skip_subdirs` and nested-mirror boundaries, inline removal of
/// symlinks and other non-regular entries.
pub(super) async fn scan_candidates(
    root: &Path,
    mirror_path: &str,
    spec: &ScanSpec,
) -> Result<HashMap<String, Candidate>, ProxyCacheError> {
    let mut ret = HashMap::new();
    let mut stack: Vec<(PathBuf, String)> = vec![(root.to_path_buf(), String::new())];

    while let Some((current, rel_prefix)) = stack.pop() {
        let mut dir = match tokio::fs::read_dir(&current).await {
            Ok(d) => d,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!("Failed to read directory `{}`:  {err}", current.display());
                return Err(ProxyCacheError::Io(err));
            }
        };

        loop {
            let entry = match dir.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to iterate directory `{}`:  {err}",
                        current.display()
                    );
                    return Err(ProxyCacheError::Io(err));
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
                            "Failed to get file type of `{}`:  {err}",
                            entry.path().display()
                        );
                    }
                }
                if spec.recurse {
                    warn!("Skipping unrecognized entry `{}`", entry.path().display());
                } else {
                    warn!(
                        "Unrecognized entry in mirror root directory: `{}`",
                        entry.path().display()
                    );
                }
                continue;
            };

            // Structured (depth-1): mirror `scan_flat_cached_debs` — structured
            // Pool admits `.deb`/`.udeb`/`.ddeb`, so filter by name before
            // touching disk.  Flat (recursive): filter after all type checks.
            if !spec.recurse && !is_deb_package(name_str) {
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
                        "Failed to get file type of `{}`:  {err}",
                        entry.path().display()
                    );
                    continue;
                }
            };

            if file_type.is_dir() {
                if spec.recurse {
                    // Skip the by-hash subtree (handled by the by-hash
                    // cleanup), the tmp partial-download dir, and recurse
                    // everything else.
                    if spec.skip_subdirs.contains(&name_str) {
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
                    if is_nested_mirror_boundary(candidate_full, &spec.boundaries) {
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
            if spec.recurse && !is_deb_package(name_str) {
                continue;
            }

            let key = if spec.recurse && !rel_prefix.is_empty() {
                format!("{rel_prefix}/{name_str}")
            } else {
                name_str.to_owned()
            };
            ret.insert(
                key,
                Candidate {
                    path: entry.path(),
                    class: SpanClass::Deb,
                },
            );
        }
    }

    Ok(ret)
}

/// Derive the paths of mirrors registered under the same `(host, port)` that
/// live *inside* `mirror_path` (segment-aligned), given the sorted list of
/// sibling paths on that host (which may include `mirror_path` itself; self
/// is filtered out by the segment-alignment check).
///
/// The empty-`mirror_path` case denotes a host-root mirror that nests every
/// other path on the host.
///
/// Sorted input lets the lookup skip directly to the prefix region via
/// `partition_point`.  Within that region, lexicographic order can still
/// interleave non-segment-aligned siblings (e.g. `debian-security` between
/// `debian` and `debian/...` since `-` < `/` in ASCII), so segment alignment
/// is enforced via `is_strict_path_descendant`; the surrounding `take_while`
/// is a safe termination optimisation, since entries sharing the byte prefix
/// are contiguous in lexicographic order.
#[must_use]
pub(super) fn derive_nested_paths(mirror_path: &str, host_paths_sorted: &[&str]) -> Vec<String> {
    if mirror_path.is_empty() {
        return host_paths_sorted
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| (*p).to_owned())
            .collect();
    }
    // `take_while` terminates the scan once we leave the contiguous
    // byte-prefix region.  Within that region the byte prefix alone is too
    // loose — `debian-security` starts with `debian` but is not a
    // segment-aligned descendant — so `is_strict_path_descendant` filters
    // out non-aligned siblings.
    let start = host_paths_sorted.partition_point(|p| *p <= mirror_path);
    host_paths_sorted[start..]
        .iter()
        .take_while(|p| p.starts_with(mirror_path))
        .filter(|p| is_strict_path_descendant(p, mirror_path))
        .map(|p| (*p).to_owned())
        .collect()
}

/// Whether the on-disk position `candidate` (the mirror-path-equivalent of
/// a subdir reached during recursion) sits at or inside a registered nested
/// mirror's root.  Match semantics are segment-aligned:
///
/// - `apt/amd64` matches the registered root `apt/amd64` (equality).
/// - `apt/amd64/foo` matches the registered root `apt/amd64` (descendant --
///   the walker has already entered the nested subtree).
/// - `apt/amd64` does **not** match the registered root `apt/amd64/special`:
///   recursion must continue into `apt/amd64` so the walker can reach the
///   real boundary at `apt/amd64/special`.
/// - `apt-tools` does not match the registered root `apt` (segment-aligned,
///   not a byte prefix).
#[must_use]
fn is_nested_mirror_boundary(candidate: &str, nested_mirror_paths: &[String]) -> bool {
    nested_mirror_paths
        .iter()
        .any(|p| path_starts_with_segment(candidate, p))
}

#[cfg(test)]
mod tests {
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
        let before = metrics::CACHE_NON_REGULAR.get();
        let out = handle_anomalous_entry(&link, ft, DirAction::Skip).await;
        assert!(matches!(out, AnomalyOutcome::Removed));
        assert_eq!(metrics::CACHE_NON_REGULAR.get(), before + 1);
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
        let before = metrics::CACHE_DIRECTORY_UNEXPECTED.get();
        let out = handle_anomalous_entry(&sub, ft, DirAction::Skip).await;
        assert!(matches!(out, AnomalyOutcome::Skipped));
        assert_eq!(metrics::CACHE_DIRECTORY_UNEXPECTED.get(), before + 1);
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
        let spec = ScanSpec {
            recurse: false,
            skip_subdirs: &[],
            boundaries: vec![],
        };
        let map = scan_candidates(dir.path(), "debian", &spec)
            .await
            .expect("scan");
        assert!(map.contains_key("a_1.0_amd64.deb"));
        assert!(!map.keys().any(|k| k.contains("b_1.0_amd64.deb"))); // never recurses
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
        let spec = ScanSpec {
            recurse: true,
            skip_subdirs: &[SUBDIR_FLAT_BYHASH, SUBDIR_TMP],
            boundaries: vec![],
        };
        let map = scan_candidates(dir.path(), "apt", &spec)
            .await
            .expect("scan");
        assert!(map.contains_key("amd64/c_1.0_amd64.deb"));
    }

    fn sorted(paths: &[&'static str]) -> Vec<&'static str> {
        let mut v = paths.to_vec();
        v.sort_unstable();
        v
    }

    #[test]
    fn derive_nested_paths_basic_nesting() {
        let host = sorted(&["debian", "debian/security", "debian/x/y", "unrelated"]);
        assert_eq!(
            derive_nested_paths("debian", &host),
            vec!["debian/security".to_owned(), "debian/x/y".to_owned()]
        );
    }

    #[test]
    fn derive_nested_paths_skips_non_segment_aligned_prefix_neighbour() {
        // `debian-security` sorts between `debian` and `debian/...` (`-` < `/`)
        // but is not a nested child; the segment-alignment filter must exclude
        // it without halting the surrounding `take_while`, so `debian/foo` and
        // `debian/security` are still returned.
        let host = sorted(&["debian", "debian-security", "debian/foo", "debian/security"]);
        assert_eq!(
            derive_nested_paths("debian", &host),
            vec!["debian/foo".to_owned(), "debian/security".to_owned()]
        );
    }

    #[test]
    fn derive_nested_paths_empty_mirror_path_nests_all_others() {
        let host = sorted(&["", "debian", "debian/security"]);
        assert_eq!(
            derive_nested_paths("", &host),
            vec!["debian".to_owned(), "debian/security".to_owned()]
        );
    }

    #[test]
    fn derive_nested_paths_excludes_self() {
        let host = sorted(&["debian"]);
        assert!(derive_nested_paths("debian", &host).is_empty());
    }

    #[test]
    fn derive_nested_paths_no_match() {
        let host = sorted(&["apt", "debian"]);
        assert!(derive_nested_paths("ubuntu", &host).is_empty());
    }

    #[test]
    fn derive_nested_paths_handles_underscore_sibling() {
        // `debian_updates` (underscore) must not be treated as nested under
        // `debian` even though it shares the `debian` byte prefix.
        // Likewise `debian-security` (hyphen, sorts before `debian/...`)
        // must be excluded.  Only `debian/foo` is a true nested child.
        let host = sorted(&["debian", "debian-security", "debian_updates", "debian/foo"]);
        assert_eq!(
            derive_nested_paths("debian", &host),
            vec!["debian/foo".to_owned()]
        );
    }

    #[test]
    fn is_nested_mirror_boundary_equality_match() {
        let nested = vec!["apt/amd64".to_owned()];
        assert!(is_nested_mirror_boundary("apt/amd64", &nested));
    }

    #[test]
    fn is_nested_mirror_boundary_descendant_inside_nested_subtree() {
        let nested = vec!["apt/amd64".to_owned()];
        assert!(is_nested_mirror_boundary("apt/amd64/foo", &nested));
    }

    #[test]
    fn is_nested_mirror_boundary_ancestor_must_recurse() {
        // Regression guard against the reversed-argument bug: a candidate
        // that is a strict ancestor of a registered nested root is NOT a
        // boundary -- the walker has to continue down to reach the real
        // nested root.
        let nested = vec!["apt/amd64/special".to_owned()];
        assert!(!is_nested_mirror_boundary("apt/amd64", &nested));
    }

    #[test]
    fn is_nested_mirror_boundary_segment_aligned_non_match() {
        let nested = vec!["apt".to_owned()];
        assert!(!is_nested_mirror_boundary("apt-tools", &nested));
    }
}
