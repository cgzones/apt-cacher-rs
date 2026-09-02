use std::borrow::Cow;
use std::ffi::OsString;
use std::io;
use std::path::Path;

use hashbrown::HashMap;
use tracing::{debug, error, trace};

use crate::cache_walk::{DirFailure, EntryKind, OnMissing, WalkContext, WalkOutcome, Walker};
use crate::cleanup::engine::SpanClass;
use crate::cleanup::model::{TreeSpec, Walk};
use crate::deb_mirror::{NestedMirrorRelation, is_deb_package, nested_mirror_relation};
use crate::error::ErrorReport;
use crate::metrics;

/// Unlink a symlink / FIFO / socket / device the walker reported: cleanup
/// removes non-regular entries wherever it walks (pool, flat tree, `dists/`,
/// by-hash, `tmp/`).  The detection warn and `CACHE_NON_REGULAR` bump are
/// the walker's; this owns the removal and its outcome lines.  Returns
/// whether the entry is gone.
pub(super) async fn remove_non_regular(path: &Path) -> bool {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {
            debug!("Removed non-regular entry `{}`", path.display());
            true
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to remove non-regular entry `{}`; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
            false
        }
    }
}

/// Recursively remove a stray directory from `tmp/` - the one place cleanup
/// removes a directory rather than retaining it (see
/// `metrics::CACHE_DIRECTORY_UNEXPECTED`).  The caller has already reported
/// it through `Entry::report_unexpected`.  Returns whether the entry is gone.
pub(super) async fn remove_stray_dir(path: &Path) -> bool {
    match tokio::fs::remove_dir_all(path).await {
        Ok(()) => {
            debug!("Removed directory tmp entry `{}`", path.display());
            true
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to remove directory tmp entry `{}`; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
            false
        }
    }
}

static RECONCILE_WALK: WalkContext = WalkContext {
    what: "a mirror directory",
    dir_failure: DirFailure::Abort("abandoning this cleanup unit"),
    entry_failure: "retaining it and excluding it from cleanup",
    non_regular: "removing it",
};

/// Unified on-disk candidate scanner, driven by the unit's [`TreeSpec`].
///
/// [`Walk::Shallow`] is the structured pool's shape: depth-1, basename keys,
/// a deb-named directory is reported as unexpected.  [`Walk::Recursive`] is
/// the flat tree's shape: relpath keys (forward-slash joined), `skip_subdirs`
/// and nested-mirror boundaries are not entered.  Either way only
/// `.deb`/`.udeb`/`.ddeb`-named regular files become candidates; every
/// symlink / FIFO / socket / device met on the way is unlinked, and an
/// unreadable directory abandons the unit (`Err`) - reconciling against a
/// partial candidate set would grace-sweep live debs.
///
/// Candidates are keyed by the entry's path *relative to `tree.root`*, which
/// is what `sweep_candidates` rejoins to reach the file - so it must stay
/// exactly that and never, say, a basename for a nested entry.
pub(super) async fn scan_candidates(
    tree: &TreeSpec,
    mirror_path: &str,
) -> Result<HashMap<OsString, SpanClass>, io::Error> {
    let mut ret = HashMap::new();
    let mut walker = Walker::new(&tree.root, &RECONCILE_WALK, OnMissing::Tolerate, ());

    while let Some(mut entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => {
                remove_non_regular(&entry.path()).await;
                continue;
            }
            EntryKind::Dir => {
                match &tree.walk {
                    // A pool holds no directories, but the mirror-level
                    // layout dirs (`dists/`, `tmp/`) share its root and are
                    // the startup scan's business; only a deb-named one is
                    // out of place here.
                    Walk::Shallow => {
                        if entry.name().to_str().is_none_or(is_deb_package) {
                            entry.report_unexpected(
                                "retaining it and excluding its contents from cleanup",
                            );
                        }
                    }
                    Walk::Recursive {
                        skip_subdirs,
                        boundaries,
                    } => {
                        let Some(name_str) = entry.name().to_str() else {
                            entry.report_unexpected(
                                "retaining it and excluding its contents from cleanup",
                            );
                            continue;
                        };
                        // The by-hash subtree (handled by the by-hash
                        // cleanup) and the tmp partial-download dir.
                        if skip_subdirs.contains(&name_str) {
                            continue;
                        }

                        // Translate the on-disk position back to a
                        // mirror-path equivalent (`<mirror_path>/<rel>`) so
                        // it can be compared against the registered nested
                        // mirror paths.  A hit delimits a boundary: the
                        // nested mirror owns everything inside, so do not
                        // descend.  Only UTF-8-named directories are ever
                        // descended into, so the relative path is UTF-8 and
                        // the lossy conversion is exact.
                        let rel_path = entry.rel_path();
                        let rel = rel_path.to_string_lossy();
                        let candidate: Cow<'_, str> = if mirror_path.is_empty() {
                            rel
                        } else {
                            Cow::Owned(format!("{mirror_path}/{rel}"))
                        };
                        match nested_mirror_relation(&candidate, boundaries) {
                            NestedMirrorRelation::Boundary => trace!(
                                "Skipping `{}` during flat cleanup: nested mirror root for `{candidate}`",
                                entry.path().display(),
                            ),
                            NestedMirrorRelation::Container | NestedMirrorRelation::Unrelated => {
                                entry.descend(());
                            }
                        }
                    }
                }
                continue;
            }
            EntryKind::File => {}
        }

        let Some(name_str) = entry.name().to_str() else {
            // Debnames are URL-decoded ASCII, so a non-UTF-8 name can never
            // be a cached deb nor match any index entry.
            entry.report_unexpected("retaining it and excluding it from cleanup");
            continue;
        };
        if !is_deb_package(name_str) {
            continue;
        }

        let key = entry.rel_path();
        debug_assert_eq!(
            entry.path(),
            tree.root.join(&key),
            "candidate key must rejoin onto the tree root"
        );
        ret.insert(key.into_os_string(), SpanClass::Deb);
    }

    match walker.finish() {
        WalkOutcome::Complete | WalkOutcome::RootMissing => Ok(ret),
        WalkOutcome::Aborted(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;
    use crate::cache_layout::{SUBDIR_FLAT_BYHASH, SUBDIR_TMP};

    #[tokio::test]
    async fn remove_non_regular_unlinks_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("t");
        tokio::fs::write(&target, b"x").await.expect("t");
        let link = dir.path().join("l");
        tokio::fs::symlink(&target, &link).await.expect("symlink");
        assert!(remove_non_regular(&link).await);
        assert!(!link.exists());
        assert!(target.exists(), "the link, not its target, is removed");
    }

    #[tokio::test]
    async fn remove_stray_dir_removes_recursively() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("d");
        tokio::fs::create_dir(&sub).await.expect("dir");
        tokio::fs::write(sub.join("nested"), b"x")
            .await
            .expect("nested");
        assert!(remove_stray_dir(&sub).await);
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
            walk: Walk::Shallow,
        };
        let map = scan_candidates(&tree, "debian").await.expect("scan");
        assert!(map.contains_key(OsStr::new("a_1.0_amd64.deb")));
        assert!(
            !map.keys()
                .any(|k| k.to_string_lossy().contains("b_1.0_amd64.deb")),
            "never recurses"
        );
        assert!(
            dir.path().join("dists").is_dir(),
            "layout dirs are retained"
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
        tokio::fs::create_dir(dir.path().join(SUBDIR_TMP))
            .await
            .expect("tmp");
        tokio::fs::write(dir.path().join("tmp/d_1.0_amd64.deb"), b"z")
            .await
            .expect("tmp deb");
        let tree = TreeSpec {
            root: dir.path().to_path_buf(),
            walk: Walk::Recursive {
                skip_subdirs: &[SUBDIR_FLAT_BYHASH, SUBDIR_TMP],
                boundaries: Vec::new(),
            },
        };
        let map = scan_candidates(&tree, "apt").await.expect("scan");
        assert!(map.contains_key(OsStr::new("amd64/c_1.0_amd64.deb")));
        assert_eq!(map.len(), 1, "skip_subdirs are not entered");
    }

    #[tokio::test]
    async fn scan_candidates_flat_stops_at_nested_mirror_boundary() {
        let dir = tempfile::tempdir().expect("tempdir");
        for sub in ["amd64", "amd64/special", "other"] {
            tokio::fs::create_dir(dir.path().join(sub))
                .await
                .expect("sub");
            tokio::fs::write(dir.path().join(sub).join("p_1.0_all.deb"), b"z")
                .await
                .expect("deb");
        }
        let tree = TreeSpec {
            root: dir.path().to_path_buf(),
            walk: Walk::Recursive {
                skip_subdirs: &[],
                boundaries: vec!["apt/amd64/special".to_owned()],
            },
        };
        let map = scan_candidates(&tree, "apt").await.expect("scan");
        // `amd64/` is the container of the nested mirror: entered, its own
        // debs are candidates; `amd64/special/` is the nested mirror's own.
        assert!(map.contains_key(OsStr::new("amd64/p_1.0_all.deb")));
        assert!(map.contains_key(OsStr::new("other/p_1.0_all.deb")));
        assert!(!map.contains_key(OsStr::new("amd64/special/p_1.0_all.deb")));
    }

    #[tokio::test]
    async fn scan_candidates_unlinks_non_regular_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        tokio::fs::write(dir.path().join("a_1.0_amd64.deb"), b"x")
            .await
            .expect("deb");
        let link = dir.path().join("l_1.0_amd64.deb");
        tokio::fs::symlink(dir.path().join("a_1.0_amd64.deb"), &link)
            .await
            .expect("symlink");
        let tree = TreeSpec {
            root: dir.path().to_path_buf(),
            walk: Walk::Shallow,
        };
        let map = scan_candidates(&tree, "debian").await.expect("scan");
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(OsStr::new("a_1.0_amd64.deb")));
        assert!(!link.exists(), "the symlink is unlinked, not a candidate");
    }

    #[tokio::test]
    async fn scan_candidates_absent_root_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tree = TreeSpec {
            root: dir.path().join("absent"),
            walk: Walk::Shallow,
        };
        let map = scan_candidates(&tree, "debian").await.expect("scan");
        assert!(map.is_empty());
    }
}
