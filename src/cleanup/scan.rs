use std::ffi::OsString;
use std::path::Path;

use hashbrown::HashMap;
use tracing::{debug, error, trace};

use crate::cache_walk::{AnomalyLevel, DirFailure, EntryKind, WalkContext, WalkOutcome, Walker};
use crate::cleanup::engine::{CleanupUnitError, SpanClass};
use crate::cleanup::model::{TreeSpec, Walk};
use crate::deb_mirror::{
    NestedMirrorRelation, is_deb_package, mirror_relative_path, nested_mirror_relation,
};
use crate::error::ErrorReport;
use crate::metrics;

/// Unlink a symlink / FIFO / socket / device the walker reported (the walker
/// already warned and counted it).  Returns whether the entry is gone.
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
/// removes a directory rather than retaining it.  The caller has already
/// reported it.  Returns whether the entry is gone.
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
    anomalies: AnomalyLevel::Warn,
};

pub(super) struct ScannedTree {
    /// Keyed by the entry's path relative to the tree root.
    pub(super) candidates: HashMap<OsString, SpanClass>,
    /// Entries left in place on a cache I/O failure, each already logged.
    pub(super) io_failures: u64,
}

/// On-disk candidate scanner, driven by the unit's [`TreeSpec`].
///
/// Only `.deb`/`.udeb`/`.ddeb`-named regular files become candidates; every
/// non-regular entry met on the way is unlinked.  An unreadable directory
/// abandons the unit (`Err`, logged by the walker): reconciling against a
/// partial candidate set would grace-sweep live debs.
pub(super) async fn scan_candidates(
    cache_root: &Path,
    tree: &TreeSpec,
    mirror_path: &str,
) -> Result<ScannedTree, CleanupUnitError> {
    let mut ret = HashMap::new();
    let mut io_failures = 0;
    let mut walker = Walker::below(cache_root, &tree.root, &RECONCILE_WALK, ());

    while let Some(mut entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => {
                if !remove_non_regular(&entry.path()).await {
                    io_failures += 1;
                }
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
                        if skip_subdirs.contains(&name_str) {
                            continue;
                        }

                        if boundaries.is_empty() {
                            entry.descend(());
                            continue;
                        }

                        // Only UTF-8-named directories are ever descended
                        // into, so the lossy conversion is exact.
                        let rel_path = entry.rel_path();
                        let rel = rel_path.to_string_lossy();
                        let candidate = mirror_relative_path(mirror_path, &rel);
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

    io_failures += walker.io_failures();
    match walker.finish() {
        WalkOutcome::Complete | WalkOutcome::RootMissing => Ok(ScannedTree {
            candidates: ret,
            io_failures,
        }),
        WalkOutcome::Aborted { logged, err: _ } => Err(CleanupUnitError(logged)),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::*;
    use crate::cache_paths::{SUBDIR_FLAT_BYHASH, SUBDIR_TMP};

    #[tokio::test]
    async fn a_pool_behind_a_symlink_yields_no_candidates() {
        let cache = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        std::fs::write(outside.path().join("a_1.0_amd64.deb"), b"x").expect("deb");
        std::fs::create_dir(cache.path().join("mirror.test")).expect("mkdir");
        std::os::unix::fs::symlink(outside.path(), cache.path().join("mirror.test/debian"))
            .expect("symlink");
        let tree = TreeSpec {
            root: cache.path().join("mirror.test/debian"),
            walk: Walk::Shallow,
        };
        let scanned = scan_candidates(cache.path(), &tree, "debian")
            .await
            .expect("a refused root is an empty tree");
        assert!(scanned.candidates.is_empty(), "{:?}", scanned.candidates);
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
        let map = scan_candidates(dir.path(), &tree, "debian")
            .await
            .expect("scan")
            .candidates;
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
        let map = scan_candidates(dir.path(), &tree, "apt")
            .await
            .expect("scan")
            .candidates;
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
        let map = scan_candidates(dir.path(), &tree, "apt")
            .await
            .expect("scan")
            .candidates;
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
        let map = scan_candidates(dir.path(), &tree, "debian")
            .await
            .expect("scan")
            .candidates;
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
        let map = scan_candidates(dir.path(), &tree, "debian")
            .await
            .expect("scan")
            .candidates;
        assert!(map.is_empty());
    }
}
