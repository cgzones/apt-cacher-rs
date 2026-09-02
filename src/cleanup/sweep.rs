use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, SystemTime};

use hashbrown::HashMap;
use tracing::{debug, error, warn};

use crate::cache_layout::{CacheEntryKeyRef, CacheLayout};
use crate::cache_walk::{DirFailure, EntryKind, OnMissing, WalkContext, Walker};
use crate::deb_mirror::{Mirror, is_deb_package};
use crate::error::ErrorReport;
use crate::humanfmt::HumanFmt;
use crate::{cache_metadata, info_once, metrics, warn_once_or_info};

use super::engine::SpanClass;
use super::scan::remove_non_regular;

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
pub(super) fn invalidate_metadata_for(path: &Path, mirror: &Mirror, layout: CacheLayout) {
    if let Some(debname) = path.file_name().and_then(|n| n.to_str()) {
        cache_metadata::store().invalidate(&CacheEntryKeyRef::new(mirror, debname, layout));
    }
}

/// Return value of [`sweep_candidates`].
#[derive(Copy, Clone)]
pub(super) struct SweepResult {
    pub(super) files_removed: u64,
    pub(super) bytes_removed: u64,
    /// Subset of `files_removed` deleted because they were unreferenced but
    /// their algorithm was covered (by-hash reference reclaim), threaded up to
    /// `CLEANUP_BYHASH_UNREFERENCED` by the by-hash unit.
    pub(super) removed_unreferenced: u64,
}

/// Per-[`SpanClass`] retention spans consulted by [`sweep_candidates`]: each
/// candidate's class selects which span gates its removal. Chosen by
/// [`decide_sweep`](crate::cleanup::model::decide_sweep) for the reconcile
/// facets, and inline by `sweep_byhash_dir` for the by-hash ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SpanTable {
    pub deb: Duration,
    pub byhash_covered: Duration,
    pub byhash_uncovered: Duration,
}

impl SpanTable {
    /// One span for every class — the shape of every policy that does not
    /// distinguish by-hash coverage.
    pub(super) const fn uniform(span: Duration) -> Self {
        Self {
            deb: span,
            byhash_covered: span,
            byhash_uncovered: span,
        }
    }
}

/// Return the reference time to use for age-based eviction of a cached file.
///
/// Prefers `created()` (birthtime); falls back to `modified()` if birthtime is
/// unavailable (e.g. on filesystems without birthtime support), logging once at
/// INFO. If both fail, bumps `CACHE_IO_FAILURE`, logs at ERROR, and returns
/// `None` so the caller can skip the entry.
pub(super) fn age_reference_time(meta: &std::fs::Metadata, path: &Path) -> Option<SystemTime> {
    match meta.created() {
        Ok(t) => Some(t),
        Err(created_err) => {
            info_once!(
                "Failed to get create timestamp for file `{}`; falling back to the modify timestamp:  {}",
                path.display(),
                ErrorReport(&created_err)
            );
            match meta.modified() {
                Ok(t) => Some(t),
                Err(modified_err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to get create timestamp ({}) and modify timestamp ({}) of file `{}`; retaining it indefinitely since it can never be aged out",
                        ErrorReport(&created_err),
                        ErrorReport(&modified_err),
                        path.display()
                    );
                    None
                }
            }
        }
    }
}

/// Remove cached files older than their per-class span, dropping any matching
/// `cache_metadata` entries on success.
///
/// Each candidate is `(name, class)` where `name` is the entry's path *relative
/// to `root`* — a bare basename for the depth-1 trees, a `/`-joined relpath for
/// the recursive flat walk. The full path is rebuilt here rather than carried on
/// the candidate: the map is filled by the scan over the whole tree (~100k
/// entries, ten mirrors at once) and only *then* reduced against the Packages
/// index, so a `PathBuf` per *scanned* entry would be megabytes held for the
/// whole unit — to spare the surviving candidates one join apiece. The sweep
/// itself does allocate one joined path per candidate it inspects.
///
/// A candidate's [`SpanClass`] selects its span from `spans`: `.deb` files use
/// `spans.deb`; by-hash files use `spans.byhash_covered`/`byhash_uncovered`.
/// `now` is injected (rather than read internally) so by-hash deletion paths are
/// testable despite birthtime not being backdatable on Linux.
///
/// Used by the flat-cleanup path both when a Packages index has reduced the map
/// down to genuinely-unreferenced files (short span) and as a fallback when the
/// Packages index is unfetchable (long span, since we cannot tell which entries
/// are still referenced).
pub(super) async fn sweep_candidates(
    root: &Path,
    candidates: &HashMap<OsString, SpanClass>,
    spans: SpanTable,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> SweepResult {
    let mut bytes_removed = 0u64;
    let mut files_removed = 0u64;
    let mut removed_unreferenced = 0u64;

    for (name, &class) in candidates {
        let path = root.join(name);
        let keep_span = match class {
            SpanClass::Deb => spans.deb,
            SpanClass::ByHashCovered => spans.byhash_covered,
            SpanClass::ByHashUncovered => spans.byhash_uncovered,
        };

        let data = match tokio::fs::symlink_metadata(&path).await {
            Ok(d) if d.file_type().is_file() => Some(d),
            Ok(_) => {
                metrics::CACHE_NON_REGULAR.increment();
                warn!(
                    "Cache file `{}` is not a regular file; retaining",
                    path.display(),
                );
                None
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to inspect cached file `{}`; retaining it:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
                None
            }
        };

        let Some(data) = data else {
            continue;
        };

        let Some(created) = age_reference_time(&data, &path) else {
            continue;
        };

        match now.duration_since(created) {
            Ok(existing_for) if existing_for < keep_span => {
                debug!(
                    "Keeping cached file `{}` since it is too new ({}, threshold={})",
                    path.display(),
                    HumanFmt::Time(existing_for),
                    HumanFmt::Time(keep_span)
                );
                continue;
            }
            Ok(_) => {}
            Err(err) => {
                warn_once_or_info!(
                    "Cache file `{}` has a future timestamp; skipping its removal:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
                continue;
            }
        }

        let size = data.len();

        if let Err(err) = tokio::fs::remove_file(&path).await {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to remove cached file `{}`; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
            continue;
        }

        invalidate_metadata_for(&path, mirror, layout);

        debug!("Removed cached file `{}`", path.display());

        bytes_removed += size;
        files_removed += 1;
        if matches!(class, SpanClass::ByHashCovered) {
            removed_unreferenced += 1;
        }
    }

    SweepResult {
        files_removed,
        bytes_removed,
        removed_unreferenced,
    }
}

/// Age out stale top-level index files in a metadata directory, dropping any
/// matching `cache_metadata` entries on success.
///
/// These volatile `Release`/`InRelease`/`Packages*`/... files are refreshed in
/// place (a fresh inode, hence a fresh birthtime) while a distribution is in
/// use, but nothing otherwise reclaims a *retired* distribution's metadata --
/// and while its `Release` lingers, reference-mode by-hash cleanup keeps every
/// digest it lists pinned. Removing regular files older than `keep_span`
/// (birthtime, via [`age_reference_time`]) bounds that growth and lets the next
/// by-hash cycle reclaim the now-unreferenced files.
///
/// Sub-directories -- notably the `by-hash/` and `tmp/` subtrees, swept
/// separately -- are skipped; a symlink / FIFO / socket / device is unlinked,
/// as everywhere cleanup walks. A flat `layout` (the flat root co-mingles
/// indexes with `.deb` files) leaves any deb-named entry to the
/// reference-based flat-deb cleanup; the structured `dists/` tree holds no debs,
/// so the filter is skipped there. Only the direct children are scanned (no
/// recursion), so nested mirrors -- which own their own flat root and cleanup --
/// are untouched.
///
/// `now` is injected for testability, matching [`sweep_candidates`]: birthtime is
/// not backdatable on Linux, so removal cannot be exercised via mtime alone.
static METADATA_WALK: WalkContext = WalkContext {
    what: "a metadata directory",
    dir_failure: DirFailure::Continue("leaving its unread entries unswept this cycle"),
    entry_failure: "retaining it",
    non_regular: "removing it",
};

pub(super) async fn sweep_aged_metadata(
    dir: &Path,
    keep_span: Duration,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> SweepResult {
    let skip_debs = layout.is_flat();

    let mut result = SweepResult {
        files_removed: 0,
        bytes_removed: 0,
        removed_unreferenced: 0,
    };

    let mut walker = Walker::new(dir, &METADATA_WALK, OnMissing::Tolerate, ());

    while let Some(entry) = walker.next().await {
        match entry.kind() {
            // `by-hash/`, `tmp/` and flat URL-dirs are swept by their own
            // units.
            EntryKind::Dir => continue,
            EntryKind::NonRegular => {
                remove_non_regular(&entry.path()).await;
                continue;
            }
            EntryKind::File => {}
        }

        // The flat root co-mingles volatile indexes with `.deb` files; the debs
        // are reconciled (with checksums) by the flat-deb cleanup, so leave them
        // be and sweep only the index metadata. `dists/` has no debs. Filtered
        // by name before the stat, so the whole deb population costs no syscalls.
        if skip_debs && entry.name().to_str().is_some_and(is_deb_package) {
            continue;
        }

        let Some(data) = entry.metadata().await else {
            continue;
        };

        let path = entry.path();

        let Some(created) = age_reference_time(&data, &path) else {
            continue;
        };

        match now.duration_since(created) {
            Ok(age) if age < keep_span => continue,
            Ok(_) => {}
            Err(err) => {
                warn_once_or_info!(
                    "Metadata file `{}` has a future timestamp; skipping its removal:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
                continue;
            }
        }

        let size = data.len();

        if let Err(err) = tokio::fs::remove_file(&path).await {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to remove stale metadata file `{}`; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
            continue;
        }

        invalidate_metadata_for(&path, mirror, layout);

        debug!("Removed stale metadata file `{}`", path.display());

        result.bytes_removed += size;
        result.files_removed += 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::{age_reference_time, sweep_aged_metadata};
    use crate::cache_layout::CacheLayout;
    use crate::config::ClientHost;
    use crate::deb_mirror::{Mirror, MirrorKind};
    use crate::test_support::structured_mirror;

    #[test]
    fn age_reference_time_returns_live_timestamp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("f");
        std::fs::write(&p, b"x").expect("write");
        let meta = std::fs::metadata(&p).expect("meta");
        let t = age_reference_time(&meta, &p).expect("some timestamp");
        // created() is available on the test fs (ext4/tmpfs); it must not be in the future.
        assert!(t <= SystemTime::now());
    }

    fn test_mirror() -> Mirror {
        structured_mirror("deb.example.org", "debian")
    }

    #[tokio::test]
    async fn sweep_candidates_selects_span_by_class_and_counts_unreferenced() {
        use hashbrown::HashMap;

        use std::ffi::OsString;

        use super::{SpanTable, sweep_candidates};
        use crate::cleanup::engine::SpanClass;

        // `invalidate_metadata_for` reaches `cache_metadata::store()`, which
        // panics unless initialised. Idempotent across the test binary.
        if crate::cache_metadata::init().is_err() {
            // Already installed by an earlier test in this process.
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let deb = dir.path().join("pkg_1.0_amd64.deb");
        let covered = dir.path().join("covered");
        let uncovered = dir.path().join("uncovered");
        for p in [&deb, &covered, &uncovered] {
            std::fs::write(p, b"x").expect("write");
        }

        let candidates: HashMap<OsString, SpanClass> = [
            (OsString::from("pkg_1.0_amd64.deb"), SpanClass::Deb),
            (OsString::from("covered"), SpanClass::ByHashCovered),
            (OsString::from("uncovered"), SpanClass::ByHashUncovered),
        ]
        .into_iter()
        .collect();

        // Birthtime is not backdatable on Linux, so inject `now` ~100 days
        // ahead: every file's age is ~100 days. Only the class whose span is
        // under 100 days (by-hash covered) is reaped, proving span-by-class
        // selection; its removal is counted as `removed_unreferenced`.
        let now = SystemTime::now() + Duration::from_hours(100 * 24);
        let spans = SpanTable {
            deb: Duration::from_hours(200 * 24),
            byhash_covered: Duration::from_hours(10 * 24),
            byhash_uncovered: Duration::from_hours(200 * 24),
        };
        let res = sweep_candidates(
            dir.path(),
            &candidates,
            spans,
            now,
            &test_mirror(),
            CacheLayout::DistsByHash,
        )
        .await;

        assert_eq!(
            res.files_removed, 1,
            "only the covered by-hash file is past its span"
        );
        assert_eq!(
            res.removed_unreferenced, 1,
            "a removed ByHashCovered candidate counts as unreferenced"
        );
        assert!(deb.exists(), "deb kept: 100d age < 200d deb span");
        assert!(
            !covered.exists(),
            "covered removed: 100d age >= 10d covered span"
        );
        assert!(
            uncovered.exists(),
            "uncovered kept: 100d age < 200d uncovered span"
        );
    }

    #[tokio::test]
    async fn sweep_aged_metadata_removes_old_keeps_young_and_skips_subdirs() {
        // `invalidate_metadata_for` reaches `cache_metadata::store()`, which
        // panics unless initialised. Idempotent across the test binary.
        if crate::cache_metadata::init().is_err() {
            // Already installed by an earlier test in this process.
        }

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("sid_Release"), b"r").expect("write release");
        std::fs::write(dir.path().join("sid_main_binary-amd64_Packages.xz"), b"p")
            .expect("write packages");
        // A `by-hash/` directory (and its contents) must be left untouched --
        // the by-hash walk owns it.
        std::fs::create_dir(dir.path().join("by-hash")).expect("mkdir by-hash");
        std::fs::write(dir.path().join("by-hash/deadbeef"), b"x").expect("write byhash file");

        let mirror = test_mirror();
        let keep_span = Duration::from_hours(90 * 24);

        // `now` far in the future so both regular files are past the span
        // (birthtime is not backdatable on Linux, so inject `now` instead).
        let now = SystemTime::now() + Duration::from_hours(91 * 24);
        let res =
            sweep_aged_metadata(dir.path(), keep_span, now, &mirror, CacheLayout::Dists).await;
        assert_eq!(res.files_removed, 2);
        assert!(res.bytes_removed >= 2);
        assert!(!dir.path().join("sid_Release").exists());
        assert!(
            !dir.path()
                .join("sid_main_binary-amd64_Packages.xz")
                .exists()
        );
        assert!(
            dir.path().join("by-hash/deadbeef").exists(),
            "the by-hash subtree must be left to the by-hash walk"
        );

        // A young file (within the span) is retained.
        std::fs::write(dir.path().join("trixie_Release"), b"r").expect("write release");
        let now = SystemTime::now() + Duration::from_hours(24);
        let res =
            sweep_aged_metadata(dir.path(), keep_span, now, &mirror, CacheLayout::Dists).await;
        assert_eq!(res.files_removed, 0);
        assert!(dir.path().join("trixie_Release").exists());
    }

    #[tokio::test]
    async fn sweep_aged_metadata_skip_debs_spares_aged_debs() {
        // Regression for the flat-root follow-up: the flat root co-mingles
        // volatile indexes with `.deb` files. With `skip_debs`, an aged `.deb`
        // must be left to the reference-based flat-deb cleanup while the aged
        // index metadata is still reclaimed.
        if crate::cache_metadata::init().is_err() {
            // Already installed by an earlier test in this process.
        }

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("Release"), b"r").expect("write release");
        std::fs::write(dir.path().join("Packages"), b"p").expect("write packages");
        std::fs::write(dir.path().join("hello_1.0_amd64.deb"), b"d").expect("write deb");

        let mirror = Mirror::new(
            ClientHost::new("deb.example.org".to_owned()).expect("valid host"),
            None,
            "apt".to_owned(),
            MirrorKind::Flat,
        );
        let keep_span = Duration::from_hours(90 * 24);
        let now = SystemTime::now() + Duration::from_hours(91 * 24);

        let res = sweep_aged_metadata(dir.path(), keep_span, now, &mirror, CacheLayout::Flat).await;
        assert_eq!(res.files_removed, 2, "only the two index files are swept");
        assert!(!dir.path().join("Release").exists());
        assert!(!dir.path().join("Packages").exists());
        assert!(
            dir.path().join("hello_1.0_amd64.deb").exists(),
            "the aged .deb must be left to the flat-deb cleanup"
        );
    }

    #[tokio::test]
    async fn sweep_aged_metadata_absent_dir_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let res = sweep_aged_metadata(
            &dir.path().join("does-not-exist"),
            Duration::from_hours(90 * 24),
            SystemTime::now() + Duration::from_hours(91 * 24),
            &test_mirror(),
            CacheLayout::Dists,
        )
        .await;
        assert_eq!(res.files_removed, 0);
        assert_eq!(res.bytes_removed, 0);
    }
}
