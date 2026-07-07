use std::io::ErrorKind;
use std::path::Path;
use std::time::{Duration, SystemTime};

use hashbrown::HashMap;
use log::{debug, error, warn};

use crate::cache_layout::CacheLayout;
use crate::deb_mirror::{Mirror, is_deb_package};
use crate::humanfmt::HumanFmt;
use crate::{info_once, metrics};

use super::engine::{Candidate, SpanClass};
use super::invalidate_metadata_for;

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
/// candidate's class selects which span gates its removal.
pub(super) struct SpanTable {
    pub deb: Duration,
    pub byhash_covered: Duration,
    pub byhash_uncovered: Duration,
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
                "Failed to get create timestamp for file `{}`:  {created_err}",
                path.display()
            );
            match meta.modified() {
                Ok(t) => Some(t),
                Err(modified_err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to get create timestamp ({created_err}) and modify timestamp ({modified_err}) of file `{}`",
                        path.display()
                    );
                    None
                }
            }
        }
    }
}

/// Remove cached files in `candidates` older than their per-class span,
/// dropping any matching `cache_metadata` entries on success.
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
    candidates: &HashMap<String, Candidate>,
    spans: SpanTable,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> SweepResult {
    let mut bytes_removed = 0u64;
    let mut files_removed = 0u64;
    let mut removed_unreferenced = 0u64;

    for candidate in candidates.values() {
        let path = &candidate.path;
        let keep_span = match candidate.class {
            SpanClass::Deb => spans.deb,
            SpanClass::ByHashCovered => spans.byhash_covered,
            SpanClass::ByHashUncovered => spans.byhash_uncovered,
        };

        let data = match tokio::fs::symlink_metadata(path).await {
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
                    "Error inspecting cached file `{}`:  {err}; retaining",
                    path.display()
                );
                None
            }
        };

        let Some(data) = data else {
            continue;
        };

        let Some(created) = age_reference_time(&data, path) else {
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
                info_once!(
                    "File `{}` has a future timestamp, skipping removal:  {err}",
                    path.display()
                );
                continue;
            }
        }

        let size = data.len();

        if let Err(err) = tokio::fs::remove_file(path).await {
            metrics::CACHE_IO_FAILURE.increment();
            error!("Error removing cached file `{}`:  {err}", path.display());
            continue;
        }

        invalidate_metadata_for(path, mirror, layout);

        debug!("Removed cached file `{}`", path.display());

        bytes_removed += size;
        files_removed += 1;
        if matches!(candidate.class, SpanClass::ByHashCovered) {
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
/// separately -- and non-regular entries are skipped. With `skip_debs` (the flat
/// root, which co-mingles indexes with `.deb` files) any deb-named entry is left
/// to the reference-based flat-deb cleanup; the structured `dists/` tree holds no
/// debs and passes `false`. Only the direct children are scanned (no recursion),
/// so nested mirrors -- which own their own flat root and cleanup -- are untouched.
///
/// `now` is injected for testability, matching [`sweep_candidates`]: birthtime is
/// not backdatable on Linux, so removal cannot be exercised via mtime alone.
pub(super) async fn sweep_aged_metadata(
    dir: &Path,
    keep_span: Duration,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
    skip_debs: bool,
) -> SweepResult {
    let mut result = SweepResult {
        files_removed: 0,
        bytes_removed: 0,
        removed_unreferenced: 0,
    };

    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(err) if err.kind() == ErrorKind::NotFound => return result,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read metadata directory `{}`:  {err}",
                dir.display()
            );
            return result;
        }
    };

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate metadata directory `{}`:  {err}",
                    dir.display()
                );
                break;
            }
        };

        // `entry.metadata()` has lstat semantics on tokio's `DirEntry`, so a
        // symlink planted here is seen as itself (non-regular) and skipped.
        let data = match entry.metadata().await {
            Ok(m) => m,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to stat metadata entry `{}`:  {err}",
                    entry.path().display()
                );
                continue;
            }
        };

        // Only regular files are volatile indexes; the `by-hash/` subtree and
        // any other directory or non-regular entry is handled elsewhere.
        if !data.file_type().is_file() {
            continue;
        }

        let path = entry.path();

        // The flat root co-mingles volatile indexes with `.deb` files; the debs
        // are reconciled (with checksums) by the flat-deb cleanup, so leave them
        // be and sweep only the index metadata. `dists/` has no debs.
        if skip_debs
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_deb_package)
        {
            continue;
        }

        let Some(created) = age_reference_time(&data, &path) else {
            continue;
        };

        match now.duration_since(created) {
            Ok(age) if age < keep_span => continue,
            Ok(_) => {}
            Err(err) => {
                info_once!(
                    "Metadata file `{}` has a future timestamp, skipping removal:  {err}",
                    path.display()
                );
                continue;
            }
        }

        let size = data.len();

        if let Err(err) = tokio::fs::remove_file(&path).await {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Error removing stale metadata file `{}`:  {err}",
                path.display()
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
        Mirror::new(
            ClientHost::new("deb.example.org".to_owned()).expect("valid host"),
            None,
            "debian".to_owned(),
            MirrorKind::Structured,
        )
    }

    #[tokio::test]
    async fn sweep_candidates_selects_span_by_class_and_counts_unreferenced() {
        use hashbrown::HashMap;

        use super::{SpanTable, sweep_candidates};
        use crate::cleanup::engine::{Candidate, SpanClass};

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

        let mut candidates: HashMap<String, Candidate> = HashMap::new();
        candidates.insert(
            "deb".to_owned(),
            Candidate {
                path: deb.clone(),
                class: SpanClass::Deb,
            },
        );
        candidates.insert(
            "covered".to_owned(),
            Candidate {
                path: covered.clone(),
                class: SpanClass::ByHashCovered,
            },
        );
        candidates.insert(
            "uncovered".to_owned(),
            Candidate {
                path: uncovered.clone(),
                class: SpanClass::ByHashUncovered,
            },
        );

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
        let res = sweep_aged_metadata(
            dir.path(),
            keep_span,
            now,
            &mirror,
            CacheLayout::Dists,
            false,
        )
        .await;
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
        let res = sweep_aged_metadata(
            dir.path(),
            keep_span,
            now,
            &mirror,
            CacheLayout::Dists,
            false,
        )
        .await;
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

        let res =
            sweep_aged_metadata(dir.path(), keep_span, now, &mirror, CacheLayout::Flat, true).await;
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
            false,
        )
        .await;
        assert_eq!(res.files_removed, 0);
        assert_eq!(res.bytes_removed, 0);
    }
}
