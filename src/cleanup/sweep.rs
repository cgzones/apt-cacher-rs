use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use hashbrown::HashMap;
use tracing::{debug, error, warn};

use crate::cache_layout::{CacheEntryKeyRef, CacheLayout};
use crate::cache_quota::accounted_size;
use crate::cache_walk::{AnomalyLevel, DirFailure, EntryKind, WalkContext, Walker};
use crate::deb_mirror::{Mirror, is_deb_package};
use crate::error::ErrorReport;
use crate::humanfmt::HumanFmt;
use crate::{cache_metadata, info_once, metrics, warn_once_or_info};

use super::engine::{SpanClass, UnitStats};
use super::scan::remove_non_regular;

/// Drop the in-memory `cache_metadata` entry keyed by `(mirror, basename, layout)`.
/// Non-UTF-8 filenames are skipped: debnames are URL-decoded ASCII, so such a
/// path cannot be in the metadata store.
///
/// The basename is the exact key only while the file's directory equals the
/// cleanup mirror's registered path. A deb nested *below* that path whose own
/// mirror row is missing is keyed under the wrong `Mirror.path` and the
/// invalidation misses; that only leaks an in-memory entry until restart.
pub(super) fn invalidate_metadata_for(path: &Path, mirror: &Mirror, layout: CacheLayout) {
    if let Some(debname) = path.file_name().and_then(|n| n.to_str()) {
        cache_metadata::store().invalidate(&CacheEntryKeyRef::new(mirror, debname, layout));
    }
}

/// Per-[`SpanClass`] retention spans: each candidate's class selects which
/// span gates its removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SpanTable {
    pub deb: Duration,
    pub byhash_covered: Duration,
    pub byhash_uncovered: Duration,
}

impl SpanTable {
    pub(super) const fn uniform(span: Duration) -> Self {
        Self {
            deb: span,
            byhash_covered: span,
            byhash_uncovered: span,
        }
    }
}

/// The reference time for age-based eviction of a cached file: birthtime,
/// falling back to mtime on filesystems without birthtime support. `None`
/// (logged) when neither is available.
fn age_reference_time(meta: &std::fs::Metadata, path: &Path) -> Option<SystemTime> {
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

/// Which age-based sweep a file is aged out by: each keeps its own log
/// wording and its own once-gate for the future-timestamp warn.
#[derive(Clone, Copy)]
enum AgeSweep {
    /// Cached debs and by-hash files.
    Candidates,
    /// Top-level index files.
    Metadata,
}

impl AgeSweep {
    /// The time the file's age counts from: [`age_reference_time`], and for
    /// index metadata the modification time when that is later. A volatile
    /// index that revalidates with a 304 keeps its inode, and with it its
    /// birthtime; only its mtime is touched (`fs_open::touch_volatile_mtime`).
    /// Aged by birthtime alone, an index whose content has not changed for
    /// `keep_span` would be removed while it is still requested every day.
    ///
    /// Only where the filesystem has birthtime: without it the touch is
    /// skipped (`Renewal::NoBirthTime`), both times are the unchanged mtime,
    /// and a revalidated index still ages from its last content change.
    fn reference_time(self, meta: &std::fs::Metadata, path: &Path) -> Option<SystemTime> {
        let created = age_reference_time(meta, path)?;
        Some(match self {
            Self::Candidates => created,
            Self::Metadata => meta
                .modified()
                .map_or(created, |modified| created.max(modified)),
        })
    }

    /// Whether the regular file at `path` is at least `keep_span` old at
    /// `now`, by [`Self::reference_time`]. A file without a usable timestamp
    /// is counted in `stats.io_failures`; a file with a future timestamp is
    /// kept.
    fn is_due(
        self,
        path: &Path,
        meta: &std::fs::Metadata,
        keep_span: Duration,
        now: SystemTime,
        stats: &mut UnitStats,
    ) -> bool {
        let Some(created) = self.reference_time(meta, path) else {
            stats.io_failures += 1;
            return false;
        };

        match now.duration_since(created) {
            Ok(existing_for) if existing_for < keep_span => {
                match self {
                    Self::Candidates => debug!(
                        "Keeping cached file `{}` since it is too new ({}, threshold={})",
                        path.display(),
                        HumanFmt::Time(existing_for),
                        HumanFmt::Time(keep_span)
                    ),
                    Self::Metadata => {}
                }
                false
            }
            Ok(_) => true,
            Err(err) => {
                match self {
                    Self::Candidates => warn_once_or_info!(
                        "Cache file `{}` has a future timestamp; skipping its removal:  {}",
                        path.display(),
                        ErrorReport(&err)
                    ),
                    Self::Metadata => warn_once_or_info!(
                        "Metadata file `{}` has a future timestamp; skipping its removal:  {}",
                        path.display(),
                        ErrorReport(&err)
                    ),
                }
                false
            }
        }
    }

    /// Settle the unlink of an aged-out file that was `size` bytes long.
    /// Returns whether the file was removed.
    fn settle_unlink(
        self,
        path: &Path,
        unlinked: std::io::Result<()>,
        size: u64,
        mirror: &Mirror,
        layout: CacheLayout,
        stats: &mut UnitStats,
    ) -> bool {
        let noun = match self {
            Self::Candidates => "cached file",
            Self::Metadata => "stale metadata file",
        };

        if let Err(err) = unlinked {
            stats.io_failures += 1;
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to remove {noun} `{}`; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
            return false;
        }

        invalidate_metadata_for(path, mirror, layout);

        debug!("Removed {noun} `{}`", path.display());

        stats.bytes_removed += accounted_size(size);
        stats.removed += 1;
        true
    }
}

/// Candidates [`sweep_candidates`] hands to one blocking job: one
/// blocking-pool hop per batch instead of two per removed candidate.
const SWEEP_BATCH: usize = 256;

/// Remove cached files older than their per-class span, dropping any matching
/// `cache_metadata` entries on success.
///
/// The returned stats leave `scanned` to the caller, which knows what its
/// unit considered.
///
/// Each candidate's name is the entry's path *relative to `root`*. The full
/// path is rebuilt here rather than carried on the candidate: the map holds
/// every scanned entry (~100k, ten mirrors at once) until it is reduced
/// against the index, so a `PathBuf` apiece would be megabytes held for the
/// whole unit.
///
/// `now` is injected because birthtime is not backdatable on Linux, so tests
/// could not otherwise exercise removal.
pub(super) async fn sweep_candidates(
    root: &Path,
    candidates: &HashMap<OsString, SpanClass>,
    spans: SpanTable,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> UnitStats {
    let mut stats = UnitStats::default();
    let mut candidates = candidates.iter();

    loop {
        let batch: Vec<(PathBuf, SpanClass)> = candidates
            .by_ref()
            .take(SWEEP_BATCH)
            .map(|(name, &class)| (root.join(name), class))
            .collect();
        if batch.is_empty() {
            break;
        }

        let mirror = mirror.clone();
        let job = move || {
            let mut stats = UnitStats::default();
            for (path, class) in batch {
                sweep_candidate(&path, class, spans, now, &mirror, layout, &mut stats);
            }
            stats
        };
        match tokio::task::spawn_blocking(job).await {
            Ok(batch_stats) => stats.accumulate(batch_stats),
            Err(join_err) => std::panic::resume_unwind(join_err.into_panic()),
        }
    }

    stats
}

/// Inspect and age out one [`sweep_candidates`] candidate. Blocking. The
/// lstat runs right before the unlink, never earlier: a stale stat would turn
/// a concurrent removal into a reported unlink failure.
fn sweep_candidate(
    path: &Path,
    class: SpanClass,
    spans: SpanTable,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
    stats: &mut UnitStats,
) {
    let keep_span = match class {
        SpanClass::Deb => spans.deb,
        SpanClass::ByHashCovered => spans.byhash_covered,
        SpanClass::ByHashUncovered => spans.byhash_uncovered,
    };

    let data = match std::fs::symlink_metadata(path) {
        Ok(d) if d.file_type().is_file() => d,
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            warn!(
                "Cache file `{}` is not a regular file; retaining",
                path.display(),
            );
            return;
        }
        // Listed by the scan, removed since (a download replacing it,
        // another cleanup unit): not an I/O failure.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            debug!(
                "Cache entry `{}` vanished before it could be inspected; skipping it",
                path.display()
            );
            return;
        }
        Err(err) => {
            stats.io_failures += 1;
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to inspect cached file `{}`; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
            return;
        }
    };

    if !AgeSweep::Candidates.is_due(path, &data, keep_span, now, stats) {
        return;
    }

    let unlinked = std::fs::remove_file(path);
    if AgeSweep::Candidates.settle_unlink(path, unlinked, data.len(), mirror, layout, stats)
        && matches!(class, SpanClass::ByHashCovered)
    {
        stats.removed_unreferenced += 1;
    }
}

static METADATA_WALK: WalkContext = WalkContext {
    what: "a metadata directory",
    dir_failure: DirFailure::Continue("leaving its unread entries unswept this cycle"),
    entry_failure: "retaining it",
    non_regular: "removing it",
    anomalies: AnomalyLevel::Warn,
};

/// Age out stale top-level index files in a metadata directory, dropping any
/// matching `cache_metadata` entries on success.
///
/// Removes regular files neither replaced nor revalidated for `keep_span`
/// (`AgeSweep::reference_time`). Only the direct children are scanned:
/// sub-directories (`by-hash/`, `tmp/`, nested mirrors) have their own
/// cleanup. A flat `layout` leaves any deb-named entry to the
/// reference-based flat-deb cleanup.
///
/// Like [`sweep_candidates`], `now` is injected and the result leaves
/// `scanned` to the caller.
pub(super) async fn sweep_aged_metadata(
    cache_root: &Path,
    dir: &Path,
    keep_span: Duration,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> UnitStats {
    let skip_debs = layout.is_flat();

    let mut result = UnitStats::default();

    let mut walker = Walker::below(cache_root, dir, &METADATA_WALK, ());

    while let Some(mut entry) = walker.next().await {
        match entry.kind() {
            EntryKind::Dir => continue,
            EntryKind::NonRegular => {
                if !remove_non_regular(&entry.path()).await {
                    result.io_failures += 1;
                }
                continue;
            }
            EntryKind::File => {}
        }

        // Filtered by name before the stat, so the whole deb population costs
        // no syscalls.
        if skip_debs && entry.name().to_str().is_some_and(is_deb_package) {
            continue;
        }

        let Some(data) = entry.metadata().await else {
            continue;
        };

        let path = entry.path();

        if !AgeSweep::Metadata.is_due(&path, &data, keep_span, now, &mut result) {
            continue;
        }

        let unlinked = tokio::fs::remove_file(&path).await;
        AgeSweep::Metadata.settle_unlink(&path, unlinked, data.len(), mirror, layout, &mut result);
    }

    result.io_failures += walker.io_failures();
    result
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::time::{Duration, SystemTime};

    use hashbrown::HashMap;

    use super::{SpanTable, sweep_aged_metadata, sweep_candidates};
    use crate::cache_layout::CacheLayout;
    use crate::cleanup::engine::SpanClass;
    use crate::config::ClientHost;
    use crate::deb_mirror::{Mirror, MirrorKind};
    use crate::metrics;
    use crate::test_support::structured_mirror;

    fn test_mirror() -> Mirror {
        structured_mirror("deb.example.org", "debian")
    }

    #[tokio::test]
    async fn sweep_candidates_selects_span_by_class_and_counts_unreferenced() {
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
        // ahead: every file's age is ~100 days.
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
            res.removed, 1,
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
    async fn sweep_candidates_skips_a_vanished_candidate_uncounted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let candidates: HashMap<OsString, SpanClass> =
            [(OsString::from("gone_1.0_amd64.deb"), SpanClass::Deb)]
                .into_iter()
                .collect();
        let io_failure = metrics::CACHE_IO_FAILURE.get();
        let res = sweep_candidates(
            dir.path(),
            &candidates,
            SpanTable::uniform(Duration::ZERO),
            SystemTime::now(),
            &test_mirror(),
            CacheLayout::StructuredPool,
        )
        .await;
        assert_eq!(res.removed, 0);
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), io_failure);
    }

    #[tokio::test]
    async fn sweep_aged_metadata_removes_old_keeps_young_and_skips_subdirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("sid_Release"), b"r").expect("write release");
        std::fs::write(dir.path().join("sid_main_binary-amd64_Packages.xz"), b"p")
            .expect("write packages");
        std::fs::create_dir(dir.path().join("by-hash")).expect("mkdir by-hash");
        std::fs::write(dir.path().join("by-hash/deadbeef"), b"x").expect("write byhash file");

        let mirror = test_mirror();
        let keep_span = Duration::from_hours(90 * 24);

        let now = SystemTime::now() + Duration::from_hours(91 * 24);
        let res = sweep_aged_metadata(
            dir.path(),
            dir.path(),
            keep_span,
            now,
            &mirror,
            CacheLayout::Dists,
        )
        .await;
        assert_eq!(res.removed, 2);
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

        std::fs::write(dir.path().join("trixie_Release"), b"r").expect("write release");
        let now = SystemTime::now() + Duration::from_hours(24);
        let res = sweep_aged_metadata(
            dir.path(),
            dir.path(),
            keep_span,
            now,
            &mirror,
            CacheLayout::Dists,
        )
        .await;
        assert_eq!(res.removed, 0);
        assert!(dir.path().join("trixie_Release").exists());
    }

    /// A 304 revalidation touches only the mtime; the birthtime stays that
    /// of the last content change. An index old by birthtime but revalidated
    /// within the span is still in use and must be kept.
    #[tokio::test]
    async fn sweep_aged_metadata_keeps_an_index_revalidated_within_the_span() {
        let dir = tempfile::tempdir().expect("tempdir");
        let revalidated = dir.path().join("sid_InRelease");
        let retired = dir.path().join("buster_InRelease");
        std::fs::write(&revalidated, b"r").expect("write revalidated");
        std::fs::write(&retired, b"r").expect("write retired");

        let keep_span = Duration::from_hours(90 * 24);
        // Both files are 91 days old by birthtime at the injected `now`.
        let now = SystemTime::now() + Duration::from_hours(91 * 24);
        std::fs::set_times(
            &revalidated,
            std::fs::FileTimes::new().set_modified(now - Duration::from_hours(1)),
        )
        .expect("touch mtime");

        let res = sweep_aged_metadata(
            dir.path(),
            dir.path(),
            keep_span,
            now,
            &test_mirror(),
            CacheLayout::Dists,
        )
        .await;
        assert_eq!(res.removed, 1, "only the index nobody revalidated is swept");
        assert!(revalidated.exists());
        assert!(!retired.exists());
    }

    #[tokio::test]
    async fn sweep_aged_metadata_skip_debs_spares_aged_debs() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("Release"), b"r").expect("write release");
        std::fs::write(dir.path().join("Packages"), b"p").expect("write packages");
        std::fs::write(dir.path().join("hello_1.0_amd64.deb"), b"d").expect("write deb");

        let mirror = Mirror::new(
            ClientHost::new("deb.example.org").expect("valid host"),
            None,
            "apt".into(),
            MirrorKind::Flat,
        );
        let keep_span = Duration::from_hours(90 * 24);
        let now = SystemTime::now() + Duration::from_hours(91 * 24);

        let res = sweep_aged_metadata(
            dir.path(),
            dir.path(),
            keep_span,
            now,
            &mirror,
            CacheLayout::Flat,
        )
        .await;
        assert_eq!(res.removed, 2, "only the two index files are swept");
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
            dir.path(),
            &dir.path().join("does-not-exist"),
            Duration::from_hours(90 * 24),
            SystemTime::now() + Duration::from_hours(91 * 24),
            &test_mirror(),
            CacheLayout::Dists,
        )
        .await;
        assert_eq!(res.removed, 0);
        assert_eq!(res.bytes_removed, 0);
    }
}
