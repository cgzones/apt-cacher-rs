//! Cleanup's reap of the `tmp/` directories that hold kept `.partial`s.
//!
//! A download may be using a partial the walk finds stale (resuming it, or
//! about to measure it for its quota reservation), so a partial is unlinked
//! only through `partial_claim::reap_unclaimed`, which skips a path a download
//! claims and re-checks the file under the claim lock.

use std::fs::Metadata;
use std::path::Path;
use std::time::{Duration, SystemTime};

use tracing::{debug, error};

use crate::cache_quota::accounted_size;
use crate::cache_walk::{AnomalyLevel, DirFailure, EntryKind, OnMissing, WalkContext, Walker};
use crate::error::ErrorReport;
use crate::metrics;
use crate::partial_claim::{FileId, Reap, reap_unclaimed};

use super::scan::{remove_non_regular, remove_stray_dir};

/// Consequence clause of every foreign-entry report in `tmp/`, whether the
/// walker raises it (symlink / FIFO / socket / device) or the loop below does
/// (stray directory): both are reaped on the same `FOREIGN_MAX_AGE` schedule,
/// which this sentence spells out.
const FOREIGN_CONSEQUENCE: &str = "removing it once it is older than a week";

/// Age before a zero-byte `.partial` is reaped. A download creates its
/// partial before the first body byte lands, so an empty one may belong to
/// a download still waiting on its upstream -- at most `http_timeout` (capped
/// at six minutes) per read. An hour is far past that, and still far below
/// the partial span that governs partials with resume state.
///
/// A download's claim on its path already keeps the reap off a partial it
/// uses; this age is the second line of defence, should a path ever escape
/// its claim.
const EMPTY_PARTIAL_MIN_AGE: Duration = Duration::from_hours(1);

/// When a `.partial` counts as stale: judged once by the walk and again,
/// under the claim lock, right before the unlink.
#[derive(Clone, Copy, Debug)]
struct PartialCutoffs {
    /// Any partial last written before this.
    partial: SystemTime,
    /// A zero-byte partial last written before this.
    empty: SystemTime,
}

impl PartialCutoffs {
    fn new(now: SystemTime, partial_max_age: Duration) -> Self {
        Self {
            partial: now - partial_max_age,
            empty: now - EMPTY_PARTIAL_MIN_AGE,
        }
    }

    /// Zero-byte partials carry no resume state and go once no download
    /// can still be about to fill them; aged partials are stale.
    fn is_stale(self, len: u64, mtime: SystemTime) -> bool {
        (len == 0 && mtime < self.empty) || mtime < self.partial
    }
}

static TMP_WALK: WalkContext = WalkContext {
    what: "a tmp directory",
    dir_failure: DirFailure::Continue("leaving its unread entries unreaped this cycle"),
    entry_failure: "retaining it this cycle",
    non_regular: FOREIGN_CONSEQUENCE,
    anomalies: AnomalyLevel::Warn,
};

/// Remove stale entries from a single `tmp/` directory.
///
/// `.partial` files are deleted when zero-byte (no useful resume state) and
/// older than `EMPTY_PARTIAL_MIN_AGE`, or older
/// than `partial_max_age` — the `PartialsUnit` span, so tuning it in
/// `model.rs` actually moves this threshold. A partial a download claims is
/// never deleted, however old ([`reap_partial`]). Any other artifact
/// (defensive — current code only writes `.partial` here) is deleted once it has
/// aged past `FOREIGN_MAX_AGE`, the longer threshold acknowledging that we don't
/// know what produced it; a stray directory or non-regular entry is reported
/// on every cycle it is seen and reaped on the same schedule.
///
/// Called by the engine's `Partials` unit arm once per mirror per layout
/// (structured `<cache>/<cache_path>/tmp` and flat `<cache>/flat/<flat_root>/tmp`
/// — see `model::classify_mirror`'s two `Partials` units). The entry count
/// is logged only; the unlinked regular files' bytes feed the quota
/// reconcile (the cache scan counts every regular file in `tmp/`), never
/// `UnitStats::removed`/`bytes_removed`: partial-download scratch files are
/// not cached content.
pub(super) async fn cleanup_tmp_dir(
    tmp_dir: &Path,
    now: SystemTime,
    partial_max_age: Duration,
) -> TmpReap {
    // `FOREIGN_CONSEQUENCE` spells this out as "a week"; keep them in step.
    const FOREIGN_MAX_AGE: Duration = Duration::from_hours(7 * 24);

    let cutoffs = PartialCutoffs::new(now, partial_max_age);
    let foreign_cutoff = now - FOREIGN_MAX_AGE;

    let mut reaped = TmpReap::default();

    let mut walker = Walker::new(tmp_dir, &TMP_WALK, OnMissing::Tolerate, ());

    while let Some(entry) = walker.next().await {
        let Some(mdata) = entry.metadata().await else {
            continue;
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
        // The tmp/ producer (`download_file`) only writes regular files, so
        // a directory here is anomalous however young it is; the walker
        // already reported a non-regular entry.
        if entry.kind() == EntryKind::Dir {
            entry.report_unexpected(FOREIGN_CONSEQUENCE);
        }
        // Apply the per-suffix `.partial` policy only to regular files: a
        // symlink-to-dir or a stray directory named `*.partial` should not
        // be measured by `len()` (zero for a symlink) and should be reaped
        // under the longer foreign cutoff instead.
        let is_partial = entry.kind() == EntryKind::File
            && entry
                .name()
                .to_str()
                .is_some_and(|name| name.ends_with(".partial"));
        let stale = if is_partial {
            cutoffs.is_stale(mdata.len(), mtime)
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
        let removed_len = match entry.kind() {
            // Neither is counted towards the cache size, so neither frees
            // accounted bytes.
            EntryKind::Dir => remove_stray_dir(&path).await.then_some(0),
            EntryKind::NonRegular => remove_non_regular(&path).await.then_some(0),
            EntryKind::File if is_partial => reap_partial(&path, &mdata, cutoffs),
            EntryKind::File => match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    debug!("Removed stale tmp entry `{}`", path.display());
                    Some(mdata.len())
                }
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to remove stale tmp entry `{}`; retaining it:  {}",
                        path.display(),
                        ErrorReport(&err)
                    );
                    None
                }
            },
        };
        if let Some(len) = removed_len {
            reaped.entries += 1;
            reaped.bytes = reaped.bytes.saturating_add(accounted_size(len));
        }
    }

    reaped
}

/// Unlink the stale partial at `path` the walk read as `walked`, unless a
/// download claims it or it changed since: the length it had when removed,
/// `None` when it stays.
///
/// That length comes from the final `lstat(2)` under the claim lock, not
/// from the walk: it is what the unlink took off the disk.
fn reap_partial(path: &Path, walked: &Metadata, cutoffs: PartialCutoffs) -> Option<u64> {
    let reap = tokio::task::block_in_place(|| {
        reap_unclaimed(path, FileId::of(walked), |now| {
            // The walk reported an unreadable mtime for this very entry, and
            // fell back the same way.
            let mtime = now.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            cutoffs.is_stale(now.len(), mtime)
        })
    });
    match reap {
        Reap::Removed { len } => {
            debug!("Removed stale tmp entry `{}`", path.display());
            Some(len)
        }
        Reap::Claimed => {
            debug!(
                "Keeping stale partial `{}`: a download is using it",
                path.display()
            );
            None
        }
        Reap::Changed => {
            debug!(
                "Skipping stale partial `{}`: it was replaced, removed or written to since the walk",
                path.display()
            );
            None
        }
        Reap::StatFailed(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to stat stale tmp entry `{}` before removing it; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
            None
        }
        Reap::RemoveFailed(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to remove stale tmp entry `{}`; retaining it:  {}",
                path.display(),
                ErrorReport(&err)
            );
            None
        }
    }
}

/// What one [`cleanup_tmp_dir`] pass removed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct TmpReap {
    /// Entries of every kind.
    pub(super) entries: u64,
    /// Sizes of the regular files among them.
    pub(super) bytes: u64,
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use filetime::{FileTime, set_file_mtime};

    use super::{EMPTY_PARTIAL_MIN_AGE, PartialCutoffs, TmpReap, cleanup_tmp_dir, reap_partial};
    use crate::partial_claim::PartialClaim;

    const PARTIAL_MAX_AGE: Duration = Duration::from_hours(1);
    const ONE_DAY: Duration = Duration::from_hours(24);

    /// Create `name` under `tmp` holding `content`, with its mtime backdated
    /// by `age` relative to `now`.
    fn plant_file(tmp: &Path, name: &str, content: &[u8], now: SystemTime, age: Duration) {
        let path = tmp.join(name);
        std::fs::write(&path, content).expect("write tmp entry");
        set_file_mtime(&path, FileTime::from_system_time(now - age)).expect("backdate mtime");
    }

    /// Create the directory `name` under `tmp` with its mtime backdated by
    /// `age` relative to `now`.
    fn plant_dir(tmp: &Path, name: &str, now: SystemTime, age: Duration) {
        let path = tmp.join(name);
        std::fs::create_dir(&path).expect("create stray dir");
        set_file_mtime(&path, FileTime::from_system_time(now - age)).expect("backdate mtime");
    }

    // A partial is reaped through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn partials_are_reaped_when_past_partial_max_age() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = dir.path();
        let now = SystemTime::now();

        // Non-empty partials follow the injected `partial_max_age`.
        plant_file(tmp, "young.partial", b"resume", now, PARTIAL_MAX_AGE / 2);
        plant_file(tmp, "old.partial", b"resume", now, PARTIAL_MAX_AGE * 2);

        let reaped = cleanup_tmp_dir(tmp, now, PARTIAL_MAX_AGE).await;

        assert_eq!(reaped.entries, 1);
        assert_eq!(
            reaped.bytes, 4096,
            "the aged partial's accounted block feeds the quota reconcile"
        );
        assert!(tmp.join("young.partial").exists(), "young partial kept");
        assert!(!tmp.join("old.partial").exists(), "aged partial reaped");
    }

    /// A partial a download claims is left alone however stale -- the
    /// download may be resuming it or about to measure it for its quota
    /// reservation -- and goes with the first cycle after the claim ends.
    // A partial is reaped through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_claimed_partial_is_reaped_only_once_released() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = dir.path();
        let now = SystemTime::now();
        plant_file(tmp, "resumed.partial", b"resume", now, PARTIAL_MAX_AGE * 2);
        let claim = PartialClaim::acquire(tmp.join("resumed.partial")).expect("unclaimed");

        let reaped = cleanup_tmp_dir(tmp, now, PARTIAL_MAX_AGE).await;
        assert_eq!(reaped, TmpReap::default(), "a download is using it");
        assert!(tmp.join("resumed.partial").exists());

        drop(claim);
        let reaped = cleanup_tmp_dir(tmp, now, PARTIAL_MAX_AGE).await;
        assert_eq!(
            reaped,
            TmpReap {
                entries: 1,
                bytes: 4096
            }
        );
        assert!(!tmp.join("resumed.partial").exists());
    }

    /// The walk's verdict is re-checked right before the unlink: a partial
    /// written to since, or replaced by a new file at the same path, stays.
    // `reap_partial` runs `block_in_place`, which needs the multi-thread
    // runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn reap_partial_rechecks_the_file_the_walk_judged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = dir.path();
        let path = tmp.join("rechecked.partial");
        let now = SystemTime::now();
        let cutoffs = PartialCutoffs::new(now, PARTIAL_MAX_AGE);
        let stat = || std::fs::symlink_metadata(&path).expect("stat");

        plant_file(
            tmp,
            "rechecked.partial",
            b"resume",
            now,
            PARTIAL_MAX_AGE * 2,
        );
        let walked = stat();
        // Written to since the walk: no longer stale.
        set_file_mtime(&path, FileTime::from_system_time(now)).expect("touch");
        assert_eq!(reap_partial(&path, &walked, cutoffs), None);
        assert!(path.exists());

        // Replaced by a new, equally aged file (the old inode held open so
        // its number is not reused).
        set_file_mtime(&path, FileTime::from_system_time(now - PARTIAL_MAX_AGE * 2))
            .expect("backdate mtime");
        let walked = stat();
        let old = std::fs::File::open(&path).expect("open old");
        std::fs::remove_file(&path).expect("unlink old");
        plant_file(tmp, "rechecked.partial", b"new", now, PARTIAL_MAX_AGE * 2);
        assert_eq!(reap_partial(&path, &walked, cutoffs), None);
        assert!(path.exists(), "the new file is not the one judged");
        drop(old);

        let walked = stat();
        assert_eq!(reap_partial(&path, &walked, cutoffs), Some(3));
        assert!(!path.exists());
    }

    /// A zero-byte partial carries no resume state, so it goes long before
    /// `partial_max_age` -- but not while young: a download creates its
    /// partial before the first body byte arrives, and reaping it then made
    /// the finished download's rename fail with `ENOENT`.
    // A partial is reaped through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn empty_partials_are_reaped_only_past_their_minimum_age() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = dir.path();
        let now = SystemTime::now();
        let long_max_age = ONE_DAY;

        plant_file(tmp, "starting.partial", b"", now, Duration::ZERO);
        plant_file(
            tmp,
            "abandoned.partial",
            b"",
            now,
            EMPTY_PARTIAL_MIN_AGE + Duration::from_mins(1),
        );
        plant_file(
            tmp,
            "resumable.partial",
            b"resume",
            now,
            EMPTY_PARTIAL_MIN_AGE + Duration::from_mins(1),
        );

        let reaped = cleanup_tmp_dir(tmp, now, long_max_age).await;

        assert_eq!(reaped.entries, 1);
        assert!(
            tmp.join("starting.partial").exists(),
            "a running download's empty partial is kept"
        );
        assert!(
            !tmp.join("abandoned.partial").exists(),
            "an old empty partial is reaped"
        );
        assert!(
            tmp.join("resumable.partial").exists(),
            "a non-empty partial waits for partial_max_age"
        );
    }

    #[tokio::test]
    async fn foreign_files_are_reaped_only_past_a_week() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = dir.path();
        let now = SystemTime::now();

        // Non-`.partial` regular files ignore `partial_max_age` (an hour here)
        // and only go once older than `FOREIGN_MAX_AGE` (a week).
        plant_file(tmp, "fresh.bin", b"", now, Duration::ZERO);
        plant_file(tmp, "six-days.bin", b"x", now, ONE_DAY * 6);
        plant_file(tmp, "eight-days.bin", b"x", now, ONE_DAY * 8);

        let reaped = cleanup_tmp_dir(tmp, now, PARTIAL_MAX_AGE).await;

        assert_eq!(reaped.entries, 1);
        assert_eq!(reaped.bytes, 4096);
        assert!(tmp.join("fresh.bin").exists(), "fresh foreign file kept");
        assert!(
            tmp.join("six-days.bin").exists(),
            "six-day foreign file kept"
        );
        assert!(
            !tmp.join("eight-days.bin").exists(),
            "eight-day foreign file reaped"
        );
    }

    #[tokio::test]
    async fn stray_directories_are_reaped_only_past_a_week() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = dir.path();
        let now = SystemTime::now();

        // A directory named `*.partial` is not a partial: it is foreign and
        // follows the week-long cutoff like any other stray directory.
        plant_dir(tmp, "young.partial", now, PARTIAL_MAX_AGE * 2);
        plant_dir(tmp, "six-days", now, ONE_DAY * 6);
        plant_dir(tmp, "eight-days", now, ONE_DAY * 8);
        // Contents do not shield an aged stray directory (adding the entry
        // bumps the directory's mtime, so backdate it again afterwards).
        std::fs::write(tmp.join("eight-days").join("inner"), b"x").expect("write inner");
        set_file_mtime(
            tmp.join("eight-days"),
            FileTime::from_system_time(now - ONE_DAY * 8),
        )
        .expect("backdate mtime");

        let reaped = cleanup_tmp_dir(tmp, now, PARTIAL_MAX_AGE).await;

        assert_eq!(reaped.entries, 1);
        assert_eq!(
            reaped.bytes, 0,
            "a stray directory's contents are never counted"
        );
        assert!(tmp.join("young.partial").is_dir(), "young stray dir kept");
        assert!(tmp.join("six-days").is_dir(), "six-day stray dir kept");
        assert!(
            !tmp.join("eight-days").exists(),
            "eight-day stray dir reaped"
        );
    }

    #[tokio::test]
    async fn missing_tmp_dir_removes_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let now = SystemTime::now();

        let reaped = cleanup_tmp_dir(&dir.path().join("absent"), now, PARTIAL_MAX_AGE).await;

        assert_eq!(reaped.entries, 0);
    }
}
