use std::path::Path;
use std::time::{Duration, SystemTime};

use tracing::{debug, error};

use crate::cache_quota::accounted_size;
use crate::cache_walk::{DirFailure, EntryKind, OnMissing, WalkContext, Walker};
use crate::error::ErrorReport;
use crate::metrics;

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
const EMPTY_PARTIAL_MIN_AGE: Duration = Duration::from_hours(1);

static TMP_WALK: WalkContext = WalkContext {
    what: "a tmp directory",
    dir_failure: DirFailure::Continue("leaving its unread entries unreaped this cycle"),
    entry_failure: "retaining it this cycle",
    non_regular: FOREIGN_CONSEQUENCE,
};

/// Remove stale entries from a single `tmp/` directory.
///
/// `.partial` files are deleted when zero-byte (no useful resume state) and
/// older than `EMPTY_PARTIAL_MIN_AGE`, or older
/// than `partial_max_age` — the `PartialsUnit` span, so tuning it in
/// `model.rs` actually moves this threshold. Any other artifact
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

    let partial_cutoff = now - partial_max_age;
    let empty_cutoff = now - EMPTY_PARTIAL_MIN_AGE;
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
            // Zero-byte partials carry no resume state and go once no
            // download can still be about to fill them; aged partials are
            // stale.
            (mdata.len() == 0 && mtime < empty_cutoff) || mtime < partial_cutoff
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
        let gone = match entry.kind() {
            // Neither is counted towards the cache size, so neither frees
            // accounted bytes.
            EntryKind::Dir => remove_stray_dir(&path).await,
            EntryKind::NonRegular => remove_non_regular(&path).await,
            EntryKind::File => match tokio::fs::remove_file(&path).await {
                Ok(()) => {
                    debug!("Removed stale tmp entry `{}`", path.display());
                    reaped.bytes = reaped.bytes.saturating_add(accounted_size(mdata.len()));
                    true
                }
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to remove stale tmp entry `{}`; retaining it:  {}",
                        path.display(),
                        ErrorReport(&err)
                    );
                    false
                }
            },
        };
        if gone {
            reaped.entries += 1;
        }
    }

    reaped
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

    use super::{EMPTY_PARTIAL_MIN_AGE, cleanup_tmp_dir};

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

    #[tokio::test]
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

    /// A zero-byte partial carries no resume state, so it goes long before
    /// `partial_max_age` -- but not while young: a download creates its
    /// partial before the first body byte arrives, and reaping it then made
    /// the finished download's rename fail with `ENOENT`.
    #[tokio::test]
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
