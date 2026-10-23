//! Readiness checks backing the `GET /healthcheck` web-interface endpoint.
//!
//! Four checks: a `Ping` round-trip through the bounded DB channel, a
//! create-write-unlink probe at the cache-directory root, disk-quota
//! headroom, and free disk space on the cache filesystem. Results are
//! memoized for one second with single-flight semantics so probe spam
//! cannot amplify disk writes or DB-channel traffic (see
//! `cached_health_report`). Each blocking probe runs through a [`ProbeSlot`],
//! so one the kernel never returns from is reported by later checks, not
//! started again.
//!
//! [`fs_space_from`] is the single reading of a `statvfs(3)` result, for the
//! disk-space and inode checks (which run the call through their slot) and
//! for [`filesystem_space`], the main loop's periodic disk-free check and the
//! download admission's `min_disk_free` floor in
//! `cache_quota::CacheQuota::refresh_disk_headroom`, which keeps its own
//! sample (`inodes: None` means a filesystem without
//! an inode limit, not "none left"). Probing runs even without
//! `min_disk_free`: inode exhaustion is invisible to that setting.

use std::io::Write as _;
use std::num::NonZero;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use coarsetime::Instant;
use nix::sys::statvfs::Statvfs;
use tokio::task::JoinError;
use tracing::{debug, info};

use crate::{
    cache_quota::CacheQuota,
    database_task::{DatabaseCommand, send_db_command},
    error::ErrorReport,
    fs_open::nofollow_nonblock_options,
    global_cache_quota, global_config, swrite, warn_once_or_debug, warn_once_or_info,
};

/// Filename of the transient cache-writability probe, created and unlinked
/// at the cache-directory root. `task_cache_scan` skips it by name so a
/// scan racing the probe window does not flag `CACHE_UNEXPECTED_REGULAR`.
pub(crate) const PROBE_FILENAME: &str = ".apt-cacher-rs.healthprobe";

/// Upper bound for each individual check.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// One blocking probe kind, run at most once at a time.
///
/// A check's timeout only stops the *waiting*: the `open(2)` or
/// `statvfs(3)` it gave up on keeps its blocking-pool thread until the
/// kernel returns (a hung network filesystem, a FIFO a writer open waits
/// on). Starting a fresh job on every check would strand one more thread
/// per probe until the pool is exhausted and every file operation of the
/// daemon stalls; instead a check whose previous job has not returned
/// reports that without starting another.
struct ProbeSlot(AtomicBool);

/// What became of a job submitted through [`ProbeSlot::run`].
enum Bounded<T> {
    Done(T),
    /// The blocking task panicked or was cancelled.
    Lost(JoinError),
    /// Still running at the deadline; the slot stays taken until it returns.
    TimedOut,
    /// Not started: the slot's previous job has not returned yet.
    Busy,
}

/// Frees its slot when the job ends, however it ends: dropped by the job's
/// closure, or with the closure if the pool never ran it.
struct SlotRelease(&'static ProbeSlot);

impl Drop for SlotRelease {
    fn drop(&mut self) {
        self.0.0.store(false, Ordering::Release);
    }
}

impl ProbeSlot {
    const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Run `job` on the blocking pool unless this slot's previous job is
    /// still running, and wait for it at most `limit`.
    async fn run<T: Send + 'static>(
        &'static self,
        limit: Duration,
        job: impl FnOnce() -> T + Send + 'static,
    ) -> Bounded<T> {
        if self.0.swap(true, Ordering::Acquire) {
            return Bounded::Busy;
        }
        let release = SlotRelease(self);
        let handle = tokio::task::spawn_blocking(move || {
            let _release = release;
            job()
        });
        match tokio::time::timeout(limit, handle).await {
            Ok(Ok(value)) => Bounded::Done(value),
            Ok(Err(err)) => Bounded::Lost(err),
            Err(_elapsed) => Bounded::TimedOut,
        }
    }
}

/// The cache-writability probe's slot.
static WRITE_PROBE: ProbeSlot = ProbeSlot::new();

/// The health check's `statvfs(3)` slot. Only the health check's own probe:
/// the main loop's periodic sample and the download admission's headroom
/// refresh call [`filesystem_space`] directly.
static STATVFS_PROBE: ProbeSlot = ProbeSlot::new();

/// One `statvfs(3)` snapshot of a filesystem's remaining capacity.
///
/// Both figures are what an unprivileged process may still consume. They
/// fail independently in practice: a cache can be byte-rich and inode-poor
/// (a mirror of many tiny index files on a small-inode ext4) and then
/// `ENOSPC` arrives with gigabytes still free.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FsSpace {
    /// Bytes available to unprivileged processes.
    pub(crate) free_bytes: u64,
    /// Inode accounting. `None` when the filesystem reports no inode limit
    /// at all (btrfs and other dynamically-allocating filesystems report a
    /// total of 0), which is not the same as "none left".
    pub(crate) inodes: Option<InodeSpace>,
}

/// Inode accounting of a filesystem that has a fixed inode table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InodeSpace {
    /// Inodes available to unprivileged processes.
    pub(crate) free: u64,
    /// Inodes the filesystem was created with.
    pub(crate) total: NonZero<u64>,
}

impl InodeSpace {
    /// Whether fewer than `1/divisor` of all inodes are still available.
    /// Integer math: no rounding surprises near the boundary.
    #[must_use]
    fn free_below_fraction(self, divisor: u64) -> bool {
        self.free.saturating_mul(divisor) < self.total.get()
    }
}

/// Remaining capacity of the filesystem holding `path`, via `statvfs(3)`.
/// Returns `None` when the blocking task is lost or the probe fails.
/// Free-byte accounting saturates at `u64::MAX` if the `statvfs` product
/// does not fit in `u64`. The blocking pool keeps a slow filesystem from
/// wedging a Tokio worker.
pub(crate) async fn filesystem_space(path: &Path) -> Option<FsSpace> {
    let owned = path.to_path_buf();
    let joined = tokio::task::spawn_blocking(move || nix::sys::statvfs::statvfs(&owned)).await;
    fs_space_from(path, joined)
}

/// [`filesystem_space`]'s reading of a finished `statvfs(3)` job, shared
/// with the health check's bounded probe.
fn fs_space_from(path: &Path, joined: Result<nix::Result<Statvfs>, JoinError>) -> Option<FsSpace> {
    let result = match joined {
        Ok(result) => result,
        Err(err) => {
            warn_once_or_debug!(
                "Failed to join the statvfs(3) probe of `{}`; treating the free space as unknown:  {}",
                path.display(),
                ErrorReport(&err)
            );
            return None;
        }
    };
    let stat = result
        .inspect_err(|err| {
            warn_once_or_debug!(
                "Failed to statvfs(3) the filesystem holding `{}`; treating the free space as unknown:  {}",
                path.display(),
                ErrorReport(err)
            );
        })
        .ok()?;
    let free_bytes = stat.blocks_available().saturating_mul(stat.fragment_size());
    Some(FsSpace {
        free_bytes,
        inodes: NonZero::new(stat.files()).map(|total| InodeSpace {
            free: stat.files_available(),
            total,
        }),
    })
}

/// Outcome of a single readiness check.
#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum CheckResult {
    Pass,
    Fail(String),
}

impl CheckResult {
    const fn ok(&self) -> bool {
        matches!(self, Self::Pass)
    }

    /// The verdict every check reports when it outran [`CHECK_TIMEOUT`];
    /// shared so the three probes cannot drift apart in wording.
    fn timed_out() -> Self {
        Self::Fail(format!("timed out after {}s", CHECK_TIMEOUT.as_secs()))
    }

    /// The verdict of a check whose previous probe is still blocked (see
    /// [`ProbeSlot`]): unhealthy, like the timeout that preceded it.
    fn still_blocked() -> Self {
        Self::Fail(format!(
            "still blocked: the probe started by an earlier check has not returned (timed out after {}s)",
            CHECK_TIMEOUT.as_secs()
        ))
    }

    fn write_json(&self, out: &mut String) {
        out.push_str("{\"ok\":");
        match self {
            Self::Pass => out.push_str("true}"),
            Self::Fail(detail) => {
                out.push_str("false,\"detail\":\"");
                json_escape_into(out, detail);
                out.push_str("\"}");
            }
        }
    }
}

/// Aggregated result of all readiness checks.
#[derive(Clone)]
pub(crate) struct HealthReport {
    database: CheckResult,
    cache_write: CheckResult,
    quota: CheckResult,
    disk_free: CheckResult,
    inodes_free: CheckResult,
}

impl HealthReport {
    #[must_use]
    pub(crate) fn healthy(&self) -> bool {
        let Self {
            database,
            cache_write,
            quota,
            disk_free,
            inodes_free,
        } = self;
        database.ok() && cache_write.ok() && quota.ok() && disk_free.ok() && inodes_free.ok()
    }

    /// Destructures `Self`, so a new check is a compile error here rather
    /// than a field silently missing from the endpoint's output.
    #[must_use]
    pub(crate) fn to_json(&self) -> String {
        let Self {
            database,
            cache_write,
            quota,
            disk_free,
            inodes_free,
        } = self;
        let mut out = String::with_capacity(128);
        out.push_str("{\"status\":\"");
        out.push_str(if self.healthy() {
            "healthy"
        } else {
            "unhealthy"
        });
        out.push_str("\",\"checks\":{\"database\":");
        database.write_json(&mut out);
        out.push_str(",\"cache_write\":");
        cache_write.write_json(&mut out);
        out.push_str(",\"quota\":");
        quota.write_json(&mut out);
        out.push_str(",\"disk_free\":");
        disk_free.write_json(&mut out);
        out.push_str(",\"inodes_free\":");
        inodes_free.write_json(&mut out);
        out.push_str("}}");
        out
    }
}

/// Append `s` to `out` with JSON string escaping (quote, backslash, control
/// characters). Detail strings are our own error Displays, so this is shape
/// correctness, not attacker-input sanitization.
fn json_escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => {
                swrite!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Disk-quota headroom: healthy when no quota is configured or the cache is
/// strictly below it — at or above the limit every new download is already
/// rejected with 503 "Disk quota reached".
fn check_quota(current_size: u64, limit: Option<NonZero<u64>>) -> CheckResult {
    match limit {
        None => CheckResult::Pass,
        Some(quota) if current_size < quota.get() => CheckResult::Pass,
        Some(quota) => CheckResult::Fail(format!(
            "disk quota exhausted: cache size {current_size} of {quota} bytes"
        )),
    }
}

/// Free-disk-space headroom on the cache filesystem: healthy when no
/// minimum is configured or the available space is at or above it. Unlike
/// the quota check this also fires on default installs — a full disk breaks
/// every new download regardless of quota configuration. `free = None`
/// (statvfs failed) fails the check: a healthcheck that cannot measure a
/// required signal must not claim health.
fn check_disk_free(free: Option<u64>, min_free: NonZero<u64>) -> CheckResult {
    match free {
        Some(free) if free >= min_free.get() => CheckResult::Pass,
        Some(free) => CheckResult::Fail(format!(
            "low disk space: {free} bytes free, minimum {min_free} bytes"
        )),
        None => CheckResult::Fail(String::from("could not determine free disk space")),
    }
}

/// Free inodes below which the cache filesystem is reported unhealthy.
/// Deliberately a constant rather than a config knob: unlike free bytes,
/// where the operator picks a policy floor, a filesystem this close to inode
/// exhaustion cannot create cache files at all -- the daemon is broken
/// regardless of policy, and the failure arrives as `ENOSPC` with plenty of
/// bytes still free.
const MIN_FREE_INODES: u64 = 1000;

/// Second inode floor, relative to the filesystem's inode table: a big
/// filesystem can hold far more than [`MIN_FREE_INODES`] and still be one
/// large mirror sync away from exhaustion, so anything under this fraction
/// of the total counts as unhealthy too.
const MIN_FREE_INODE_FRACTION: u64 = 10;

/// Free-inode headroom on the cache filesystem. Passes when the filesystem
/// reports no inode limit (btrfs and friends report a total of 0) or when
/// the probe produced no sample: `disk_free` already owns the
/// "cannot measure" verdict wherever a minimum is configured, and inode
/// accounting has no configured minimum to make it required.
fn check_inodes_free(inodes: Option<InodeSpace>) -> CheckResult {
    match low_inodes_detail(inodes) {
        Some(detail) => CheckResult::Fail(detail),
        None => CheckResult::Pass,
    }
}

/// Returns the operator-facing detail when either inode floor
/// ([`MIN_FREE_INODES`], [`MIN_FREE_INODE_FRACTION`]) is breached, `None`
/// otherwise. The floors live here only: `main_loop`'s startup warn calls
/// this too, so both verdicts always agree.
#[must_use]
pub(crate) fn low_inodes_detail(inodes: Option<InodeSpace>) -> Option<String> {
    let inodes = inodes?;
    let InodeSpace { free, total } = inodes;
    if free < MIN_FREE_INODES {
        return Some(format!(
            "low free inodes: {free} of {total} total, minimum {MIN_FREE_INODES}"
        ));
    }
    if inodes.free_below_fraction(MIN_FREE_INODE_FRACTION) {
        return Some(format!(
            "low free inodes: {free} of {total} total, minimum {}% of the inode table",
            100 / MIN_FREE_INODE_FRACTION
        ));
    }
    None
}

/// One statvfs feeding both filesystem checks, bounded by [`CHECK_TIMEOUT`]
/// like the other probes. Returns `(disk_free, inodes_free)`. The probe runs
/// even without a configured `min_disk_free`, because inode exhaustion is
/// invisible to that setting.
async fn probe_filesystem(
    cache_dir: &Path,
    min_free: Option<NonZero<u64>>,
) -> (CheckResult, CheckResult) {
    probe_filesystem_in(&STATVFS_PROBE, CHECK_TIMEOUT, cache_dir, min_free).await
}

/// [`probe_filesystem`] through `slot` with deadline `limit`, so a test can
/// own both.
async fn probe_filesystem_in(
    slot: &'static ProbeSlot,
    limit: Duration,
    cache_dir: &Path,
    min_free: Option<NonZero<u64>>,
) -> (CheckResult, CheckResult) {
    // No sample at all: inodes fail open as on a failed statvfs, and the
    // byte check fails only where a minimum makes it required.
    let unmeasured = |verdict: CheckResult| {
        let disk_free = match min_free {
            Some(_) => verdict,
            None => CheckResult::Pass,
        };
        (disk_free, CheckResult::Pass)
    };
    let owned = cache_dir.to_path_buf();
    let space = match slot
        .run(limit, move || nix::sys::statvfs::statvfs(&owned))
        .await
    {
        Bounded::Done(result) => fs_space_from(cache_dir, Ok(result)),
        Bounded::Lost(err) => fs_space_from(cache_dir, Err(err)),
        Bounded::TimedOut => return unmeasured(CheckResult::timed_out()),
        Bounded::Busy => return unmeasured(CheckResult::still_blocked()),
    };

    let disk_free = match min_free {
        Some(min_free) => check_disk_free(space.map(|s| s.free_bytes), min_free),
        None => CheckResult::Pass,
    };
    (disk_free, check_inodes_free(space.and_then(|s| s.inodes)))
}

/// Cache-directory writability: create, write, and unlink a small probe
/// file at the cache root, as one blocking job through [`WRITE_PROBE`].
async fn check_cache_write(cache_dir: &Path) -> CheckResult {
    check_cache_write_in(&WRITE_PROBE, CHECK_TIMEOUT, cache_dir).await
}

/// [`check_cache_write`] through `slot` with deadline `limit`, so a test can
/// own both.
async fn check_cache_write_in(
    slot: &'static ProbeSlot,
    limit: Duration,
    cache_dir: &Path,
) -> CheckResult {
    let probe = cache_dir.join(PROBE_FILENAME);
    match slot.run(limit, move || probe_write(&probe)).await {
        Bounded::Done(Ok(())) => CheckResult::Pass,
        Bounded::Done(Err(err)) => CheckResult::Fail(format!("{}", ErrorReport(&err))),
        Bounded::Lost(err) => CheckResult::Fail(format!("probe task lost: {}", ErrorReport(&err))),
        Bounded::TimedOut => CheckResult::timed_out(),
        Bounded::Busy => CheckResult::still_blocked(),
    }
}

/// The probe itself, on a blocking-pool thread. `O_NOFOLLOW` means a planted
/// symlink fails the check - correct, since that indicates a compromised
/// cache directory. `O_NONBLOCK` (inert for a regular file) keeps a FIFO
/// planted at the path from parking the open until a reader appears: with
/// none it fails with `ENXIO`, with one it opens and the type check refuses
/// it. `.create(true)` (not `create_new`) so an orphaned probe from a crashed
/// run is reopened and truncated.
fn probe_write(probe: &Path) -> std::io::Result<()> {
    let mut file = nofollow_nonblock_options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(probe)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other(format!(
            "`{}` is not a regular file",
            probe.display()
        )));
    }
    // A synchronous write, so a full disk surfaces here rather than parked in
    // a background write as through `tokio::fs::File`.
    file.write_all(b"ok")?;
    drop(file);
    // A failed unlink still passes the check: the file is scanner-ignored
    // and rewritten by the next probe.
    if let Err(err) = std::fs::remove_file(probe) {
        debug!(
            "Failed to remove healthcheck probe `{}`; the next probe rewrites it:  {}",
            probe.display(),
            ErrorReport(&err)
        );
    }
    Ok(())
}

/// Database readiness: a `Ping` round-trip through the bounded DB channel.
/// Proves the DB task is alive and draining its queue AND that the pool
/// answers queries - not merely that the channel accepts sends. Only
/// callable inside a running daemon (`DB_TASK_QUEUE_SENDER` is initialized
/// in `main_loop()`), hence integration-tested, not unit-tested.
async fn check_database() -> CheckResult {
    let round_trip = async {
        let (tx, rx) = tokio::sync::oneshot::channel();
        send_db_command(DatabaseCommand::Ping(tx)).await;
        rx.await
    };
    match tokio::time::timeout(CHECK_TIMEOUT, round_trip).await {
        Ok(Ok(Ok(()))) => CheckResult::Pass,
        Ok(Ok(Err(err))) => CheckResult::Fail(format!("query failed: {err}")),
        Ok(Err(_recv_err)) => CheckResult::Fail(String::from("database task unavailable")),
        Err(_elapsed) => CheckResult::timed_out(),
    }
}

/// Memoized report + timestamp. A `tokio::sync::Mutex` (held across the
/// checks) gives single-flight semantics: concurrent requests coalesce
/// into one probe run, capping cost at one disk probe + one DB ping per
/// `CACHE_TTL` regardless of request rate.
static HEALTH_CACHE: tokio::sync::Mutex<Option<(Instant, HealthReport)>> =
    tokio::sync::Mutex::const_new(None);

/// Memoization window. Long enough to defang probe spam, short enough
/// that a 5s-interval orchestrator probe never sees stale state.
const CACHE_TTL: coarsetime::Duration = coarsetime::Duration::from_secs(1);

/// Run all readiness checks concurrently; wall-clock is bounded by the
/// slowest single check timeout, not the sum.
async fn run_healthcheck(
    quota: &CacheQuota,
    cache_dir: &Path,
    min_disk_free: Option<NonZero<u64>>,
) -> HealthReport {
    let (database, cache_write, (disk_free, inodes_free)) = tokio::join!(
        check_database(),
        check_cache_write(cache_dir),
        probe_filesystem(cache_dir, min_disk_free)
    );
    let quota = check_quota(quota.current_size(), quota.quota_limit());
    HealthReport {
        database,
        cache_write,
        quota,
        disk_free,
        inodes_free,
    }
}

/// Daemon-facing entry: serve the memoized report, refreshing it when
/// older than [`CACHE_TTL`]. Reaches for the globals, so only callable in
/// a running daemon; the pure pieces live in [`run_healthcheck`] and the
/// individual checks.
///
/// The memoized entry's timestamp is captured after the checks complete,
/// not before, so slow checks (up to ~5s each) don't pre-expire the entry.
pub(crate) async fn cached_health_report() -> HealthReport {
    let mut cache = HEALTH_CACHE.lock().await;
    let now = Instant::now();
    if let Some((at, report)) = cache.as_ref()
        && now.duration_since(*at) < CACHE_TTL
    {
        return report.clone();
    }
    // Captured for the recovery line: naming what had been failing is the
    // difference between "it is fine now" and an actionable record.
    let previous_failure = cache
        .as_ref()
        .filter(|(_at, prev)| !prev.healthy())
        .map(|(_at, prev)| prev);
    let config = global_config();
    let report = run_healthcheck(
        global_cache_quota(),
        &config.cache_directory,
        config.min_disk_free,
    )
    .await;
    if !report.healthy() {
        warn_once_or_info!(
            "Health check failing; /healthcheck answers 503: {}",
            report.to_json()
        );
    } else if let Some(previous) = previous_failure {
        // Without this the log records only that the daemon went unhealthy,
        // never that it came back -- leaving the failure looking open-ended.
        info!("Health check recovered, was: {}", previous.to_json());
    }
    *cache = Some((Instant::now(), report.clone()));
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::nonzero;

    #[test]
    fn quota_none_passes() {
        assert_eq!(check_quota(u64::MAX, None), CheckResult::Pass);
    }

    #[test]
    fn quota_below_limit_passes() {
        assert_eq!(check_quota(99, Some(nonzero!(100_u64))), CheckResult::Pass);
    }

    #[test]
    fn quota_at_limit_fails() {
        assert_eq!(
            check_quota(100, Some(nonzero!(100_u64))),
            CheckResult::Fail(String::from(
                "disk quota exhausted: cache size 100 of 100 bytes"
            ))
        );
    }

    #[test]
    fn quota_above_limit_fails() {
        assert_eq!(
            check_quota(101, Some(nonzero!(100_u64))),
            CheckResult::Fail(String::from(
                "disk quota exhausted: cache size 101 of 100 bytes"
            ))
        );
    }

    #[test]
    fn disk_free_at_or_above_minimum_passes() {
        assert_eq!(
            check_disk_free(Some(100), nonzero!(100_u64)),
            CheckResult::Pass
        );
        assert_eq!(
            check_disk_free(Some(101), nonzero!(100_u64)),
            CheckResult::Pass
        );
    }

    #[test]
    fn disk_free_below_minimum_fails() {
        assert_eq!(
            check_disk_free(Some(99), nonzero!(100_u64)),
            CheckResult::Fail(String::from(
                "low disk space: 99 bytes free, minimum 100 bytes"
            ))
        );
    }

    #[test]
    fn disk_free_unknown_fails() {
        assert_eq!(
            check_disk_free(None, nonzero!(100_u64)),
            CheckResult::Fail(String::from("could not determine free disk space"))
        );
    }

    #[expect(clippy::unnecessary_wraps, reason = "used for unit testing")]
    fn inodes(free: u64, total: u64) -> Option<InodeSpace> {
        Some(InodeSpace {
            free,
            total: NonZero::new(total).expect("non-zero total"),
        })
    }

    #[test]
    fn inodes_free_above_both_floors_passes() {
        // 10% of the table and above the absolute floor.
        assert_eq!(
            check_inodes_free(inodes(10_000, 100_000)),
            CheckResult::Pass
        );
    }

    #[test]
    fn inodes_free_below_absolute_floor_fails() {
        // Above 10% of a small table, but under the absolute floor.
        assert_eq!(
            check_inodes_free(inodes(MIN_FREE_INODES - 1, 2000)),
            CheckResult::Fail(format!(
                "low free inodes: {} of 2000 total, minimum {MIN_FREE_INODES}",
                MIN_FREE_INODES - 1
            ))
        );
        assert!(!check_inodes_free(inodes(0, 2000)).ok());
    }

    #[test]
    fn inodes_free_below_fraction_fails() {
        // Comfortably above the absolute floor, but under 10% of the table.
        assert_eq!(
            check_inodes_free(inodes(9_999, 100_000)),
            CheckResult::Fail(String::from(
                "low free inodes: 9999 of 100000 total, minimum 10% of the inode table"
            ))
        );
    }

    #[test]
    fn inodes_free_unmeasured_passes() {
        // No inode limit (btrfs) and a failed probe both fail open: unlike
        // free bytes there is no configured policy making the figure
        // required.
        assert_eq!(check_inodes_free(None), CheckResult::Pass);
    }

    /// The production deadline through a slot of the test's own, so tests
    /// running in one process cannot find each other's job in flight.
    async fn probe_fs(
        slot: &'static ProbeSlot,
        dir: &Path,
        min_free: Option<NonZero<u64>>,
    ) -> (CheckResult, CheckResult) {
        probe_filesystem_in(slot, CHECK_TIMEOUT, dir, min_free).await
    }

    #[tokio::test]
    async fn filesystem_probe_uses_real_statvfs() {
        static SLOT: ProbeSlot = ProbeSlot::new();
        let dir = tempfile::tempdir().expect("tempdir");
        // 1 byte of required headroom passes on any writable filesystem, and
        // a real filesystem is never within 1000 inodes of exhaustion here.
        let (disk_free, inodes_free) = probe_fs(&SLOT, dir.path(), Some(nonzero!(1_u64))).await;
        assert_eq!(disk_free, CheckResult::Pass);
        assert_eq!(inodes_free, CheckResult::Pass);
        // A missing directory must fail the disk-free probe, not silently
        // pass; the inode check fails open on the same failed sample.
        let (disk_free, inodes_free) = probe_fs(
            &SLOT,
            &dir.path().join("nonexistent"),
            Some(nonzero!(1_u64)),
        )
        .await;
        assert_eq!(
            disk_free,
            CheckResult::Fail(String::from("could not determine free disk space"))
        );
        assert_eq!(inodes_free, CheckResult::Pass);
    }

    #[tokio::test]
    async fn filesystem_probe_checks_inodes_without_configured_minimum() {
        static SLOT: ProbeSlot = ProbeSlot::new();
        let dir = tempfile::tempdir().expect("tempdir");
        // Without `min_disk_free` the byte check is skipped, but the statvfs
        // still runs so inode exhaustion stays visible.
        let (disk_free, inodes_free) = probe_fs(&SLOT, dir.path(), None).await;
        assert_eq!(disk_free, CheckResult::Pass);
        assert_eq!(inodes_free, CheckResult::Pass);
    }

    #[test]
    fn json_escape_plain_passthrough() {
        let mut out = String::new();
        json_escape_into(&mut out, "plain ascii and umlauts");
        assert_eq!(out, "plain ascii and umlauts");
    }

    #[test]
    fn json_escape_specials() {
        let mut out = String::new();
        json_escape_into(&mut out, "a\"b\\c\nd\te");
        assert_eq!(out, "a\\\"b\\\\c\\u000ad\\u0009e");
    }

    #[test]
    fn json_escape_empty() {
        let mut out = String::new();
        json_escape_into(&mut out, "");
        assert_eq!(out, "");
    }

    /// [`check_cache_write`] through a slot of the test's own (see
    /// [`probe_fs`]).
    async fn write_probe(slot: &'static ProbeSlot, dir: &Path) -> CheckResult {
        check_cache_write_in(slot, CHECK_TIMEOUT, dir).await
    }

    #[tokio::test]
    async fn cache_write_probe_passes_and_cleans_up() {
        static SLOT: ProbeSlot = ProbeSlot::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let r = write_probe(&SLOT, dir.path()).await;
        assert_eq!(r, CheckResult::Pass);
        assert!(
            !dir.path().join(PROBE_FILENAME).exists(),
            "probe file must be unlinked after a successful check"
        );
    }

    #[tokio::test]
    async fn cache_write_probe_fails_on_missing_directory() {
        static SLOT: ProbeSlot = ProbeSlot::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let gone = dir.path().join("nonexistent");
        let r = write_probe(&SLOT, &gone).await;
        assert!(matches!(r, CheckResult::Fail(_)), "unexpected: {r:?}");
    }

    #[tokio::test]
    async fn cache_write_probe_refuses_symlink() {
        static SLOT: ProbeSlot = ProbeSlot::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").expect("write target");
        std::os::unix::fs::symlink(&target, dir.path().join(PROBE_FILENAME)).expect("symlink");
        let r = write_probe(&SLOT, dir.path()).await;
        assert!(!r.ok(), "O_NOFOLLOW must refuse a planted symlink");
    }

    /// A FIFO planted at the probe path fails the check at once instead of
    /// parking the open, which no timeout could reclaim: without a reader the
    /// nonblocking open fails (`ENXIO`), with one it opens and the type check
    /// refuses it. Either way the probe returns, so its slot is free again.
    #[tokio::test]
    async fn cache_write_probe_refuses_a_fifo_without_blocking() {
        static SLOT: ProbeSlot = ProbeSlot::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join(PROBE_FILENAME);
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");

        let without_reader = write_probe(&SLOT, dir.path()).await;
        assert!(
            matches!(&without_reader, CheckResult::Fail(detail) if detail.contains("No such device or address")),
            "a writer open of a reader-less FIFO must fail with ENXIO: {without_reader:?}"
        );

        let _reader = nofollow_nonblock_options()
            .read(true)
            .open(&fifo)
            .expect("open the FIFO's read end");
        let with_reader = write_probe(&SLOT, dir.path()).await;
        assert!(
            matches!(&with_reader, CheckResult::Fail(detail) if detail.contains("is not a regular file")),
            "a FIFO with a reader must be refused by type: {with_reader:?}"
        );
    }

    /// Wait until `slot`'s job has returned and released it.
    async fn wait_for_release(slot: &'static ProbeSlot) {
        let deadline = Duration::from_secs(5);
        tokio::time::timeout(deadline, async {
            while slot.0.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the released job frees its slot");
    }

    /// A job still blocked past its deadline keeps its slot: the next check
    /// reports it without starting a second job, and once the first returns
    /// the slot runs jobs again.
    #[tokio::test]
    async fn a_blocked_probe_is_not_started_again_until_it_returns() {
        static SLOT: ProbeSlot = ProbeSlot::new();
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let first = SLOT
            .run(Duration::from_millis(20), move || {
                blocked.recv().expect("released by the test");
            })
            .await;
        assert!(matches!(first, Bounded::TimedOut));

        let started = std::sync::Arc::new(AtomicBool::new(false));
        let second = {
            let started = std::sync::Arc::clone(&started);
            SLOT.run(CHECK_TIMEOUT, move || {
                started.store(true, Ordering::Relaxed);
            })
            .await
        };
        assert!(matches!(second, Bounded::Busy));
        assert!(
            !started.load(Ordering::Relaxed),
            "a busy slot must not start the job"
        );

        release.send(()).expect("the blocked job is still waiting");
        wait_for_release(&SLOT).await;
        let third = SLOT.run(CHECK_TIMEOUT, || 7).await;
        assert!(matches!(third, Bounded::Done(7)));
    }

    /// A blocked statvfs keeps the byte check failing (without inventing an
    /// inode verdict), now naming the earlier probe, and passes it where no
    /// minimum is configured.
    #[tokio::test]
    async fn filesystem_probe_reports_a_blocked_statvfs() {
        static SLOT: ProbeSlot = ProbeSlot::new();
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let held = SLOT
            .run(Duration::from_millis(20), move || {
                blocked.recv().expect("released by the test");
            })
            .await;
        assert!(matches!(held, Bounded::TimedOut));

        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            probe_fs(&SLOT, dir.path(), Some(nonzero!(1_u64))).await,
            (CheckResult::still_blocked(), CheckResult::Pass)
        );
        assert_eq!(
            probe_fs(&SLOT, dir.path(), None).await,
            (CheckResult::Pass, CheckResult::Pass)
        );
        release.send(()).expect("the blocked job is still waiting");
        wait_for_release(&SLOT).await;
        assert_eq!(
            probe_fs(&SLOT, dir.path(), Some(nonzero!(1_u64))).await,
            (CheckResult::Pass, CheckResult::Pass)
        );
    }

    #[test]
    fn report_json_healthy() {
        let report = HealthReport {
            database: CheckResult::Pass,
            cache_write: CheckResult::Pass,
            quota: CheckResult::Pass,
            disk_free: CheckResult::Pass,
            inodes_free: CheckResult::Pass,
        };
        assert!(report.healthy());
        assert_eq!(
            report.to_json(),
            "{\"status\":\"healthy\",\"checks\":{\"database\":{\"ok\":true},\
             \"cache_write\":{\"ok\":true},\"quota\":{\"ok\":true},\
             \"disk_free\":{\"ok\":true},\"inodes_free\":{\"ok\":true}}}"
        );
    }

    #[test]
    fn report_json_unhealthy_with_detail() {
        let report = HealthReport {
            database: CheckResult::Pass,
            cache_write: CheckResult::Fail(String::from("boom \"quoted\"")),
            quota: CheckResult::Pass,
            disk_free: CheckResult::Pass,
            inodes_free: CheckResult::Pass,
        };
        assert!(!report.healthy());
        assert_eq!(
            report.to_json(),
            "{\"status\":\"unhealthy\",\"checks\":{\"database\":{\"ok\":true},\
             \"cache_write\":{\"ok\":false,\"detail\":\"boom \\\"quoted\\\"\"},\
             \"quota\":{\"ok\":true},\"disk_free\":{\"ok\":true},\
             \"inodes_free\":{\"ok\":true}}}"
        );
    }
}
