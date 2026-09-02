//! Readiness checks backing the `GET /healthcheck` web-interface endpoint.
//!
//! Four checks: a `Ping` round-trip through the bounded DB channel, a
//! create-write-unlink probe at the cache-directory root, disk-quota
//! headroom, and free disk space on the cache filesystem. Results are
//! memoized for one second with single-flight semantics so probe spam
//! cannot amplify disk writes or DB-channel traffic (see
//! `cached_health_report`).
//!
//! [`filesystem_space`] is the single `statvfs(3)` entry for both the
//! disk-space and inode checks (and for the main loop's periodic disk-free
//! check) (`inodes: None` means a filesystem without
//! an inode limit, not "none left"). Probing runs even without
//! `min_disk_free`: inode exhaustion is invisible to that setting.

use std::num::NonZero;
use std::path::Path;
use std::time::Duration;

use coarsetime::Instant;
use tokio::io::AsyncWriteExt as _;
use tracing::{debug, info};

use crate::{
    cache_quota::CacheQuota,
    database_task::{DatabaseCommand, DbCmdPing, send_db_command},
    error::ErrorReport,
    fs_open::tokio_nofollow_options,
    global_cache_quota, global_config, swrite, warn_once_or_debug, warn_once_or_info,
};

/// Filename of the transient cache-writability probe, created and unlinked
/// at the cache-directory root. `task_cache_scan` skips it by name so a
/// scan racing the probe window does not flag `CACHE_UNEXPECTED_REGULAR`.
pub(crate) const PROBE_FILENAME: &str = ".apt-cacher-rs.healthprobe";

/// Upper bound for each individual check.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

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
    pub(crate) fn free_below_fraction(self, divisor: u64) -> bool {
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
#[cfg_attr(test, derive(Debug, PartialEq))]
enum CheckResult {
    Pass,
    Fail(String),
}

impl CheckResult {
    const fn ok(&self) -> bool {
        matches!(self, Self::Pass)
    }

    fn detail(&self) -> Option<&str> {
        match self {
            Self::Pass => None,
            Self::Fail(detail) => Some(detail),
        }
    }
}

/// One readiness check, as both renderers see it: the `/healthcheck` JSON
/// keys on `key`, the dashboard prints `label`. Sourcing both from
/// [`HealthReport::checks`] is what keeps the endpoint and the page from
/// drifting apart.
pub(crate) struct Check<'a> {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    pub(crate) ok: bool,
    pub(crate) detail: Option<&'a str>,
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

    /// Every check in the order `/healthcheck` reports them. Destructures
    /// `Self`, so a new check is a compile error here rather than a field
    /// silently missing from both the endpoint and the dashboard.
    #[must_use]
    pub(crate) fn checks(&self) -> [Check<'_>; 5] {
        let Self {
            database,
            cache_write,
            quota,
            disk_free,
            inodes_free,
        } = self;
        [
            ("database", "Database", database),
            ("cache_write", "Cache Write", cache_write),
            ("quota", "Disk Quota", quota),
            ("disk_free", "Free Disk Space", disk_free),
            ("inodes_free", "Free Inodes", inodes_free),
        ]
        .map(|(key, label, result)| Check {
            key,
            label,
            ok: result.ok(),
            detail: result.detail(),
        })
    }

    #[must_use]
    pub(crate) fn to_json(&self) -> String {
        let mut out = String::with_capacity(128);
        out.push_str("{\"status\":\"");
        out.push_str(if self.healthy() {
            "healthy"
        } else {
            "unhealthy"
        });
        out.push_str("\",\"checks\":{");
        for (i, check) in self.checks().into_iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            out.push_str(check.key);
            out.push_str("\":{\"ok\":");
            match check.detail {
                None => out.push_str("true}"),
                Some(detail) => {
                    out.push_str("false,\"detail\":\"");
                    json_escape_into(&mut out, detail);
                    out.push_str("\"}");
                }
            }
        }
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
    let space = match tokio::time::timeout(CHECK_TIMEOUT, filesystem_space(cache_dir)).await {
        Ok(space) => space,
        Err(_elapsed) => {
            let disk_free = match min_free {
                Some(_) => {
                    CheckResult::Fail(format!("timed out after {}s", CHECK_TIMEOUT.as_secs()))
                }
                None => CheckResult::Pass,
            };
            return (disk_free, CheckResult::Pass);
        }
    };

    let disk_free = match min_free {
        Some(min_free) => check_disk_free(space.map(|s| s.free_bytes), min_free),
        None => CheckResult::Pass,
    };
    (disk_free, check_inodes_free(space.and_then(|s| s.inodes)))
}

/// Cache-directory writability: create, write, and unlink a small probe
/// file at the cache root. `O_NOFOLLOW` (via `tokio_nofollow_options`)
/// means a planted symlink fails the check - correct, since that indicates
/// a compromised cache directory. `.create(true)` (not `create_new`) so an
/// orphaned probe from a crashed run is reopened and truncated.
async fn check_cache_write(cache_dir: &Path) -> CheckResult {
    let probe = cache_dir.join(PROBE_FILENAME);
    match tokio::time::timeout(CHECK_TIMEOUT, probe_write(&probe)).await {
        Ok(Ok(())) => CheckResult::Pass,
        Ok(Err(err)) => CheckResult::Fail(format!("{}", ErrorReport(&err))),
        Err(_elapsed) => CheckResult::Fail(format!("timed out after {}s", CHECK_TIMEOUT.as_secs())),
    }
}

async fn probe_write(probe: &Path) -> std::io::Result<()> {
    let mut file = tokio_nofollow_options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(probe)
        .await?;
    file.write_all(b"ok").await?;
    // tokio's File parks a failed background write in `last_write_err` and
    // `write_all` still returns Ok; only flush surfaces it. Without this a
    // full disk passes the very check meant to detect it.
    file.flush().await?;
    drop(file);
    // A failed unlink still passes the check: the file is scanner-ignored
    // and rewritten by the next probe.
    if let Err(err) = tokio::fs::remove_file(probe).await {
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
        send_db_command(DatabaseCommand::Ping(DbCmdPing { reply: tx })).await;
        rx.await
    };
    match tokio::time::timeout(CHECK_TIMEOUT, round_trip).await {
        Ok(Ok(Ok(()))) => CheckResult::Pass,
        Ok(Ok(Err(err))) => CheckResult::Fail(format!("query failed: {err}")),
        Ok(Err(_recv_err)) => CheckResult::Fail(String::from("database task unavailable")),
        Err(_elapsed) => CheckResult::Fail(format!("timed out after {}s", CHECK_TIMEOUT.as_secs())),
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
        .map(|(_at, prev)| prev.to_json());
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
        info!("Health check recovered, was: {previous}");
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
        assert!(!check_quota(101, Some(nonzero!(100_u64))).ok());
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

    #[tokio::test]
    async fn filesystem_probe_uses_real_statvfs() {
        let dir = tempfile::tempdir().expect("tempdir");
        // 1 byte of required headroom passes on any writable filesystem, and
        // a real filesystem is never within 1000 inodes of exhaustion here.
        let (disk_free, inodes_free) = probe_filesystem(dir.path(), Some(nonzero!(1_u64))).await;
        assert_eq!(disk_free, CheckResult::Pass);
        assert_eq!(inodes_free, CheckResult::Pass);
        // A missing directory must fail the disk-free probe, not silently
        // pass; the inode check fails open on the same failed sample.
        let (disk_free, inodes_free) =
            probe_filesystem(&dir.path().join("nonexistent"), Some(nonzero!(1_u64))).await;
        assert_eq!(
            disk_free,
            CheckResult::Fail(String::from("could not determine free disk space"))
        );
        assert_eq!(inodes_free, CheckResult::Pass);
    }

    #[tokio::test]
    async fn filesystem_probe_checks_inodes_without_configured_minimum() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Without `min_disk_free` the byte check is skipped, but the statvfs
        // still runs so inode exhaustion stays visible.
        let (disk_free, inodes_free) = probe_filesystem(dir.path(), None).await;
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

    #[tokio::test]
    async fn cache_write_probe_passes_and_cleans_up() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = check_cache_write(dir.path()).await;
        assert_eq!(r, CheckResult::Pass);
        assert!(
            !dir.path().join(PROBE_FILENAME).exists(),
            "probe file must be unlinked after a successful check"
        );
    }

    #[tokio::test]
    async fn cache_write_probe_fails_on_missing_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gone = dir.path().join("nonexistent");
        let r = check_cache_write(&gone).await;
        assert!(matches!(r, CheckResult::Fail(_)), "unexpected: {r:?}");
    }

    #[tokio::test]
    async fn cache_write_probe_refuses_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").expect("write target");
        std::os::unix::fs::symlink(&target, dir.path().join(PROBE_FILENAME)).expect("symlink");
        let r = check_cache_write(dir.path()).await;
        assert!(!r.ok(), "O_NOFOLLOW must refuse a planted symlink");
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
