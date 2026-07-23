//! Readiness checks backing the `GET /healthcheck` web-interface endpoint.
//!
//! Three checks: a `Ping` round-trip through the bounded DB channel, a
//! create-write-unlink probe at the cache-directory root, and disk-quota
//! headroom. Results are memoized for one second with single-flight
//! semantics so probe spam cannot amplify disk writes or DB-channel
//! traffic (see `cached_health_report`).

use std::num::NonZero;
use std::path::Path;
use std::time::Duration;

use tokio::io::AsyncWriteExt as _;
use tracing::debug;

use crate::{error::ErrorReport, utils::tokio_nofollow_options};

/// Filename of the transient cache-writability probe, created and unlinked
/// at the cache-directory root. `task_cache_scan` skips it by name so a
/// scan racing the probe window does not flag `CACHE_UNEXPECTED_REGULAR`.
pub(crate) const PROBE_FILENAME: &str = ".apt-cacher-rs.healthprobe";

/// Upper bound for each individual check.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

use crate::swrite;

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
}

impl HealthReport {
    #[must_use]
    pub(crate) fn healthy(&self) -> bool {
        let Self {
            database,
            cache_write,
            quota,
        } = self;
        database.ok() && cache_write.ok() && quota.ok()
    }

    #[must_use]
    pub(crate) fn to_json(&self) -> String {
        let Self {
            database,
            cache_write,
            quota,
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
        Err(_elapsed) => CheckResult::Fail(format!(
            "timed out after {}s",
            CHECK_TIMEOUT.as_secs()
        )),
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
            "Failed to remove healthcheck probe `{}`:  {err}",
            probe.display()
        );
    }
    Ok(())
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
        std::os::unix::fs::symlink(&target, dir.path().join(PROBE_FILENAME))
            .expect("symlink");
        let r = check_cache_write(dir.path()).await;
        assert!(!r.ok(), "O_NOFOLLOW must refuse a planted symlink");
    }

    #[test]
    fn report_json_healthy() {
        let report = HealthReport {
            database: CheckResult::Pass,
            cache_write: CheckResult::Pass,
            quota: CheckResult::Pass,
        };
        assert!(report.healthy());
        assert_eq!(
            report.to_json(),
            "{\"status\":\"healthy\",\"checks\":{\"database\":{\"ok\":true},\
             \"cache_write\":{\"ok\":true},\"quota\":{\"ok\":true}}}"
        );
    }

    #[test]
    fn report_json_unhealthy_with_detail() {
        let report = HealthReport {
            database: CheckResult::Pass,
            cache_write: CheckResult::Fail(String::from("boom \"quoted\"")),
            quota: CheckResult::Pass,
        };
        assert!(!report.healthy());
        assert_eq!(
            report.to_json(),
            "{\"status\":\"unhealthy\",\"checks\":{\"database\":{\"ok\":true},\
             \"cache_write\":{\"ok\":false,\"detail\":\"boom \\\"quoted\\\"\"},\
             \"quota\":{\"ok\":true}}}"
        );
    }
}
