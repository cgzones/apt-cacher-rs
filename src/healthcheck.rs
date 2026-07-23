//! Readiness checks backing the `GET /healthcheck` web-interface endpoint.
//!
//! Three checks: a `Ping` round-trip through the bounded DB channel, a
//! create-write-unlink probe at the cache-directory root, and disk-quota
//! headroom. Results are memoized for one second with single-flight
//! semantics so probe spam cannot amplify disk writes or DB-channel
//! traffic (see `cached_health_report`).

use std::num::NonZero;

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
