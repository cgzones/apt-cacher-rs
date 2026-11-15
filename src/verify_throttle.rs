//! Backoff for resources that repeatedly fail checksum verification.
//!
//! A download failing [`crate::integrity`] verification is discarded and
//! never cached, so a client re-requesting the same resource would make the
//! proxy re-download it from upstream on every request. [`VerifyThrottle`]
//! records each mismatch and lets the origination gates reject further
//! requests for that resource with 503 -- without contacting upstream --
//! for an exponentially growing window (doubling per consecutive failure,
//! capped). A successful commit clears the entry.
//!
//! Keyed like `active_downloads`: `(Mirror, debname, CacheLayout)`, where
//! `Mirror` is the alias-resolved canonical mirror
//! (`request_dispatch::decide_request`), so every alias of a mirror shares
//! one throttle entry.

use coarsetime::{Duration, Instant};
use hashbrown::HashMap;

use crate::active_downloads::Declined;
use crate::cache_layout::{CacheEntryKey, CacheEntryKeyRef, ConnectionDetails};
use crate::humanfmt::HumanFmt;
use crate::mem_usage::Footprint;
use crate::{global_verify_throttle, metrics, warn_once, warn_once_or_info};

/// Soft cap on the entry count. Every entry requires an actual upstream
/// download that failed verification, so realistic workloads stay tiny;
/// the cap purely bounds memory if an upstream serves endless garbage.
pub(crate) const MAX_THROTTLE_ENTRIES: usize = 256;

#[derive(Clone, Copy, Debug)]
struct ThrottleEntry {
    /// Consecutive failures, always >= 1.
    failures: u32,
    /// End of the current backoff window.
    until: Instant,
}

#[derive(Debug)]
pub(crate) struct Throttled {
    pub(crate) remaining: std::time::Duration,
    pub(crate) failures: u32,
}

/// Logs, counts and builds the `503` for a throttled resource; `lead` opens
/// the log line. Cleanup's probes bypass the throttle: they run once per 24h
/// cycle and a 503 would hard-fail the index-fetch cascade; their commit
/// outcome still records/clears the state.
pub(crate) fn refusal(conn_details: &ConnectionDetails, lead: &str) -> Option<Declined> {
    if conn_details.client.is_cleanup_synthetic() {
        return None;
    }
    let Throttled {
        remaining,
        failures,
    } = global_verify_throttle().check(conn_details.key())?;
    warn_once_or_info!(
        "{lead} request for {} from client {} since it recently failed checksum verification ({failures} consecutive failures), retry in {}",
        conn_details.debname,
        conn_details.client,
        HumanFmt::Time(remaining)
    );
    metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.increment();
    Some(Declined::VerifyThrottled { remaining })
}

#[derive(Debug)]
pub(crate) struct VerifyThrottle {
    map: parking_lot::RwLock<HashMap<CacheEntryKey, ThrottleEntry>>,
    /// Window after the first failure. `None` (a configured zero) disables
    /// the whole feature.
    base: Option<Duration>,
    /// Upper bound on the window. Doubles as the streak-reset TTL: a
    /// failure arriving more than `cap` after the previous window ended
    /// starts a fresh streak at `base`.
    cap: Duration,
}

impl VerifyThrottle {
    #[must_use]
    pub(crate) fn new(base: std::time::Duration, cap: std::time::Duration) -> Self {
        let base = Duration::from(base);
        Self {
            map: parking_lot::RwLock::new(HashMap::new()),
            base: (base.as_ticks() != 0).then_some(base),
            cap: Duration::from(cap).max(base),
        }
    }

    pub(crate) fn footprint(&self) -> Footprint {
        let map = self.map.read();
        let keys: usize = map
            .keys()
            .map(|key| key.mirror.heap_bytes() + key.debname.capacity())
            .sum();
        Footprint {
            entries: map.len(),
            bytes: map.allocation_size() + keys,
        }
    }

    #[must_use]
    pub(crate) fn check(&self, key: CacheEntryKeyRef<'_>) -> Option<Throttled> {
        self.check_at(key, Instant::now())
    }

    fn check_at(&self, key: CacheEntryKeyRef<'_>, now: Instant) -> Option<Throttled> {
        // Disabled: keep the per-request gate free of a lock and a hash.
        self.base?;
        let ThrottleEntry { failures, until } = self.map.read().get(&key).copied()?;
        (now < until).then(|| Throttled {
            remaining: until.duration_since(now).into(),
            failures,
        })
    }

    /// Returns the new `(window, consecutive_failures)`, or `None` when the
    /// throttle is disabled.
    pub(crate) fn record_failure(
        &self,
        key: CacheEntryKeyRef<'_>,
    ) -> Option<(std::time::Duration, u32)> {
        self.record_failure_at(key, Instant::now())
    }

    fn record_failure_at(
        &self,
        key: CacheEntryKeyRef<'_>,
        now: Instant,
    ) -> Option<(std::time::Duration, u32)> {
        let base = self.base?;
        let mut map = self.map.write();

        let previous = map.get(&key).copied();
        let failures = match previous {
            // A failure within the streak-reset TTL of the previous
            // window continues the streak; a later one starts over.
            Some(ThrottleEntry { failures, until }) if now <= until + self.cap => {
                failures.saturating_add(1)
            }
            _ => 1,
        };
        if previous.is_none() && map.len() >= MAX_THROTTLE_ENTRIES {
            // Best-effort cap: purge entries whose streak already reset,
            // then clear outright rather than implement proper LRU.
            let cap = self.cap;
            map.retain(|_, entry| now <= entry.until + cap);
            if map.len() >= MAX_THROTTLE_ENTRIES {
                // Clearing drops live backoff windows, so the proxy resumes
                // fetching content it knows fails verification: worth a WARN.
                warn_once!(
                    "Verification throttle reached {MAX_THROTTLE_ENTRIES} entries; clearing all backoff windows"
                );
                map.clear();
            }
        }

        let window = base
            .saturating_mul(2u32.saturating_pow(failures - 1))
            .min(self.cap);
        map.insert(
            key.to_owned(),
            ThrottleEntry {
                failures,
                until: now + window,
            },
        );
        drop(map);
        Some((window.into(), failures))
    }

    pub(crate) fn record_success(&self, key: CacheEntryKeyRef<'_>) {
        if self.map.read().is_empty() {
            return;
        }
        self.map.write().remove(&key);
    }

    /// Resources inside a backoff window; expired-but-not-yet-purged streak
    /// entries are excluded.
    #[must_use]
    pub(crate) fn active_len(&self) -> usize {
        self.active_len_at(Instant::now())
    }

    fn active_len_at(&self, now: Instant) -> usize {
        self.map
            .read()
            .values()
            .filter(|entry| now < entry.until)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_layout::CacheLayout;
    use crate::config::ClientHost;
    use crate::deb_mirror::{Mirror, MirrorKind};
    use crate::test_support::structured_mirror;

    const BASE_SECS: u64 = 30;
    const CAP_SECS: u64 = 3600;
    const BASE: Duration = Duration::from_secs(BASE_SECS);
    const CAP: Duration = Duration::from_secs(CAP_SECS);
    const SECOND: Duration = Duration::from_secs(1);

    fn std_secs(secs: u64) -> std::time::Duration {
        std::time::Duration::from_secs(secs)
    }

    fn test_mirror() -> Mirror {
        structured_mirror("deb.debian.org", "")
    }

    fn key<'a>(mirror: &'a Mirror, debname: &'a str) -> CacheEntryKeyRef<'a> {
        CacheEntryKeyRef::new(mirror, debname, CacheLayout::StructuredPool)
    }

    fn throttle() -> VerifyThrottle {
        VerifyThrottle::new(std_secs(BASE_SECS), std_secs(CAP_SECS))
    }

    #[test]
    fn unknown_resource_is_unthrottled() {
        let t = throttle();
        let mirror = test_mirror();
        assert!(
            t.check_at(key(&mirror, "foo.deb"), Instant::now())
                .is_none()
        );
    }

    #[test]
    fn first_failure_throttles_for_base_then_expires() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        let (window, failures) = t
            .record_failure_at(key(&mirror, "foo.deb"), t0)
            .expect("throttle enabled");
        assert_eq!(window, std_secs(BASE_SECS));
        assert_eq!(failures, 1);

        let throttled = t
            .check_at(
                key(&mirror, "foo.deb"),
                t0 + Duration::from_secs(BASE_SECS / 2),
            )
            .expect("inside the window");
        assert_eq!(throttled.failures, 1);
        assert_eq!(throttled.remaining, std_secs(BASE_SECS / 2));

        assert!(t.check_at(key(&mirror, "foo.deb"), t0 + BASE).is_none());
    }

    #[test]
    fn consecutive_failures_double_up_to_cap() {
        const EXPECTED: [(u64, u32); 10] = [
            (30, 1),
            (60, 2),
            (120, 3),
            (240, 4),
            (480, 5),
            (960, 6),
            (1920, 7),
            (3600, 8),
            (3600, 9),
            (3600, 10),
        ];
        assert_eq!(EXPECTED[0].0, BASE_SECS);
        assert_eq!(EXPECTED[9].0, CAP_SECS);

        let t = throttle();
        let mirror = test_mirror();
        let mut now = Instant::now();

        for (want_secs, want_failures) in EXPECTED {
            let (window, failures) = t
                .record_failure_at(key(&mirror, "foo.deb"), now)
                .expect("throttle enabled");
            assert_eq!(window, std_secs(want_secs), "failure #{want_failures}");
            assert_eq!(failures, want_failures);
            now += SECOND;
        }
    }

    /// The first window ends at `t0 + base`; the streak survives until
    /// exactly `cap` after that (`now <= until + cap`).
    #[test]
    fn a_failure_within_the_ttl_of_the_previous_window_continues_the_streak() {
        for (delay, want_secs, want_failures) in [
            (BASE + SECOND, 2 * BASE_SECS, 2),
            (BASE + CAP, 2 * BASE_SECS, 2),
            (BASE + CAP + SECOND, BASE_SECS, 1),
        ] {
            let t = throttle();
            let mirror = test_mirror();
            let t0 = Instant::now();

            t.record_failure_at(key(&mirror, "foo.deb"), t0);
            let (window, failures) = t
                .record_failure_at(key(&mirror, "foo.deb"), t0 + delay)
                .expect("throttle enabled");
            assert_eq!(
                (window, failures),
                (std_secs(want_secs), want_failures),
                "second failure {}s after the first",
                delay.as_secs()
            );
        }
    }

    #[test]
    fn success_clears_entry_and_resets_streak() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        t.record_failure_at(key(&mirror, "foo.deb"), t0);
        t.record_failure_at(key(&mirror, "foo.deb"), t0 + SECOND);
        t.record_success(key(&mirror, "foo.deb"));
        assert!(t.check_at(key(&mirror, "foo.deb"), t0 + SECOND).is_none());

        let (window, failures) = t
            .record_failure_at(key(&mirror, "foo.deb"), t0 + SECOND * 2)
            .expect("throttle enabled");
        assert_eq!(window, std_secs(BASE_SECS));
        assert_eq!(failures, 1);
    }

    #[test]
    fn zero_base_disables() {
        let t = VerifyThrottle::new(std::time::Duration::ZERO, std_secs(CAP_SECS));
        let mirror = test_mirror();
        let now = Instant::now();

        assert!(t.record_failure_at(key(&mirror, "foo.deb"), now).is_none());
        assert!(t.map.read().is_empty());
        assert!(t.check_at(key(&mirror, "foo.deb"), now).is_none());
    }

    #[test]
    fn cap_below_base_is_clamped() {
        let t = VerifyThrottle::new(std_secs(BASE_SECS), std_secs(1));
        let mirror = test_mirror();
        let now = Instant::now();

        let (window, _) = t
            .record_failure_at(key(&mirror, "foo.deb"), now)
            .expect("throttle enabled");
        assert_eq!(window, std_secs(BASE_SECS));
        let (window, _) = t
            .record_failure_at(key(&mirror, "foo.deb"), now + SECOND)
            .expect("throttle enabled");
        assert_eq!(
            window,
            std_secs(BASE_SECS),
            "clamped cap bounds the doubled window"
        );
    }

    #[test]
    fn bounding_purges_expired_streaks_then_clears() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        for i in 0..MAX_THROTTLE_ENTRIES {
            t.record_failure_at(key(&mirror, &format!("pkg{i}.deb")), t0);
        }
        assert_eq!(t.map.read().len(), MAX_THROTTLE_ENTRIES);

        // All existing streaks are past their reset TTL: the new insert
        // purges them instead of clearing.
        let later = t0 + BASE + CAP + SECOND;
        t.record_failure_at(key(&mirror, "fresh.deb"), later);
        assert_eq!(t.map.read().len(), 1);

        for i in 0..MAX_THROTTLE_ENTRIES - 1 {
            t.record_failure_at(key(&mirror, &format!("live{i}.deb")), later);
        }
        assert_eq!(t.map.read().len(), MAX_THROTTLE_ENTRIES);

        // All entries live: cap-and-clear, leaving only the new insert.
        t.record_failure_at(key(&mirror, "over.deb"), later);
        assert_eq!(t.map.read().len(), 1);
        assert!(t.check_at(key(&mirror, "over.deb"), later).is_some());
    }

    #[test]
    fn keys_discriminate_mirror_and_layout() {
        let t = throttle();
        let mirror = test_mirror();
        let other_mirror = Mirror::new(
            ClientHost::new("archive.ubuntu.com").expect("valid host"),
            None,
            "".into(),
            MirrorKind::Structured,
        );
        let now = Instant::now();

        t.record_failure_at(key(&mirror, "foo.deb"), now);
        assert!(t.check_at(key(&other_mirror, "foo.deb"), now).is_none());
        assert!(
            t.check_at(
                CacheEntryKeyRef::new(&mirror, "foo.deb", CacheLayout::Flat),
                now
            )
            .is_none()
        );
        assert!(t.check_at(key(&mirror, "foo.deb"), now).is_some());
    }

    #[test]
    fn active_len_counts_only_live_windows() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        t.record_failure_at(key(&mirror, "a.deb"), t0);
        t.record_failure_at(key(&mirror, "b.deb"), t0);
        assert_eq!(t.active_len_at(t0 + SECOND), 2);
        assert_eq!(t.active_len_at(t0 + BASE), 0);
    }
}
