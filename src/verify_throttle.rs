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
//! Keyed like `active_downloads`: `(Mirror, debname, CacheLayout)`. Two
//! aliases of the same physical mirror therefore throttle independently --
//! the same granularity trade-off `ActiveDownloadKey` makes.
//!
//! Time is tracked on `coarsetime` (the crate-preferred clock); its ~1ms
//! resolution is irrelevant for second-scale backoff windows. The public
//! API speaks `std::time::Duration` (config input, log output).

use coarsetime::{Duration, Instant};
use hashbrown::{Equivalent, HashMap};

use crate::cache_layout::CacheLayout;
use crate::deb_mirror::Mirror;

/// Soft cap on the entry count. Every entry requires an actual upstream
/// download that failed verification, so realistic workloads stay tiny;
/// the cap purely bounds memory if an upstream serves endless garbage.
const MAX_THROTTLE_ENTRIES: usize = 256;

#[derive(Debug, Eq, Hash, PartialEq)]
struct ThrottleKey {
    mirror: Mirror,
    debname: String,
    layout: CacheLayout,
}

#[derive(Hash)]
struct ThrottleKeyRef<'a> {
    mirror: &'a Mirror,
    debname: &'a str,
    layout: CacheLayout,
}

impl Equivalent<ThrottleKey> for ThrottleKeyRef<'_> {
    fn equivalent(&self, key: &ThrottleKey) -> bool {
        let &Self {
            mirror,
            debname,
            layout,
        } = self;
        let ThrottleKey {
            mirror: kmirror,
            debname: kdebname,
            layout: klayout,
        } = key;
        mirror == kmirror && debname == kdebname && layout == *klayout
    }
}

#[derive(Debug)]
struct ThrottleEntry {
    /// Consecutive verification failures for this resource (>= 1).
    failures: u32,
    /// When the current backoff window ends.
    until: Instant,
}

/// Snapshot returned by [`VerifyThrottle::check`] for a throttled resource;
/// carries the context the rejection log line needs.
#[derive(Debug)]
pub(crate) struct Throttled {
    pub(crate) remaining: std::time::Duration,
    pub(crate) failures: u32,
}

#[derive(Debug)]
pub(crate) struct VerifyThrottle {
    map: parking_lot::RwLock<HashMap<ThrottleKey, ThrottleEntry>>,
    /// Window after the first failure; zero disables the whole feature.
    base: Duration,
    /// Upper bound on the window. Doubles as the streak-reset TTL: a
    /// failure arriving more than `cap` after the previous window ended
    /// starts a fresh streak at `base`.
    cap: Duration,
}

impl VerifyThrottle {
    #[must_use]
    pub(crate) fn new(base: std::time::Duration, cap: std::time::Duration) -> Self {
        let base = Duration::from(base);
        let cap = Duration::from(cap);
        Self {
            map: parking_lot::RwLock::new(HashMap::new()),
            base,
            cap: cap.max(base),
        }
    }

    fn is_disabled(&self) -> bool {
        self.base.as_ticks() == 0
    }

    /// Whether the resource is inside its backoff window.
    #[must_use]
    pub(crate) fn check(
        &self,
        mirror: &Mirror,
        debname: &str,
        layout: CacheLayout,
    ) -> Option<Throttled> {
        self.check_at(mirror, debname, layout, Instant::now())
    }

    fn check_at(
        &self,
        mirror: &Mirror,
        debname: &str,
        layout: CacheLayout,
        now: Instant,
    ) -> Option<Throttled> {
        if self.is_disabled() {
            return None;
        }
        let key = ThrottleKeyRef {
            mirror,
            debname,
            layout,
        };
        let (failures, until) = self
            .map
            .read()
            .get(&key)
            .map(|entry| (entry.failures, entry.until))?;
        (now < until).then(|| Throttled {
            remaining: until.duration_since(now).into(),
            failures,
        })
    }

    /// Record a checksum-verification failure and arm/extend the backoff
    /// window. Returns the new `(window, consecutive_failures)` for the
    /// caller's log line, or `None` when the throttle is disabled.
    pub(crate) fn record_failure(
        &self,
        mirror: &Mirror,
        debname: &str,
        layout: CacheLayout,
    ) -> Option<(std::time::Duration, u32)> {
        self.record_failure_at(mirror, debname, layout, Instant::now())
    }

    fn record_failure_at(
        &self,
        mirror: &Mirror,
        debname: &str,
        layout: CacheLayout,
        now: Instant,
    ) -> Option<(std::time::Duration, u32)> {
        if self.is_disabled() {
            return None;
        }
        let key = ThrottleKeyRef {
            mirror,
            debname,
            layout,
        };
        let mut map = self.map.write();

        let failures = match map.get(&key) {
            // A failure within the streak-reset TTL of the previous
            // window continues the streak; a later one starts over.
            Some(entry) if now <= entry.until + self.cap => entry.failures.saturating_add(1),
            _ => 1,
        };
        if !map.contains_key(&key) && map.len() >= MAX_THROTTLE_ENTRIES {
            // Best-effort cap: purge entries whose streak already reset,
            // then clear outright rather than implement proper LRU.
            let cap = self.cap;
            map.retain(|_, entry| now <= entry.until + cap);
            if map.len() >= MAX_THROTTLE_ENTRIES {
                map.clear();
            }
        }

        let window = self
            .base
            .saturating_mul(2u32.saturating_pow(failures - 1))
            .min(self.cap);
        map.insert(
            ThrottleKey {
                mirror: mirror.clone(),
                debname: debname.to_owned(),
                layout,
            },
            ThrottleEntry {
                failures,
                until: now + window,
            },
        );
        drop(map);
        Some((window.into(), failures))
    }

    /// Clear the entry after a successful commit -- the resource verified,
    /// so any earlier failures are stale.
    pub(crate) fn record_success(&self, mirror: &Mirror, debname: &str, layout: CacheLayout) {
        if self.map.read().is_empty() {
            return;
        }
        let key = ThrottleKeyRef {
            mirror,
            debname,
            layout,
        };
        self.map.write().remove(&key);
    }

    /// Number of resources currently inside a backoff window (dashboard
    /// gauge; expired-but-not-yet-purged streak entries are excluded).
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
    use crate::config::ClientHost;
    use crate::deb_mirror::MirrorKind;

    const BASE_SECS: u64 = 30;
    const CAP_SECS: u64 = 3600;
    const BASE: Duration = Duration::from_secs(BASE_SECS);
    const CAP: Duration = Duration::from_secs(CAP_SECS);
    const SECOND: Duration = Duration::from_secs(1);

    fn std_secs(secs: u64) -> std::time::Duration {
        std::time::Duration::from_secs(secs)
    }

    fn test_mirror() -> Mirror {
        Mirror::new(
            ClientHost::new("deb.debian.org".to_string()).expect("valid host"),
            None,
            String::new(),
            MirrorKind::Structured,
        )
    }

    fn throttle() -> VerifyThrottle {
        VerifyThrottle::new(std_secs(BASE_SECS), std_secs(CAP_SECS))
    }

    #[test]
    fn unknown_resource_is_unthrottled() {
        let t = throttle();
        let mirror = test_mirror();
        assert!(
            t.check_at(
                &mirror,
                "foo.deb",
                CacheLayout::StructuredPool,
                Instant::now()
            )
            .is_none()
        );
    }

    #[test]
    fn first_failure_throttles_for_base_then_expires() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        let (window, failures) = t
            .record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, t0)
            .expect("throttle enabled");
        assert_eq!(window, std_secs(BASE_SECS));
        assert_eq!(failures, 1);

        let throttled = t
            .check_at(
                &mirror,
                "foo.deb",
                CacheLayout::StructuredPool,
                t0 + Duration::from_secs(BASE_SECS / 2),
            )
            .expect("inside the window");
        assert_eq!(throttled.failures, 1);
        assert_eq!(throttled.remaining, std_secs(BASE_SECS / 2));

        assert!(
            t.check_at(&mirror, "foo.deb", CacheLayout::StructuredPool, t0 + BASE)
                .is_none()
        );
    }

    #[test]
    fn consecutive_failures_double_up_to_cap() {
        let t = throttle();
        let mirror = test_mirror();
        let mut now = Instant::now();

        let mut expected = vec![];
        let mut secs = BASE_SECS;
        for _ in 0..10 {
            expected.push(secs.min(CAP_SECS));
            secs *= 2;
        }

        for want in expected {
            let (window, _) = t
                .record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, now)
                .expect("throttle enabled");
            assert_eq!(window, std_secs(want));
            now += SECOND;
        }
    }

    #[test]
    fn success_clears_entry_and_resets_streak() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        t.record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, t0);
        t.record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, t0 + SECOND);
        t.record_success(&mirror, "foo.deb", CacheLayout::StructuredPool);
        assert!(
            t.check_at(&mirror, "foo.deb", CacheLayout::StructuredPool, t0 + SECOND)
                .is_none()
        );

        let (window, failures) = t
            .record_failure_at(
                &mirror,
                "foo.deb",
                CacheLayout::StructuredPool,
                t0 + SECOND * 2,
            )
            .expect("throttle enabled");
        assert_eq!(window, std_secs(BASE_SECS));
        assert_eq!(failures, 1);
    }

    #[test]
    fn streak_resets_after_ttl() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        t.record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, t0);
        let (window, failures) = t
            .record_failure_at(
                &mirror,
                "foo.deb",
                CacheLayout::StructuredPool,
                t0 + BASE + CAP + SECOND,
            )
            .expect("throttle enabled");
        assert_eq!(window, std_secs(BASE_SECS));
        assert_eq!(failures, 1);
    }

    #[test]
    fn streak_survives_window_expiry_within_ttl() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        t.record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, t0);
        // Window (base) expired, but the streak-reset TTL (cap) has not.
        let (window, failures) = t
            .record_failure_at(
                &mirror,
                "foo.deb",
                CacheLayout::StructuredPool,
                t0 + BASE + SECOND,
            )
            .expect("throttle enabled");
        assert_eq!(window, std_secs(2 * BASE_SECS));
        assert_eq!(failures, 2);
    }

    #[test]
    fn zero_base_disables() {
        let t = VerifyThrottle::new(std::time::Duration::ZERO, std_secs(CAP_SECS));
        let mirror = test_mirror();
        let now = Instant::now();

        assert!(
            t.record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, now)
                .is_none()
        );
        assert!(t.map.read().is_empty());
        assert!(
            t.check_at(&mirror, "foo.deb", CacheLayout::StructuredPool, now)
                .is_none()
        );
    }

    #[test]
    fn cap_below_base_is_clamped() {
        let t = VerifyThrottle::new(std_secs(BASE_SECS), std_secs(1));
        let mirror = test_mirror();
        let now = Instant::now();

        let (window, _) = t
            .record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, now)
            .expect("throttle enabled");
        assert_eq!(window, std_secs(BASE_SECS));
        let (window, _) = t
            .record_failure_at(
                &mirror,
                "foo.deb",
                CacheLayout::StructuredPool,
                now + SECOND,
            )
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
            t.record_failure_at(
                &mirror,
                &format!("pkg{i}.deb"),
                CacheLayout::StructuredPool,
                t0,
            );
        }
        assert_eq!(t.map.read().len(), MAX_THROTTLE_ENTRIES);

        // All existing streaks are past their reset TTL: the new insert
        // purges them instead of clearing.
        let later = t0 + BASE + CAP + SECOND;
        t.record_failure_at(&mirror, "fresh.deb", CacheLayout::StructuredPool, later);
        assert_eq!(t.map.read().len(), 1);

        for i in 0..MAX_THROTTLE_ENTRIES - 1 {
            t.record_failure_at(
                &mirror,
                &format!("live{i}.deb"),
                CacheLayout::StructuredPool,
                later,
            );
        }
        assert_eq!(t.map.read().len(), MAX_THROTTLE_ENTRIES);

        // All entries live: cap-and-clear, leaving only the new insert.
        t.record_failure_at(&mirror, "over.deb", CacheLayout::StructuredPool, later);
        assert_eq!(t.map.read().len(), 1);
        assert!(
            t.check_at(&mirror, "over.deb", CacheLayout::StructuredPool, later)
                .is_some()
        );
    }

    #[test]
    fn keys_discriminate_mirror_and_layout() {
        let t = throttle();
        let mirror = test_mirror();
        let other_mirror = Mirror::new(
            ClientHost::new("archive.ubuntu.com".to_string()).expect("valid host"),
            None,
            String::new(),
            MirrorKind::Structured,
        );
        let now = Instant::now();

        t.record_failure_at(&mirror, "foo.deb", CacheLayout::StructuredPool, now);
        assert!(
            t.check_at(&other_mirror, "foo.deb", CacheLayout::StructuredPool, now)
                .is_none()
        );
        assert!(
            t.check_at(&mirror, "foo.deb", CacheLayout::Flat, now)
                .is_none()
        );
        assert!(
            t.check_at(&mirror, "foo.deb", CacheLayout::StructuredPool, now)
                .is_some()
        );
    }

    #[test]
    fn active_len_counts_only_live_windows() {
        let t = throttle();
        let mirror = test_mirror();
        let t0 = Instant::now();

        t.record_failure_at(&mirror, "a.deb", CacheLayout::StructuredPool, t0);
        t.record_failure_at(&mirror, "b.deb", CacheLayout::StructuredPool, t0);
        assert_eq!(t.active_len_at(t0 + SECOND), 2);
        assert_eq!(t.active_len_at(t0 + BASE), 0);
    }
}
