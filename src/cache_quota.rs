//! Disk-quota accounting for the cache directory.
//!
//! One mutex guards every number the quota decision depends on, so a check,
//! its reservation, a finalisation and the cleanup reconcile can never
//! interleave inconsistently:
//!
//! - `size`: the accounted cache size. Files below the mirror directories
//!   plus the full reservation of every download in flight. Partials and
//!   `tmp/` scratch files are never counted (neither by the startup scan nor
//!   here), so an abandoned partial is disk usage outside the quota.
//! - `inflight_reserved` / `inflight_replaced`: what the live reservations
//!   added to and subtracted from `size`. The reconcile adds their net to the
//!   scanned on-disk total instead of asking the active-downloads registry,
//!   so the comparison is taken under the same lock as `size`.
//! - `committed_grown` / `committed_shrunk`: monotonic on-disk deltas of
//!   finished commits (renames). A reconcile snapshots them before its scan
//!   and treats commits that landed during the scan as unknown-to-the-scan:
//!   the accounted size is only "repaired" when it lies outside the interval
//!   those commits could explain. Without that, a download committed after
//!   the scan had walked its directory was repaired away, under-counting the
//!   cache until the next cleanup.
//!
//! A [`QuotaReservation`] is minted only by [`CacheQuota::try_acquire`] /
//! [`CacheQuota::acquire_for_cleanup`], is required to build a download
//! barrier (`guards.rs`), is finalised inside the rename step
//! (`integrity::verify_and_rename`, in the same blocking closure as the
//! `rename(2)`, so a cancelled commit future cannot land the file and revert
//! the reservation), and reverts itself on drop.

use std::{cmp::Ordering, num::NonZero, sync::Arc};

use tracing::{error, info, trace};

use crate::{humanfmt::HumanFmt, metrics, upstream_head::ContentLength, warn_once_or_info};

/// Represents a quota violation.
pub(crate) struct QuotaExceeded;

#[derive(Debug, Default)]
struct Accounting {
    /// Accounted cache size: on-disk tracked files plus live reservations.
    size: u64,
    /// Sum of `reserved` over live reservations.
    inflight_reserved: u64,
    /// Sum of `prev_file_size` over live reservations.
    inflight_replaced: u64,
    /// Monotonic sum of `bytes_received - prev_file_size` over commits that
    /// grew the on-disk size.
    committed_grown: u64,
    /// Monotonic sum of `prev_file_size - bytes_received` over commits that
    /// shrank the on-disk size.
    committed_shrunk: u64,
}

impl Accounting {
    /// Net of the live reservations (`reserved - replaced`); what the
    /// reservations currently contribute to `size` on top of the on-disk
    /// files. Signed as `(add, sub)` because a shrinking overwrite
    /// contributes a negative net.
    const fn inflight_net(&self) -> (u64, u64) {
        if self.inflight_reserved >= self.inflight_replaced {
            (self.inflight_reserved - self.inflight_replaced, 0)
        } else {
            (0, self.inflight_replaced - self.inflight_reserved)
        }
    }

    fn add(&mut self, amount: u64, what: &str) {
        if let Some(val) = self.size.checked_add(amount) {
            self.size = val;
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache-size accounting overflowed on {what}: current={} added={amount}; clamping to u64::MAX, all further downloads are rejected as over quota until the next cleanup reconcile",
                self.size
            );
            self.size = u64::MAX;
        }
    }

    fn subtract(&mut self, amount: u64, what: &str) {
        if let Some(val) = self.size.checked_sub(amount) {
            self.size = val;
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache-size accounting underflowed on {what}: current={} removed={amount}; clamping to 0, the accounted cache size now understates the on-disk size until the next cleanup reconcile",
                self.size
            );
            self.size = 0;
        }
    }

    /// Remove a reservation's contribution from the in-flight tallies.
    fn retire(&mut self, reserved: u64, prev_file_size: u64) {
        self.inflight_reserved = self.inflight_reserved.saturating_sub(reserved);
        self.inflight_replaced = self.inflight_replaced.saturating_sub(prev_file_size);
    }
}

#[derive(Clone)]
pub(crate) struct CacheQuota {
    accounting: Arc<parking_lot::Mutex<Accounting>>,
    quota_config: Option<NonZero<u64>>,
}

/// Snapshot of the commit counters taken before a reconcile's scan; see the
/// module doc.
#[derive(Clone, Copy)]
#[must_use]
pub(crate) struct ReconcileWindow {
    grown: u64,
    shrunk: u64,
}

/// What `subtract_and_reconcile` saw and did; every field is for the
/// caller's log line.
#[must_use]
pub(crate) struct Reconciled {
    /// Accounted size after subtracting the cleanup's removals, before any
    /// repair.
    pub(crate) stored: u64,
    /// Scanned on-disk size plus the net of the live reservations: the value
    /// the accounted size must have if no commit landed during the scan.
    pub(crate) expected: u64,
    /// On-disk bytes added / removed by commits during the scan window.
    pub(crate) grown_during_scan: u64,
    pub(crate) shrunk_during_scan: u64,
    /// Accounted size after the reconcile.
    pub(crate) corrected: u64,
    /// `|corrected - stored|`; 0 when no repair was needed.
    pub(crate) difference: u64,
}

impl CacheQuota {
    #[must_use]
    /// Create a new `CacheQuota` with the given initial size and quota configuration.
    pub(crate) fn new(initial: u64, quota_config: Option<NonZero<u64>>) -> Self {
        Self {
            accounting: Arc::new(parking_lot::Mutex::new(Accounting {
                size: initial,
                ..Accounting::default()
            })),
            quota_config,
        }
    }

    /// Atomically check quota and reserve space for a download.
    ///
    /// `content_length.upper()` is the maximum size we might write.
    /// `prev_file_size` is the size of an existing file being replaced
    /// (subtracted from the delta). It must be the real on-disk size when a
    /// download overwrites an entry (e.g. a stale-volatile re-fetch): passing
    /// 0 silently over-counts the quota, which only surfaces later as a
    /// `Repaired cache size discrepancy` warn from cleanup.
    pub(crate) fn try_acquire(
        &self,
        content_length: ContentLength,
        prev_file_size: u64,
        debname: &str,
    ) -> Result<QuotaReservation, QuotaExceeded> {
        let reserved = content_length.upper();
        let mg = self.accounting.lock();
        let curr = mg.size;

        if let Some(quota) = self.quota_config {
            // Compute the prospective post-reservation cache size as
            // `curr - prev_file_size + reserved`. Using saturating arithmetic
            // and accounting for `prev_file_size` *before* adding `reserved`
            // lets a smaller-replacement download proceed when the cache is
            // currently over quota — net cache size decreases by
            // `prev_file_size - reserved`, so rejecting would prevent
            // self-heal via volatile re-fetches. Saturation on add yields
            // `u64::MAX` only if `curr - prev + reserved` would overflow,
            // which rejects via `> quota.get()`.
            let new_size = curr
                .saturating_sub(prev_file_size)
                .saturating_add(reserved.get());
            if new_size > quota.get() {
                drop(mg);
                // A cache sitting at its quota rejects on *every* cacheable
                // miss until cleanup runs, so only the first rejection is a
                // warning -- the rest stay visible at info.
                warn_once_or_info!(
                    "Disk quota reached while reserving space for {debname} (cache size {}, reserving {}, quota {}); rejecting the download with 503",
                    HumanFmt::Size(curr),
                    HumanFmt::Size(reserved.get()),
                    HumanFmt::Size(quota.get()),
                );
                metrics::DOWNLOAD_REJECTED_QUOTA.increment();
                return Err(QuotaExceeded);
            }
        }

        Ok(self.reserve_locked(mg, reserved, prev_file_size, debname))
    }

    /// Reserve space for one of cleanup's own index fetches without
    /// enforcing the limit.
    ///
    /// Cleanup can only free space after reconciling against the current
    /// `Release`/`Packages` indexes, and it fetches them through the regular
    /// cache path. At quota, a grown index would be rejected, the mirror
    /// would bail conservatively, and nothing would ever be evicted -- the
    /// cache would stay full forever. Indexes are bounded by
    /// `max_object_size`, so the overshoot is small and the cleanup that
    /// caused it sweeps it back below the limit. Serving a stale cached index
    /// instead is not an option: reconciling against an outdated reference
    /// set would grace-sweep live debs.
    pub(crate) fn acquire_for_cleanup(
        &self,
        content_length: ContentLength,
        prev_file_size: u64,
        debname: &str,
    ) -> QuotaReservation {
        let reserved = content_length.upper();
        let mg = self.accounting.lock();
        let curr = mg.size;
        if let Some(quota) = self.quota_config {
            let new_size = curr
                .saturating_sub(prev_file_size)
                .saturating_add(reserved.get());
            if new_size > quota.get() {
                info!(
                    "Disk quota reached while reserving space for cleanup index fetch {debname} (cache size {}, reserving {}, quota {}); admitting it over quota so cleanup can reconcile and free space",
                    HumanFmt::Size(curr),
                    HumanFmt::Size(reserved.get()),
                    HumanFmt::Size(quota.get()),
                );
            }
        }
        self.reserve_locked(mg, reserved, prev_file_size, debname)
    }

    /// Apply a reservation to the accounting and mint its token. Takes the
    /// held guard so the caller's check and this update are one critical
    /// section.
    fn reserve_locked(
        &self,
        mut mg: parking_lot::MutexGuard<'_, Accounting>,
        reserved: NonZero<u64>,
        prev_file_size: u64,
        debname: &str,
    ) -> QuotaReservation {
        trace!(
            "Adjusting cache size for file {debname} to be downloaded by {reserved} minus previous file size {prev_file_size}"
        );

        // Same formula as the quota check; reconcile catches any residual
        // drift from `prev_file_size > curr` caller bugs and emits `Repaired
        // cache size discrepancy`.
        mg.size = mg
            .size
            .saturating_sub(prev_file_size)
            .saturating_add(reserved.get());
        mg.inflight_reserved = mg.inflight_reserved.saturating_add(reserved.get());
        mg.inflight_replaced = mg.inflight_replaced.saturating_add(prev_file_size);
        let new_size = mg.size;
        drop(mg);

        self.sample_utilization_peak_with(new_size);

        QuotaReservation {
            quota: self.clone(),
            reserved,
            prev_file_size,
            finalized: false,
        }
    }

    /// Return the current cache size.
    #[must_use]
    pub(crate) fn current_size(&self) -> u64 {
        self.accounting.lock().size
    }

    /// Configured quota limit, if any. `None` means unlimited.
    #[must_use]
    pub(crate) const fn quota_limit(&self) -> Option<NonZero<u64>> {
        self.quota_config
    }

    /// Update `CACHE_QUOTA_UTIL_PEAK_BPS` with the current utilization
    /// (in basis points: hundredths of a percent). No-op when no quota is
    /// configured, since utilization is not well defined.
    ///
    /// `current` is taken as a parameter so callers that already hold (or
    /// just released) the accounting lock do not have to re-acquire it.
    pub(crate) fn sample_utilization_peak_with(&self, current: u64) {
        let Some(quota) = self.quota_config else {
            return;
        };
        // bps = current * 10000 / quota, computed in u128 to avoid overflow.
        // Clamp to 10_000 (= 100.00 %) so over-quota states do not produce a
        // misleading sentinel; `quota` is NonZero so no div-by-zero.
        let bps = u128::from(current).saturating_mul(10_000) / std::num::NonZeroU128::from(quota);
        let bps = u64::try_from(bps.min(10_000)).expect("10_000 fits in u64");
        metrics::CACHE_QUOTA_UTIL_PEAK_BPS.update(bps);
    }

    /// Seed the accounted size with the startup scan's total. Runs before
    /// the listener accepts, so no reservation can be live yet.
    pub(crate) fn record_startup_scan(&self, scanned: u64) {
        let mut mg = self.accounting.lock();
        debug_assert_eq!(
            (mg.inflight_reserved, mg.inflight_replaced),
            (0, 0),
            "the startup scan must complete before any download is admitted"
        );
        mg.add(scanned, "startup scan");
        let new_size = mg.size;
        drop(mg);
        self.sample_utilization_peak_with(new_size);
    }

    /// Snapshot the commit counters. Take it *before* the reconcile's cache
    /// scan starts and hand it to [`Self::subtract_and_reconcile`].
    pub(crate) fn begin_reconcile_window(&self) -> ReconcileWindow {
        let mg = self.accounting.lock();
        ReconcileWindow {
            grown: mg.committed_grown,
            shrunk: mg.committed_shrunk,
        }
    }

    /// Atomically subtract `removed` bytes (what this cleanup run deleted)
    /// and reconcile against `actual_cache_size`, the on-disk total the scan
    /// after those deletions produced.
    ///
    /// The scan takes time, and a commit that lands during it is visible to
    /// the scan only if its directory had not been walked yet. So the
    /// accounted size is compared against an interval, not a point: the
    /// scanned total plus the live reservations, widened by the on-disk
    /// deltas of the commits since `window` was taken. A value inside the
    /// interval is left alone; one outside is moved to the nearest bound.
    pub(crate) fn subtract_and_reconcile(
        &self,
        removed: u64,
        actual_cache_size: u64,
        window: ReconcileWindow,
    ) -> Reconciled {
        let mut mg = self.accounting.lock();
        mg.size = mg.size.saturating_sub(removed);
        let stored = mg.size;

        let (inflight_add, inflight_sub) = mg.inflight_net();
        let expected = if let Some(val) = actual_cache_size.checked_add(inflight_add) {
            val.saturating_sub(inflight_sub)
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache-quota reconcile overflowed: actual_cache_size={actual_cache_size} inflight_reserved={} inflight_replaced={}; recording the cache as full, downloads are rejected as over quota until the next reconcile",
                mg.inflight_reserved, mg.inflight_replaced
            );
            u64::MAX
        };
        let grown_during_scan = mg.committed_grown.wrapping_sub(window.grown);
        let shrunk_during_scan = mg.committed_shrunk.wrapping_sub(window.shrunk);
        let lower = expected.saturating_sub(shrunk_during_scan);
        let upper = expected.saturating_add(grown_during_scan);

        let corrected = stored.clamp(lower, upper);
        let difference = stored.abs_diff(corrected);
        if difference != 0 {
            mg.size = corrected;
            metrics::RECONCILE_EVENTS.increment();
            metrics::RECONCILE_BYTES_REPAIRED.increment_by(difference);
        }
        drop(mg);
        // An upward reconcile may push past the prior utilisation peak; downward
        // reconciles cannot, so skip the sample to avoid pointless work.
        if corrected > stored {
            self.sample_utilization_peak_with(corrected);
        }
        Reconciled {
            stored,
            expected,
            grown_during_scan,
            shrunk_during_scan,
            corrected,
            difference,
        }
    }
}

impl std::fmt::Debug for CacheQuota {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheQuota")
            .field("accounting", &*self.accounting.lock())
            .field("quota_config", &self.quota_config)
            .finish()
    }
}

#[must_use]
pub(crate) struct QuotaReservation {
    quota: CacheQuota,
    reserved: NonZero<u64>,
    prev_file_size: u64,
    finalized: bool,
}

impl QuotaReservation {
    /// Finalize the reservation after the download landed in the cache.
    ///
    /// Adjusts the accounted size so the net change from acquire + finalize
    /// equals `bytes_received - prev_file_size`. For `ContentLength::Exact`
    /// with an honest upstream this is a no-op. For `ContentLength::Unknown`
    /// (or an upstream that under-delivered), the unused reservation is
    /// reclaimed. For an upstream that over-delivered (sent more bytes than
    /// announced via `Content-Length`), the extra is added so the accounted
    /// size tracks the actual on-disk size.
    ///
    /// Call it right after the `rename(2)` that made the file visible, in
    /// the same non-cancellable step: it also records the commit's on-disk
    /// delta for a concurrent reconcile (see the module doc).
    pub(crate) fn finalize(mut self, bytes_received: u64) {
        let reserved = self.reserved.get();
        let prev = self.prev_file_size;
        let mut mg = self.quota.accounting.lock();
        mg.retire(reserved, prev);
        match reserved.cmp(&bytes_received) {
            Ordering::Equal => {}
            Ordering::Greater => {
                let diff = reserved - bytes_received;
                trace!(
                    "Finalizing quota reservation: reserved={reserved} received={bytes_received} diff=-{diff}"
                );
                mg.subtract(diff, "finalize");
            }
            Ordering::Less => {
                let diff = bytes_received - reserved;
                trace!(
                    "Finalizing quota reservation: reserved={reserved} received={bytes_received} diff=+{diff}"
                );
                mg.add(diff, "finalize");
            }
        }
        match bytes_received.cmp(&prev) {
            Ordering::Equal => {}
            Ordering::Greater => {
                mg.committed_grown = mg.committed_grown.wrapping_add(bytes_received - prev);
            }
            Ordering::Less => {
                mg.committed_shrunk = mg.committed_shrunk.wrapping_add(prev - bytes_received);
            }
        }
        let new_size = mg.size;
        drop(mg);
        self.finalized = true;
        if bytes_received > reserved {
            self.quota.sample_utilization_peak_with(new_size);
        }
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }

        // Revert: remove the reserved amount, add back prev_file_size.
        let reserved = self.reserved.get();
        let prev = self.prev_file_size;
        let mut mg = self.quota.accounting.lock();
        mg.retire(reserved, prev);
        match reserved.cmp(&prev) {
            Ordering::Equal => {}
            Ordering::Less => {
                let revert = prev - reserved;
                trace!(
                    "Reverting quota reservation: reserved={reserved} prev_file_size={prev} revert=+{revert}"
                );
                mg.add(revert, "revert");
            }
            Ordering::Greater => {
                let revert = reserved - prev;
                trace!(
                    "Reverting quota reservation: reserved={reserved} prev_file_size={prev} revert=-{revert}"
                );
                mg.subtract(revert, "revert");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nz(v: u64) -> NonZero<u64> {
        NonZero::new(v).expect("non-zero test value")
    }

    fn exact(v: u64) -> ContentLength {
        ContentLength::Exact(nz(v))
    }

    #[test]
    fn fresh_download_under_quota_accepts() {
        let quota = CacheQuota::new(80, Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(10), 0, "fresh-under")
            .ok()
            .expect("fresh download under quota should be accepted");
        assert_eq!(quota.current_size(), 90);
        drop(reservation);
        // Drop reverts the reservation since `finalize` was not called.
        assert_eq!(quota.current_size(), 80);
    }

    #[test]
    fn fresh_download_over_quota_rejects() {
        let quota = CacheQuota::new(100, Some(nz(100)));
        let res = quota.try_acquire(exact(10), 0, "fresh-over");
        assert!(
            res.is_err(),
            "fresh download that would exceed quota must be rejected"
        );
        assert_eq!(quota.current_size(), 100);
    }

    #[test]
    fn overwrite_same_size_under_quota_accepts() {
        let quota = CacheQuota::new(80, Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(10), 10, "overwrite-same")
            .ok()
            .expect("same-size overwrite under quota should be accepted");
        // Reserve adds 10, subtracts prev 10: net 0.
        assert_eq!(quota.current_size(), 80);
        drop(reservation);
        assert_eq!(quota.current_size(), 80);
    }

    #[test]
    fn overwrite_smaller_while_over_quota_accepts() {
        // Cache is currently over quota, and the replacement would actually
        // shrink it: `curr - prev + reserved = 110 - 20 + 5 = 95 <= 100`.
        let quota = CacheQuota::new(110, Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(5), 20, "shrink-while-over")
            .ok()
            .expect("smaller overwrite must be accepted to allow self-heal");
        assert_eq!(quota.current_size(), 95);
        drop(reservation);
        assert_eq!(quota.current_size(), 110);
    }

    #[test]
    fn overwrite_larger_that_would_push_over_rejects() {
        let quota = CacheQuota::new(80, Some(nz(100)));
        // 80 - 10 + 40 = 110 > 100 → reject.
        let res = quota.try_acquire(exact(40), 10, "grow-over");
        assert!(
            res.is_err(),
            "overwrite that would push past quota must be rejected"
        );
        assert_eq!(quota.current_size(), 80);
    }

    #[test]
    fn release_round_trip_finalize_exact() {
        let quota = CacheQuota::new(50, Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(20), 5, "round-trip")
            .ok()
            .expect("must accept");
        // 50 - 5 + 20 = 65 in flight.
        assert_eq!(quota.current_size(), 65);
        // Finalize with the announced size: no further adjustment.
        reservation.finalize(20);
        assert_eq!(quota.current_size(), 65);
    }

    #[test]
    fn release_round_trip_finalize_under_delivers() {
        let quota = CacheQuota::new(50, Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(20), 0, "under-deliver")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), 70);
        // Upstream sent only 12 bytes — the unused 8-byte reservation
        // must be reclaimed.
        reservation.finalize(12);
        assert_eq!(quota.current_size(), 62);
    }

    #[test]
    fn release_round_trip_drop_without_finalize_reverts() {
        let quota = CacheQuota::new(50, Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(20), 5, "drop-revert")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), 65);
        drop(reservation);
        // Drop without finalize reverts net change: back to original 50.
        assert_eq!(quota.current_size(), 50);
    }

    #[test]
    fn no_quota_configured_always_accepts() {
        let quota = CacheQuota::new(u64::MAX / 2, None);
        let reservation = quota
            .try_acquire(exact(1_000), 0, "no-quota")
            .ok()
            .expect("must accept when quota is unconfigured");
        drop(reservation);
    }

    #[test]
    fn cleanup_index_fetch_is_admitted_over_quota() {
        let quota = CacheQuota::new(100, Some(nz(100)));
        let reservation = quota.acquire_for_cleanup(exact(10), 4, "Packages.xz");
        // Accounted like any other reservation: 100 - 4 + 10.
        assert_eq!(quota.current_size(), 106);
        reservation.finalize(10);
        assert_eq!(quota.current_size(), 106);
    }

    #[test]
    fn reconcile_in_flight_overwrite_is_not_a_discrepancy() {
        // A stale volatile re-fetch in flight: on disk the 20-byte previous
        // file still exists, the reservation holds 30 for the replacement.
        let quota = CacheQuota::new(80, Some(nz(1000)));
        let reservation = quota
            .try_acquire(exact(30), 20, "index")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), 90);
        let window = quota.begin_reconcile_window();
        // The scan still sees the old 20-byte file among the 80 on disk.
        let r = quota.subtract_and_reconcile(0, 80, window);
        assert_eq!(r.difference, 0, "in-flight net must explain the gap");
        assert_eq!(quota.current_size(), 90);
        reservation.finalize(30);
        assert_eq!(quota.current_size(), 90);
    }

    #[test]
    fn reconcile_shrinking_in_flight_overwrite_is_not_a_discrepancy() {
        let quota = CacheQuota::new(80, Some(nz(1000)));
        let reservation = quota
            .try_acquire(exact(5), 20, "index")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), 65);
        let window = quota.begin_reconcile_window();
        let r = quota.subtract_and_reconcile(0, 80, window);
        assert_eq!(r.difference, 0);
        drop(reservation);
        assert_eq!(quota.current_size(), 80);
    }

    #[test]
    fn reconcile_keeps_commit_the_scan_missed() {
        let quota = CacheQuota::new(50, Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        // During the scan a 30-byte download commits after its directory was
        // walked: the scan reports 50, the accounted size is already 80.
        let reservation = quota
            .try_acquire(exact(30), 0, "late")
            .ok()
            .expect("must accept");
        reservation.finalize(30);
        assert_eq!(quota.current_size(), 80);
        let r = quota.subtract_and_reconcile(0, 50, window);
        assert_eq!(r.difference, 0, "a commit during the scan is not drift");
        assert_eq!(r.grown_during_scan, 30);
        assert_eq!(quota.current_size(), 80);
    }

    #[test]
    fn reconcile_accepts_commit_the_scan_saw() {
        let quota = CacheQuota::new(50, Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let reservation = quota
            .try_acquire(exact(30), 0, "early")
            .ok()
            .expect("must accept");
        reservation.finalize(30);
        // The scan walked the directory after the commit: it reports 80.
        let r = quota.subtract_and_reconcile(0, 80, window);
        assert_eq!(r.difference, 0);
        assert_eq!(quota.current_size(), 80);
    }

    #[test]
    fn reconcile_repairs_real_drift_beyond_the_window() {
        let quota = CacheQuota::new(50, Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let reservation = quota
            .try_acquire(exact(30), 0, "late")
            .ok()
            .expect("must accept");
        reservation.finalize(30);
        // Scan reports 40: even if the commit was missed, 80 exceeds
        // 40 + 30, so 10 bytes are genuine drift.
        let r = quota.subtract_and_reconcile(0, 40, window);
        assert_eq!(r.difference, 10);
        assert_eq!(r.corrected, 70);
        assert_eq!(quota.current_size(), 70);
    }

    #[test]
    fn reconcile_repairs_under_count_upwards() {
        let quota = CacheQuota::new(10, Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let r = quota.subtract_and_reconcile(0, 40, window);
        assert_eq!(r.difference, 30);
        assert_eq!(quota.current_size(), 40);
    }

    #[test]
    fn reconcile_subtracts_removed_first() {
        let quota = CacheQuota::new(100, Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        // Cleanup deleted 40 bytes; the scan after the deletions reports 60.
        let r = quota.subtract_and_reconcile(40, 60, window);
        assert_eq!(r.stored, 60);
        assert_eq!(r.difference, 0);
        assert_eq!(quota.current_size(), 60);
    }

    #[test]
    fn startup_scan_seeds_the_size() {
        let quota = CacheQuota::new(0, Some(nz(1000)));
        quota.record_startup_scan(123);
        assert_eq!(quota.current_size(), 123);
    }
}
