use std::{cmp::Ordering, num::NonZero, sync::Arc};

use log::{error, trace, warn};

use crate::{ContentLength, metrics};

/// Represents a quota violation.
pub(crate) struct QuotaExceeded;

#[derive(Clone)]
pub(crate) struct CacheQuota {
    cache_size: Arc<parking_lot::Mutex<u64>>,
    quota_config: Option<NonZero<u64>>,
}

impl CacheQuota {
    #[must_use]
    /// Create a new `CacheQuota` with the given initial size and quota configuration.
    pub(crate) fn new(initial: u64, quota_config: Option<NonZero<u64>>) -> Self {
        Self {
            cache_size: Arc::new(parking_lot::Mutex::new(initial)),
            quota_config,
        }
    }

    /// Atomically check quota and reserve space for a download.
    ///
    /// `content_length.upper()` is the maximum size we might write.
    /// `prev_file_size` is the size of an existing file being replaced (subtracted from the delta).
    pub(crate) fn try_acquire(
        &self,
        content_length: ContentLength,
        prev_file_size: u64,
        debname: &str,
    ) -> Result<QuotaReservation, QuotaExceeded> {
        let reserved = content_length.upper();
        let mut mg = self.cache_size.lock();
        let curr = *mg;

        if let Some(quota) = self.quota_config {
            // Compute the prospective post-reservation cache size as
            // `curr - prev_file_size + reserved`. Using saturating arithmetic
            // and accounting for `prev_file_size` *before* adding `reserved`
            // lets a smaller-replacement download proceed when the cache is
            // currently over quota — net cache size decreases by
            // `prev_file_size - reserved`, so rejecting would prevent
            // self-heal via volatile re-fetches. Saturation on add yields
            // `u64::MAX` only if `curr - prev + reserved` would overflow,
            // which rejects via `> quota.get()`, matching the previous
            // `checked_add(...).is_none_or(...)` behaviour for that case.
            let new_size = curr
                .saturating_sub(prev_file_size)
                .saturating_add(reserved.get());
            if new_size > quota.get() {
                drop(mg);
                warn!(
                    "Disk quota reached: file={debname} cache_size={curr} content_length={content_length:?} quota={quota}"
                );
                metrics::DOWNLOAD_REJECTED_QUOTA.increment();
                return Err(QuotaExceeded);
            }
        }

        trace!(
            "Adjusting cache size for file {debname} to be downloaded by {content_length:?} minus previous file size {prev_file_size}"
        );

        // Same formula as the quota-check branch above; reconcile catches any
        // residual drift from `prev_file_size > curr` caller bugs and emits
        // `Repaired cache size discrepancy`.
        let new_size = curr
            .saturating_sub(prev_file_size)
            .saturating_add(reserved.get());
        *mg = new_size;
        drop(mg);

        self.sample_utilization_peak_with(new_size);

        Ok(QuotaReservation {
            quota: self.clone(),
            reserved,
            prev_file_size,
            finalized: false,
        })
    }

    /// Return the current cache size.
    #[must_use]
    pub(crate) fn current_size(&self) -> u64 {
        *self.cache_size.lock()
    }

    /// Update `CACHE_QUOTA_UTIL_PEAK_BPS` with the current utilization
    /// (in basis points: hundredths of a percent). No-op when no quota is
    /// configured, since utilization is not well defined.
    ///
    /// `current` is taken as a parameter so callers that already hold (or
    /// just released) the `cache_size` lock do not have to re-acquire it.
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

    /// Atomically subtract `removed` bytes and reconcile against the actual
    /// on-disk cache size. Returns the in-memory size after the subtract (i.e.
    /// the value that would stand if no reconciliation were needed), the
    /// (corrected) cache size, and the discrepancy that was repaired (0 if
    /// none).
    pub(crate) fn subtract_and_reconcile(
        &self,
        removed: u64,
        actual_cache_size: u64,
        active_downloading_size: u64,
    ) -> (u64, u64, u64) {
        let mut mg = self.cache_size.lock();
        *mg = mg.saturating_sub(removed);
        let stored = *mg;

        let expected = if let Some(val) = actual_cache_size.checked_add(active_downloading_size) {
            val
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache size corruption: reconcile: actual_cache_size={actual_cache_size} active_downloading_size={active_downloading_size}"
            );
            u64::MAX
        };
        let difference = stored.abs_diff(expected);
        let increased = expected > stored;
        if difference != 0 {
            *mg = expected;
            metrics::RECONCILE_EVENTS.increment();
            metrics::RECONCILE_BYTES_REPAIRED.increment_by(difference);
        }
        drop(mg);
        // An upward reconcile may push past the prior utilisation peak; downward
        // reconciles cannot, so skip the sample to avoid pointless work.
        if increased {
            self.sample_utilization_peak_with(expected);
        }
        (stored, expected, difference)
    }

    pub(crate) fn add(&self, amount: u64) {
        let mut mg = self.cache_size.lock();
        if let Some(val) = mg.checked_add(amount) {
            *mg = val;
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!("Cache size corruption: add: current={} added={amount}", *mg);
            *mg = u64::MAX;
        }
        let new_size = *mg;
        drop(mg);
        self.sample_utilization_peak_with(new_size);
    }

    fn subtract(&self, amount: u64) {
        let mut mg = self.cache_size.lock();
        if let Some(val) = mg.checked_sub(amount) {
            *mg = val;
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache size corruption: subtract: current={} removed={amount}",
                *mg
            );
            *mg = 0;
        }
    }
}

impl std::fmt::Debug for CacheQuota {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheQuota")
            .field("cache_size", &*self.cache_size.lock())
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
    /// Finalize the reservation after a successful download.
    ///
    /// Adjusts `cache_size` so the net change from `try_acquire` + `finalize`
    /// equals `bytes_received - prev_file_size`. For `ContentLength::Exact`
    /// with an honest upstream this is a no-op. For `ContentLength::Unknown`
    /// (or an upstream that under-delivered), the unused reservation is
    /// reclaimed. For an upstream that over-delivered (sent more bytes than
    /// announced via `Content-Length`), the extra is added so `cache_quota`
    /// tracks the actual on-disk size.
    pub(crate) fn finalize(mut self, bytes_received: u64) {
        match self.reserved.get().cmp(&bytes_received) {
            Ordering::Equal => {}
            Ordering::Greater => {
                let diff = self.reserved.get() - bytes_received;
                trace!(
                    "Finalizing quota reservation: reserved={} received={bytes_received} diff=-{diff}",
                    self.reserved
                );
                self.quota.subtract(diff);
            }
            Ordering::Less => {
                let diff = bytes_received - self.reserved.get();
                trace!(
                    "Finalizing quota reservation: reserved={} received={bytes_received} diff=+{diff}",
                    self.reserved
                );
                self.quota.add(diff);
            }
        }
        self.finalized = true;
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if self.finalized {
            return;
        }

        // Revert: remove the reserved amount, add back prev_file_size

        match self.reserved.get().cmp(&self.prev_file_size) {
            Ordering::Equal => {}

            Ordering::Less => {
                let revert = self.prev_file_size - self.reserved.get();
                trace!(
                    "Reverting quota reservation: reserved={} prev_file_size={} revert=+{revert}",
                    self.reserved, self.prev_file_size
                );
                self.quota.add(revert);
            }

            Ordering::Greater => {
                let revert = self.reserved.get() - self.prev_file_size;
                trace!(
                    "Reverting quota reservation: reserved={} prev_file_size={} revert=-{revert}",
                    self.reserved, self.prev_file_size
                );
                self.quota.subtract(revert);
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
        // The bug being fixed: cache is currently over quota, and the
        // replacement would actually shrink it. Old code rejected because
        // saturated `net_add = max(0, reserved - prev) = 0`, then compared
        // `curr + 0 > quota` → reject. New code computes
        // `curr - prev + reserved = 110 - 20 + 5 = 95 <= 100` → accept.
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
}
