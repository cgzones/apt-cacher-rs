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
            let net_add = reserved.get().saturating_sub(prev_file_size);
            let new_size = curr.checked_add(net_add);
            if new_size.is_none_or(|s| s > quota.get()) {
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

        let new_size = curr.saturating_add(reserved.get());
        let new_size = if let Some(val) = new_size.checked_sub(prev_file_size) {
            val
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache size corruption: quota acquire: file={debname} current_cache_size={curr} content_length={content_length:?} previous_file_size={prev_file_size}"
            );
            new_size
        };

        *mg = new_size;
        drop(mg);

        self.sample_utilization_peak();

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
    pub(crate) fn sample_utilization_peak(&self) {
        let Some(quota) = self.quota_config else {
            return;
        };
        let current = self.current_size();
        // bps = current * 10000 / quota, computed in u128 to avoid overflow.
        // Clamp to 10_000 (= 100.00 %) so over-quota states do not produce a
        // misleading sentinel; `quota` is NonZero so no div-by-zero.
        let bps = u128::from(current).saturating_mul(10_000) / std::num::NonZeroU128::from(quota);
        let bps = usize::try_from(bps.min(10_000)).expect("10_000 fits in u64");
        metrics::CACHE_QUOTA_UTIL_PEAK_BPS.update(bps as u64);
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

        let expected = actual_cache_size + active_downloading_size;
        let difference = stored.abs_diff(expected);
        if difference != 0 {
            *mg = expected;
            metrics::RECONCILE_EVENTS.increment();
            metrics::RECONCILE_BYTES_REPAIRED.increment_by(difference);
        }
        drop(mg);
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
        drop(mg);
        self.sample_utilization_peak();
    }

    pub(crate) fn subtract(&self, amount: u64) {
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
    /// Adjusts `cache_size` by the difference between reserved (upper bound) and
    /// actual bytes received. For `ContentLength::Exact`, this is a no-op (diff=0).
    /// For `ContentLength::Unknown`, this reclaims the unused reservation.
    pub(crate) fn finalize(mut self, bytes_received: u64) {
        let size_diff = self.reserved.get().saturating_sub(bytes_received);
        if size_diff != 0 {
            trace!(
                "Finalizing quota reservation: reserved={} received={bytes_received} diff={size_diff}",
                self.reserved
            );
            self.quota.subtract(size_diff);
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
                    "Reverting quota reservation: reserved={} prev_file_size={} revert=-{revert}",
                    self.reserved, self.prev_file_size
                );
                self.quota.add(revert);
            }

            Ordering::Greater => {
                let revert = self.reserved.get() - self.prev_file_size;
                trace!(
                    "Reverting quota reservation: reserved={} prev_file_size={} revert={revert}",
                    self.reserved, self.prev_file_size
                );
                self.quota.subtract(revert);
            }
        }
    }
}
