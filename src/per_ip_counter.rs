//! A per-source-IP concurrency limiter with an RAII permit.
//!
//! Two independent caps are expressed with it -
//! `max_connections_per_client_ip` ([`crate::client_counter`]) and
//! `https_tunnel_max_connections_per_client` ([`crate::tunnel_limiter`]) -
//! and each owns its own counter instance, its own refusal metric and its own
//! composition with a global cap. What they share, and what used to be
//! written twice, is the bookkeeping: admit while under the cap, and on
//! release decrement and drop the entry at zero so an idle map does not grow
//! one entry per IP ever seen.

use std::{net::IpAddr, num::NonZero};

use hashbrown::HashMap;

use crate::metrics;

/// Live count of held permits per source IP. An IP with no permit has no
/// entry, so the map is bounded by concurrent clients rather than by clients
/// ever seen.
pub(crate) struct PerIpCounter {
    held: parking_lot::Mutex<HashMap<IpAddr, usize>>,
    /// Gauge sampled on every admission, where the cap surfaces one. Kept
    /// here rather than at the call site so the count and the gauge cannot
    /// be read from different instants.
    peak: Option<&'static metrics::Peak>,
}

impl PerIpCounter {
    #[must_use]
    pub(crate) fn new(peak: Option<&'static metrics::Peak>) -> Self {
        Self {
            held: parking_lot::Mutex::new(HashMap::new()),
            peak,
        }
    }

    /// Admit one more concurrent user of `ip` while fewer than `max` are
    /// held, or return `None` at the cap.
    ///
    /// Takes `&'static self` because the permit outlives the call and must
    /// name the counter to release into; every counter is a `static`.
    #[must_use]
    pub(crate) fn try_acquire(
        &'static self,
        ip: IpAddr,
        max: NonZero<usize>,
    ) -> Option<PerIpPermit> {
        let mut map = self.held.lock();
        let count = map.entry(ip).or_insert(0);
        if *count >= max.get() {
            return None;
        }
        *count += 1;
        let held = *count as u64;
        drop(map);
        if let Some(peak) = self.peak {
            peak.update(held);
        }
        Some(PerIpPermit { counter: self, ip })
    }

    /// Whether `ip` currently holds a permit. Only the tests need it; the
    /// production paths hold a permit or they do not.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn tracks(&self, ip: IpAddr) -> bool {
        self.held.lock().contains_key(&ip)
    }
}

/// One admitted slot, released on drop.
pub(crate) struct PerIpPermit {
    counter: &'static PerIpCounter,
    ip: IpAddr,
}

impl Drop for PerIpPermit {
    fn drop(&mut self) {
        let mut map = self.counter.held.lock();
        if let hashbrown::hash_map::Entry::Occupied(mut entry) = map.entry(self.ip) {
            let count = entry.get_mut();
            *count -= 1;
            if *count == 0 {
                entry.remove();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    static COUNTER: std::sync::LazyLock<PerIpCounter> =
        std::sync::LazyLock::new(|| PerIpCounter::new(None));

    #[test]
    fn permits_are_capped_per_ip_and_released_on_drop() {
        let ip: IpAddr = "192.0.2.31".parse().expect("test address");

        let first = COUNTER.try_acquire(ip, nonzero!(2)).expect("first slot");
        let second = COUNTER.try_acquire(ip, nonzero!(2)).expect("second slot");
        assert!(
            COUNTER.try_acquire(ip, nonzero!(2)).is_none(),
            "the cap must refuse a third"
        );

        drop(second);
        let third = COUNTER
            .try_acquire(ip, nonzero!(2))
            .expect("a released slot is handed out again");

        drop(first);
        drop(third);
        assert!(
            !COUNTER.tracks(ip),
            "the last permit's drop must remove the map entry"
        );
    }

    #[test]
    fn one_ip_at_its_cap_does_not_block_another() {
        let busy: IpAddr = "192.0.2.32".parse().expect("test address");
        let other: IpAddr = "192.0.2.33".parse().expect("test address");

        let held = COUNTER.try_acquire(busy, nonzero!(1)).expect("first slot");
        assert!(
            COUNTER.try_acquire(busy, nonzero!(1)).is_none(),
            "cap reached"
        );
        let unrelated = COUNTER
            .try_acquire(other, nonzero!(1))
            .expect("a different IP is unaffected");

        drop(held);
        drop(unrelated);
    }
}
