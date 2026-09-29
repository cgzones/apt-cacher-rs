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

use std::{
    net::{IpAddr, Ipv6Addr},
    num::NonZero,
};

use hashbrown::HashMap;

use crate::metrics;

/// Live count of held permits per source IP. An IP with no permit has no
/// entry, so the map is bounded by concurrent clients rather than by clients
/// ever seen.
pub(crate) struct PerIpCounter {
    held: parking_lot::Mutex<Held>,
    /// Gauge sampled on every admission, where the cap surfaces one. Kept
    /// here rather than at the call site so the count and the gauge cannot
    /// be read from different instants.
    peak: Option<&'static metrics::Peak>,
    /// Runs while at least one IP holds its cap, so the dashboard can say
    /// how long the cap was refusing someone. Moved under the map lock, so
    /// its spans are exact.
    cap_clock: &'static metrics::CapClock,
}

/// The map and, under the same lock, how many IPs sit at their cap.
#[derive(Default)]
struct Held {
    per_ip: HashMap<IpAddr, usize>,
    at_cap: usize,
}

impl PerIpCounter {
    #[must_use]
    pub(crate) fn new(
        peak: Option<&'static metrics::Peak>,
        cap_clock: &'static metrics::CapClock,
    ) -> Self {
        Self {
            held: parking_lot::Mutex::new(Held::default()),
            peak,
            cap_clock,
        }
    }

    /// The most permits any single IP holds right now: the live figure the
    /// per-IP cap is compared against.
    #[must_use]
    pub(crate) fn busiest(&self) -> usize {
        self.held.lock().per_ip.values().copied().max().unwrap_or(0)
    }

    /// Admit one more concurrent user of `ip` while fewer than `max` are
    /// held, or return `None` at the cap.
    ///
    /// `ip` is canonicalized here rather than trusted to arrive that way
    /// (`ClientInfo::ip` already is): a dual-stack listener reports an IPv4
    /// client as `::ffff:a.b.c.d`, and keyed raw that client would hold a
    /// second set of slots beside its plain IPv4 form. An IPv6 address then
    /// counts as its first `ipv6_prefix_len` bits (`client_ipv6_prefix_len`,
    /// see [`counter_key`]).
    ///
    /// Takes `&'static self` because the permit outlives the call and must
    /// name the counter to release into; every counter is a `static`.
    #[must_use]
    pub(crate) fn try_acquire(
        &'static self,
        ip: IpAddr,
        max: NonZero<usize>,
        ipv6_prefix_len: u8,
    ) -> Option<PerIpPermit> {
        let ip = counter_key(ip, ipv6_prefix_len);
        let mut held = self.held.lock();
        let Held { per_ip, at_cap } = &mut *held;
        let count = per_ip.entry(ip).or_insert(0);
        if *count >= max.get() {
            return None;
        }
        *count += 1;
        let now_held = *count as u64;
        if *count == max.get() {
            *at_cap += 1;
            if *at_cap == 1 {
                self.cap_clock.enter();
            }
        }
        drop(held);
        if let Some(peak) = self.peak {
            peak.update(now_held);
        }
        Some(PerIpPermit {
            counter: self,
            ip,
            max,
        })
    }

    /// Whether `ip`, keyed as [`Self::try_acquire`] keys it with
    /// `ipv6_prefix_len`, currently holds a permit. Only the tests need it;
    /// the production paths hold a permit or they do not.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn tracks(&self, ip: IpAddr, ipv6_prefix_len: u8) -> bool {
        self.held
            .lock()
            .per_ip
            .contains_key(&counter_key(ip, ipv6_prefix_len))
    }
}

/// The address `ip` is counted under: its canonical form, and for IPv6 only
/// its first `ipv6_prefix_len` bits (1..=128), so one host cannot multiply
/// its cap by using more addresses of its network (a /64 holds 2^64).
#[must_use]
fn counter_key(ip: IpAddr, ipv6_prefix_len: u8) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(ipv6_prefix_len.min(128)))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// One admitted slot, released on drop.
pub(crate) struct PerIpPermit {
    counter: &'static PerIpCounter,
    ip: IpAddr,
    /// The cap this permit was admitted under, so the release knows whether
    /// it takes its IP off the cap.
    max: NonZero<usize>,
}

impl Drop for PerIpPermit {
    fn drop(&mut self) {
        let mut held = self.counter.held.lock();
        let Held { per_ip, at_cap } = &mut *held;
        if let hashbrown::hash_map::Entry::Occupied(mut entry) = per_ip.entry(self.ip) {
            let count = entry.get_mut();
            if *count == self.max.get() {
                *at_cap = at_cap.saturating_sub(1);
                if *at_cap == 0 {
                    self.counter.cap_clock.leave();
                }
            }
            *count -= 1;
            if *count == 0 {
                entry.remove();
            }
        }
        drop(held);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    static CLOCK: metrics::CapClock = metrics::CapClock::new();
    static COUNTER: std::sync::LazyLock<PerIpCounter> =
        std::sync::LazyLock::new(|| PerIpCounter::new(None, &CLOCK));

    /// The clock runs while any IP sits at its cap, and stops once none
    /// does: two IPs at the cap, one released, still at the cap.
    #[test]
    fn the_cap_clock_runs_while_any_ip_is_at_its_cap() {
        static CLOCK: metrics::CapClock = metrics::CapClock::new();
        static COUNTER: std::sync::LazyLock<PerIpCounter> =
            std::sync::LazyLock::new(|| PerIpCounter::new(None, &CLOCK));
        let a: IpAddr = "192.0.2.41".parse().expect("test address");
        let b: IpAddr = "192.0.2.42".parse().expect("test address");

        let a1 = COUNTER.try_acquire(a, nonzero!(2), 128).expect("slot");
        assert!(!CLOCK.is_at_cap(), "one of two is not the cap");
        let a2 = COUNTER.try_acquire(a, nonzero!(2), 128).expect("slot");
        assert!(CLOCK.is_at_cap());
        let b1 = COUNTER.try_acquire(b, nonzero!(1), 128).expect("slot");
        assert_eq!(COUNTER.busiest(), 2);
        drop(a2);
        assert!(CLOCK.is_at_cap(), "b still holds its cap");
        drop(b1);
        assert!(!CLOCK.is_at_cap());
        drop(a1);
        assert_eq!(COUNTER.busiest(), 0);
    }

    #[test]
    fn ipv6_clients_count_by_prefix() {
        let key = |ip: &str, prefix| counter_key(ip.parse().expect("test address"), prefix);
        assert_eq!(
            key("2001:db8:1:2:aaaa::1", 64),
            key("2001:db8:1:2:bbbb::2", 64)
        );
        assert_ne!(key("2001:db8:1:2::1", 64), key("2001:db8:1:3::1", 64));
        assert_ne!(key("2001:db8::1", 128), key("2001:db8::2", 128));
        assert_eq!(key("2001:db8::1", 128), key("2001:db8::1", 128));
        assert_eq!(key("2001:db8::1", 1), key("3fff::1", 1));
        assert_eq!(
            key("::ffff:192.0.2.1", 64),
            key("192.0.2.1", 64),
            "IPv4 is canonical and unmasked"
        );
        assert_ne!(key("192.0.2.1", 64), key("192.0.2.2", 64));
    }

    /// Grouped by `/64`, two addresses of one network share a cap and the
    /// permit releases under the same key it was admitted under.
    #[test]
    fn a_prefix_groups_ipv6_addresses_under_one_cap() {
        let a: IpAddr = "2001:db8:41::a".parse().expect("test address");
        let b: IpAddr = "2001:db8:41::b".parse().expect("test address");
        let held = COUNTER.try_acquire(a, nonzero!(1), 64).expect("slot");
        assert!(
            COUNTER.try_acquire(b, nonzero!(1), 64).is_none(),
            "the network's cap is taken"
        );
        let own = COUNTER
            .try_acquire(b, nonzero!(1), 128)
            .expect("per address, b has its own cap");
        assert!(COUNTER.tracks(b, 64));
        drop(held);
        drop(own);
        assert!(!COUNTER.tracks(a, 64) && !COUNTER.tracks(b, 128));
    }

    #[test]
    fn permits_are_capped_per_ip_and_released_on_drop() {
        let ip: IpAddr = "192.0.2.31".parse().expect("test address");

        let first = COUNTER
            .try_acquire(ip, nonzero!(2), 128)
            .expect("first slot");
        let second = COUNTER
            .try_acquire(ip, nonzero!(2), 128)
            .expect("second slot");
        assert!(
            COUNTER.try_acquire(ip, nonzero!(2), 128).is_none(),
            "the cap must refuse a third"
        );

        drop(second);
        let third = COUNTER
            .try_acquire(ip, nonzero!(2), 128)
            .expect("a released slot is handed out again");

        drop(first);
        drop(third);
        assert!(
            !COUNTER.tracks(ip, 128),
            "the last permit's drop must remove the map entry"
        );
    }

    #[test]
    fn one_ip_at_its_cap_does_not_block_another() {
        let busy: IpAddr = "192.0.2.32".parse().expect("test address");
        let other: IpAddr = "192.0.2.33".parse().expect("test address");

        let held = COUNTER
            .try_acquire(busy, nonzero!(1), 128)
            .expect("first slot");
        assert!(
            COUNTER.try_acquire(busy, nonzero!(1), 128).is_none(),
            "cap reached"
        );
        let unrelated = COUNTER
            .try_acquire(other, nonzero!(1), 128)
            .expect("a different IP is unaffected");

        drop(held);
        drop(unrelated);
    }

    /// An IPv4 client reported by a dual-stack listener as an IPv4-mapped
    /// IPv6 address shares its slots with the plain IPv4 form, and an IPv6
    /// client stays apart from both.
    #[test]
    fn a_mapped_ipv4_client_shares_its_slots_with_the_plain_form() {
        let plain: IpAddr = "192.0.2.34".parse().expect("test address");
        let mapped: IpAddr = "::ffff:192.0.2.34".parse().expect("test address");
        let native: IpAddr = "2001:db8::34".parse().expect("test address");

        let held = COUNTER
            .try_acquire(mapped, nonzero!(1), 128)
            .expect("first slot");
        assert!(
            COUNTER.try_acquire(plain, nonzero!(1), 128).is_none(),
            "the plain form must count against the mapped one's slot"
        );
        assert!(COUNTER.tracks(plain, 128));
        let unrelated = COUNTER
            .try_acquire(native, nonzero!(1), 128)
            .expect("an IPv6 client is a different client");

        drop(held);
        assert!(
            !COUNTER.tracks(mapped, 128),
            "released under the canonical key"
        );
        let again = COUNTER
            .try_acquire(plain, nonzero!(1), 128)
            .expect("the released slot is free for the plain form");
        drop(again);
        drop(unrelated);
    }
}
