//! The concurrency cap on uncached passthrough relays
//! (`max_passthrough_relays`).
//!
//! A cache-fetch relay starts as a download: the upstream request is made
//! before the answer is known to be a passthrough, under the
//! `max_upstream_downloads` slot its `InitBarrier` holds. Both backends
//! `decline` that barrier, giving the slot back, before the body is relayed,
//! so the relay takes a [`RelaySlot`] of its own; it is admitted before the
//! `decline`, so a refusal is what joiners are told (`Declined::RelayRefused`).
//! The refused upstream answer is dropped undrained.
//!
//! Passthroughs are not downloads, so `max_upstream_downloads` does not
//! bound them, yet each one holds an upstream connection and its buffers for
//! as long as the client keeps reading. The cap is global, not per source
//! IP: the per-IP accept cap already bounds a single client, this one bounds
//! the upstream side as a whole.

use std::num::NonZero;

use crate::{client_info::ClientInfo, metrics, warn_once_or_info};

/// Body of the 503 a refused passthrough is answered with.
pub(crate) const REFUSAL_BODY: &str = "Too many concurrent passthrough requests";

/// The count and the clock move under one lock: with the count an atomic
/// and the clock updated beside it, an admission landing between a
/// release's decrement and its `leave` would see the span still running
/// (its `enter` a no-op), and the `leave` would then stop the span with the
/// cap full again.
struct RelayCounter {
    held: parking_lot::Mutex<usize>,
    cap_clock: &'static metrics::CapClock,
}

impl RelayCounter {
    #[must_use]
    const fn new(cap_clock: &'static metrics::CapClock) -> Self {
        Self {
            held: parking_lot::Mutex::new(0),
            cap_clock,
        }
    }

    /// `None` at the cap. Counts and updates the peak gauge without a cap
    /// too, so the dashboard reflects real activity on an uncapped
    /// deployment.
    fn try_acquire(&'static self, max: Option<NonZero<usize>>) -> Option<RelaySlot> {
        let mut held = self.held.lock();
        if max.is_some_and(|max| *held >= max.get()) {
            return None;
        }
        *held += 1;
        let now_held = *held;
        if max.is_some_and(|max| now_held >= max.get()) {
            self.cap_clock.enter();
        }
        drop(held);
        metrics::PASSTHROUGH_ADMITTED.increment();
        metrics::PASSTHROUGH_ACTIVE_PEAK.update(now_held as u64);
        Some(RelaySlot { counter: self })
    }

    #[must_use]
    fn active(&self) -> usize {
        *self.held.lock()
    }
}

static RELAYS: RelayCounter = RelayCounter::new(&metrics::PASSTHROUGH_CAP_CLOCK);

#[must_use]
pub(crate) fn active_relays() -> usize {
    RELAYS.active()
}

/// One admitted passthrough relay; released on drop. Hold it for as long as
/// the relay can move bytes.
pub(crate) struct RelaySlot {
    counter: &'static RelayCounter,
}

impl std::fmt::Debug for RelaySlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { counter: _ } = self;
        f.write_str("RelaySlot")
    }
}

impl Drop for RelaySlot {
    fn drop(&mut self) {
        let mut held = self.counter.held.lock();
        *held -= 1;
        // Under the lock, so no admission can refill the cap between the
        // decrement and the clock.
        self.counter.cap_clock.leave();
        drop(held);
    }
}

fn try_acquire(max: Option<NonZero<usize>>) -> Option<RelaySlot> {
    RELAYS.try_acquire(max)
}

/// Counts and logs a refusal; the caller answers a `None` with 503
/// [`REFUSAL_BODY`].
#[must_use]
pub(crate) fn admit(
    max: Option<NonZero<usize>>,
    uri: impl std::fmt::Display,
    client: &ClientInfo,
) -> Option<RelaySlot> {
    let slot = try_acquire(max);
    if slot.is_none() {
        metrics::PASSTHROUGH_REJECTED_CAP.increment();
        warn_once_or_info!(
            "Max passthrough relays ({}) exceeded for `{uri}` from client {client}; returning 503",
            max.map_or(0, NonZero::get)
        );
    }
    slot
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::local_client;

    // `RELAYS` is process-wide and other tests may hold slots, so the cap is
    // expressed relative to the count seen at the start.
    #[test]
    fn slots_are_capped_and_released_on_drop() {
        let base = active_relays();
        let max = NonZero::new(base + 2).expect("non-zero");
        let first = try_acquire(Some(max)).expect("first slot");
        let second = try_acquire(Some(max)).expect("second slot");
        let before = metrics::PASSTHROUGH_REJECTED_CAP.get();
        assert!(
            admit(Some(max), "/x", &local_client()).is_none(),
            "a third relay must be refused"
        );
        assert!(metrics::PASSTHROUGH_REJECTED_CAP.get() > before);

        drop(second);
        let third = try_acquire(Some(max)).expect("a released slot is handed out again");
        drop(first);
        drop(third);
    }

    #[test]
    fn the_cap_clock_runs_exactly_while_the_relays_are_at_the_cap() {
        static CLOCK: metrics::CapClock = metrics::CapClock::new();
        static COUNTER: RelayCounter = RelayCounter::new(&CLOCK);
        let max = NonZero::new(2);

        let first = COUNTER.try_acquire(max).expect("first slot");
        assert!(!CLOCK.is_at_cap(), "one of two is not the cap");
        let second = COUNTER.try_acquire(max).expect("second slot");
        assert!(CLOCK.is_at_cap());
        assert!(
            COUNTER.try_acquire(max).is_none(),
            "the cap refuses a third"
        );
        assert!(CLOCK.is_at_cap(), "a refusal leaves the span running");
        drop(first);
        assert!(!CLOCK.is_at_cap());
        let third = COUNTER.try_acquire(max).expect("a released slot");
        assert!(CLOCK.is_at_cap(), "refilling the cap restarts the span");
        drop(second);
        drop(third);
        assert!(!CLOCK.is_at_cap());
        assert_eq!(COUNTER.active(), 0);
    }

    #[test]
    fn no_cap_admits_and_counts() {
        let slot = try_acquire(None).expect("uncapped");
        assert!(active_relays() >= 1);
        assert!(metrics::PASSTHROUGH_ACTIVE_PEAK.get() >= 1);
        drop(slot);
    }
}
