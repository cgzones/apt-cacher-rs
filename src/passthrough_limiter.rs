//! The concurrency cap on uncached passthrough relays
//! (`max_passthrough_relays`), shared by every backend that relays one: the
//! hyper simple proxy, `splice_simple_proxy`, and a cache fetch whose
//! upstream answer (a non-200 the planner passes through) is relayed
//! uncached.
//!
//! A cache-fetch relay starts as a download: the upstream request is made
//! before the answer is known to be a passthrough, under the
//! `max_upstream_downloads` slot its `InitBarrier` holds. Both backends
//! `decline` that barrier, giving the slot back, before the body is relayed,
//! so the relay takes a [`RelaySlot`] of its own; it is admitted before the
//! `decline`, so a refusal is what joiners are told (`Declined::RelayRefused`).
//! The refused upstream answer is dropped undrained.
//!
//! Passthroughs are not downloads, so `max_upstream_downloads` never saw
//! them, yet each one holds an upstream connection and its buffers (up to
//! 256 KiB over TLS in splice) for as long as the client keeps reading. The
//! cap is global, not per source IP: the per-IP accept cap already bounds a
//! single client, this one bounds the upstream side as a whole.
//!
//! Composed like the per-IP caps: the counter owns admission, the RAII
//! release and the peak gauge; [`admit`] adds the refusal metric and the one
//! log line both backends emit, and each backend renders the 503 with
//! [`REFUSAL_BODY`].

use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{client_info::ClientInfo, metrics, warn_once_or_info};

/// Body of the 503 a refused passthrough is answered with (the proxy-side
/// overload convention: a 503 with a specific body).
pub(crate) const REFUSAL_BODY: &str = "Too many concurrent passthrough requests";

/// Passthrough relays currently held, across all clients.
static ACTIVE_RELAYS: AtomicUsize = AtomicUsize::new(0);

/// Current number of active passthrough relays.
#[must_use]
pub(crate) fn active_relays() -> usize {
    ACTIVE_RELAYS.load(Ordering::Relaxed)
}

/// One admitted passthrough relay; released on drop. Hold it for as long as
/// the relay can move bytes: across `splice_simple_proxy`, inside the hyper
/// response body.
#[derive(Debug)]
pub(crate) struct RelaySlot {
    _private: (),
}

impl Drop for RelaySlot {
    fn drop(&mut self) {
        ACTIVE_RELAYS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Admit one more relay while fewer than `max` are held (`None`: no cap), or
/// return `None` at the cap. Counts and updates the peak gauge either way,
/// so the dashboard reflects real activity on an uncapped deployment too.
fn try_acquire(max: Option<NonZero<usize>>) -> Option<RelaySlot> {
    let admitted = ACTIVE_RELAYS.try_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
        max.is_none_or(|max| held < max.get()).then_some(held + 1)
    });
    let held = admitted.ok()? + 1;
    metrics::PASSTHROUGH_ACTIVE_PEAK.update(held as u64);
    Some(RelaySlot { _private: () })
}

/// [`try_acquire`] against `max_passthrough_relays`, counting and logging a
/// refusal. The caller answers a `None` with 503 [`REFUSAL_BODY`].
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

    // `ACTIVE_RELAYS` is process-wide and other tests (or this module's own,
    // in parallel) may hold slots, so the cap is expressed relative to the
    // count seen at the start and the assertions stay on this test's slots.
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
    fn no_cap_admits_and_counts() {
        let slot = try_acquire(None).expect("uncapped");
        assert!(active_relays() >= 1);
        assert!(metrics::PASSTHROUGH_ACTIVE_PEAK.get() >= 1);
        drop(slot);
    }
}
