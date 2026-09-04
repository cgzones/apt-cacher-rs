//! The most recently seen uncacheable requests, for the web interface's
//! uncacheable table.
//!
//! A bounded ring of `(requested host, requested path)` pairs: re-recording
//! a pair moves it to the most-recent end, and only a *fresh* pair bumps
//! [`metrics::UNCACHEABLE`], so that counter tracks distinct uncacheable
//! resources rather than request volume - which is what lets the dashboard
//! derive the ring's eviction count from it.

use std::{num::NonZero, sync::LazyLock};

use crate::{config::ClientHost, metrics, nonzero, ringbuffer::RingBuffer};

pub(crate) const UNCACHEABLES_MAX: NonZero<usize> = nonzero!(20);

static UNCACHEABLES: LazyLock<parking_lot::RwLock<RingBuffer<(ClientHost, String)>>> =
    LazyLock::new(|| parking_lot::RwLock::new(RingBuffer::new(UNCACHEABLES_MAX)));

/// Record a request as uncacheable for web-interface display.
///
/// A re-recorded entry moves to the end, refreshing its most-recently-seen
/// position.
pub(crate) fn record_uncacheable(host: &ClientHost, path: &str) {
    let uncacheables = &mut *UNCACHEABLES.write();

    // Remove and re-add existing entries to keep them recent.
    if let Some(idx) = uncacheables
        .iter()
        .position(|(h, p)| h == host && p == path)
    {
        let entry = uncacheables.remove(idx).expect("entry exists");
        debug_assert_eq!(entry.0, *host, "host was used as lookup key");
        debug_assert_eq!(entry.1, path, "path was used as lookup key");

        uncacheables.push(entry);
    } else {
        uncacheables.push((host.to_owned(), path.to_owned()));
        // Bump only on a fresh (host, path) insertion so the counter
        // tracks unique resources observed (not raw request count). This
        // is what the dashboard's "Uncacheable Evictions" line subtracts
        // UNCACHEABLES_MAX from.
        metrics::UNCACHEABLE.increment();
    }
}

pub(crate) fn get_uncacheables() -> &'static parking_lot::RwLock<RingBuffer<(ClientHost, String)>> {
    &UNCACHEABLES
}
