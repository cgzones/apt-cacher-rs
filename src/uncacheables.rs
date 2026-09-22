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

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> ClientHost {
        ClientHost::new(name.to_owned()).expect("valid host")
    }

    fn snapshot() -> Vec<(String, String)> {
        get_uncacheables()
            .read()
            .iter()
            .map(|(h, p)| (h.to_string(), p.clone()))
            .collect()
    }

    fn contains(host: &ClientHost, path: &str) -> bool {
        get_uncacheables()
            .read()
            .iter()
            .any(|(h, p)| h == host && p == path)
    }

    /// One test drives the whole ring: the store is a process-global, so
    /// separate tests would race on ordering under a multi-threaded runner.
    #[test]
    fn ring_orders_dedups_counts_and_evicts() {
        let a = host("a.example");
        let b = host("b.example");
        let cap = UNCACHEABLES_MAX.get();

        // Miss before anything is recorded.
        assert!(!contains(&a, "/x"));

        // Fresh pairs bump the metric, once each.
        let before = metrics::UNCACHEABLE.get();
        record_uncacheable(&a, "/x");
        record_uncacheable(&b, "/x");
        record_uncacheable(&a, "/y");
        assert_eq!(metrics::UNCACHEABLE.get() - before, 3);
        assert!(contains(&a, "/x"));
        assert!(contains(&b, "/x"));
        assert!(!contains(&b, "/y"), "host is part of the key");
        assert_eq!(
            snapshot(),
            [
                ("a.example".to_owned(), "/x".to_owned()),
                ("b.example".to_owned(), "/x".to_owned()),
                ("a.example".to_owned(), "/y".to_owned()),
            ]
        );

        // Re-recording moves the pair to the most-recent end without a bump.
        let before = metrics::UNCACHEABLE.get();
        record_uncacheable(&a, "/x");
        assert_eq!(metrics::UNCACHEABLE.get() - before, 0);
        assert_eq!(get_uncacheables().read().len(), 3);
        assert_eq!(
            snapshot(),
            [
                ("b.example".to_owned(), "/x".to_owned()),
                ("a.example".to_owned(), "/y".to_owned()),
                ("a.example".to_owned(), "/x".to_owned()),
            ]
        );

        // Fill to capacity: the ring never exceeds UNCACHEABLES_MAX and the
        // oldest pair (b, /x) is the first one evicted.
        let before = metrics::UNCACHEABLE.get();
        for i in 0..cap {
            record_uncacheable(&a, &format!("/fill{i}"));
        }
        assert_eq!(metrics::UNCACHEABLE.get() - before, cap as u64);
        let ring = get_uncacheables().read();
        assert_eq!(ring.len(), cap);
        assert!(ring.is_full());
        drop(ring);
        assert!(!contains(&b, "/x"));
        assert!(!contains(&a, "/y"));
        assert!(!contains(&a, "/x"));
        assert!(contains(&a, "/fill0"));
        assert!(contains(&a, &format!("/fill{}", cap - 1)));

        // A refresh of the oldest surviving pair keeps it out of the next
        // eviction, which takes /fill1 instead.
        record_uncacheable(&a, "/fill0");
        record_uncacheable(&a, "/extra");
        assert!(contains(&a, "/fill0"));
        assert!(!contains(&a, "/fill1"));
        assert_eq!(snapshot().last().map(|(_, p)| p.as_str()), Some("/extra"));
    }
}
