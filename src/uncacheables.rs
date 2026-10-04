//! The most recently seen uncacheable requests, for the web interface's
//! uncacheable table.
//!
//! A bounded ring of `(requested host and port, requested path)` entries:
//! re-recording an entry moves it to the most-recent end, and only a *fresh*
//! entry bumps [`metrics::UNCACHEABLE`], so that counter tracks distinct
//! uncacheable resources rather than request volume - which is what lets the
//! dashboard derive the ring's eviction count from it.

use std::{borrow::Cow, num::NonZero, sync::LazyLock};

use crate::{config::ClientHost, metrics, nonzero, ringbuffer::RingBuffer};

pub(crate) const UNCACHEABLES_MAX: NonZero<usize> = nonzero!(20);

/// One uncacheable request: the host and port the client named, and the
/// path it asked for. The port is part of the identity, as a mirror's is.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Uncacheable {
    pub(crate) host: ClientHost,
    pub(crate) port: Option<NonZero<u16>>,
    pub(crate) path: String,
}

impl Uncacheable {
    /// The requested URI authority, `host[:port]` (an IPv6 host bracketed).
    #[must_use]
    pub(crate) fn authority(&self) -> Cow<'_, str> {
        let Self {
            host,
            port,
            path: _,
        } = self;
        host.format_authority(*port)
    }
}

static UNCACHEABLES: LazyLock<parking_lot::RwLock<RingBuffer<Uncacheable>>> =
    LazyLock::new(|| parking_lot::RwLock::new(RingBuffer::new(UNCACHEABLES_MAX)));

/// Record a request as uncacheable for web-interface display.
///
/// A re-recorded entry moves to the end, refreshing its most-recently-seen
/// position.
pub(crate) fn record_uncacheable(host: &ClientHost, port: Option<NonZero<u16>>, path: &str) {
    let uncacheables = &mut *UNCACHEABLES.write();

    if let Some(idx) = uncacheables
        .iter()
        .position(|entry| entry.host == *host && entry.port == port && entry.path == path)
    {
        let entry = uncacheables.remove(idx).expect("entry exists");
        debug_assert_eq!(entry.host, *host, "host was used as lookup key");
        debug_assert_eq!(entry.port, port, "port was used as lookup key");
        debug_assert_eq!(entry.path, path, "path was used as lookup key");

        uncacheables.push(entry);
    } else {
        uncacheables.push(Uncacheable {
            host: host.clone(),
            port,
            path: path.to_owned(),
        });
        // Bump only on a fresh (host, port, path) insertion so the counter
        // tracks unique resources observed (not raw request count). This
        // is what the dashboard's "Uncacheable Evictions" line subtracts
        // UNCACHEABLES_MAX from.
        metrics::UNCACHEABLE.increment();
    }
}

pub(crate) fn get_uncacheables() -> parking_lot::RwLockReadGuard<'static, RingBuffer<Uncacheable>> {
    UNCACHEABLES.read()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str) -> ClientHost {
        ClientHost::new(name).expect("valid host")
    }

    fn snapshot() -> Vec<(String, String)> {
        get_uncacheables()
            .iter()
            .map(|entry| (entry.authority().into_owned(), entry.path.clone()))
            .collect()
    }

    fn contains(host: &ClientHost, path: &str) -> bool {
        get_uncacheables()
            .iter()
            .any(|entry| entry.host == *host && entry.port.is_none() && entry.path == path)
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
        record_uncacheable(&a, None, "/x");
        record_uncacheable(&b, None, "/x");
        record_uncacheable(&a, None, "/y");
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
        record_uncacheable(&a, None, "/x");
        assert_eq!(metrics::UNCACHEABLE.get() - before, 0);
        assert_eq!(get_uncacheables().len(), 3);
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
            record_uncacheable(&a, None, &format!("/fill{i}"));
        }
        assert_eq!(metrics::UNCACHEABLE.get() - before, cap as u64);
        let ring = get_uncacheables();
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
        record_uncacheable(&a, None, "/fill0");
        record_uncacheable(&a, None, "/extra");
        assert!(contains(&a, "/fill0"));
        assert!(!contains(&a, "/fill1"));
        assert_eq!(snapshot().last().map(|(_, p)| p.as_str()), Some("/extra"));

        // The port is part of the key and of the rendered authority, and an
        // IPv6 host renders bracketed.
        let before = metrics::UNCACHEABLE.get();
        record_uncacheable(&a, NonZero::new(8080), "/extra");
        record_uncacheable(&host("2001:db8::1"), NonZero::new(8080), "/v6");
        assert_eq!(metrics::UNCACHEABLE.get() - before, 2);
        let tail: Vec<_> = snapshot().split_off(cap - 2);
        assert_eq!(
            tail,
            [
                ("a.example:8080".to_owned(), "/extra".to_owned()),
                ("[2001:db8::1]:8080".to_owned(), "/v6".to_owned()),
            ]
        );
    }
}
