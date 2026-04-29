use std::{num::NonZero, sync::LazyLock};

use crate::{config::DomainName, metrics, nonzero, ringbuffer::RingBuffer};

pub(crate) const UNCACHEABLES_MAX: NonZero<usize> = nonzero!(20);

static UNCACHEABLES: LazyLock<parking_lot::RwLock<RingBuffer<(DomainName, String)>>> =
    LazyLock::new(|| parking_lot::RwLock::new(RingBuffer::new(UNCACHEABLES_MAX)));

/// Record a request as uncacheable for web-interface display.
///
/// Moves existing entries to the end so the most recent entries stay newest.
pub(crate) fn record_uncacheable(host: &DomainName, path: &str) {
    let uncacheables = &mut *UNCACHEABLES.write();

    // Remove and re-add existing entries to keep them recent.
    if let Some((idx, (_h, _p))) = uncacheables
        .iter()
        .enumerate()
        .find(|(_idx, (h, p))| *h == *host && *p == path)
    {
        let entry = uncacheables.remove(idx).expect("entry exists");
        debug_assert_eq!(entry.0, *host, "host was used as lookup key");
        debug_assert_eq!(entry.1, path, "path was used as lookup key");

        uncacheables.push(entry);
    } else {
        uncacheables.push((host.to_owned(), path.to_owned()));
    }

    metrics::UNCACHEABLE.increment();
}

pub(crate) fn get_uncacheables() -> &'static parking_lot::RwLock<RingBuffer<(DomainName, String)>> {
    &UNCACHEABLES
}
