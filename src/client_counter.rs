use std::{
    net::IpAddr,
    num::NonZero,
    sync::atomic::{AtomicUsize, Ordering},
};

use hashbrown::HashMap;

use crate::metrics;

static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);
static CLIENT_DOWNLOADS: AtomicUsize = AtomicUsize::new(0);

static CONNECTIONS_PER_IP: std::sync::LazyLock<parking_lot::Mutex<HashMap<IpAddr, usize>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

#[must_use]
pub(crate) fn connected_clients() -> usize {
    CONNECTED_CLIENTS.load(Ordering::Relaxed)
}

/// Smallest global connection cap the derived default settles on.
const MIN_DERIVED_MAX_CONNECTIONS: NonZero<usize> = NonZero::new(64).expect("non-zero");

/// The default `max_connections` for a soft `RLIMIT_NOFILE` of `soft_limit`:
/// three quarters of it, leaving the rest for cache files, upstream
/// sockets, the database and the listener, with a floor of
/// [`MIN_DERIVED_MAX_CONNECTIONS`] so a tiny limit still admits clients.
/// Pure so the formula is unit-testable; [`default_max_connections`] reads
/// the live limit.
#[must_use]
pub(crate) fn derive_max_connections(soft_limit: u64) -> NonZero<usize> {
    let derived = usize::try_from(soft_limit / 4 * 3).unwrap_or(usize::MAX);
    NonZero::new(derived).map_or(MIN_DERIVED_MAX_CONNECTIONS, |n| {
        n.max(MIN_DERIVED_MAX_CONNECTIONS)
    })
}

/// [`derive_max_connections`] of the process's soft `RLIMIT_NOFILE`.  An
/// unreadable limit falls back to the classic 1024 descriptors.
#[must_use]
pub(crate) fn default_max_connections() -> NonZero<usize> {
    let soft = match nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE) {
        Ok((soft, _hard)) => soft,
        Err(_errno) => 1024,
    };
    derive_max_connections(soft)
}

/// Which cap refused a connection in [`ClientCounter::try_new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnectionCap {
    /// `max_connections_per_client_ip` for the connecting IP.
    PerIp(NonZero<usize>),
    /// `max_connections` across all clients.
    Global(NonZero<usize>),
}

pub(crate) struct ClientCounter {
    client_ip: IpAddr,
    /// `true` iff `try_new` inserted/incremented an entry in
    /// `CONNECTIONS_PER_IP`. When `false`, `Drop` skips the mutex
    /// acquire entirely — the no-cap deployment path is then a single
    /// atomic decrement.
    tracked_per_ip: bool,
}

impl ClientCounter {
    /// Admit a connection from `client_ip` against both caps, or say which
    /// one refused it.  The global cap is checked first (it is the cheaper,
    /// lock-free one and the one an fd-exhaustion flood exercises); the
    /// per-IP map is only touched when that cap is configured.
    pub(crate) fn try_new(
        client_ip: IpAddr,
        max_per_ip: Option<NonZero<usize>>,
        max_global: Option<NonZero<usize>>,
    ) -> Result<Self, ConnectionCap> {
        // Reserve the global slot atomically: bump, and back out when that
        // pushed the count past the cap.
        let current = CONNECTED_CLIENTS.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(max) = max_global
            && current > max.get()
        {
            CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
            metrics::CONNECTION_REJECTED_GLOBAL_CAP.increment();
            return Err(ConnectionCap::Global(max));
        }
        metrics::CONNECTED_CLIENTS_PEAK.update(current as u64);

        let tracked_per_ip = if let Some(max) = max_per_ip {
            let mut map = CONNECTIONS_PER_IP.lock();
            let count = map.entry(client_ip).or_insert(0);
            if *count >= max.get() {
                drop(map);
                CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
                metrics::CONNECTION_REJECTED_PER_IP_CAP.increment();
                return Err(ConnectionCap::PerIp(max));
            }
            *count += 1;
            let observed = *count as u64;
            drop(map);
            metrics::PER_CLIENT_IP_PEAK.update(observed);
            true
        } else {
            false
        };
        Ok(Self {
            client_ip,
            tracked_per_ip,
        })
    }
}

impl Drop for ClientCounter {
    fn drop(&mut self) {
        CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
        if !self.tracked_per_ip {
            return;
        }
        let mut map = CONNECTIONS_PER_IP.lock();
        if let hashbrown::hash_map::Entry::Occupied(mut entry) = map.entry(self.client_ip) {
            let count = entry.get_mut();
            *count -= 1;
            if *count == 0 {
                entry.remove();
            }
        }
    }
}

#[must_use]
pub(crate) fn active_client_downloads() -> usize {
    CLIENT_DOWNLOADS.load(Ordering::Relaxed)
}

#[derive(Debug)]
pub(crate) struct ClientDownload {
    _private: (),
}

impl ClientDownload {
    pub(crate) fn new() -> Self {
        let current = CLIENT_DOWNLOADS.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::ACTIVE_CLIENT_DOWNLOADS_PEAK.update(current as u64);
        Self { _private: () }
    }
}

impl Drop for ClientDownload {
    fn drop(&mut self) {
        CLIENT_DOWNLOADS.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_cap_leaves_a_quarter_of_the_fd_limit() {
        assert_eq!(derive_max_connections(16 * 1024).get(), 12 * 1024);
        assert_eq!(derive_max_connections(1024).get(), 768);
    }

    #[test]
    fn derived_cap_has_a_floor() {
        assert_eq!(derive_max_connections(10).get(), 64);
        assert_eq!(derive_max_connections(0).get(), 64);
    }
}
