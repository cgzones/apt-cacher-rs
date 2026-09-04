use std::{
    net::IpAddr,
    num::NonZero,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    metrics,
    per_ip_counter::{PerIpCounter, PerIpPermit},
};

static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);
static CLIENT_DOWNLOADS: AtomicUsize = AtomicUsize::new(0);

static CONNECTIONS_PER_IP: std::sync::LazyLock<PerIpCounter> =
    std::sync::LazyLock::new(|| PerIpCounter::new(Some(&metrics::PER_CLIENT_IP_PEAK)));

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
fn derive_max_connections(soft_limit: u64) -> NonZero<usize> {
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
    /// `Some` iff `max_connections_per_client_ip` is configured and this
    /// connection was admitted against it. `None` - the no-cap deployment
    /// path - releases with a single atomic decrement and never touches the
    /// per-IP mutex.
    per_ip: Option<PerIpPermit>,
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

        let per_ip = match max_per_ip {
            Some(max) => {
                let Some(permit) = CONNECTIONS_PER_IP.try_acquire(client_ip, max) else {
                    CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
                    metrics::CONNECTION_REJECTED_PER_IP_CAP.increment();
                    return Err(ConnectionCap::PerIp(max));
                };
                Some(permit)
            }
            None => None,
        };
        Ok(Self { per_ip })
    }
}

impl Drop for ClientCounter {
    fn drop(&mut self) {
        // Release in the reverse of the acquire order (global, then per-IP),
        // so the invariant `per-IP count <= global count` holds at every
        // instant a racing `try_new` could observe the two.
        drop(self.per_ip.take());
        CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
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
    /// Count an active client download for the lifetime of the returned
    /// guard; dropping it right away would leave the counter untouched.
    #[must_use]
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
    use crate::nonzero;

    #[test]
    fn per_ip_cap_refuses_and_releases() {
        // `CONNECTIONS_PER_IP` is process-wide: use an address no other test
        // touches, and compare the global count against its starting value.
        let ip: IpAddr = "192.0.2.21".parse().expect("test address");
        let before = connected_clients();

        let admitted = ClientCounter::try_new(ip, Some(nonzero!(1)), None).expect("first admitted");
        assert_eq!(connected_clients(), before + 1);
        assert_eq!(
            ClientCounter::try_new(ip, Some(nonzero!(1)), None).err(),
            Some(ConnectionCap::PerIp(nonzero!(1))),
        );
        assert_eq!(
            connected_clients(),
            before + 1,
            "a refused connection must not keep its global slot"
        );

        assert!(
            metrics::PER_CLIENT_IP_PEAK.get() >= 1,
            "admitting under the per-IP cap samples the peak gauge"
        );

        drop(admitted);
        let again = ClientCounter::try_new(ip, Some(nonzero!(1)), None).expect("slot released");
        drop(again);
        assert_eq!(connected_clients(), before);
    }

    /// Without `max_connections_per_client_ip` the per-IP map is never
    /// touched, so an unconfigured deployment pays one atomic per connection
    /// and keeps no per-IP state at all.
    #[test]
    fn no_per_ip_cap_keeps_no_per_ip_state() {
        let ip: IpAddr = "192.0.2.24".parse().expect("test address");
        let before = connected_clients();

        let admitted = ClientCounter::try_new(ip, None, None).expect("admitted");
        assert_eq!(connected_clients(), before + 1);
        assert!(
            !CONNECTIONS_PER_IP.tracks(ip),
            "an unconfigured per-IP cap must not populate the map"
        );

        drop(admitted);
        assert_eq!(connected_clients(), before);
    }

    #[test]
    fn global_cap_refuses_the_connection_past_the_limit() {
        let ip: IpAddr = "192.0.2.22".parse().expect("test address");
        let before = connected_clients();
        let max = NonZero::new(before + 1).expect("at least one slot");

        let admitted = ClientCounter::try_new(ip, None, Some(max)).expect("under the cap");
        assert_eq!(
            ClientCounter::try_new(ip, None, Some(max)).err(),
            Some(ConnectionCap::Global(max)),
        );

        drop(admitted);
        assert_eq!(connected_clients(), before);
    }

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
