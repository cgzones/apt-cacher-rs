//! The peer identity a request carries through the proxy: the client's
//! socket address plus the marker that tells cleanup's in-process index
//! fetches apart from a real client.

use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
};

#[derive(Copy, Clone, Debug)]
pub(crate) struct ClientInfo {
    addr: SocketAddr,
    is_cleanup: bool,
}

/// Address attached to in-process requests synthesised by `task_cleanup`
/// (Packages fetches for the GC reference set).  Distinct from `127.0.0.1`
/// so logging and metrics can distinguish real loopback clients from the
/// cleanup-driven probes.
pub(crate) const CLEANUP_CLIENT_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0));

impl ClientInfo {
    #[must_use]
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            is_cleanup: false,
        }
    }

    #[must_use]
    pub(crate) fn new_cleanup() -> Self {
        Self {
            addr: CLEANUP_CLIENT_ADDR,
            is_cleanup: true,
        }
    }

    #[must_use]
    #[inline]
    pub(crate) fn ip(&self) -> IpAddr {
        self.addr.ip().to_canonical()
    }

    /// `true` when this client is the in-process sentinel used by
    /// `task_cleanup` to fetch a Packages index — never a real client.
    /// Used by upstream-error logging to demote a routine 4xx during a
    /// cleanup probe (e.g. the deliberate `.xz → .gz → raw` walk) from
    /// WARN to DEBUG.
    #[must_use]
    #[inline]
    pub(crate) fn is_cleanup_synthetic(&self) -> bool {
        self.is_cleanup
    }
}

impl Display for ClientInfo {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddrV6;

    use super::*;

    #[test]
    fn real_client_is_not_the_cleanup_sentinel() {
        let client = ClientInfo::new(CLEANUP_CLIENT_ADDR);
        assert!(
            !client.is_cleanup_synthetic(),
            "the marker is the constructor, not the address"
        );
        assert!(ClientInfo::new_cleanup().is_cleanup_synthetic());
    }

    #[test]
    fn ipv4_mapped_addresses_are_canonicalised() {
        // Usage rows and the dashboard's per-client stats key on `ip()`,
        // so a v4-mapped v6 peer must not mint a second identity for a
        // client that also connects over plain IPv4.
        let mapped = Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped();
        let client = ClientInfo::new(SocketAddr::V6(SocketAddrV6::new(mapped, 0, 0, 0)));
        assert_eq!(client.ip(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(client.to_string(), "192.0.2.1");
    }

    #[test]
    fn cleanup_sentinel_is_distinct_from_loopback() {
        assert_ne!(
            ClientInfo::new_cleanup().ip(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "the sentinel must stay distinguishable from a real loopback client"
        );
    }
}
