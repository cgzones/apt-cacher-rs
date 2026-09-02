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
