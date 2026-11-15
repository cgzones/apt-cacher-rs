use std::{
    fmt::{self, Display},
    io::ErrorKind,
    net::SocketAddr,
};

use nix::sys::socket::{setsockopt, sockopt::TcpCork};
use tokio::net::TcpStream;
use tracing::warn;

use crate::{error::ErrorReport, warn_once_or_debug};

/// A socket address for log lines, or `<unknown>` when it could not be
/// read. The IP is canonicalized, so an IPv4 client of the dual-stack
/// listener reads `192.0.2.1:40000`, not `[::ffff:192.0.2.1]:40000`.
struct Endpoint(std::io::Result<SocketAddr>);

impl Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(addr) => Display::fmt(&SocketAddr::new(addr.ip().to_canonical(), addr.port()), f),
            Err(_err) => f.write_str("<unknown>"),
        }
    }
}

/// RAII guard that sets `TCP_CORK` on creation and clears it on drop.
/// While corked, the kernel buffers small writes to coalesce them into
/// full MSS-sized TCP segments (e.g. headers + sendfile body).
#[must_use = "dropping the guard immediately uncorks the socket"]
pub(crate) struct CorkGuard<'a>(&'a TcpStream);

impl<'a> CorkGuard<'a> {
    fn new(stream: &'a TcpStream) -> std::io::Result<Self> {
        setsockopt(stream, TcpCork, &true)?;
        Ok(Self(stream))
    }

    #[must_use = "dropping the guard immediately uncorks the socket"]
    pub(crate) fn new_optional(stream: &'a TcpStream) -> Option<Self> {
        match Self::new(stream) {
            Ok(guard) => Some(guard),
            // A kernel/socket family without TCP_CORK is an environmental
            // fact, not an operator-actionable fault: say it once, then
            // demote. Any other errno keeps full severity every time.
            Err(err) if err.kind() == ErrorKind::Unsupported => {
                warn_once_or_debug!(
                    "Failed to cork TCP socket from {} to {}; sending without corking:  {}",
                    Endpoint(stream.local_addr()),
                    Endpoint(stream.peer_addr()),
                    ErrorReport(&err)
                );

                None
            }
            Err(err) => {
                warn!(
                    "Failed to cork TCP socket from {} to {}; sending without corking:  {}",
                    Endpoint(stream.local_addr()),
                    Endpoint(stream.peer_addr()),
                    ErrorReport(&err)
                );

                None
            }
        }
    }
}

impl Drop for CorkGuard<'_> {
    fn drop(&mut self) {
        let stream = self.0;

        if let Err(errno) = setsockopt(stream, TcpCork, &false) {
            warn!(
                "Failed to uncork TCP socket from {} to {}; leaving the socket corked:  {}",
                Endpoint(stream.local_addr()),
                Endpoint(stream.peer_addr()),
                ErrorReport(&std::io::Error::from(errno))
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn endpoint_renders_a_mapped_peer_as_ipv4() {
        let mapped = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped(), 40000));
        assert_eq!(Endpoint(Ok(mapped)).to_string(), "192.0.2.1:40000");

        let v6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 80));
        assert_eq!(Endpoint(Ok(v6)).to_string(), "[2001:db8::1]:80");

        let failed = Endpoint(Err(std::io::Error::other("getpeername")));
        assert_eq!(failed.to_string(), "<unknown>");
    }
}
