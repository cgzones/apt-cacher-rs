use std::{
    fmt::{self, Display},
    io::ErrorKind,
    net::SocketAddr,
    os::fd::AsRawFd as _,
};

use tokio::net::TcpStream;
use tracing::warn;

use crate::{error::ErrorReport, static_assert, warn_once_or_debug};

/// One end of a socket as the log lines below render it: the address, or
/// `<unknown>` when `getsockname`/`getpeername` failed. Formats straight into
/// the `Formatter` instead of allocating a `String` per log site.
///
/// The IP is canonicalized as `ClientInfo` renders it, so an IPv4 client of
/// the dual-stack listener reads `192.0.2.1:40000` here too, not
/// `[::ffff:192.0.2.1]:40000`.
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
    /// Creates a new `CorkGuard` that sets `TCP_CORK` on the given stream.
    fn new(stream: &'a TcpStream) -> std::io::Result<Self> {
        Self::set_tcp_cork(stream, true)?;
        Ok(Self(stream))
    }

    /// Creates a new `CorkGuard` that sets `TCP_CORK` on the given stream, if possible.
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

    fn set_tcp_cork(stream: &TcpStream, cork: bool) -> std::io::Result<()> {
        let val: nix::libc::c_int = cork.into();
        static_assert!(size_of::<nix::libc::c_int>() == 4);

        // TODO: refactor once https://github.com/nix-rust/nix/pull/2769 is merged
        // SAFETY: stream.as_raw_fd() is a valid socket fd; val is a stack-local c_int.
        let ret = unsafe {
            nix::libc::setsockopt(
                stream.as_raw_fd(),
                nix::libc::IPPROTO_TCP,
                nix::libc::TCP_CORK,
                std::ptr::from_ref::<nix::libc::c_int>(&val).cast(),
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "size_of c_int (4) always fits in socklen_t (u32)"
                )]
                {
                    size_of_val(&val) as nix::libc::socklen_t
                },
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl Drop for CorkGuard<'_> {
    fn drop(&mut self) {
        let stream = self.0;

        if let Err(err) = Self::set_tcp_cork(stream, false) {
            warn!(
                "Failed to uncork TCP socket from {} to {}; leaving the socket corked:  {}",
                Endpoint(stream.local_addr()),
                Endpoint(stream.peer_addr()),
                ErrorReport(&err)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// An IPv4 peer of the dual-stack listener renders as IPv4, like every
    /// other log line names that client; a real IPv6 peer stays bracketed.
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
