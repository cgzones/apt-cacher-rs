use std::{io::ErrorKind, os::fd::AsRawFd as _};

use log::warn;
use tokio::net::TcpStream;

use crate::{static_assert, warn_once_or_debug};

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
            Err(err) if err.kind() == ErrorKind::Unsupported => {
                warn_once_or_debug!(
                    "Failed to cork TCP socket from {} to {}:  {err}",
                    stream
                        .local_addr()
                        .map_or_else(|_| String::from("<unknown>"), |a| a.to_string()),
                    stream
                        .peer_addr()
                        .map_or_else(|_| String::from("<unknown>"), |a| a.to_string())
                );

                None
            }
            Err(err) => {
                warn!(
                    "Failed to cork TCP socket from {} to {}:  {err}",
                    stream
                        .local_addr()
                        .map_or_else(|_| String::from("<unknown>"), |a| a.to_string()),
                    stream
                        .peer_addr()
                        .map_or_else(|_| String::from("<unknown>"), |a| a.to_string())
                );

                None
            }
        }
    }

    fn set_tcp_cork(stream: &TcpStream, cork: bool) -> std::io::Result<()> {
        let val: nix::libc::c_int = cork.into();
        static_assert!(std::mem::size_of::<nix::libc::c_int>() == 4);

        // TODO: refactor once https://github.com/nix-rust/nix/pull/2769 got merged
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
                    std::mem::size_of_val(&val) as nix::libc::socklen_t
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
                "Failed to uncork TCP socket from {} to {}:  {err}",
                stream
                    .local_addr()
                    .map_or_else(|_| String::from("<unknown>"), |a| a.to_string()),
                stream
                    .peer_addr()
                    .map_or_else(|_| String::from("<unknown>"), |a| a.to_string())
            );
        }
    }
}
