//! A client stream wrapper bounding how long a write may make no progress:
//! [`WriteStallTimeout`].
//!
//! The sendfile and splice writers enforce `http_timeout` on every client
//! write themselves (`wait_socket_rated`). Two client paths write through a
//! generic `AsyncWrite` instead and get the same bound from this wrapper:
//! every hyper-served connection (`hyper_conn`), whose tunnels it keeps
//! across the upgrade, and the sendfile backend's CONNECT tunnel relay
//! (`sendfile_conn::run_connect_tunnel`).

use std::{future::Future as _, pin::Pin, task::Poll, time::Duration};

use crate::humanfmt::HumanFmt;

/// Why a [`WriteStallTimeout`] write failed: the client accepted no bytes
/// for `timeout`. Carried inside the `TimedOut` `io::Error`, so a caller
/// can tell a stalled client from a socket-level timeout
/// ([`is_client_write_stall`]).
#[derive(Debug)]
pub(crate) struct ClientWriteStalled {
    timeout: Duration,
}

impl std::fmt::Display for ClientWriteStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { timeout } = self;
        write!(
            f,
            "client accepted no response bytes for {}",
            HumanFmt::Time(*timeout)
        )
    }
}

impl std::error::Error for ClientWriteStalled {}

/// Whether `err` is a [`WriteStallTimeout`] firing.
#[must_use]
pub(crate) fn is_client_write_stall(err: &std::io::Error) -> bool {
    err.get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<ClientWriteStalled>)
}

/// Client stream wrapper failing a write that makes no progress for
/// `timeout` (`http_timeout`) with `TimedOut` ([`ClientWriteStalled`]), the
/// bound the sendfile backend's rated writes enforce.
///
/// hyper has no write timeout of its own, and once its write queue is full
/// it only flushes and stops polling the response body, so the body-level
/// rate check never runs: a client that stops reading would otherwise hold
/// the connection, its connection slot and whatever the body owns (a
/// `max_passthrough_relays` slot, an upstream connection, a feeder's queued
/// buffers) for good. A tunnel relay only watches for idleness in both
/// directions, which a client that keeps sending while it stops reading
/// never trips. The deadline is armed by the first write that finds the
/// socket full and disarmed by the next one that makes progress.
pub(crate) struct WriteStallTimeout<S> {
    inner: S,
    timeout: Duration,
    /// Allocated on the first stall, reset on every later one.
    stall: Option<Pin<Box<tokio::time::Sleep>>>,
    armed: bool,
}

impl<S> WriteStallTimeout<S> {
    pub(crate) const fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            stall: None,
            armed: false,
        }
    }

    /// The stream back, for the connection a handoff returns.
    #[cfg(all(feature = "hyper", feature = "sendfile"))]
    pub(crate) fn into_inner(self) -> S {
        let Self {
            inner,
            timeout: _,
            stall: _,
            armed: _,
        } = self;
        inner
    }

    /// Account one write that returned `Pending`: arm the deadline if it is
    /// not armed yet, and fail once it has passed.
    fn poll_stall<T>(&mut self, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<T>> {
        let deadline = || tokio::time::Instant::now() + self.timeout;
        let stall = match &mut self.stall {
            Some(stall) => {
                if !self.armed {
                    stall.as_mut().reset(deadline());
                }
                stall
            }
            None => self
                .stall
                .insert(Box::pin(tokio::time::sleep_until(deadline()))),
        };
        self.armed = true;
        match stall.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.armed = false;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    ClientWriteStalled {
                        timeout: self.timeout,
                    },
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Pass a write's outcome through, accounting a stall.
    fn account<T>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        polled: Poll<std::io::Result<T>>,
    ) -> Poll<std::io::Result<T>> {
        if polled.is_pending() {
            self.poll_stall(cx)
        } else {
            self.armed = false;
            polled
        }
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WriteStallTimeout<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WriteStallTimeout<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.account(cx, polled)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.account(cx, polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.account(cx, polled)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::{WriteStallTimeout, is_client_write_stall};

    #[tokio::test]
    async fn a_write_the_client_never_reads_times_out() {
        let (_client, server) = tokio::io::duplex(64);
        let mut server = WriteStallTimeout::new(server, Duration::from_millis(50));
        let err = server.write_all(&[0; 1024]).await.expect_err("stalls");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(is_client_write_stall(&err));
        assert!(!is_client_write_stall(&std::io::Error::from(
            std::io::ErrorKind::TimedOut
        )));
    }

    /// Every write that makes progress disarms the deadline: a slow reader
    /// taking far longer than the timeout in total is not cut off.
    #[tokio::test]
    async fn a_slowly_reading_client_is_not_timed_out() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut server = WriteStallTimeout::new(server, Duration::from_millis(200));
        let reader = tokio::spawn(async move {
            let mut buf = [0; 16];
            let mut total = 0;
            while total < 1024 {
                tokio::time::sleep(Duration::from_millis(5)).await;
                total += client.read(&mut buf).await.expect("read");
            }
            total
        });
        server
            .write_all(&[0; 1024])
            .await
            .expect("progress keeps the write alive");
        assert_eq!(reader.await.expect("reader"), 1024);
    }
}
