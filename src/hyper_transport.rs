//! Preserve the provenance of upstream I/O errors before Hyper erases it.
//!
//! Hyper's HTTP/1 body decoder and TLS reads both return `io::Error`s with
//! kinds such as `InvalidData`. Wrap the transport outside TLS and the
//! timeout stream, so `hyper_conn::upstream_body_error` can recognize a
//! decoder error without guessing from its message. Successful I/O is
//! forwarded unchanged; only errors allocate a wrapper.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{TryFutureExt as _, future::MapOk};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection};
use tower_service::Service;

#[derive(Clone, Copy, Debug)]
pub(crate) struct TransportConnector<C>(C);

impl<C> TransportConnector<C> {
    pub(crate) const fn new(connector: C) -> Self {
        Self(connector)
    }
}

impl<C: Service<http::Uri>> Service<http::Uri> for TransportConnector<C> {
    type Response = TransportIo<C::Response>;
    type Error = C::Error;
    type Future = MapOk<C::Future, fn(C::Response) -> Self::Response>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, req: http::Uri) -> Self::Future {
        let wrap: fn(C::Response) -> Self::Response = TransportIo::new;
        self.0.call(req).map_ok(wrap)
    }
}

#[derive(Debug)]
pub(crate) struct TransportIo<T> {
    inner: T,
}

impl<T> TransportIo<T> {
    pub(crate) const fn new(inner: T) -> Self {
        Self { inner }
    }
}

impl<T: Connection> Connection for TransportIo<T> {
    fn connected(&self) -> Connected {
        self.inner.connected()
    }
}

impl<T: Read + Unpin> Read for TransportIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf).map_err(tag)
    }
}

impl<T: Write + Unpin> Write for TransportIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf).map_err(tag)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(tag)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx).map_err(tag)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner)
            .poll_write_vectored(cx, bufs)
            .map_err(tag)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("upstream transport I/O failed")]
struct TransportError(#[source] io::Error);

fn tag(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), TransportError(error))
}

/// Check the private marker, not the I/O kind or error wording. `get_ref`
/// sees the wrapper itself; `source` can skip it to the original error.
pub(crate) fn is_transport_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(<dyn std::error::Error + Send + Sync>::is::<TransportError>)
}

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

    #[test]
    fn a_transport_marker_preserves_the_cause_without_repeating_it() {
        let original = io::Error::new(io::ErrorKind::InvalidData, "injected TLS read failure");
        assert!(!is_transport_error(&original));
        let tagged = tag(original);
        assert!(is_transport_error(&tagged));
        assert_eq!(tagged.kind(), io::ErrorKind::InvalidData);
        let source = tagged
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .expect("original I/O error remains in the chain");
        assert_eq!(source.kind(), io::ErrorKind::InvalidData);
        assert_eq!(source.to_string(), "injected TLS read failure");
        assert_eq!(
            crate::error::ErrorReport(&tagged).to_string(),
            "upstream transport I/O failed:  injected TLS read failure"
        );
    }
}
