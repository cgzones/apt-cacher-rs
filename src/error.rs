use std::fmt::Display;

#[must_use]
pub(crate) struct ErrorReport<'a, E>(pub(crate) &'a E)
where
    E: ?Sized + std::error::Error;

impl<E> Display for ErrorReport<'_, E>
where
    E: ?Sized + std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;

        let mut cause = self.0.source();
        while let Some(c) = cause {
            write!(f, ":  {c}")?;
            cause = c.source();
        }

        Ok(())
    }
}

/// Reason an upstream fetch failed, captured at the point the proxy synthesises a
/// `502 Bad Gateway`. Attached to that response as an `http::Extensions` value so an
/// internal caller (cleanup) can recover the real transport error instead of seeing
/// only the laundered status code. The wire response never carries it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub(crate) struct UpstreamFetchError {
    /// Full `source()`-chain rendering of the transport error (e.g. `... timed out`).
    pub(crate) reason: String,
}

/// Whether the peer terminated the connection (reset, abort, half-close or
/// EOF): routine "client went away" events, logged at info rather than warn.
///
/// `ErrorKind::TimedOut` is deliberately *not* included: such errors
/// overwhelmingly come from the proxy's own timeouts and rate-stalls, which
/// already bump dedicated `HTTP_TIMEOUT_*` counters; including them would
/// double-attribute them to `CLIENT_DISCONNECTED_MID_BODY`. A call site that
/// wants a different severity for a `TimedOut` must check for it first.
#[must_use]
pub(crate) fn is_peer_disconnect(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

/// Whether a failed client write is an expected end of the exchange: the
/// peer hung up ([`is_peer_disconnect`]) or stalled past its deadline
/// (`TimedOut`, already counted by an `HTTP_TIMEOUT_*` counter). Logged at
/// INFO; anything else is WARN (see `docs/logging.md`).
#[cfg(feature = "sendfile")]
#[must_use]
pub(crate) fn is_expected_client_end(err: &std::io::Error) -> bool {
    is_peer_disconnect(err) || err.kind() == std::io::ErrorKind::TimedOut
}

/// Whether any error in `err`'s `source()` chain is a `TimedOut` `io::Error`.
/// Hyper wraps the connector's timeout several layers deep.
#[must_use]
pub(crate) fn is_io_timed_out_in_chain(err: &(dyn std::error::Error + 'static)) -> bool {
    chain(err)
        .filter_map(|e| e.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::TimedOut)
}

/// `err` and every error below it in its `source()` chain, outermost first.
pub(crate) fn chain<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(err), |e| e.source())
}

/// Whether `err`'s chain holds a TLS client's rejection of the upstream's
/// certificate (untrusted issuer, expired, wrong name, none presented), as
/// opposed to a TLS failure that proves nothing about the peer (refused
/// connection, timeout, no TLS on the port). Auto mode may fall back to
/// plain HTTP after the latter, never after a rejection: presenting a bad
/// certificate is what an interceptor does. Decided on the TLS library's
/// typed error, never its message.
///
/// An `io::Error`'s `source()` is its wrapped error's *source*, skipping the
/// wrapped error itself (`tokio-rustls` wraps the `rustls::Error` that way),
/// so the walk steps into an `io::Error` through `get_ref`.
#[must_use]
pub(crate) fn is_tls_certificate_rejection(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if is_certificate_rejection_error(e) {
            return true;
        }
        cur = match e
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            Some(inner) => Some(inner),
            None => e.source(),
        };
    }
    false
}

#[cfg(feature = "tls_rustls")]
fn is_certificate_rejection_error(err: &(dyn std::error::Error + 'static)) -> bool {
    matches!(
        err.downcast_ref::<rustls::Error>(),
        Some(rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented)
    )
}

/// On Linux a native-tls handshake failure's source is OpenSSL's error
/// queue, where a failed chain verification is
/// `SSL_R_CERTIFICATE_VERIFY_FAILED`.
#[cfg(feature = "tls_hyper")]
fn is_certificate_rejection_error(err: &(dyn std::error::Error + 'static)) -> bool {
    // From OpenSSL's `err.h` and `sslerr.h`, which `openssl-sys` does not
    // bind; unchanged since OpenSSL 1.0 and identical in LibreSSL.
    const ERR_LIB_SSL: std::ffi::c_int = 20;
    const SSL_R_CERTIFICATE_VERIFY_FAILED: std::ffi::c_int = 134;
    err.downcast_ref::<openssl::error::ErrorStack>()
        .is_some_and(|stack| {
            stack.errors().iter().any(|e| {
                e.library_code() == ERR_LIB_SSL
                    && e.reason_code() == SSL_R_CERTIFICATE_VERIFY_FAILED
            })
        })
}

#[cfg(feature = "splice")]
pub(crate) fn errno_to_io_error(errno: nix::errno::Errno, msg: &'static str) -> std::io::Error {
    // `Display` prints only the context message: `ErrorReport` appends the
    // errno text from the inner io::Error it reaches via `source()`, so
    // embedding it here would print it twice.
    #[derive(Debug, thiserror::Error)]
    #[error("{msg}")]
    struct ErrnoIoError {
        msg: &'static str,
        source: std::io::Error,
    }

    let err = std::io::Error::from(errno);
    let kind = err.kind();
    std::io::Error::new(kind, ErrnoIoError { msg, source: err })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "splice")]
    #[test]
    fn errno_to_io_error_report_does_not_duplicate_errno_text() {
        let err = errno_to_io_error(nix::errno::Errno::ENOENT, "sendfile failed");
        let report = format!("{}", ErrorReport(&err));

        assert!(
            report.starts_with("sendfile failed:  "),
            "unexpected prefix: {report}"
        );
        let needle = "(os error";
        assert_eq!(
            report.matches(needle).count(),
            1,
            "errno text duplicated in report: {report}"
        );
        assert_eq!(
            report.matches("sendfile failed").count(),
            1,
            "context message duplicated in report: {report}"
        );
    }

    /// The wrapper keeps the errno's `ErrorKind` but not its `raw_os_error`;
    /// the errno itself lives on the inner `io::Error` reached via `source()`.
    #[cfg(feature = "splice")]
    #[test]
    fn errno_to_io_error_keeps_kind_and_moves_errno_to_source() {
        use std::error::Error as _;

        let err = errno_to_io_error(nix::errno::Errno::ENOENT, "open failed");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(err.raw_os_error(), None);

        let source = err.source().expect("the errno error is the source");
        let inner = source
            .downcast_ref::<std::io::Error>()
            .expect("the source is the errno io::Error");
        assert_eq!(inner.raw_os_error(), Some(nix::libc::ENOENT));
        assert_eq!(inner.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn is_peer_disconnect_excludes_timed_out() {
        use std::io::{Error, ErrorKind};

        assert!(!is_peer_disconnect(&Error::from(ErrorKind::TimedOut)));
        assert!(!is_peer_disconnect(&Error::from(ErrorKind::Other)));
        assert!(is_peer_disconnect(&Error::from(ErrorKind::BrokenPipe)));
        assert!(is_peer_disconnect(&Error::from(ErrorKind::UnexpectedEof)));
    }

    #[cfg(feature = "sendfile")]
    #[test]
    fn a_client_timeout_is_an_expected_end_like_a_hang_up() {
        use std::io::{Error, ErrorKind};

        assert!(is_expected_client_end(&Error::from(ErrorKind::TimedOut)));
        assert!(is_expected_client_end(&Error::from(ErrorKind::BrokenPipe)));
        assert!(is_expected_client_end(&Error::from(
            ErrorKind::ConnectionReset
        )));
        assert!(!is_expected_client_end(&Error::from(ErrorKind::Other)));
        assert!(!is_expected_client_end(&Error::from(ErrorKind::WriteZero)));
    }

    #[cfg(feature = "hyper")]
    #[test]
    fn is_io_timed_out_in_chain_walks_nested_sources() {
        #[derive(Debug, thiserror::Error)]
        #[error("outer")]
        struct Outer<E>(#[source] E);

        #[derive(Debug, thiserror::Error)]
        #[error("middle")]
        struct Middle<E>(#[source] E);

        #[derive(Debug, thiserror::Error)]
        #[error("leaf")]
        struct Leaf;

        let timed_out = Outer(Middle(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        assert!(is_io_timed_out_in_chain(&timed_out));

        let other_io = Outer(Middle(std::io::Error::from(std::io::ErrorKind::BrokenPipe)));
        assert!(!is_io_timed_out_in_chain(&other_io));

        let no_io = Outer(Middle(Leaf));
        assert!(!is_io_timed_out_in_chain(&no_io));
    }

    /// The shapes the connectors produce: `tokio-rustls` wraps the
    /// `rustls::Error` in an `io::Error` (whose `source()` skips it), and
    /// hyper boxes that again behind its own error.
    #[cfg(feature = "tls_rustls")]
    #[test]
    fn tls_certificate_rejection_is_found_through_io_error_wrappers() {
        use std::io::{Error, ErrorKind};

        #[derive(Debug, thiserror::Error)]
        #[error("connect")]
        struct Outer(#[source] Box<dyn std::error::Error + Send + Sync>);

        let rejected = || {
            Error::new(
                ErrorKind::InvalidData,
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
            )
        };
        assert!(is_tls_certificate_rejection(&rejected()));
        assert!(is_tls_certificate_rejection(&Outer(Box::new(rejected()))));
        assert!(is_tls_certificate_rejection(&Error::new(
            ErrorKind::InvalidData,
            rustls::Error::NoCertificatesPresented,
        )));

        // No TLS on the port: a protocol failure proving nothing about the
        // peer's identity, so Auto mode may still fall back.
        let not_tls = Error::new(
            ErrorKind::InvalidData,
            rustls::Error::InvalidMessage(rustls::InvalidMessage::InvalidContentType),
        );
        assert!(!is_tls_certificate_rejection(&not_tls));
        assert!(!is_tls_certificate_rejection(&Outer(Box::new(not_tls))));
        assert!(!is_tls_certificate_rejection(&Error::from(
            ErrorKind::ConnectionRefused
        )));
    }
}
