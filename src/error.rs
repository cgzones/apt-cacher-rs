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

/// Returns `true` when `err` indicates the peer terminated the connection
/// (by reset, abort, half-close, or EOF). Used to demote routine "client
/// went away" log lines from warn to info, since they are not actionable
/// for the operator.
///
/// `ErrorKind::TimedOut` is deliberately *not* included here: in this
/// codebase, `TimedOut` `io::Error`s overwhelmingly originate from the
/// proxy's own decisions — `wait_socket_rated` HTTP per-op timeouts and
/// `rate_checked_body` rate-stalls — which already bump dedicated
/// `HTTP_TIMEOUT_*` counters at construction. Folding them into
/// "peer disconnect" was double-attributing them to
/// `CLIENT_DISCONNECTED_MID_BODY`. The rare OS-level `ETIMEDOUT`
/// (TCP keepalive / `TCP_USER_TIMEOUT`) is the only remaining source and
/// is acceptable to log as a warn-level timeout rather than an
/// info-level "peer disconnect" — the wording stays accurate either way.
///
/// Call sites that want to demote a `TimedOut` to a different severity
/// (e.g. the header-read idle-timeout debug path, or the splice
/// boundary-chunk demote-on-stall path) MUST add an explicit
/// `err.kind() == ErrorKind::TimedOut` branch before this check.
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

/// Whether any error in `err`'s `source()` chain is a `TimedOut` `io::Error`.
/// Hyper wraps the connector's timeout several layers deep; this is what the
/// hyper backend's 502/504 split reads.
#[cfg(feature = "hyper")]
#[must_use]
pub(crate) fn is_io_timed_out_in_chain(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::TimedOut
        {
            return true;
        }
        cur = e.source();
    }
    false
}

#[cfg(feature = "splice")]
pub(crate) fn errno_to_io_error(errno: nix::errno::Errno, msg: &'static str) -> std::io::Error {
    // `Display` prints only the context message; the errno text lives on the
    // inner io::Error exposed via `source()` and is appended by `ErrorReport`.
    // Embedding it here would duplicate the errno string because
    // `io::Error::new(_, custom)` makes the outer io::Error's `source()`
    // delegate to this struct's source, so `ErrorReport` would walk through
    // this struct to the inner io::Error and print the errno a second time.
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
        // ENOENT is portable enough to assert a stable substring on.
        let err = errno_to_io_error(nix::errno::Errno::ENOENT, "sendfile failed");
        let report = format!("{}", ErrorReport(&err));

        // Expected shape: "<msg>:  <errno_text>" - the message once, the
        // errno text once, separated by the two-space ErrorReport joiner.
        assert!(
            report.starts_with("sendfile failed:  "),
            "unexpected prefix: {report}"
        );
        // The errno string must appear exactly once.
        let needle = "(os error";
        assert_eq!(
            report.matches(needle).count(),
            1,
            "errno text duplicated in report: {report}"
        );
        // And the message must not be repeated either.
        assert_eq!(
            report.matches("sendfile failed").count(),
            1,
            "context message duplicated in report: {report}"
        );
    }

    #[test]
    fn upstream_fetch_error_display_is_the_reason() {
        let err = UpstreamFetchError {
            reason: "client error (SendRequest):  connection error:  timed out".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "client error (SendRequest):  connection error:  timed out"
        );
    }
}
