use std::fmt::Display;

use crate::{
    ClientInfo, ContentLength, channel_body::ChannelBodyError, deb_mirror::Mirror,
    rate_checker::InsufficientRate,
};

#[derive(Clone, Debug)]
pub(crate) struct MirrorDownloadRate {
    pub(crate) download_rate_err: InsufficientRate,
    pub(crate) mirror: Mirror,
    pub(crate) debname: String,
}

#[derive(Debug)]
pub(crate) enum ProxyCacheError {
    Io(std::io::Error),
    Hyper(hyper::Error),
    Sqlx(sqlx::Error),
    ClientDownloadRate {
        error: InsufficientRate,
        client: ClientInfo,
    },
    MirrorDownloadRate(MirrorDownloadRate),
    Memfd(memfd::Error),
    ContentTooLarge {
        announced: ContentLength,
        received: u64,
    },
}

impl std::fmt::Display for ProxyCacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{}", ErrorReport(e)),
            Self::Hyper(e) => write!(f, "{}", ErrorReport(e)),
            Self::Sqlx(e) => write!(f, "{}", ErrorReport(e)),
            Self::ClientDownloadRate { error, client } => {
                error.fmt_with_context(f, format_args!(" for client {client}"))
            }
            Self::MirrorDownloadRate(MirrorDownloadRate {
                download_rate_err,
                mirror,
                debname,
            }) => download_rate_err.fmt_with_context(
                f,
                format_args!(" for mirror {mirror} downloading file {debname}"),
            ),
            Self::Memfd(e) => write!(f, "{}", ErrorReport(e)),
            Self::ContentTooLarge {
                announced,
                received,
            } => {
                write!(
                    f,
                    "Upstream sent {received} bytes, exceeding the announced Content-Length of {announced}"
                )
            }
        }
    }
}

impl std::error::Error for ProxyCacheError {}

impl From<std::io::Error> for ProxyCacheError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<hyper::Error> for ProxyCacheError {
    fn from(value: hyper::Error) -> Self {
        Self::Hyper(value)
    }
}

impl From<sqlx::Error> for ProxyCacheError {
    fn from(value: sqlx::Error) -> Self {
        Self::Sqlx(value)
    }
}

impl From<ChannelBodyError> for ProxyCacheError {
    fn from(value: ChannelBodyError) -> Self {
        match value {
            ChannelBodyError::MirrorDownloadRate(mdr) => Self::MirrorDownloadRate(mdr),
        }
    }
}

impl From<std::io::Error> for Box<ProxyCacheError> {
    fn from(value: std::io::Error) -> Self {
        Self::new(ProxyCacheError::Io(value))
    }
}

impl From<hyper::Error> for Box<ProxyCacheError> {
    fn from(value: hyper::Error) -> Self {
        Self::new(ProxyCacheError::Hyper(value))
    }
}

#[must_use]
pub(crate) struct ErrorReport<'a, E>(pub(crate) &'a E)
where
    E: std::error::Error;

impl<E> Display for ErrorReport<'_, E>
where
    E: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;

        let mut cause: &dyn std::error::Error = self.0;

        while let Some(c) = cause.source() {
            write!(f, ":  {c}")?;
            cause = c;
        }

        Ok(())
    }
}

/// Reason an upstream fetch failed, captured at the point the proxy synthesises a
/// `502 Bad Gateway`. Attached to that response as an `http::Extensions` value so an
/// internal caller (cleanup) can recover the real transport error instead of seeing
/// only the laundered status code. The wire response never carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpstreamFetchError {
    /// Full `source()`-chain rendering of the transport error (e.g. `... timed out`).
    pub(crate) reason: String,
}

impl Display for UpstreamFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

#[cfg(feature = "sendfile")]
pub(crate) fn errno_to_io_error(errno: nix::errno::Errno, msg: &'static str) -> std::io::Error {
    #[derive(Debug)]
    struct ErrnoIoError {
        msg: &'static str,
        source: std::io::Error,
    }
    impl Display for ErrnoIoError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // Print only the context message; the errno text lives on the
            // inner io::Error exposed via `source()` and is appended by
            // `ErrorReport`. Embedding it here would duplicate the errno
            // string because `io::Error::new(_, custom)` makes the outer
            // io::Error's `source()` delegate to this struct's source, so
            // `ErrorReport` would walk through this struct to the inner
            // io::Error and print the errno a second time.
            f.write_str(self.msg)
        }
    }
    impl std::error::Error for ErrnoIoError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.source)
        }
    }

    let err = std::io::Error::from(errno);
    let kind = err.kind();
    std::io::Error::new(kind, ErrnoIoError { msg, source: err })
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "sendfile")]
    use super::*;

    #[cfg(feature = "sendfile")]
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
        let err = super::UpstreamFetchError {
            reason: "client error (SendRequest):  connection error:  timed out".to_owned(),
        };
        assert_eq!(
            err.to_string(),
            "client error (SendRequest):  connection error:  timed out"
        );
    }
}
