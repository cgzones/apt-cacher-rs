use std::{borrow::Cow, io::ErrorKind};

use http::{HeaderName, StatusCode};
use tokio::net::TcpStream;

use crate::{
    Never, global_config,
    humanfmt::HumanFmt,
    metrics,
    response_head::{ResponseHead, ResponseKind, WireBody, retry_after_secs},
};

/// Represents the action to take after sending a response.
#[derive(Copy, Clone)]
pub(crate) enum ConnectionAction {
    Close,
    KeepAlive,
}

impl std::fmt::Display for ConnectionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Close => "close",
            Self::KeepAlive => "keep-alive",
        })
    }
}

/// Represents the version of the HTTP protocol used in a connection.
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum ConnectionVersion {
    Http10,
    Http11,
}

/// Distinguishes header-only writes from body-payload writes for timeout
/// metric attribution in [`write_all_to_stream`].
#[derive(Copy, Clone)]
pub(crate) enum WritePhase {
    Header,
    Body,
}

impl std::fmt::Display for ConnectionVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        })
    }
}

/// Find the end of the HTTP request header block, returning the index just
/// past the terminating empty line.
///
/// Recognizes both the canonical `CRLF` line terminator and a lone `LF`
/// (RFC 9112 §2.2 permits a recipient to treat a bare LF as a line
/// terminator). This matches `httparse`'s lenient parsing, so the index
/// returned here agrees with the byte count `httparse` consumes for the same
/// request — keeping the sendfile read/advance boundary in lockstep with the
/// parser (and with the hyper backend, which parses via the same `httparse`).
/// A CRLF-only scan desyncs on a bare-LF-terminated pipelined request,
/// advancing past the *following* request and dropping it.
#[must_use]
#[inline]
pub(crate) fn find_header_end(buf: &[u8]) -> Option<usize> {
    // The header block ends at the first empty line. Every header line ends in
    // LF (optionally preceded by CR), so an empty line begins right after some
    // LF: either LF LF (bare-LF empty line) or LF CR LF. Do NOT simplify this
    // to a `\r\n\r\n` search: httparse accepts bare LF, and a CRLF-only scan
    // desyncs the sendfile keep-alive request boundary against the parser,
    // dropping the next pipelined request.
    for (i, &b) in buf.iter().enumerate() {
        if b != b'\n' {
            continue;
        }
        match buf.get(i + 1) {
            Some(b'\n') => return Some(i + 2),
            Some(b'\r') if buf.get(i + 2) == Some(&b'\n') => return Some(i + 3),
            _ => {}
        }
    }
    None
}

/// Find a header value by name (case-insensitive).
#[must_use]
pub(crate) fn find_header<'a>(
    headers: &[httparse::Header<'a>],
    header: &'static HeaderName,
) -> Option<&'a str> {
    let name: &'static str = header.as_str();

    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
}

/// Renders `Name: value\r\n` when `value` is `Some`, or nothing when `None`,
/// writing straight into the formatter.  Lets a response template keep an
/// optional header inline (`{opt_header}`) without a throwaway per-header
/// `String` allocation on the hot serve path.
pub(crate) struct OptHeader<T: std::fmt::Display>(pub(crate) &'static str, pub(crate) Option<T>);

impl<T: std::fmt::Display> std::fmt::Display for OptHeader<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(name, value) = self;
        match value {
            Some(value) => write!(f, "{name}: {value}\r\n"),
            None => Ok(()),
        }
    }
}

/// Write a 304 Not Modified response to the stream.
///
/// Times out after the configured HTTP timeout.
pub(crate) async fn write_304_response(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    last_modified_str: &str,
    age: u32,
    etag: Option<&str>,
) -> std::io::Result<()> {
    // No `Content-Length`: RFC 9110 section 8.6 allows it on a 304 only when
    // it equals the 200 representation's length, which `0` never does.
    // `Accept-Ranges` is advertised on the representation-bearing responses
    // only, matching hyper's 304.
    let head = ResponseHead {
        last_modified: Some(last_modified_str),
        etag,
        age: Some(age),
        ..ResponseHead::bare(StatusCode::NOT_MODIFIED, ResponseKind::Success)
    };
    head.write_to(stream, conn_version, conn_action, WireBody::None)
        .await
}

/// Write a 416 Range Not Satisfiable response to the stream.
///
/// Times out after the configured HTTP timeout.
pub(crate) async fn write_416_response(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    file_size: u64,
) -> std::io::Result<()> {
    // An `Error` head like hyper's 416 (proxy-generated rejection, carries
    // `Server:`). `Content-Length: 0` frames the empty body for keep-alive;
    // hyper emits the same automatically for its empty body.
    let head = ResponseHead {
        content_length: Some(0),
        content_range: Some(ResponseHead::unsatisfied_range(file_size)),
        ..ResponseHead::bare(StatusCode::RANGE_NOT_SATISFIABLE, ResponseKind::Error)
    };
    head.write_to(stream, conn_version, conn_action, WireBody::None)
        .await
}

/// Write an error response to the stream.
///
/// Times out after the configured HTTP timeout.
pub(crate) async fn write_invalid_response(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    status: StatusCode,
    msg: &'static str,
    retry_after: Option<std::time::Duration>,
) -> std::io::Result<()> {
    let head = ResponseHead {
        content_length: Some(msg.len() as u64),
        retry_after: retry_after.map(retry_after_secs),
        ..ResponseHead::error(status)
    };
    head.write_to(stream, conn_version, conn_action, WireBody::Inline(msg))
        .await
}

pub(crate) struct ResponseHeaders<'a> {
    pub(crate) conn_version: ConnectionVersion,
    pub(crate) status: StatusCode,
    pub(crate) conn_action: ConnectionAction,
    pub(crate) content_length: u64,
    pub(crate) content_type: &'static str,
    pub(crate) last_modified_str: &'a str,
    pub(crate) age: u32,
    pub(crate) content_range: Option<&'a str>,
    pub(crate) etag: Option<&'a str>,
}

/// Write HTTP response headers for a file response whose body follows via
/// `sendfile(2)`/`splice(2)`.
///
/// Times out after the configured HTTP timeout.
pub(crate) async fn write_response_headers(
    stream: &TcpStream,
    headers: ResponseHeaders<'_>,
) -> std::io::Result<()> {
    let ResponseHeaders {
        conn_version,
        status,
        conn_action,
        content_length,
        content_type,
        last_modified_str,
        age,
        content_range,
        etag,
    } = headers;
    let head = ResponseHead {
        content_length: Some(content_length),
        content_type: Some(content_type),
        accept_ranges: true,
        last_modified: Some(last_modified_str),
        etag,
        age: Some(age),
        content_range: content_range.map(Cow::Borrowed),
        ..ResponseHead::bare(status, ResponseKind::Success)
    };
    head.write_to(stream, conn_version, conn_action, WireBody::Follows)
        .await
}

/// Which syscall the shared write loop issues, and which timeout counter its
/// deadline bumps.
#[derive(Copy, Clone)]
enum WriteMode {
    /// `write(2)`, through tokio's `try_write`.
    Plain(WritePhase),
    /// `send(2)` with `MSG_MORE`; see [`write_all_to_stream_msg_more`].
    MsgMore,
}

/// Write every byte of `data`, handling partial writes, `EAGAIN`/`EINTR` and
/// the configured HTTP timeout.  The one loop behind
/// [`write_all_to_stream`] and [`write_all_to_stream_msg_more`]: they differ
/// only in the syscall and the timeout counter.
async fn write_all(stream: &TcpStream, mut data: &[u8], mode: WriteMode) -> std::io::Result<()> {
    use std::os::fd::AsRawFd as _;

    use nix::sys::socket::{MsgFlags, send};

    let http_timeout = global_config().http_timeout;
    let deadline = tokio::time::sleep(http_timeout);
    tokio::pin!(deadline);

    while !data.is_empty() {
        tokio::select! {
            biased;
            ready = stream.writable() => {
                ready?;
                let result = match mode {
                    WriteMode::Plain(_) => stream.try_write(data),
                    // `try_io` keeps tokio's readiness cache honest: a raw
                    // send(2) EAGAIN is invisible to it otherwise.
                    WriteMode::MsgMore => stream.try_io(tokio::io::Interest::WRITABLE, || {
                        // nix's MsgFlags does not re-export MSG_MORE; build the
                        // flag set from the libc constants it wraps.
                        let flags = MsgFlags::from_bits_retain(
                            nix::libc::MSG_MORE | nix::libc::MSG_DONTWAIT,
                        );
                        send(stream.as_raw_fd(), data, flags).map_err(std::io::Error::from)
                    }),
                };
                let _: Never = match result {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            ErrorKind::WriteZero,
                            "failed to write to TCP stream",
                        ));
                    }
                    Ok(n) => {
                        data = &data[n..];
                        continue;
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => {
                        continue;
                    }
                    Err(err) => return Err(err),
                };
            }
            () = &mut deadline => {
                match mode {
                    WriteMode::Plain(WritePhase::Body) => {
                        metrics::HTTP_TIMEOUT_CLIENT_BODY.increment();
                    }
                    WriteMode::Plain(WritePhase::Header) | WriteMode::MsgMore => {
                        metrics::HTTP_TIMEOUT_CLIENT_HEADER_WRITE.increment();
                    }
                }
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "TCP stream write operation timed out after {}",
                        HumanFmt::Time(http_timeout)
                    ),
                ));
            }
        }
    }

    Ok(())
}

/// Like [`write_all_to_stream`] with `WritePhase::Header`, but issues the
/// bytes via `send(2)` with `MSG_MORE`: the kernel holds the trailing
/// partial segment until the body written right after completes it — the
/// same header+body coalescing `TCP_CORK` gave, without the per-response
/// setsockopt on/off pair.
///
/// Only correct when body bytes follow immediately on the same socket and
/// the body write does *not* carry the flag (sendfile(2) does not), so the
/// body tail flushes without an uncork.
pub(crate) async fn write_all_to_stream_msg_more(
    stream: &TcpStream,
    data: &[u8],
) -> std::io::Result<()> {
    write_all(stream, data, WriteMode::MsgMore).await
}

/// Write all bytes to the TCP stream, handling partial writes.
///
/// `phase` selects which timeout counter to bump if the configured HTTP
/// timeout fires (`HTTP_TIMEOUT_CLIENT_HEADER_WRITE` for headers, control
/// frames, and small fixed responses; `HTTP_TIMEOUT_CLIENT_BODY` for
/// response-body bytes).
pub(crate) async fn write_all_to_stream(
    stream: &TcpStream,
    data: &[u8],
    phase: WritePhase,
) -> std::io::Result<()> {
    write_all(stream, data, WriteMode::Plain(phase)).await
}

#[cfg(test)]
mod tests {
    use http::header::{HOST, IF_MODIFIED_SINCE, RANGE};

    use super::*;

    #[test]
    fn test_find_header_end() {
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Some(37)
        );
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nHost: example.com\r\n"),
            None
        );
        assert_eq!(find_header_end(b"GET /"), None);
        assert_eq!(find_header_end(b"\r\n\r\n"), Some(4));
        // Bare-LF line terminators (RFC 9112 §2.2), as httparse accepts.
        assert_eq!(find_header_end(b"GET / HTTP/1.1\nHost: x\n\n"), Some(24));
        assert_eq!(find_header_end(b"\n\n"), Some(2));
        // Mixed: LF-terminated header line then a CRLF empty line.
        assert_eq!(find_header_end(b"GET / HTTP/1.1\nHost: x\n\r\n"), Some(25));
        // Pipelined bare-LF request A followed by request B: the returned
        // index must be the END OF A, not A+B, or B gets dropped.
        assert_eq!(
            find_header_end(b"GET /a HTTP/1.1\nHost: x\n\nGET /b HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(25)
        );
    }

    #[test]
    fn test_find_header() {
        let headers = [
            httparse::Header {
                name: "Host",
                value: b"example.com",
            },
            httparse::Header {
                name: "Range",
                value: b"bytes=0-100",
            },
        ];
        assert_eq!(find_header(&headers, &HOST), Some("example.com"));
        assert_eq!(find_header(&headers, &RANGE), Some("bytes=0-100"));
        assert_eq!(find_header(&headers, &IF_MODIFIED_SINCE), None);
    }
}
