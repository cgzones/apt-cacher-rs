use std::io::ErrorKind;

use http::{HeaderName, StatusCode};
use log::trace;
use tokio::net::TcpStream;

use crate::{APP_NAME, APP_VIA, Never, global_config, http_range::format_http_date};

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

impl std::fmt::Display for ConnectionVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        })
    }
}

/// Check if the buffer contains the end of HTTP headers (\r\n\r\n) and return the index after the end.
#[must_use]
#[inline]
pub(crate) fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.array_windows()
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

/// Find a header value by name (case-insensitive).
#[must_use]
pub(crate) fn find_header<'a>(
    headers: &[httparse::Header<'a>],
    header: &HeaderName,
) -> Option<&'a str> {
    let name = header.as_str();

    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
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
    let date = format_http_date();

    let etag_header = match etag {
        Some(etag) => format!("ETag: {etag}\r\n"),
        None => String::new(),
    };

    let response = format!(
        "{conn_version} 304 Not Modified\r\n\
         Date: {date}\r\n\
         Via: {APP_VIA}\r\n\
         Connection: {conn_action}\r\n\
         Last-Modified: {last_modified_str}\r\n\
         Content-Length: 0\r\n\
         {etag_header}\
         Accept-Ranges: bytes\r\n\
         Age: {age}\r\n\
         \r\n"
    );
    trace!("Outgoing 304 response:\n{response}");
    write_all_to_stream(stream, response.as_bytes()).await
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
    let date = format_http_date();

    let response = format!(
        "{conn_version} 416 Range Not Satisfiable\r\n\
        Date: {date}\r\n\
        Via: {APP_VIA}\r\n\
        Connection: {conn_action}\r\n\
        Content-Length: 0\r\n\
        Content-Range: bytes */{file_size}\r\n\
        Accept-Ranges: bytes\r\n\
        \r\n"
    );
    trace!("Outgoing 416 response:\n{response}");
    write_all_to_stream(stream, response.as_bytes()).await
}

/// Write an error response to the stream.
///
/// Times out after the configured HTTP timeout.
pub(crate) async fn write_invalid_response(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    status: StatusCode,
    msg: &str,
) -> std::io::Result<()> {
    let date = format_http_date();
    let content_length = msg.len();

    let extra_headers = if status == StatusCode::METHOD_NOT_ALLOWED {
        "Allow: GET\r\n"
    } else {
        ""
    };

    let response = format!(
        "{conn_version} {status}\r\n\
         Server: {APP_NAME}\r\n\
         Date: {date}\r\n\
         Connection: {conn_action}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {content_length}\r\n\
         Accept-Ranges: bytes\r\n\
         {extra_headers}\
         \r\n\
         {msg}"
    );
    trace!("Outgoing error response:\n{response}");
    write_all_to_stream(stream, response.as_bytes()).await
}

pub(crate) struct ResponseHeaders<'a> {
    pub(crate) conn_version: ConnectionVersion,
    pub(crate) status: StatusCode,
    pub(crate) conn_action: ConnectionAction,
    pub(crate) content_length: u64,
    pub(crate) content_type: &'a str,
    pub(crate) last_modified_str: &'a str,
    pub(crate) age: u32,
    pub(crate) content_range: Option<&'a str>,
    pub(crate) etag: Option<&'a str>,
}

/// Write HTTP response headers for a file response.
///
/// Times out after the configured HTTP timeout.
pub(crate) async fn write_response_headers(
    stream: &TcpStream,
    headers: ResponseHeaders<'_>,
) -> std::io::Result<()> {
    let date = format_http_date();

    let etag_header = match headers.etag {
        Some(etag) => format!("ETag: {etag}\r\n"),
        None => String::new(),
    };

    let content_range_header = match headers.content_range {
        Some(cr) => format!("Content-Range: {cr}\r\n"),
        None => String::new(),
    };

    let response = format!(
        "{conn_version} {status}\r\n\
         Date: {date}\r\n\
         Via: {APP_VIA}\r\n\
         Connection: {conn_action}\r\n\
         Content-Length: {content_length}\r\n\
         Content-Type: {content_type}\r\n\
         {content_range_header}\
         Last-Modified: {last_modified_str}\r\n\
         {etag_header}\
         Accept-Ranges: bytes\r\n\
         Age: {age}\r\n\
         \r\n",
        conn_version = headers.conn_version,
        status = headers.status,
        conn_action = headers.conn_action,
        content_length = headers.content_length,
        content_type = headers.content_type,
        last_modified_str = headers.last_modified_str,
        age = headers.age,
    );

    trace!("Outgoing file response headers:\n{response}");
    write_all_to_stream(stream, response.as_bytes()).await
}

/// Write all bytes to the TCP stream, handling partial writes.
///
/// Times out after the configured HTTP timeout.
pub(crate) async fn write_all_to_stream(stream: &TcpStream, data: &[u8]) -> std::io::Result<()> {
    async fn inner(stream: &TcpStream, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            stream.writable().await?;

            let _: Never = match stream.try_write(data) {
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

        Ok(())
    }

    match tokio::time::timeout(global_config().http_timeout, inner(stream, data)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(tokio::time::error::Elapsed { .. }) => Err(std::io::Error::new(
            ErrorKind::TimedOut,
            "TCP stream write operation timed out",
        )),
    }
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
