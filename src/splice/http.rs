//! HTTP/1.1 wire handling between the splice proxy and upstream:
//! [`format_http_request`]/[`send_and_read_headers`] on the request side,
//! [`parse_upstream_response`] into [`UpstreamResponse`] on the response
//! side, and the body relays hanging off the shared [`BodyFraming`]
//! (`relay_to_client`, `read_to_vec`) that stream or buffer a body according
//! to its framing.
//! [`ChunkDecoder`] is the one chunked transfer-coding state machine;
//! [`forward_upstream_chunked_body`] and [`read_dechunk_body_to_vec`] are its
//! I/O wrappers. A relayed chunked body reaches an HTTP/1.1 client in its raw
//! encoding but an HTTP/1.0 client de-chunked and close-delimited
//! ([`ChunkedRelay`]).
//!
//! Consumers: `acquire` (request/parse), the drive in
//! `mod.rs` and `volatile`/`simple_proxy`/`cleanup_bridge` (framing relays).

use std::{
    future::Future,
    io::ErrorKind,
    num::{ParseIntError, Saturating},
    ops::Range,
    time::Duration,
};

use bytes::BytesMut;
use http::{
    StatusCode,
    header::{
        CONNECTION, CONTENT_RANGE, CONTENT_TYPE, ETAG, LAST_MODIFIED, LOCATION, TRANSFER_ENCODING,
    },
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

use crate::cache_layout::ConnectionDetails;
use crate::http_helpers::{
    ConnectionAction, ConnectionVersion, OptHeader, find_header, find_header_end,
};
use crate::http_range::parse_content_range;
use crate::humanfmt::HumanFmt;
use crate::limits::{MAX_UPSTREAM_HEADER_SIZE, MAX_UPSTREAM_HEADERS};
use crate::precise_instant::PreciseInstant;
use crate::rate_checker::RateChecker;
use crate::sendfile_conn::write_all_to_stream_rated;
use crate::transfer_error::{ClientError, DeliveryFailure, UpstreamError};
use crate::upstream_head::{
    BodyFraming, RejectReason, UpstreamHead, resolve_body_framing, well_formed_etag,
};
use crate::{
    build_info::{APP_USER_AGENT, APP_VIA},
    cache_metadata::{self, InvalidValidator},
    global_config, metrics, warn_once_or_info,
};

use super::{
    VolatileCondHeaders,
    upstream::{ResponseBody, TLS_READ_BUF_SIZE, UpstreamConn},
};

/// Maximum body worth draining solely to reuse an upstream connection.
pub(super) const MAX_ERROR_BODY_DRAIN: usize = 64 * 1024;

/// A failed request head, classified where the failure originated. TLS
/// reads can report `InvalidData` too, so an I/O error's kind cannot tell
/// a broken transport from a malformed HTTP response.
///
/// The protocol arm carries a reason, not an error: nothing below the HTTP
/// layer failed, so there is no `io::Error` to preserve as a source.
#[derive(Debug)]
pub(super) enum HeadError {
    Transport(std::io::Error),
    Protocol(String),
}

impl HeadError {
    pub(super) fn into_upstream(self) -> UpstreamError {
        match self {
            Self::Transport(err) => {
                UpstreamError::head_io("upstream request or response headers", err)
            }
            Self::Protocol(reason) => UpstreamError::head_protocol(reason),
        }
    }
}

/// Format an HTTP GET request for the upstream mirror. Always keep-alive:
/// whether the connection is pooled afterwards is the response's say
/// (`UpstreamResponse::connection_close`). `Via` names this proxy, so a
/// request looping back into it is refused by `preflight_via`.
/// `Accept-Encoding: identity`: a request without the field accepts any
/// content coding (RFC 9110 §12.5.3), and a coded body would be cached,
/// and relayed, without its `Content-Encoding`.
pub(super) fn format_http_request(
    path: &str,
    host_authority: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> String {
    let range_header = if resume_offset > 0 {
        format!(
            "Range: bytes={resume_offset}-\r\n{}",
            OptHeader("If-Range", resume_if_range)
        )
    } else {
        String::new()
    };

    let volatile_headers = match volatile_cond {
        Some(vc) => format!(
            "{}Cache-Control: max-age=300\r\n{}",
            OptHeader("If-Modified-Since", vc.if_modified_since.as_deref()),
            OptHeader("If-None-Match", vc.if_none_match.as_deref())
        ),
        None => String::new(),
    };

    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_authority}\r\n\
         User-Agent: {APP_USER_AGENT}\r\n\
         Via: {APP_VIA}\r\n\
         Accept-Encoding: identity\r\n\
         Connection: keep-alive\r\n\
         {range_header}\
         {volatile_headers}\
         \r\n"
    )
}

/// Send an HTTP GET request to the upstream stream (generic over TCP/TLS).
///
/// Times out after the configured HTTP timeout.
async fn send_upstream_request(
    upstream: &mut UpstreamConn,
    host_authority: &str,
    path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> std::io::Result<()> {
    async fn write_and_flush(upstream: &mut UpstreamConn, data: &[u8]) -> std::io::Result<()> {
        upstream.write_all(data).await?;
        upstream.flush().await
    }

    let request = format_http_request(
        path,
        host_authority,
        resume_offset,
        resume_if_range,
        volatile_cond,
    );

    let http_timeout = global_config().http_timeout;
    match tokio::time::timeout(http_timeout, write_and_flush(upstream, request.as_bytes())).await {
        Ok(result) => result,
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => Err(std::io::Error::new(
            ErrorKind::TimedOut,
            format!(
                "write operation timed out after {}",
                HumanFmt::Time(http_timeout)
            ),
        )),
    }
}

/// Read HTTP response headers from the upstream stream (generic over TCP/TLS).
/// Returns the byte index where the body starts.
///
/// Times out after the configured HTTP timeout.
async fn read_upstream_response_headers(
    upstream: &mut UpstreamConn,
    buf: &mut BytesMut,
) -> Result<usize, HeadError> {
    let http_timeout = global_config().http_timeout;
    let deadline = tokio::time::sleep(http_timeout);
    tokio::pin!(deadline);

    // Incremental scan offset: bytes before this index were already checked for
    // the \r\n\r\n terminator on a prior iteration. Subtract 3 so a terminator
    // that straddles the read boundary is still found.
    let mut search_offset = 0usize;

    loop {
        let read_fut = upstream.read_buf(buf);
        tokio::pin!(read_fut);
        let n = tokio::select! {
            biased;
            r = &mut read_fut => r.map_err(HeadError::Transport)?,
            () = &mut deadline => {
                metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                return Err(HeadError::Transport(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "timed out reading upstream response headers after {}",
                        HumanFmt::Time(http_timeout)
                    ),
                )));
            }
        };

        if n == 0 {
            return Err(HeadError::Transport(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "upstream closed before sending complete headers",
            )));
        }

        // Scan only the tail not yet covered (plus a 3-byte overlap to catch
        // a terminator that straddles the previous read boundary). The
        // terminator test is `find_header_end`'s, which accepts the bare-LF
        // endings httparse accepts: a CRLF-only scan would swallow an
        // LF-only upstream's body as header bytes.
        let scan_from = search_offset.saturating_sub(3);
        if let Some(rel) = find_header_end(&buf[scan_from..]) {
            return Ok(scan_from + rel);
        }
        search_offset = buf.len();

        if buf.len() > MAX_UPSTREAM_HEADER_SIZE {
            return Err(HeadError::Protocol(format!(
                "upstream response header size of {} bytes exceeds {MAX_UPSTREAM_HEADER_SIZE} byte cap",
                buf.len()
            )));
        }
    }
}

/// The splice side of [`BodyFraming`], whose type and resolution rule
/// (`resolve_body_framing`) live in `upstream_head`, shared with hyper: the
/// framing line a relayed head announces and the body relays.
impl BodyFraming {
    /// The client connection's fate after a response relayed with this
    /// framing to a `client` speaking that HTTP version: a body relayed
    /// close-delimited (a close-delimited upstream body, or a chunked one
    /// de-chunked for HTTP/1.0) ends only when the connection closes, so the
    /// client's keep-alive cannot survive it.
    pub(super) fn client_action(
        self,
        requested: ConnectionAction,
        client: ConnectionVersion,
    ) -> ConnectionAction {
        match self {
            Self::ContentLength(_) => requested,
            Self::Chunked => match ChunkedRelay::for_client(client) {
                ChunkedRelay::Raw => requested,
                ChunkedRelay::Decoded => ConnectionAction::Close,
            },
            Self::CloseDelimited => ConnectionAction::Close,
        }
    }

    /// The framing header a relayed head announces to a `client` speaking
    /// that HTTP version, CRLF-terminated; none for a body relayed
    /// close-delimited or a `status` that never carries one.
    pub(super) fn header_line(
        self,
        status: StatusCode,
        client: ConnectionVersion,
    ) -> Option<String> {
        if is_bodyless_status(status) {
            return None;
        }
        match self {
            Self::ContentLength(len) => Some(format!("Content-Length: {len}\r\n")),
            Self::Chunked => match ChunkedRelay::for_client(client) {
                ChunkedRelay::Raw => Some("Transfer-Encoding: chunked\r\n".to_owned()),
                ChunkedRelay::Decoded => None,
            },
            Self::CloseDelimited => None,
        }
    }

    /// Relay the response body to a `client_stream` speaking HTTP version
    /// `client`, framed per `self` (a chunked body de-chunked for HTTP/1.0,
    /// see [`Self::client_action`]), and return the number of body bytes
    /// sent (`body_prefix` included).
    ///
    /// Takes ownership so every error or cancellation closes the connection.
    /// Only a complete length-delimited or chunked body returns it to the pool.
    pub(super) async fn relay_to_client(
        self,
        mut upstream: ResponseBody,
        client_stream: &TcpStream,
        client: ConnectionVersion,
        body_prefix: &[u8],
        max_bytes: usize,
    ) -> Result<u64, DeliveryFailure> {
        /// Write the bytes that arrived with the headers, rate-checked.
        async fn write_prefix(
            client_stream: &TcpStream,
            body_prefix: &[u8],
        ) -> Result<(), ClientError> {
            if body_prefix.is_empty() {
                return Ok(());
            }
            let config = global_config();
            let mut rate_checker = RateChecker::from_config(config);
            write_all_to_stream_rated(
                client_stream,
                body_prefix,
                &mut rate_checker,
                config.http_timeout,
            )
            .await?;
            metrics::BYTES_SERVED_PASSTHROUGH.increment_by(body_prefix.len() as u64);
            Ok(())
        }

        let prefix_len = body_prefix.len() as u64;
        match self {
            Self::ContentLength(cl) => {
                write_prefix(client_stream, body_prefix).await?;
                let remaining = cl.saturating_sub(prefix_len);
                let forwarded = if remaining > 0 {
                    forward_upstream_body(&mut upstream, client_stream, remaining).await?
                } else {
                    0
                };
                upstream.complete();
                Ok(prefix_len + forwarded)
            }
            Self::Chunked => {
                // Raw framing is forwarded unchanged (or decoded, for an
                // HTTP/1.0 client); the helper consumes the closing CRLF
                // after the `0` chunk, so the connection stays reusable on
                // success.
                let forwarded = forward_upstream_chunked_body(
                    &mut upstream,
                    client_stream,
                    ChunkedRelay::for_client(client),
                    body_prefix,
                    max_bytes,
                )
                .await?;
                upstream.complete();
                Ok(forwarded)
            }
            Self::CloseDelimited => {
                write_prefix(client_stream, body_prefix).await?;
                let forwarded =
                    forward_upstream_body_until_eof(&mut upstream, client_stream, max_bytes)
                        .await?;
                Ok(prefix_len + forwarded)
            }
        }
    }

    /// Read the whole response body into memory, framed per `self`, up to
    /// `max_bytes` of payload (`body_prefix` included).
    ///
    /// Same poolability contract as [`Self::relay_to_client`]: the upstream
    /// is closed on every error and for close-delimited bodies, and becomes
    /// reusable only after a length-delimited or chunked body was consumed
    /// to its terminator.
    pub(super) async fn read_to_vec(
        self,
        mut upstream: ResponseBody,
        body_prefix: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>, UpstreamError> {
        match self {
            Self::Chunked => {
                let body = read_dechunk_body_to_vec(&mut upstream, body_prefix, max_bytes).await?;
                upstream.complete();
                Ok(body)
            }
            Self::ContentLength(cl) => {
                let body =
                    read_body_to_vec_with_content_length(&mut upstream, body_prefix, cl, max_bytes)
                        .await?;
                upstream.complete();
                Ok(body)
            }
            Self::CloseDelimited => {
                read_body_to_vec_until_eof(&mut upstream, body_prefix, max_bytes).await
            }
        }
    }
}

/// Parsed upstream response header info.
pub(super) struct UpstreamResponse {
    pub(super) status_code: StatusCode,
    pub(super) framing: BodyFraming,
    pub(super) content_type: Option<String>,
    pub(super) last_modified: Option<String>,
    pub(super) etag: Option<String>,
    content_range: Option<String>,
    pub(super) location: Option<String>,
    pub(super) connection_close: bool,
    /// Instant the upstream request was sent - start of the upstream-rate
    /// window.
    pub(super) request_sent_at: PreciseInstant,
}

impl UpstreamResponse {
    /// Whether this head plus the `prefix_len` body bytes that arrived with
    /// it can be relayed to a client as-is.  Runs *before* any byte of the
    /// head is written: an interim (1xx) head or a body prefix longer than
    /// the declared `Content-Length` fails closed as a 502, and the caller
    /// must not return the upstream connection to the pool (its socket
    /// still carries the unread remainder).
    pub(super) fn check_relayable(&self, prefix_len: u64) -> Result<(), RejectReason> {
        if self.status_code.is_informational() {
            return Err(RejectReason::InterimResponse {
                status: self.status_code.as_u16(),
            });
        }
        if let BodyFraming::ContentLength(content_length) = self.framing
            && prefix_len > content_length
        {
            return Err(RejectReason::InconsistentBodyFraming {
                content_length,
                prefix_len,
            });
        }
        Ok(())
    }

    /// A 3xx the drive follows (301/302/307/308) when the `Location` target
    /// is allowed; the other redirects (303, 304 as a status, 300) are
    /// relayed as-is.
    pub(super) fn is_redirect(&self) -> bool {
        matches!(
            self.status_code,
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        )
    }

    /// The body's fixed length, only when the response is length-delimited
    /// (`Content-Length`). `None` for chunked or close-delimited framing.
    pub(super) fn content_length(&self) -> Option<u64> {
        match self.framing {
            BodyFraming::ContentLength(n) => Some(n),
            BodyFraming::Chunked | BodyFraming::CloseDelimited => None,
        }
    }

    /// The backend-neutral projection consumed by
    /// `upstream_head::plan_download`.
    /// Its `ETag` goes through the same `well_formed_etag` filter as hyper's
    /// projection, so the planner's input does not depend on whether
    /// [`Self::discard_invalid_validators`] ran first.
    pub(super) fn head(&self) -> UpstreamHead<'_> {
        UpstreamHead {
            status: self.status_code,
            content_length: self.content_length(),
            content_range: self.content_range.as_deref().and_then(parse_content_range),
            etag: well_formed_etag(self.etag.as_deref()),
        }
    }

    /// Discard malformed `ETag`/`Last-Modified` values before they reach a
    /// client response header, an `If-Range` comparison or an xattr.
    ///
    /// Wording mirrors `hyper_conn.rs::serve_new_file` modulo the subsystem
    /// prefix.
    pub(super) fn discard_invalid_validators(&mut self, conn_details: &ConnectionDetails) {
        let (etag, last_modified) = cache_metadata::check_upstream_validators(
            self.etag.take(),
            self.last_modified.take(),
            |invalid| match invalid {
                InvalidValidator::ETag(etag) => warn_once_or_info!(
                    "splice proxy: upstream mirror {} sent an invalid ETag `{}` for {}; discarding it",
                    conn_details.mirror,
                    etag.escape_debug(),
                    conn_details.debname
                ),
                InvalidValidator::LastModified(lm) => warn_once_or_info!(
                    "splice proxy: upstream mirror {} sent an invalid Last-Modified `{}` for {}; discarding it",
                    conn_details.mirror,
                    lm.escape_debug(),
                    conn_details.debname
                ),
                InvalidValidator::Oversized { header, len } => warn_once_or_info!(
                    "splice proxy: upstream mirror {} sent a {len} byte {header} for {}; discarding it",
                    conn_details.mirror,
                    conn_details.debname
                ),
            },
        );
        self.etag = etag;
        self.last_modified = last_modified;
    }
}

/// Whether a response with `status` never carries a body, whatever its
/// framing headers claim (RFC 9112 §6.3: 1xx, 204 and 304).
pub(super) fn is_bodyless_status(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

/// Parse the upstream HTTP response head in `buf[..header_end]`, sent in
/// answer to the request that went out at `request_sent_at`.
///
/// On success the upstream status is recorded and the body bytes that
/// arrived with the head (`buf[header_end..]`) are credited as downloaded;
/// an unparsable response is neither. Later reads of the body credit
/// themselves.
pub(super) fn parse_upstream_response(
    buf: &[u8],
    header_end: usize,
    request_sent_at: PreciseInstant,
) -> Result<UpstreamResponse, String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_UPSTREAM_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);

    match resp.parse(&buf[..header_end]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => {
            return Err("failed to parse upstream response headers".to_owned());
        }
    }

    let raw_code = resp.code.expect("complete header parsed");
    let status_code = StatusCode::from_u16(raw_code)
        .map_err(|_err| "invalid HTTP status code from upstream".to_owned())?;
    let http10 = resp.version == Some(0);

    let headers = resp.headers;

    // RFC 9112 §6.1: an HTTP/1.0 message carrying `Transfer-Encoding` has
    // faulty framing whatever else it says; hyper's client refuses it too.
    if http10
        && headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str()))
    {
        return Err("Transfer-Encoding in an HTTP/1.0 response from upstream".to_owned());
    }

    let framing = resolve_body_framing(headers.iter().map(|h| (h.name, h.value)))?;

    let content_type = find_header(headers, &CONTENT_TYPE).map(String::from);

    // Raw values: `UpstreamResponse::discard_invalid_validators` filters them
    // once the driver knows which file they belong to.
    let last_modified = find_header(headers, &LAST_MODIFIED).map(String::from);

    let etag = find_header(headers, &ETAG).map(String::from);

    let content_range = find_header(headers, &CONTENT_RANGE).map(String::from);

    let location = find_header(headers, &LOCATION).map(String::from);

    // RFC 9112 section 9.3: a `close` option on any `Connection` line ends the
    // connection after this response, and an HTTP/1.0 response persists only
    // with a `keep-alive` option. Pooling such a connection would leave the
    // next request racing the upstream's FIN, caught only if
    // `upstream::check_alive`'s probe sees it first.
    let mut close = false;
    let mut keep_alive = false;
    for value in headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(CONNECTION.as_str()))
        .filter_map(|h| str::from_utf8(h.value).ok())
    {
        for token in value.split(',').map(str::trim_ascii) {
            close |= token.eq_ignore_ascii_case("close");
            keep_alive |= token.eq_ignore_ascii_case("keep-alive");
        }
    }
    let connection_close = close || (http10 && !keep_alive);

    // RFC 9112 §6.3: 1xx, 204, and 304 responses never carry a message body,
    // regardless of Content-Length / Transfer-Encoding headers. Force
    // zero-length framing so relay/consumer paths do not read-until-EOF
    // (stalling a keep-alive upstream) or mis-frame a bodyless response.
    let framing = if is_bodyless_status(status_code) {
        BodyFraming::ContentLength(0)
    } else {
        framing
    };

    let body_prefix_len = (buf.len() - header_end) as u64;
    if body_prefix_len > 0 {
        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(body_prefix_len);
    }
    metrics::record_upstream_status(status_code);

    Ok(UpstreamResponse {
        status_code,
        framing,
        content_type,
        last_modified,
        etag,
        content_range,
        location,
        connection_close,
        request_sent_at,
    })
}

/// Send request and read+parse response headers on an existing connection.
///
/// Times out after the configured HTTP timeout.
pub(super) async fn send_and_read_headers(
    up: &mut UpstreamConn,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> Result<(UpstreamResponse, BytesMut, usize), HeadError> {
    send_upstream_request(
        up,
        host_authority,
        upstream_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
    )
    .await
    .map_err(HeadError::Transport)?;
    let request_sent_at = PreciseInstant::now();

    let mut hdr_buf = BytesMut::with_capacity(MAX_UPSTREAM_HEADER_SIZE);
    let hdr_end = read_upstream_response_headers(up, &mut hdr_buf).await?;
    let resp = parse_upstream_response(&hdr_buf, hdr_end, request_sent_at)
        .inspect_err(|_reason| {
            metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
        })
        .map_err(HeadError::Protocol)?;
    Ok((resp, hdr_buf, hdr_end))
}

/// Feed `n` freshly read upstream bytes to the mirror-rate checker and fail
/// with the shared `TimedOut` error once the mirror has fallen below
/// `min_download_rate`. A `None` checker means the limit is disabled.
///
/// The one gate for every body reader below; the `BYTES_DOWNLOADED_UPSTREAM`
/// bump stays at the call sites, which differ in what they check between the
/// read and this gate.
fn check_upstream_read_rate(
    rate_checker: &mut Option<RateChecker>,
    n: usize,
) -> Result<(), UpstreamError> {
    let Some(rate_checker) = rate_checker.as_mut() else {
        return Ok(());
    };
    rate_checker.add(n);
    match rate_checker.check_fail() {
        Some(rate) => Err(UpstreamError::rate(rate)),
        None => Ok(()),
    }
}

/// The `TimedOut` error every upstream body read in this module returns:
/// bumps `HTTP_TIMEOUT_UPSTREAM_READ` and names the phase alongside the
/// budget that ran out.
fn upstream_read_timeout(timeout: Duration) -> UpstreamError {
    metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
    UpstreamError::timeout("upstream read timed out", timeout)
}

/// One upstream body read under the `http_timeout` deadline, for the body
/// readers below: a deadline hit surfaces as [`upstream_read_timeout`]
/// tagged with `phase`. A `0` (EOF) is the caller's to interpret.
async fn read_upstream_timed(
    read: impl Future<Output = std::io::Result<usize>>,
    phase: &'static str,
    http_timeout: Duration,
) -> Result<usize, UpstreamError> {
    match tokio::time::timeout(http_timeout, read).await {
        Ok(result) => result.map_err(|error| UpstreamError::io(phase, error)),
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
            Err(upstream_read_timeout(http_timeout))
        }
    }
}

/// Forward remaining body bytes from upstream to client (no caching).
/// Used for relaying bodies verbatim: non-200 responses on the cache path
/// and any status via `splice_simple_proxy`.
/// On error the connection state is indeterminate -- callers must mark the upstream non-poolable.
async fn forward_upstream_body(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    count: u64,
) -> Result<u64, DeliveryFailure> {
    let config = global_config();
    // `Vec::with_capacity` reserves uninitialized backing storage; `read_buf`
    // fills bytes into the spare capacity via `BufMut`, so the buffer is
    // never zero-initialized before being overwritten by upstream data.
    let mut buf: Vec<u8> = Vec::with_capacity(TLS_READ_BUF_SIZE);
    let mut remaining = count;
    let mut rate_checker = RateChecker::from_config(config);
    let mut client_rate_checker = RateChecker::from_config(config);

    while remaining > 0 {
        debug_assert_eq!(
            buf.capacity(),
            TLS_READ_BUF_SIZE,
            "buffer capacity should remain constant"
        );
        buf.clear();
        let to_read = std::cmp::min(remaining, TLS_READ_BUF_SIZE as u64);
        let n = read_upstream_timed(
            (&mut *upstream).take(to_read).read_buf(&mut buf),
            "body forward",
            config.http_timeout,
        )
        .await?;
        if n == 0 {
            return Err(DeliveryFailure::from(UpstreamError::protocol(
                "upstream closed before sending complete body",
            )));
        }

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        check_upstream_read_rate(&mut rate_checker, n)?;

        write_all_to_stream_rated(client, &buf, &mut client_rate_checker, config.http_timeout)
            .await?;
        metrics::BYTES_SERVED_PASSTHROUGH.increment_by(n as u64);
        remaining = remaining
            .checked_sub(n as u64)
            .expect("read should not return more than requested");
    }

    Ok(count)
}

/// Forward body bytes from upstream to client until EOF, with a size cap.
/// Used for relayed responses that lack a Content-Length header (non-200 on
/// the cache path, any status via `splice_simple_proxy`).
async fn forward_upstream_body_until_eof(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    max_bytes: usize,
) -> Result<u64, DeliveryFailure> {
    let config = global_config();
    let mut buf = BytesMut::with_capacity(TLS_READ_BUF_SIZE);
    let mut total = 0;
    let mut rate_checker = RateChecker::from_config(config);
    let mut client_rate_checker = RateChecker::from_config(config);

    loop {
        buf.clear();
        let n = read_upstream_timed(
            upstream.read_buf(&mut buf),
            "body forward",
            config.http_timeout,
        )
        .await?;
        if n == 0 {
            break;
        }

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        total += n as u64;
        if total > max_bytes as u64 {
            return Err(DeliveryFailure::from(UpstreamError::body_limit(format!(
                "upstream error response body exceeded {max_bytes} byte cap (size={total} bytes)"
            ))));
        }

        check_upstream_read_rate(&mut rate_checker, n)?;

        write_all_to_stream_rated(
            client,
            &buf[..n],
            &mut client_rate_checker,
            config.http_timeout,
        )
        .await?;
        metrics::BYTES_SERVED_PASSTHROUGH.increment_by(n as u64);
    }

    Ok(total)
}

/// Framing position of a [`ChunkDecoder`].
enum ChunkedState {
    /// Accumulating the hex chunk-size line (up to `\r\n`).
    ReadingSize,
    /// Inside chunk data; `remaining` counts undecoded payload bytes.
    ReadingData { remaining: usize },
    /// Expecting the `\r\n` trailer after chunk data.
    ReadingTrailer { seen_cr: bool },
    /// The final `0\r\n` chunk has been received; still expecting the
    /// closing `\r\n` that terminates the (empty) trailer section.
    /// `remaining` is the count of still-unseen bytes of that final CRLF
    /// (starts at 2, decrements to 0 when fully consumed).
    Done { remaining: u8 },
}

/// Why [`ChunkDecoder::feed`] stopped early.
#[derive(Debug)]
enum ChunkDecodeError {
    /// The declared payload total crossed the decoder's cap. The decoder
    /// leaves logging to callers; the I/O wrappers add body context.
    SizeCap {
        max_bytes: usize,
        declared_bytes: usize,
    },
    /// A framing violation, as the reason phrase its I/O wrapper hands to
    /// `UpstreamError::protocol` (which owns the counter bump).
    Framing(&'static str),
}

/// What one [`ChunkDecoder::feed`] call took from its input.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Consumed {
    /// Raw bytes (framing and payload) consumed from the input. Equals the
    /// input length unless `done` is set: then the decoder stopped right
    /// after the closing CRLF and left everything past it untouched.
    raw: usize,
    /// The terminating `0\r\n\r\n` has been fully consumed.
    done: bool,
}

impl Consumed {
    /// Reject input past the terminator. Well-behaved upstreams send no
    /// bytes after the closing `\r\n`; anything there is a framing
    /// violation (smuggling attempt, buggy upstream) that must neither be
    /// relayed nor left in the socket buffer to poison the next checkout,
    /// so callers must mark the upstream non-poolable on this error.
    ///
    /// Kept out of [`ChunkDecoder::feed`] so the streaming relay can first
    /// forward the validated `[..raw]` prefix (the terminator included) and
    /// only then fail the connection.
    fn ensure_no_trailing_bytes(self, data_len: usize) -> Result<(), &'static str> {
        let Self { raw, done } = self;
        if done && raw < data_len {
            return Err("chunked encoding: trailing bytes after 0-length chunk");
        }
        Ok(())
    }
}

/// Parse a chunk-size line (its CRLF already stripped) as RFC 9112 §7.1's
/// `chunk-size [ chunk-ext ]`: `1*HEXDIG`, then optionally `BWS ";"` and the
/// extensions, which are ignored.
///
/// The relay forwards the raw encoding, so any leniency here is a chunk
/// boundary a stricter (or differently lenient) client may place elsewhere.
/// Refused: a sign or `0x` prefix, whitespace other than the `BWS` before
/// `;` (so `5 ` and ` 5` are refused, as is any Unicode space), and a
/// control character in the extensions -- a bare CR or LF there is a line
/// end to some parsers. The extension grammar (`token` / `quoted-string`) is
/// deliberately not checked further: without CR/LF it cannot move a
/// boundary, and the extensions are dropped unread.
fn parse_chunk_size_line(line: &[u8]) -> Result<usize, &'static str> {
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    let (hex, rest) = line.split_at(digits);
    if hex.is_empty() {
        return Err("chunked encoding: invalid chunk-size hex");
    }
    if !rest.is_empty() {
        let bws = rest
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count();
        let Some(ext) = rest[bws..].strip_prefix(b";") else {
            return Err("chunked encoding: invalid chunk-size line");
        };
        if ext.iter().any(|&b| b.is_ascii_control() && b != b'\t') {
            return Err("chunked encoding: invalid chunk extension");
        }
    }
    let hex = std::str::from_utf8(hex).expect("ASCII hex digits are UTF-8");
    usize::from_str_radix(hex, 16)
        .map_err(|_err @ ParseIntError { .. }| "chunked encoding: chunk size overflows")
}

/// Incremental decoder for the chunked transfer coding (RFC 9112 section 7.1).
///
/// The single framing implementation behind both the streaming relay
/// [`forward_upstream_chunked_body`] (which forwards the raw encoding
/// unchanged and only needs to know where the body ends, or, for an
/// HTTP/1.0 client, streams the decoded payload) and the buffered reader
/// [`read_dechunk_body_to_vec`] (which collects the decoded payload).
/// Chunk-size lines are held to RFC 9112's grammar ([`parse_chunk_size_line`])
/// and chunk extensions after `;` are ignored; trailer fields between `0\r\n`
/// and the final `\r\n` are rejected as a framing sanity check rather than
/// skipped, to catch truncation and smuggling. The declared payload total is
/// checked against `max_bytes` at every chunk-size line.
///
/// Terminator policy, binding on both readers: on success the closing
/// `\r\n` after the `0\r\n` has been fully consumed from the upstream socket
/// buffer, so the connection can be returned to the pool. On error the
/// connection state is indeterminate and the caller must mark the upstream
/// non-poolable.
struct ChunkDecoder {
    state: ChunkedState,
    size_buf: Vec<u8>,
    /// Sum of the declared chunk sizes seen so far.
    total: Saturating<usize>,
    max_bytes: usize,
}

impl ChunkDecoder {
    fn new(max_bytes: usize) -> Self {
        Self {
            state: ChunkedState::ReadingSize,
            size_buf: Vec::with_capacity(32),
            total: Saturating(0),
            max_bytes,
        }
    }

    /// Run the state machine over `data`, reporting every payload byte range
    /// (relative to `data`) through `on_payload`.
    ///
    /// Stops right after the closing CRLF of the terminator (see
    /// [`Consumed::raw`]) so the caller can detect bytes past it; otherwise
    /// consumes all of `data`. On error the input position is lost and the
    /// upstream connection state is indeterminate.
    fn feed(
        &mut self,
        data: &[u8],
        mut on_payload: impl FnMut(Range<usize>),
    ) -> Result<Consumed, ChunkDecodeError> {
        fn framing_violation(msg: &'static str) -> ChunkDecodeError {
            ChunkDecodeError::Framing(msg)
        }

        let mut i = 0usize;
        while i < data.len() {
            match self.state {
                ChunkedState::ReadingSize => {
                    let b = data[i];
                    i += 1;
                    self.size_buf.push(b);
                    if b == b'\n' {
                        // Only CRLF ends the line. A bare LF is refused on
                        // sight: a client treating it as the terminator
                        // (RFC 9112 §2.2 lets it) would read what follows
                        // as chunk data, a different boundary than ours.
                        let Some(line) = self.size_buf.strip_suffix(b"\r\n") else {
                            return Err(framing_violation(
                                "chunked encoding: bare LF in chunk-size line",
                            ));
                        };
                        let chunk_size = parse_chunk_size_line(line).map_err(framing_violation)?;
                        self.size_buf.clear();
                        if chunk_size == 0 {
                            // Terminal chunk; still need to consume the
                            // closing \r\n that ends the (empty) trailer
                            // section.
                            self.state = ChunkedState::Done { remaining: 2 };
                        } else {
                            self.total += chunk_size;
                            if self.total > Saturating(self.max_bytes) {
                                return Err(ChunkDecodeError::SizeCap {
                                    max_bytes: self.max_bytes,
                                    declared_bytes: self.total.0,
                                });
                            }
                            self.state = ChunkedState::ReadingData {
                                remaining: chunk_size,
                            };
                        }
                    } else if self.size_buf.len() > 64 {
                        // Guard against absurdly long size lines.
                        return Err(framing_violation(
                            "chunked encoding: chunk-size line too long",
                        ));
                    }
                }
                ChunkedState::ReadingData { ref mut remaining } => {
                    let taken = (data.len() - i).min(*remaining);
                    on_payload(i..i + taken);
                    *remaining -= taken;
                    i += taken;
                    if *remaining == 0 {
                        self.state = ChunkedState::ReadingTrailer { seen_cr: false };
                    }
                }
                ChunkedState::ReadingTrailer { ref mut seen_cr } => {
                    let b = data[i];
                    i += 1;
                    if !*seen_cr && b == b'\r' {
                        *seen_cr = true;
                    } else if *seen_cr && b == b'\n' {
                        self.state = ChunkedState::ReadingSize;
                    } else {
                        return Err(framing_violation(
                            "chunked encoding: expected CRLF after chunk data",
                        ));
                    }
                }
                ChunkedState::Done { ref mut remaining } => {
                    // Validate the closing \r\n after the 0-length chunk.
                    while i < data.len() && *remaining > 0 {
                        let b = data[i];
                        i += 1;
                        let expected = if *remaining == 2 { b'\r' } else { b'\n' };
                        if b != expected {
                            return Err(framing_violation(
                                "chunked encoding: expected \\r\\n after 0-length chunk \
                                 (trailer sections are not supported)",
                            ));
                        }
                        *remaining -= 1;
                    }
                    if *remaining == 0 {
                        // Stop here: leave any trailing bytes unconsumed so
                        // the caller can detect them.
                        return Ok(Consumed { raw: i, done: true });
                    }
                }
            }
        }
        Ok(Consumed {
            raw: i,
            done: matches!(self.state, ChunkedState::Done { remaining: 0 }),
        })
    }
}

/// What [`forward_upstream_chunked_body`] hands the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkedRelay {
    /// The raw encoding, unchanged: an HTTP/1.1 client decodes it itself.
    Raw,
    /// The decoded payload only, for an HTTP/1.0 client, which knows no
    /// transfer coding (RFC 9112 §6.1): the relayed body is close-delimited.
    Decoded,
}

impl ChunkedRelay {
    /// How a chunked body is relayed to a client speaking `client`.
    fn for_client(client: ConnectionVersion) -> Self {
        match client {
            ConnectionVersion::Http11 => Self::Raw,
            ConnectionVersion::Http10 => Self::Decoded,
        }
    }
}

/// One buffer's worth of [`forward_upstream_chunked_body`]: validate the
/// framing, then forward the validated raw bytes -- or, for
/// [`ChunkedRelay::Decoded`], the payload they carry, collected in
/// `payload` -- to the client. Returns `true` once the terminator has been
/// consumed.
///
/// Framing is validated before anything is forwarded, so the client never
/// receives bytes past a detected framing error: on invalid framing the
/// caller's error-return path closes the client connection, and without the
/// pre-check the client would first receive the corrupt bytes and only then
/// see the connection drop. When the terminator is consumed only the
/// validated prefix `data[..raw]` goes out; bytes past the closing `\r\n`
/// are rejected afterwards by [`Consumed::ensure_no_trailing_bytes`].
#[expect(
    clippy::too_many_arguments,
    reason = "one per-buffer step of one relay loop; the arguments are that loop's state"
)]
async fn forward_chunked_buf(
    decoder: &mut ChunkDecoder,
    data: &[u8],
    relay: ChunkedRelay,
    payload: &mut Vec<u8>,
    client: &TcpStream,
    client_rate_checker: &mut Option<RateChecker>,
    client_total: &mut u64,
    http_timeout: Duration,
) -> Result<bool, DeliveryFailure> {
    payload.clear();
    let fed = match relay {
        ChunkedRelay::Raw => decoder.feed(data, |_payload| {}),
        ChunkedRelay::Decoded => {
            decoder.feed(data, |range| payload.extend_from_slice(&data[range]))
        }
    };
    let consumed = match fed {
        Ok(consumed) => consumed,
        Err(ChunkDecodeError::SizeCap {
            max_bytes,
            declared_bytes,
        }) => {
            return Err(DeliveryFailure::from(UpstreamError::body_limit(format!(
                "chunked response body exceeded {max_bytes} byte cap (declared payload={declared_bytes} bytes)"
            ))));
        }
        Err(ChunkDecodeError::Framing(reason)) => {
            return Err(DeliveryFailure::from(UpstreamError::protocol(reason)));
        }
    };
    let forward_slice = match relay {
        ChunkedRelay::Raw => &data[..consumed.raw],
        ChunkedRelay::Decoded => payload.as_slice(),
    };
    if !forward_slice.is_empty() {
        write_all_to_stream_rated(client, forward_slice, client_rate_checker, http_timeout).await?;
        metrics::BYTES_SERVED_PASSTHROUGH.increment_by(forward_slice.len() as u64);
        *client_total += forward_slice.len() as u64;
    }
    consumed
        .ensure_no_trailing_bytes(data.len())
        .map_err(UpstreamError::protocol)?;
    Ok(consumed.done)
}

/// Forward a chunked transfer-encoded body from upstream to client.
///
/// For [`ChunkedRelay::Raw`] all raw bytes (chunk-size lines, data, CRLFs)
/// are forwarded unchanged and the [`ChunkDecoder`] only tracks framing to
/// detect the terminating zero-length chunk, so the connection can be
/// reused afterwards. For [`ChunkedRelay::Decoded`] only the payload the
/// decoder reports goes out, as a close-delimited body.
///
/// Terminator and pool-safety policy: [`ChunkDecoder`].
async fn forward_upstream_chunked_body(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    relay: ChunkedRelay,
    body_prefix: &[u8],
    max_bytes: usize,
) -> Result<u64, DeliveryFailure> {
    let config = global_config();
    let mut rate_checker = RateChecker::from_config(config);
    let mut client_rate_checker = RateChecker::from_config(config);

    let mut decoder = ChunkDecoder::new(max_bytes);
    // The decoded payload of the current buffer; stays empty for `Raw`.
    let mut payload = Vec::new();
    // Tracks the bytes written to the client: raw framing + data, or the
    // decoded payload.
    let mut client_total: u64 = 0;

    // Bootstrap: process bytes that arrived with the response headers.
    if forward_chunked_buf(
        &mut decoder,
        body_prefix,
        relay,
        &mut payload,
        client,
        &mut client_rate_checker,
        &mut client_total,
        config.http_timeout,
    )
    .await?
    {
        return Ok(client_total);
    }

    let mut buf = BytesMut::with_capacity(TLS_READ_BUF_SIZE);
    loop {
        buf.clear();
        let n = read_upstream_timed(
            upstream.read_buf(&mut buf),
            "chunked body forward",
            config.http_timeout,
        )
        .await?;
        if n == 0 {
            return Err(DeliveryFailure::from(UpstreamError::protocol(
                "upstream closed during chunked body transfer",
            )));
        }

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        check_upstream_read_rate(&mut rate_checker, n)?;

        if forward_chunked_buf(
            &mut decoder,
            &buf[..n],
            relay,
            &mut payload,
            client,
            &mut client_rate_checker,
            &mut client_total,
            config.http_timeout,
        )
        .await?
        {
            return Ok(client_total);
        }
    }
}

/// Read upstream body into a `Vec<u8>` until EOF, up to `max_bytes`.
/// Returns the buffered body. Connection is not poolable after this.
async fn read_body_to_vec_until_eof(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, UpstreamError> {
    let config = global_config();
    let size = (prefix.len() + 4096).min(max_bytes.saturating_add(1));
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(prefix);
    let mut rate_checker = RateChecker::from_config(config);

    loop {
        if body.len() > max_bytes {
            return Err(UpstreamError::body_limit(format!(
                "volatile response body exceeded {max_bytes} byte cap (size={} bytes)",
                body.len()
            )));
        }

        // The +1 keeps the take limit strictly positive (so a 0-byte read
        // can only mean upstream EOF, never "we hit our own cap") and lets a
        // single over-cap byte slip through so the check above can reject it
        // on the next iteration.
        let remaining = (max_bytes - body.len()).saturating_add(1);
        // Ensure ample spare capacity so each read syscall can transfer a
        // useful chunk; `Vec::reserve` is a no-op when spare capacity
        // already covers this.
        body.reserve(TLS_READ_BUF_SIZE.min(remaining));

        let n = read_upstream_timed(
            (&mut *upstream).take(remaining as u64).read_buf(&mut body),
            "volatile body buffering",
            config.http_timeout,
        )
        .await?;
        if n == 0 {
            break;
        }

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        check_upstream_read_rate(&mut rate_checker, n)?;
    }

    Ok(body)
}

/// Read an upstream body with known `Content-Length` into a `Vec<u8>`.
async fn read_body_to_vec_with_content_length(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    content_length: u64,
    max_bytes: usize,
) -> Result<Vec<u8>, UpstreamError> {
    let content_length = usize::try_from(content_length).map_err(|_err| {
        UpstreamError::body_limit("content-length value too large to fit in memory address space")
    })?;
    if content_length > max_bytes {
        return Err(UpstreamError::body_limit(
            "content-length exceeds the body buffering cap",
        ));
    }
    if prefix.len() > content_length {
        return Err(UpstreamError::protocol(
            "upstream body prefix exceeds content-length",
        ));
    }

    let config = global_config();
    // Allocate incrementally (the per-iteration `reserve` below), like
    // `read_body_to_vec_until_eof`: `content_length` is an untrusted upstream
    // header and must not size an up-front allocation.
    let mut body = Vec::with_capacity((prefix.len() + 32 * 1024).min(content_length));
    body.extend_from_slice(prefix);
    let mut rate_checker = RateChecker::from_config(config);

    while body.len() < content_length {
        let remaining = content_length - body.len();
        body.reserve(TLS_READ_BUF_SIZE.min(remaining));
        let n = read_upstream_timed(
            (&mut *upstream).take(remaining as u64).read_buf(&mut body),
            "length-delimited body buffering",
            config.http_timeout,
        )
        .await?;
        if n == 0 {
            return Err(UpstreamError::protocol(
                "upstream closed before content-length body completed",
            ));
        }

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        check_upstream_read_rate(&mut rate_checker, n)?;
    }

    Ok(body)
}

/// Dechunk a chunked-encoded body from upstream into a `Vec<u8>`, up to `max_bytes`
/// of decoded payload.
///
/// Terminator and pool-safety policy: [`ChunkDecoder`].
async fn read_dechunk_body_to_vec(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, UpstreamError> {
    let config = global_config();
    let mut body = Vec::with_capacity(4096);
    let mut rate_checker = RateChecker::from_config(config);
    let mut decoder = ChunkDecoder::new(max_bytes);
    let mut read_buf = BytesMut::with_capacity(TLS_READ_BUF_SIZE);

    // The bytes that arrived with the headers are decoded first; every later
    // iteration reads from upstream (`take` leaves an empty slice behind).
    let mut pending: &[u8] = prefix;

    loop {
        let data = if pending.is_empty() {
            read_buf.clear();
            let n = read_upstream_timed(
                upstream.read_buf(&mut read_buf),
                "chunked body buffering",
                config.http_timeout,
            )
            .await?;
            if n == 0 {
                return Err(UpstreamError::protocol(
                    "upstream closed during chunked body buffering",
                ));
            }
            metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);
            check_upstream_read_rate(&mut rate_checker, n)?;
            &read_buf[..n]
        } else {
            std::mem::take(&mut pending)
        };

        let consumed = match decoder.feed(data, |payload| body.extend_from_slice(&data[payload])) {
            Ok(consumed) => consumed,
            Err(ChunkDecodeError::SizeCap {
                max_bytes,
                declared_bytes,
            }) => {
                return Err(UpstreamError::body_limit(format!(
                    "chunked volatile body exceeded {max_bytes} byte cap (declared payload={declared_bytes} bytes)"
                )));
            }
            Err(ChunkDecodeError::Framing(reason)) => return Err(UpstreamError::protocol(reason)),
        };

        if consumed.done {
            consumed
                .ensure_no_trailing_bytes(data.len())
                .map_err(UpstreamError::protocol)?;
            break;
        }
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chunked_relay_write_failure_keeps_client_side_and_os_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        client.shutdown().await.unwrap();
        let err = forward_chunked_buf(
            &mut ChunkDecoder::new(1024),
            b"1\r\nx\r\n0\r\n\r\n",
            ChunkedRelay::Raw,
            &mut Vec::new(),
            &client,
            &mut None,
            &mut 0,
            Duration::from_secs(1),
        )
        .await
        .expect_err("writing after shutdown must fail");
        assert!(
            matches!(err, DeliveryFailure::Client(ref error) if error.is_peer_disconnect()),
            "client write must retain its source and disconnect cause"
        );
    }

    /// For an HTTP/1.0 client only the payload goes out, whatever buffer
    /// boundaries split the size lines and the chunk data.
    #[tokio::test]
    async fn decoded_chunked_relay_forwards_only_the_payload() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();

        let mut decoder = ChunkDecoder::new(1024);
        let mut payload = Vec::new();
        let mut total = 0;
        for (data, done) in [
            (&b"5\r\nhel"[..], false),
            (b"lo\r\n1", false),
            (b"\r\n!\r\n0\r\n\r\n", true),
        ] {
            let finished = forward_chunked_buf(
                &mut decoder,
                data,
                ChunkedRelay::Decoded,
                &mut payload,
                &client,
                &mut None,
                &mut total,
                Duration::from_secs(1),
            )
            .await
            .expect("valid chunked input");
            assert_eq!(finished, done, "{:?}", data.escape_ascii().to_string());
        }
        assert_eq!(total, 6);

        drop(client);
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"hello!");
    }

    #[test]
    fn test_parse_upstream_response() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 12345\r\n\
                        Content-Type: application/vnd.debian.binary-package\r\n\
                        Last-Modified: Thu, 01 Jan 2025 00:00:00 GMT\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length(), Some(12345));
        assert_eq!(
            resp.content_type.as_deref(),
            Some("application/vnd.debian.binary-package")
        );
        assert_eq!(
            resp.last_modified.as_deref(),
            Some("Thu, 01 Jan 2025 00:00:00 GMT")
        );
    }

    #[test]
    fn test_parse_upstream_response_no_content_length() {
        let headers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length(), None);
        assert_eq!(resp.framing, BodyFraming::Chunked);
    }

    #[test]
    fn test_parse_upstream_response_not_chunked() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.framing, BodyFraming::ContentLength(42));
        assert_eq!(resp.content_length(), Some(42));
    }

    #[test]
    fn parse_upstream_response_chunked_takes_precedence_over_content_length() {
        // RFC 9112 §6.1: a Content-Length sent alongside chunked must be
        // ignored. The parser resolves the precedence so no consumer can
        // observe both at once.
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 42\r\n\
                        Transfer-Encoding: chunked\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.framing, BodyFraming::Chunked);
        assert_eq!(resp.content_length(), None);
    }

    #[test]
    fn parse_upstream_response_close_delimited_without_framing_headers() {
        let headers = b"HTTP/1.1 200 OK\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.framing, BodyFraming::CloseDelimited);
        assert_eq!(resp.content_length(), None);
    }

    #[test]
    fn parse_upstream_response_304_is_bodyless() {
        // RFC 9112 §6.3: a 304 never carries a body even with Content-Length.
        let headers = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.framing, BodyFraming::ContentLength(0));
        assert_eq!(resp.content_length(), Some(0));
    }

    #[test]
    fn parse_upstream_response_204_is_bodyless() {
        // RFC 9112 §6.3: a 204 never carries a body even with chunked framing.
        let headers = b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.framing, BodyFraming::ContentLength(0));
    }

    #[test]
    fn test_parse_upstream_response_404() {
        let headers = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.status_code, 404);
    }

    #[test]
    fn test_parse_upstream_response_etag() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        ETag: \"abc123\"\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.etag.as_deref(), Some("\"abc123\""));
    }

    #[test]
    fn test_parse_upstream_response_keeps_raw_validators() {
        // The parser forwards validators verbatim; `discard_invalid_validators`
        // filters them once the driver knows the file they belong to.
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        ETag: not-a-valid-etag\r\n\
                        Last-Modified: not a date\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.etag.as_deref(), Some("not-a-valid-etag"));
        assert_eq!(resp.last_modified.as_deref(), Some("not a date"));
    }

    #[test]
    fn test_parse_upstream_response_content_range() {
        let headers = b"HTTP/1.1 206 Partial Content\r\n\
                        Content-Length: 500\r\n\
                        Content-Range: bytes 100-599/1000\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.status_code, 206);
        assert_eq!(resp.content_range.as_deref(), Some("bytes 100-599/1000"));
    }

    #[test]
    fn test_parse_upstream_response_connection_close() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        Connection: close\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert!(resp.connection_close);
    }

    #[test]
    fn test_parse_upstream_response_connection_keep_alive() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        Connection: keep-alive\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert!(!resp.connection_close);
    }

    #[test]
    fn test_parse_upstream_response_no_connection_header() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert!(!resp.connection_close);
    }

    #[test]
    fn test_parse_upstream_response_case_insensitive_headers() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        content-length: 42\r\n\
                        content-type: text/plain\r\n\
                        last-modified: Mon, 01 Jan 2024 00:00:00 GMT\r\n\
                        etag: \"xyz\"\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.content_length(), Some(42));
        assert_eq!(resp.content_type.as_deref(), Some("text/plain"));
        assert_eq!(
            resp.last_modified.as_deref(),
            Some("Mon, 01 Jan 2024 00:00:00 GMT")
        );
        assert_eq!(resp.etag.as_deref(), Some("\"xyz\""));
    }

    /// A non-ASCII (obs-text) `ETag` survives splice's raw head parse but is
    /// absent to the planner and discarded as a validator, as it is on
    /// hyper (`upstream_head`'s projection test), so both backends plan a
    /// resume against it the same way.
    #[test]
    fn obs_text_etag_is_absent_from_the_head_and_discarded() {
        let headers = "HTTP/1.1 206 Partial Content\r\n\
                       content-length: 60\r\n\
                       content-range: bytes 40-99/100\r\n\
                       etag: \"caffe\u{e9}\"\r\n\
                       \r\n"
            .as_bytes();
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.etag.as_deref(), Some("\"caffe\u{e9}\""), "kept raw");
        assert_eq!(resp.head().etag, None);
        let mut discarded = Vec::new();
        let (etag, _) = cache_metadata::check_upstream_validators(resp.etag, None, |v| {
            discarded.push(format!("{v:?}"));
        });
        assert_eq!(etag, None);
        assert_eq!(discarded.len(), 1);
    }

    #[test]
    fn test_parse_upstream_response_malformed() {
        let garbage = b"not an http response at all";
        assert!(parse_upstream_response(garbage, garbage.len(), PreciseInstant::now()).is_err());
    }

    #[test]
    fn test_parse_upstream_response_all_fields() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 999\r\n\
                        Content-Type: application/octet-stream\r\n\
                        Last-Modified: Sat, 15 Mar 2025 12:00:00 GMT\r\n\
                        ETag: \"full-test\"\r\n\
                        Content-Range: bytes 0-998/999\r\n\
                        Connection: close\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length(), Some(999));
        assert_eq!(
            resp.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(
            resp.last_modified.as_deref(),
            Some("Sat, 15 Mar 2025 12:00:00 GMT")
        );
        assert_eq!(resp.etag.as_deref(), Some("\"full-test\""));
        assert_eq!(resp.content_range.as_deref(), Some("bytes 0-998/999"));
        assert!(resp.connection_close);
    }

    #[test]
    fn test_parse_upstream_response_no_optional_fields() {
        let headers = b"HTTP/1.1 200 OK\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length(), None);
        assert_eq!(resp.content_type, None);
        assert_eq!(resp.last_modified, None);
        assert_eq!(resp.etag, None);
        assert_eq!(resp.content_range, None);
        assert!(!resp.connection_close);
    }

    /// Builds a minimal well-formed HTTP/1.1 response: a `200 OK` status line
    /// followed by a single `X-Pad` header whose value is `pad_len` bytes of
    /// `'a'` (an empty value when `pad_len == 0`).
    fn make_padded_response(pad_len: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"HTTP/1.1 200 OK\r\nX-Pad: ");
        buf.extend(std::iter::repeat_n(b'a', pad_len));
        buf.extend_from_slice(b"\r\n\r\n");
        buf
    }

    /// `parse_upstream_response` accepts a response whose headers fit exactly
    /// at `MAX_UPSTREAM_HEADER_SIZE` bytes without error.
    #[test]
    fn test_parse_upstream_response_at_max_header_size() {
        // The read-loop enforces `> MAX_UPSTREAM_HEADER_SIZE`, so a response
        // whose total header block is exactly MAX_UPSTREAM_HEADER_SIZE bytes
        // must parse successfully.
        let preamble = b"HTTP/1.1 200 OK\r\nX-Pad: \r\n\r\n";
        let pad_len = MAX_UPSTREAM_HEADER_SIZE - preamble.len();
        let buf = make_padded_response(pad_len);
        assert_eq!(buf.len(), MAX_UPSTREAM_HEADER_SIZE);
        let result = parse_upstream_response(&buf, buf.len(), PreciseInstant::now());
        assert!(
            result.is_ok(),
            "expected Ok for response at exact cap, got Err"
        );
    }

    /// The byte cap is enforced by `read_upstream_response_headers`, not by
    /// the parser: handed a head one byte over `MAX_UPSTREAM_HEADER_SIZE`,
    /// `parse_upstream_response` still parses it.
    #[test]
    fn test_parse_upstream_response_is_not_size_capped() {
        let preamble = b"HTTP/1.1 200 OK\r\nX-Pad: \r\n\r\n";
        let pad_len = MAX_UPSTREAM_HEADER_SIZE - preamble.len() + 1;
        let buf = make_padded_response(pad_len);
        assert_eq!(buf.len(), MAX_UPSTREAM_HEADER_SIZE + 1);
        let resp = parse_upstream_response(&buf, buf.len(), PreciseInstant::now())
            .expect("the parser itself applies no size cap");
        assert_eq!(resp.status_code, StatusCode::OK);
    }

    /// Header-value edge cases the parser resolves itself: identical
    /// `Content-Length` duplicates (folded or on separate lines) collapse to
    /// one value, a 1xx head is bodyless whatever it claims, a lone
    /// `chunked` coding (empty list elements aside) wins over
    /// `Content-Length`, a `close` token anywhere in `Connection` -- on any
    /// of its lines -- closes, and an HTTP/1.0 response persists only with
    /// `keep-alive`.
    #[test]
    fn parse_upstream_response_header_value_edge_cases() {
        struct Case {
            head: &'static [u8],
            framing: BodyFraming,
            connection_close: bool,
        }
        let cases = [
            Case {
                head: b"HTTP/1.1 200 OK\r\nContent-Length: 100, 100\r\n\r\n",
                framing: BodyFraming::ContentLength(100),
                connection_close: false,
            },
            Case {
                head: b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\ncontent-length:\t100 \r\n\r\n",
                framing: BodyFraming::ContentLength(100),
                connection_close: false,
            },
            Case {
                head: b"HTTP/1.1 100 Continue\r\nContent-Length: 5\r\n\r\n",
                framing: BodyFraming::ContentLength(0),
                connection_close: false,
            },
            Case {
                head:
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: , CHUNKED\r\nContent-Length: 5\r\n\r\n",
                framing: BodyFraming::Chunked,
                connection_close: false,
            },
            Case {
                head:
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: junk\r\n\r\n",
                framing: BodyFraming::Chunked,
                connection_close: false,
            },
            Case {
                head:
                    b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: keep-alive, close\r\n\r\n",
                framing: BodyFraming::ContentLength(7),
                connection_close: true,
            },
            Case {
                head: b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n",
                framing: BodyFraming::ContentLength(7),
                connection_close: true,
            },
            Case {
                head: b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n",
                framing: BodyFraming::ContentLength(7),
                connection_close: true,
            },
            Case {
                head: b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\n\r\n",
                framing: BodyFraming::ContentLength(7),
                connection_close: true,
            },
            Case {
                head: b"HTTP/1.0 200 OK\r\nContent-Length: 7\r\nConnection: Keep-Alive\r\n\r\n",
                framing: BodyFraming::ContentLength(7),
                connection_close: false,
            },
        ];
        for case in cases {
            let head = case.head;
            let resp = parse_upstream_response(head, head.len(), PreciseInstant::now())
                .expect("every case is a syntactically valid head");
            assert_eq!(
                resp.framing,
                case.framing,
                "framing for {:?}",
                head.escape_ascii().to_string()
            );
            assert_eq!(
                resp.content_length(),
                match case.framing {
                    BodyFraming::ContentLength(n) => Some(n),
                    BodyFraming::Chunked | BodyFraming::CloseDelimited => None,
                },
                "content_length() for {:?}",
                head.escape_ascii().to_string()
            );
            assert_eq!(
                resp.connection_close,
                case.connection_close,
                "connection_close for {:?}",
                head.escape_ascii().to_string()
            );
        }
    }

    /// A head whose framing headers a client could read differently from
    /// the relay is refused outright, not resolved: the pass-through relays
    /// announce only the framing resolved here, so refusing is what keeps a
    /// forged response from riding in a body's tail.
    #[test]
    fn parse_upstream_response_refuses_ambiguous_framing() {
        for (head, reason) in [
            (
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"[..],
                "unsupported Transfer-Encoding `gzip, chunked` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
                "unsupported Transfer-Encoding `gzip, chunked` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
                "unsupported Transfer-Encoding `chunked, chunked` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
                "unsupported Transfer-Encoding `gzip` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \r\n\r\n",
                "unsupported Transfer-Encoding `` from upstream",
            ),
            (
                b"HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: identity\r\n\r\n",
                "unsupported Transfer-Encoding `identity` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Length: 10\r\n\r\n",
                "conflicting Content-Length values 100 and 10 from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\n",
                "conflicting Content-Length values 5 and 6 from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n",
                "unparsable Content-Length `abc` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n",
                "unparsable Content-Length `+5` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n",
                "unparsable Content-Length `-5` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5,\r\n\r\n",
                "unparsable Content-Length `5,` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n",
                "unparsable Content-Length `` from upstream",
            ),
            (
                b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                "Transfer-Encoding in an HTTP/1.0 response from upstream",
            ),
            (
                b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\n",
                "Transfer-Encoding in an HTTP/1.0 response from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0x10\r\n\r\n",
                "unparsable Content-Length `0x10` from upstream",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
                "unparsable Content-Length `99999999999999999999` from upstream",
            ),
        ] {
            let err = parse_upstream_response(head, head.len(), PreciseInstant::now())
                .err()
                .expect("an ambiguous framing must be refused");
            assert_eq!(err, reason, "{:?}", head.escape_ascii().to_string());
        }
    }

    /// `MAX_UPSTREAM_HEADERS` is the httparse slot count: exactly that many
    /// headers parse, one more is a parse failure.
    #[test]
    fn parse_upstream_response_header_count_cap() {
        let build = |count: usize| {
            let mut buf = b"HTTP/1.1 200 OK\r\n".to_vec();
            for i in 0..count {
                buf.extend_from_slice(format!("X-H{i}: v\r\n").as_bytes());
            }
            buf.extend_from_slice(b"\r\n");
            buf
        };

        let at_cap = build(MAX_UPSTREAM_HEADERS);
        assert!(
            parse_upstream_response(&at_cap, at_cap.len(), PreciseInstant::now()).is_ok(),
            "exactly MAX_UPSTREAM_HEADERS headers must parse"
        );

        let over_cap = build(MAX_UPSTREAM_HEADERS + 1);
        // `UpstreamResponse` is not `Debug`, so go through `Option`.
        let err = parse_upstream_response(&over_cap, over_cap.len(), PreciseInstant::now())
            .err()
            .expect("one header over the slot count must fail to parse");
        assert_eq!(err, "failed to parse upstream response headers");
    }

    // Feed one buffer through a decoder, collecting the reported payload
    // ranges as bytes (what the buffered reader appends) alongside the
    // consumption report (what the streaming relay forwards `[..raw]` of).
    fn feed_collect(
        decoder: &mut ChunkDecoder,
        input: &[u8],
    ) -> Result<(Vec<u8>, Consumed), ChunkDecodeError> {
        let mut body = Vec::new();
        let consumed = decoder.feed(input, |payload| body.extend_from_slice(&input[payload]))?;
        Ok((body, consumed))
    }

    // Drive a fresh decoder over a single input buffer.
    fn dechunk_once(
        input: &[u8],
        max_bytes: usize,
    ) -> Result<(Vec<u8>, Consumed), ChunkDecodeError> {
        let mut decoder = ChunkDecoder::new(max_bytes);
        feed_collect(&mut decoder, input)
    }

    fn assert_framing_error(err: &ChunkDecodeError) {
        assert!(
            matches!(err, ChunkDecodeError::Framing(reason) if reason.starts_with("chunked encoding:")),
            "expected a chunked-framing error, got {err:?}",
        );
    }

    #[test]
    fn test_chunk_decoder_consumes_closing_crlf() {
        // Well-formed chunked body: one 5-byte chunk "hello", then terminator.
        // The decoder must consume every byte (including the final \r\n) so
        // the upstream socket buffer is left empty and the connection can be
        // returned to the pool.
        let input: &[u8] = b"5\r\nhello\r\n0\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert_eq!(body, b"hello");
        assert_eq!(
            consumed,
            Consumed {
                raw: input.len(),
                done: true
            },
            "decoder must consume every byte of the chunked frame, including the closing CRLF",
        );
    }

    #[test]
    fn test_chunk_decoder_empty_body() {
        // `0\r\n\r\n` -- a body that is purely the terminal chunk. Must
        // consume all 5 bytes and produce an empty body.
        let input: &[u8] = b"0\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert!(
            body.is_empty(),
            "empty chunked body should decode to no bytes"
        );
        assert_eq!(consumed, Consumed { raw: 5, done: true });
    }

    #[test]
    fn test_chunk_decoder_multi_chunk() {
        // Two data chunks then terminator.
        let input: &[u8] = b"3\r\nfoo\r\n4\r\nbarz\r\n0\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert_eq!(body, b"foobarz");
        assert_eq!(
            consumed,
            Consumed {
                raw: input.len(),
                done: true
            }
        );
    }

    #[test]
    fn test_chunk_decoder_rejects_trailer_fields() {
        // Trailer fields between `0\r\n` and the final `\r\n` are not
        // supported. A header line starting with `X` after `0\r\n` must be
        // rejected because the byte after `0\r\n` is expected to be `\r`.
        let input: &[u8] = b"0\r\nX-Trailer: foo\r\n\r\n";
        let err = dechunk_once(input, 1024).expect_err("trailer fields must be rejected");
        assert_framing_error(&err);
    }

    #[test]
    fn test_chunk_decoder_rejects_garbage_after_zero_chunk() {
        // The bytes following `0\r\n` must be exactly `\r\n`. Garbage in
        // place of the CR triggers a framing error rather than silently
        // succeeding (the pre-fix decoder did the latter, leaving the
        // garbage in the upstream socket buffer).
        let input: &[u8] = b"0\r\nXY";
        let err = dechunk_once(input, 1024).expect_err("garbage after 0-chunk must be rejected");
        assert_framing_error(&err);
    }

    #[test]
    fn test_chunk_decoder_split_closing_crlf() {
        // The closing `\r\n` arrives in two separate buffers (the `\r` in
        // one read, the `\n` in the next). Verifies `Done { remaining }`
        // correctly counts down across buffer boundaries.
        let mut decoder = ChunkDecoder::new(1024);

        // First buffer: data chunk + terminal `0\r\n` + the `\r` of the
        // closing CRLF (1 byte short of the full terminator).
        let part1: &[u8] = b"5\r\nhello\r\n0\r\n\r";
        let (body1, c1) = feed_collect(&mut decoder, part1).expect("part1 decode");
        assert_eq!(body1, b"hello");
        assert_eq!(
            c1,
            Consumed {
                raw: part1.len(),
                done: false
            },
            "after part1 the decoder must still be waiting for one more byte (the LF)",
        );
        assert!(matches!(decoder.state, ChunkedState::Done { remaining: 1 }));

        // Second buffer: just the `\n` that finishes the closing CRLF.
        let part2: &[u8] = b"\n";
        let (body2, c2) = feed_collect(&mut decoder, part2).expect("part2 decode");
        assert_eq!(body2, b"");
        assert_eq!(c2, Consumed { raw: 1, done: true });
    }

    #[test]
    fn test_chunk_decoder_stops_at_done_leaves_trailing_bytes() {
        // After fully consuming `0\r\n\r\n` the decoder must stop and
        // leave any trailing bytes in the input unconsumed -- the I/O
        // wrappers turn that into a framing-violation error (via
        // `Consumed::ensure_no_trailing_bytes`) so a misbehaving upstream
        // cannot poison the connection pool. The streaming relay relies on
        // `raw` stopping there to forward only the validated prefix.
        let input: &[u8] = b"0\r\n\r\nGARBAGE";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert_eq!(body, [] as [u8; 0]);
        assert_eq!(
            consumed,
            Consumed { raw: 5, done: true },
            "decoder must stop right after the closing CRLF, not swallow trailing bytes",
        );
        let reason = consumed
            .ensure_no_trailing_bytes(input.len())
            .expect_err("trailing bytes after the terminator must be rejected");
        assert_eq!(
            reason,
            "chunked encoding: trailing bytes after 0-length chunk"
        );
        // A frame that ends exactly at the terminator passes the check.
        consumed
            .ensure_no_trailing_bytes(5)
            .expect("no trailing bytes when the input ends at the terminator");
        // An unfinished frame never trips it, whatever the input length.
        Consumed {
            raw: 3,
            done: false,
        }
        .ensure_no_trailing_bytes(3)
        .expect("unfinished frames are not checked for trailing bytes");
    }

    #[test]
    fn test_chunk_decoder_chunk_extensions_ignored() {
        // RFC 9112 allows chunk extensions after `;` on the chunk-size
        // line; they must be parsed and ignored.
        let input: &[u8] = b"5;ext=foo\r\nhello\r\n0;final\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert_eq!(body, b"hello");
        assert_eq!(
            consumed,
            Consumed {
                raw: input.len(),
                done: true
            }
        );
    }

    /// The chunk-size line is RFC 9112 §7.1's `1*HEXDIG [ BWS ";" chunk-ext ]
    /// CRLF` and nothing more lenient: a sign, surrounding whitespace, a hex
    /// prefix, or a bare CR/LF anywhere in the line would let a client that
    /// parses the line differently find a different chunk boundary than the
    /// relay did.
    #[test]
    fn chunk_size_line_accepts_only_the_rfc_grammar() {
        for line in [
            &b"5"[..],
            b"05",
            b"0000000000000005",
            b"5;ext",
            b"5;ext=foo",
            b"5 ;ext",
            b"5\t; ext = \"v\"",
            b"5;ext=\"a;b\"",
            b"5;ext=\xc3\xa9",
        ] {
            let mut input = line.to_vec();
            input.extend_from_slice(b"\r\nhello\r\n0\r\n\r\n");
            let result = dechunk_once(&input, 1024);
            assert!(
                result.is_ok(),
                "{:?} must be accepted, got {result:?}",
                line.escape_ascii().to_string()
            );
            let (body, consumed) = result.expect("asserted above");
            assert_eq!(body, b"hello", "{:?}", line.escape_ascii().to_string());
            assert!(consumed.done, "{:?}", line.escape_ascii().to_string());
        }
        let (body, _) = dechunk_once(b"A\r\n0123456789\r\n0\r\n\r\n", 1024).expect("upper hex");
        assert_eq!(body, b"0123456789");
        let (body, _) = dechunk_once(b"a\r\n0123456789\r\n0\r\n\r\n", 1024).expect("lower hex");
        assert_eq!(body, b"0123456789");

        for line in [
            &b"+5"[..],
            b"-5",
            b" 5",
            b"\t5",
            b"5 ",
            b"5\t",
            b"5 5",
            b"\xc2\xa05",
            b"5\xc2\xa0",
            b"0x5",
            b"",
            b";ext",
            b"5;a\rb",
            b"5;\x00",
            b"5;\x7f",
            b"5\r",
            b"ffffffffffffffffff",
        ] {
            let mut input = line.to_vec();
            input.extend_from_slice(b"\r\nhello\r\n0\r\n\r\n");
            let err = dechunk_once(&input, 1024).expect_err(&format!(
                "{:?} must be rejected",
                line.escape_ascii().to_string()
            ));
            assert_framing_error(&err);
        }

        // A bare LF ends no chunk-size line, not even inside an extension:
        // a lenient client would take the bytes after it as chunk data.
        for input in [
            &b"5\nhello\r\n0\r\n\r\n"[..],
            b"5;ext\nhello\r\n0\r\n\r\n",
            b"5;ext\n0\r\n\r\nX\r\n",
        ] {
            let err = dechunk_once(input, 1024).expect_err(&format!(
                "{:?} must be rejected",
                input.escape_ascii().to_string()
            ));
            assert_framing_error(&err);
        }
        // Rejected on sight, without waiting for a CRLF that may never come.
        let err = dechunk_once(b"5;ext\n", 1024).expect_err("bare LF rejected on sight");
        assert_framing_error(&err);
    }

    #[test]
    fn test_chunk_decoder_size_line_split_across_reads() {
        // The chunk-size line arrives one byte per read, including a split
        // between its `\r` and `\n`; `size_buf` accumulates across feeds.
        let mut decoder = ChunkDecoder::new(1024);
        let mut body = Vec::new();
        for part in [&b"a"[..], b";", b"x", b"\r", b"\n"] {
            let (payload, consumed) = feed_collect(&mut decoder, part).expect("size line piece");
            assert_eq!(payload, b"");
            assert_eq!(
                consumed,
                Consumed {
                    raw: 1,
                    done: false
                }
            );
            body.extend_from_slice(&payload);
        }
        assert!(matches!(
            decoder.state,
            ChunkedState::ReadingData { remaining: 10 }
        ));
        let (payload, consumed) =
            feed_collect(&mut decoder, b"0123456789\r\n0\r\n\r\n").expect("rest of the frame");
        body.extend_from_slice(&payload);
        assert_eq!(body, b"0123456789");
        assert_eq!(
            consumed,
            Consumed {
                raw: 17,
                done: true
            }
        );
    }

    #[test]
    fn test_chunk_decoder_chunk_data_split_across_reads() {
        // Chunk data and the CRLF after it straddle read boundaries; every
        // feed that does not finish the frame must consume its whole input
        // (the streaming relay forwards `[..raw]` and relies on that), and
        // the payload ranges must add up to exactly the chunk data.
        let mut decoder = ChunkDecoder::new(1024);
        let mut body = Vec::new();
        let parts: [&[u8]; 6] = [
            b"6\r\nab",
            b"cd",
            b"ef\r",
            b"\n3\r\nx",
            b"yz\r\n0\r",
            b"\n\r\n",
        ];
        for (idx, part) in parts.iter().enumerate() {
            let (payload, consumed) = feed_collect(&mut decoder, part).expect("piece decodes");
            body.extend_from_slice(&payload);
            let last = idx + 1 == parts.len();
            assert_eq!(
                consumed,
                Consumed {
                    raw: part.len(),
                    done: last
                },
                "piece {idx} must be consumed whole",
            );
        }
        assert_eq!(body, b"abcdefxyz");
    }

    #[test]
    fn test_chunk_decoder_payload_ranges_are_input_relative() {
        // The ranges handed to `on_payload` index into the fed buffer, one
        // per chunk (or chunk fragment), covering the data bytes only.
        let mut decoder = ChunkDecoder::new(1024);
        let input: &[u8] = b"2\r\nab\r\n3\r\ncde\r\n0\r\n\r\n";
        let mut ranges = Vec::new();
        let consumed = decoder
            .feed(input, |payload| ranges.push(payload))
            .expect("decode succeeds");
        assert_eq!(ranges, [3..5, 10..13]);
        assert_eq!(
            consumed,
            Consumed {
                raw: input.len(),
                done: true
            }
        );
    }

    #[test]
    fn test_chunk_decoder_rejects_bad_byte_after_chunk_data() {
        // The CRLF after chunk data is mandatory; a chunk whose declared
        // size undercounts its data trips the check on the first extra byte.
        let input: &[u8] = b"2\r\nabc\r\n0\r\n\r\n";
        let err = dechunk_once(input, 1024).expect_err("missing CRLF after data must be rejected");
        assert_framing_error(&err);
        // Likewise a lone CR followed by something other than LF.
        let input: &[u8] = b"2\r\nab\rX0\r\n\r\n";
        let err = dechunk_once(input, 1024).expect_err("CR without LF must be rejected");
        assert_framing_error(&err);
    }

    #[test]
    fn test_chunk_decoder_rejects_invalid_size_line() {
        // Non-hex size digits and a non-UTF-8 size line are both framing
        // errors; an overlong size line is cut off at 64 bytes without
        // waiting for its CRLF.
        let err = dechunk_once(b"zz\r\n", 1024).expect_err("non-hex size must be rejected");
        assert_framing_error(&err);
        let err = dechunk_once(b"\xff\r\n", 1024).expect_err("non-UTF-8 size must be rejected");
        assert_framing_error(&err);
        let long_line = [b'1'; 65];
        let err = dechunk_once(&long_line, 1024).expect_err("overlong size line must be rejected");
        assert_framing_error(&err);
        // 64 bytes without a CRLF are still tolerated (the cap is `> 64`).
        let (body, consumed) =
            dechunk_once(&long_line[..64], 1024).expect("64-byte size line still pending");
        assert_eq!(body, b"");
        assert_eq!(
            consumed,
            Consumed {
                raw: 64,
                done: false
            }
        );
    }

    #[test]
    fn test_chunk_decoder_size_cap() {
        // The cap applies to the declared payload total at each size line:
        // a frame whose chunks sum to exactly `max_bytes` passes, one byte
        // more is refused before any of that chunk's data is consumed, and
        // the error is distinct from a framing violation so the I/O
        // wrappers can add their own error context.
        let input: &[u8] = b"3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 6).expect("exactly at the cap is fine");
        assert_eq!(body, b"foobar");
        assert!(consumed.done);

        let err = dechunk_once(input, 5).expect_err("one byte over the cap must be refused");
        assert!(
            matches!(
                err,
                ChunkDecodeError::SizeCap {
                    max_bytes: 5,
                    declared_bytes: 6
                }
            ),
            "expected SizeCap, got {err:?}",
        );
    }
}
