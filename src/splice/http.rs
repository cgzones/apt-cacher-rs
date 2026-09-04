//! HTTP/1.1 wire handling between the splice proxy and upstream:
//! [`format_http_request`]/[`send_and_read_headers`] on the request side,
//! [`parse_upstream_response`] into [`UpstreamResponse`] on the response
//! side, and the body relays hanging off [`BodyFraming`] (`relay_to_client`,
//! `read_to_vec`) that stream or buffer a body according to its framing.
//! [`ChunkDecoder`] is the one chunked transfer-coding state machine;
//! [`forward_upstream_chunked_body`] and [`read_dechunk_body_to_vec`] are its
//! I/O wrappers.
//!
//! Consumers: `acquire` and `ktls_path` (request/parse), the drive in
//! `mod.rs` and `volatile`/`simple_proxy`/`cleanup_bridge` (framing relays).

use std::{io::ErrorKind, num::Saturating, ops::Range, time::Duration};

use bytes::BytesMut;
use http::{
    StatusCode,
    header::{
        CONNECTION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, LAST_MODIFIED, LOCATION,
        TRANSFER_ENCODING,
    },
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
};

use crate::cache_layout::ConnectionDetails;
use crate::error::ErrorReport;
use crate::http_helpers::{ConnectionAction, OptHeader, find_header, find_header_end};
use crate::http_range::parse_content_range;
use crate::humanfmt::HumanFmt;
use crate::limits::{MAX_UPSTREAM_HEADER_SIZE, MAX_UPSTREAM_HEADERS};
use crate::precise_instant::PreciseInstant;
use crate::rate_checker::{RateCheckDirection, RateChecker};
use crate::sendfile_conn::write_all_to_stream_rated;
use crate::upstream_head::{RejectReason, UpstreamHead};
use crate::{
    build_info::APP_USER_AGENT,
    cache_metadata::{self, InvalidValidator},
    global_config, metrics, warn_once_or_info,
};

use super::VolatileCondHeaders;
use super::upstream::{PoolGuard, TLS_READ_BUF_SIZE, UnconsumedBodyGuard, UpstreamConn};

/// Format an HTTP GET request for the upstream mirror.
pub(super) fn format_http_request(
    path: &str,
    host_authority: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
    connection: ConnectionAction,
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
            "If-Modified-Since: {}\r\nCache-Control: max-age=300\r\n{}",
            vc.if_modified_since,
            OptHeader("If-None-Match", vc.if_none_match.as_deref())
        ),
        None => String::new(),
    };

    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_authority}\r\n\
         User-Agent: {APP_USER_AGENT}\r\n\
         Connection: {connection}\r\n\
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
        ConnectionAction::KeepAlive,
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
) -> std::io::Result<usize> {
    let http_timeout = global_config().http_timeout;
    let deadline = tokio::time::sleep(http_timeout);
    tokio::pin!(deadline);

    // Incremental scan offset: bytes before this index were already checked for
    // the \r\n\r\n terminator on a prior iteration. Subtract 3 so a terminator
    // that straddles the read boundary is still found. Mirrors the kTLS
    // Phase-3 header-read loop (`header_search_offset` in `unbuffered_ktls_request`).
    let mut search_offset = 0usize;

    loop {
        let read_fut = upstream.read_buf(buf);
        tokio::pin!(read_fut);
        let n = tokio::select! {
            biased;
            r = &mut read_fut => r?,
            () = &mut deadline => {
                metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "timed out reading upstream response headers after {}",
                        HumanFmt::Time(http_timeout)
                    ),
                ));
            }
        };

        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "upstream closed before sending complete headers",
            ));
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
            warn_once_or_info!(
                "splice proxy: upstream response header size of {} bytes exceeds {} bytes; aborting the upstream request",
                buf.len(),
                MAX_UPSTREAM_HEADER_SIZE
            );
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "upstream response headers too large",
            ));
        }
    }
}

/// How an upstream HTTP response body is framed on the wire.
///
/// Resolved once by [`parse_upstream_response`] with chunked-takes-precedence
/// semantics (RFC 9112 §6.1): when `Transfer-Encoding: chunked` is present its
/// framing wins and any accompanying `Content-Length` is ignored. Modelling the
/// two as one sum type means "both at once" is no longer representable, so every
/// consumer reads a single, already-disambiguated framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BodyFraming {
    /// `Content-Length: N` and not chunked. Splice-eligible when `N > 0`.
    ContentLength(u64),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Neither header present: the body runs until the connection closes.
    CloseDelimited,
}

impl BodyFraming {
    /// Relay the response body to the client, framed per `self`, and return
    /// the number of body bytes sent (`body_prefix` included).
    ///
    /// The single owner of the "half-read connection must not re-enter the
    /// pool" rule for relayed bodies: an [`UnconsumedBodyGuard`] poisons the
    /// upstream on every error path and is defused only when a
    /// length-delimited or chunked body was consumed to its terminator. A
    /// close-delimited body never defuses it - the upstream closes anyway.
    pub(super) async fn relay_to_client(
        self,
        upstream: &mut PoolGuard,
        client_stream: &TcpStream,
        body_prefix: &[u8],
        max_bytes: usize,
    ) -> std::io::Result<u64> {
        /// Write the bytes that arrived with the headers, rate-checked.
        async fn write_prefix(
            client_stream: &TcpStream,
            body_prefix: &[u8],
        ) -> std::io::Result<()> {
            if body_prefix.is_empty() {
                return Ok(());
            }
            let config = global_config();
            let mut rate_checker = RateChecker::from_config(config);
            write_all_to_stream_rated(
                client_stream,
                body_prefix,
                &mut rate_checker,
                RateCheckDirection::Client,
                config.http_timeout,
            )
            .await?;
            metrics::BYTES_SERVED_PASSTHROUGH.increment_by(body_prefix.len() as u64);
            Ok(())
        }

        let mut guard = UnconsumedBodyGuard::new(upstream);
        let prefix_len = body_prefix.len() as u64;
        match self {
            Self::ContentLength(cl) => {
                write_prefix(client_stream, body_prefix).await?;
                let remaining = cl.saturating_sub(prefix_len);
                let forwarded = if remaining > 0 {
                    forward_upstream_body(&mut guard, client_stream, remaining).await?
                } else {
                    0
                };
                guard.consumed();
                Ok(prefix_len + forwarded)
            }
            Self::Chunked => {
                // Raw framing is forwarded unchanged; the helper consumes the
                // closing CRLF after the `0` chunk, so the connection stays
                // reusable on success.
                let forwarded = forward_upstream_chunked_body(
                    &mut guard,
                    client_stream,
                    body_prefix,
                    max_bytes,
                )
                .await?;
                guard.consumed();
                Ok(forwarded)
            }
            Self::CloseDelimited => {
                write_prefix(client_stream, body_prefix).await?;
                let forwarded =
                    forward_upstream_body_until_eof(&mut guard, client_stream, max_bytes).await?;
                Ok(prefix_len + forwarded)
            }
        }
    }

    /// Read the whole response body into memory, framed per `self`, up to
    /// `max_bytes` of payload (`body_prefix` included).
    ///
    /// Same poolability contract as [`Self::relay_to_client`]: the upstream
    /// is poisoned on every error and for close-delimited bodies, and stays
    /// reusable only after a length-delimited or chunked body was consumed
    /// to its terminator.
    pub(super) async fn read_to_vec(
        self,
        upstream: &mut PoolGuard,
        body_prefix: &[u8],
        max_bytes: usize,
    ) -> std::io::Result<Vec<u8>> {
        let mut guard = UnconsumedBodyGuard::new(upstream);
        match self {
            Self::Chunked => {
                let body = read_dechunk_body_to_vec(&mut guard, body_prefix, max_bytes).await?;
                guard.consumed();
                Ok(body)
            }
            Self::ContentLength(cl) => {
                let body =
                    read_body_to_vec_with_content_length(&mut guard, body_prefix, cl, max_bytes)
                        .await?;
                guard.consumed();
                Ok(body)
            }
            Self::CloseDelimited => {
                read_body_to_vec_until_eof(&mut guard, body_prefix, max_bytes).await
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
    /// window. `None` only on responses built by the bare parser in tests.
    pub(super) request_sent_at: Option<PreciseInstant>,
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
    pub(super) fn head(&self) -> UpstreamHead {
        UpstreamHead {
            status: self.status_code,
            content_length: self.content_length(),
            content_range: self.content_range.as_deref().and_then(parse_content_range),
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
                    "splice proxy: upstream mirror {} sent an invalid ETag `{etag}` for {}; discarding it",
                    conn_details.mirror,
                    conn_details.debname
                ),
                InvalidValidator::LastModified(lm) => warn_once_or_info!(
                    "splice proxy: upstream mirror {} sent an invalid Last-Modified `{lm}` for {}; discarding it",
                    conn_details.mirror,
                    conn_details.debname
                ),
            },
        );
        self.etag = etag;
        self.last_modified = last_modified;
    }
}

/// Parse upstream HTTP response headers.
///
/// Does **not** record the upstream status metric — callers must call
/// `metrics::record_upstream_status` themselves once the response is going
/// to be honored. The kTLS path may parse a response that is then thrown
/// away in favor of a standard-path reconnect (`ResponseNotSpliceable`); a
/// metric bump here would double-count for that flow.
pub(super) fn parse_upstream_response(
    buf: &[u8],
    header_end: usize,
    host_authority: &str,
) -> std::io::Result<UpstreamResponse> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_UPSTREAM_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);

    match resp.parse(&buf[..header_end]) {
        Ok(httparse::Status::Complete(_)) => {}
        _ => {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "failed to parse upstream response headers",
            ));
        }
    }

    let raw_code = resp.code.expect("complete header parsed");
    let status_code = StatusCode::from_u16(raw_code).map_err(|_err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            "invalid HTTP status code from upstream",
        )
    })?;

    let headers = resp.headers;

    // A present-but-unparsable Content-Length (junk, a folded duplicate like
    // `100, 100`, non-UTF8) silently degrades framing to close-delimited:
    // permanent files then 502 with "no Content-Length" (reading as if the
    // header were absent), volatile ones take the buffered path, and
    // passthrough burns the pooled connection. It is also a response-
    // smuggling signal, so say the value out loud.
    let content_length = find_header(headers, &CONTENT_LENGTH).and_then(|v| {
        let parsed = v.trim().parse::<u64>().ok();
        if parsed.is_none() {
            warn_once_or_info!(
                "splice proxy: upstream {host_authority} sent an unparsable Content-Length `{}`; treating the body as close-delimited",
                v.escape_debug()
            );
        }
        parsed
    });

    let content_type = find_header(headers, &CONTENT_TYPE).map(String::from);

    // Raw values: `UpstreamResponse::discard_invalid_validators` filters them
    // once the driver knows which file they belong to.
    let last_modified = find_header(headers, &LAST_MODIFIED).map(String::from);

    let etag = find_header(headers, &ETAG).map(String::from);

    let content_range = find_header(headers, &CONTENT_RANGE).map(String::from);

    let location = find_header(headers, &LOCATION).map(String::from);

    let connection_close = find_header(headers, &CONNECTION)
        .is_some_and(|s| s.split(',').any(|v| v.trim().eq_ignore_ascii_case("close")));

    let is_chunked = find_header(headers, &TRANSFER_ENCODING).is_some_and(|s| {
        s.split(',')
            .any(|v| v.trim().eq_ignore_ascii_case("chunked"))
    });

    // RFC 9112 §6.1: chunked framing takes precedence; a `Content-Length` sent
    // alongside `Transfer-Encoding: chunked` must be ignored (defense against
    // response smuggling). Resolve the precedence once, here, so no consumer
    // can observe both at the same time.
    let framing = if is_chunked {
        BodyFraming::Chunked
    } else if let Some(len) = content_length {
        BodyFraming::ContentLength(len)
    } else {
        BodyFraming::CloseDelimited
    };

    // RFC 9112 §6.3: 1xx, 204, and 304 responses never carry a message body,
    // regardless of Content-Length / Transfer-Encoding headers. Force
    // zero-length framing so relay/consumer paths do not read-until-EOF
    // (stalling a keep-alive upstream) or mis-frame a bodyless response.
    let framing = if status_code.is_informational()
        || status_code == StatusCode::NO_CONTENT
        || status_code == StatusCode::NOT_MODIFIED
    {
        BodyFraming::ContentLength(0)
    } else {
        framing
    };

    Ok(UpstreamResponse {
        status_code,
        framing,
        content_type,
        last_modified,
        etag,
        content_range,
        location,
        connection_close,
        request_sent_at: None,
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
) -> Result<(UpstreamResponse, BytesMut, usize), std::io::Error> {
    send_upstream_request(
        up,
        host_authority,
        upstream_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
    )
    .await?;
    let request_sent_at = PreciseInstant::now();

    let mut hdr_buf = BytesMut::with_capacity(MAX_UPSTREAM_HEADER_SIZE);
    let hdr_end = read_upstream_response_headers(up, &mut hdr_buf).await?;
    let mut resp = parse_upstream_response(&hdr_buf, hdr_end, host_authority).inspect_err(|err| {
        metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
        warn_once_or_info!(
            "splice proxy: upstream {host_authority} sent malformed HTTP; failing the upstream request:  {}",
            ErrorReport(err)
        );
    })?;
    // Credit body bytes that arrived bundled with the response headers
    // in the same read (the body_prefix). Done after parse so an
    // unparsable response is not credited as a successful download —
    // mirrors `record_upstream_status` below. Subsequent reads of
    // remaining body bytes credit themselves separately.
    let body_prefix_len = (hdr_buf.len() - hdr_end) as u64;
    if body_prefix_len > 0 {
        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(body_prefix_len);
    }
    metrics::record_upstream_status(resp.status_code);
    resp.request_sent_at = Some(request_sent_at);
    Ok((resp, hdr_buf, hdr_end))
}

/// Forward remaining body bytes from upstream to client (no caching).
/// Used for relaying bodies verbatim: non-200 responses on the cache path
/// and any status via `splice_simple_proxy`.
/// On error the connection state is indeterminate -- callers must mark the upstream non-poolable.
async fn forward_upstream_body(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    count: u64,
) -> std::io::Result<u64> {
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
        let n = match tokio::time::timeout(
            config.http_timeout,
            (&mut *upstream).take(to_read).read_buf(&mut buf),
        )
        .await
        {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "upstream closed before sending complete body",
                ));
            }
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "upstream read timed out during body forward after {}",
                        HumanFmt::Time(config.http_timeout)
                    ),
                ));
            }
        };

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        if let Some(ref mut rc) = rate_checker {
            rc.add(n);
            if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                return Err(rate.to_timeout_io_error(format_args!(" for upstream")));
            }
        }

        write_all_to_stream_rated(
            client,
            &buf,
            &mut client_rate_checker,
            RateCheckDirection::Client,
            config.http_timeout,
        )
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
) -> std::io::Result<u64> {
    let config = global_config();
    let mut buf = BytesMut::with_capacity(TLS_READ_BUF_SIZE);
    let mut total = 0;
    let mut rate_checker = RateChecker::from_config(config);
    let mut client_rate_checker = RateChecker::from_config(config);

    loop {
        buf.clear();
        let n = match tokio::time::timeout(config.http_timeout, upstream.read_buf(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "upstream read timed out during body forward after {}",
                        HumanFmt::Time(config.http_timeout)
                    ),
                ));
            }
        };

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        total += n as u64;
        if total > max_bytes as u64 {
            warn_once_or_info!(
                "splice proxy: upstream error response body exceeded {} byte cap; truncating the relayed body",
                max_bytes
            );
            return Err(std::io::Error::other(
                "upstream error response body exceeded size cap",
            ));
        }

        if let Some(ref mut rc) = rate_checker {
            rc.add(n);
            if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                return Err(rate.to_timeout_io_error(format_args!(" for upstream")));
            }
        }

        write_all_to_stream_rated(
            client,
            &buf[..n],
            &mut client_rate_checker,
            RateCheckDirection::Client,
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
    /// does not log this: the two I/O wrappers word the line differently
    /// (relayed body vs volatile body) and each keeps its own
    /// `warn_once_or_info!` gate.
    SizeCap { max_bytes: usize },
    /// A framing violation; `UPSTREAM_PROTOCOL_VIOLATION` has been bumped.
    Framing(std::io::Error),
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
    fn ensure_no_trailing_bytes(self, data_len: usize) -> std::io::Result<()> {
        let Self { raw, done } = self;
        if done && raw < data_len {
            metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "chunked encoding: trailing bytes after 0-length chunk",
            ));
        }
        Ok(())
    }
}

/// Incremental decoder for the chunked transfer coding (RFC 9112 section 7.1).
///
/// The single framing implementation behind both the streaming relay
/// [`forward_upstream_chunked_body`] (which forwards the raw encoding
/// unchanged and only needs to know where the body ends) and the buffered
/// reader [`read_dechunk_body_to_vec`] (which collects the decoded payload).
/// Chunk extensions after `;` are ignored; trailer fields between `0\r\n`
/// and the final `\r\n` are rejected as a framing sanity check rather than
/// skipped, to catch truncation and smuggling. The declared payload total is
/// checked against `max_bytes` at every chunk-size line.
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
            metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
            ChunkDecodeError::Framing(std::io::Error::new(ErrorKind::InvalidData, msg))
        }

        let mut i = 0usize;
        while i < data.len() {
            match self.state {
                ChunkedState::ReadingSize => {
                    let b = data[i];
                    i += 1;
                    self.size_buf.push(b);
                    if b == b'\n'
                        && self.size_buf.len() >= 2
                        && self.size_buf[self.size_buf.len() - 2] == b'\r'
                    {
                        // Parse the hex chunk size; ignore optional chunk
                        // extensions after ';'.
                        let line = &self.size_buf[..self.size_buf.len() - 2];
                        let hex_end = line.iter().position(|&c| c == b';').unwrap_or(line.len());
                        let hex_str = std::str::from_utf8(&line[..hex_end]).map_err(|_err| {
                            framing_violation("chunked encoding: invalid chunk-size line")
                        })?;
                        let chunk_size =
                            usize::from_str_radix(hex_str.trim(), 16).map_err(|_err| {
                                framing_violation("chunked encoding: invalid chunk-size hex")
                            })?;
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

/// One buffer's worth of [`forward_upstream_chunked_body`]: validate the
/// framing, then forward the validated raw bytes to the client. Returns
/// `true` once the terminator has been consumed.
///
/// Framing is validated before anything is forwarded, so the client never
/// receives bytes past a detected framing error: on invalid framing the
/// caller's error-return path closes the client connection, and without the
/// pre-check the client would first receive the corrupt bytes and only then
/// see the connection drop. When the terminator is consumed only the
/// validated prefix `data[..raw]` goes out; bytes past the closing `\r\n`
/// are rejected afterwards by [`Consumed::ensure_no_trailing_bytes`].
async fn forward_chunked_buf(
    decoder: &mut ChunkDecoder,
    data: &[u8],
    client: &TcpStream,
    client_rate_checker: &mut Option<RateChecker>,
    client_total: &mut u64,
    http_timeout: Duration,
) -> std::io::Result<bool> {
    let consumed = match decoder.feed(data, |_payload| {}) {
        Ok(consumed) => consumed,
        Err(ChunkDecodeError::SizeCap { max_bytes }) => {
            warn_once_or_info!(
                "splice proxy: chunked response body exceeded {} byte cap; truncating the relayed body",
                max_bytes
            );
            return Err(std::io::Error::other(
                "chunked response body exceeded size cap",
            ));
        }
        Err(ChunkDecodeError::Framing(err)) => return Err(err),
    };
    let forward_slice = &data[..consumed.raw];
    if !forward_slice.is_empty() {
        write_all_to_stream_rated(
            client,
            forward_slice,
            client_rate_checker,
            RateCheckDirection::Client,
            http_timeout,
        )
        .await
        .map_err(|e| {
            std::io::Error::new(e.kind(), format!("chunked forward: client write:  {e}"))
        })?;
        metrics::BYTES_SERVED_PASSTHROUGH.increment_by(forward_slice.len() as u64);
        *client_total += forward_slice.len() as u64;
    }
    consumed.ensure_no_trailing_bytes(data.len())?;
    Ok(consumed.done)
}

/// Forward a chunked transfer-encoded body from upstream to client.
///
/// All raw bytes (chunk-size lines, data, CRLFs) are forwarded unchanged.
/// The [`ChunkDecoder`] only tracks framing to detect the terminating
/// zero-length chunk, so the connection can be reused afterwards.
///
/// On success the closing `\r\n` after the `0\r\n` terminator has been fully
/// consumed from the upstream socket buffer, so the connection can be safely
/// returned to the pool (the buffered variant [`read_dechunk_body_to_vec`]
/// shares the decoder and therefore the terminator policy). On error the
/// connection state is indeterminate -- callers must mark the upstream
/// non-poolable.
async fn forward_upstream_chunked_body(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    body_prefix: &[u8],
    max_bytes: usize,
) -> std::io::Result<u64> {
    let config = global_config();
    let mut rate_checker = RateChecker::from_config(config);
    let mut client_rate_checker = RateChecker::from_config(config);

    let mut decoder = ChunkDecoder::new(max_bytes);
    // Tracks raw bytes (framing + data) written to the client.
    let mut client_total: u64 = 0;

    // Bootstrap: process bytes that arrived with the response headers.
    if forward_chunked_buf(
        &mut decoder,
        body_prefix,
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
        let n = match tokio::time::timeout(config.http_timeout, upstream.read_buf(&mut buf)).await {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "upstream closed during chunked body transfer",
                ));
            }
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "upstream read timed out during chunked body forward after {}",
                        HumanFmt::Time(config.http_timeout)
                    ),
                ));
            }
        };

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        if let Some(ref mut rc) = rate_checker {
            rc.add(n);
            if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                return Err(rate.to_timeout_io_error(format_args!(" for upstream")));
            }
        }

        if forward_chunked_buf(
            &mut decoder,
            &buf[..n],
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
) -> std::io::Result<Vec<u8>> {
    let config = global_config();
    let size = (prefix.len() + 4096).min(max_bytes.saturating_add(1));
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(prefix);
    let mut rate_checker = RateChecker::from_config(config);

    loop {
        if body.len() > max_bytes {
            warn_once_or_info!(
                "splice proxy: volatile response body exceeded {max_bytes} byte cap; aborting the download"
            );
            return Err(std::io::Error::other(
                "volatile response body exceeded size cap",
            ));
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

        let n = match tokio::time::timeout(
            config.http_timeout,
            (&mut *upstream).take(remaining as u64).read_buf(&mut body),
        )
        .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "upstream read timed out during volatile body buffering after {}",
                        HumanFmt::Time(config.http_timeout)
                    ),
                ));
            }
        };

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        if let Some(ref mut rc) = rate_checker {
            rc.add(n);
            if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                return Err(rate.to_timeout_io_error(format_args!(" for upstream")));
            }
        }
    }

    Ok(body)
}

/// Read an upstream body with known `Content-Length` into a `Vec<u8>`.
async fn read_body_to_vec_with_content_length(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    content_length: u64,
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let content_length = usize::try_from(content_length).map_err(|_err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            "content-length value too large to fit in memory address space",
        )
    })?;
    if content_length > max_bytes {
        return Err(std::io::Error::other(
            "content-length exceeds cleanup buffering cap",
        ));
    }
    if prefix.len() > content_length {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
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
        let n = match tokio::time::timeout(
            config.http_timeout,
            (&mut *upstream).take(remaining as u64).read_buf(&mut body),
        )
        .await
        {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "upstream closed before content-length body completed",
                ));
            }
            Ok(Ok(n)) => n,
            Ok(Err(err)) => return Err(err),
            Err(tokio::time::error::Elapsed { .. }) => {
                metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "upstream read timed out during cleanup body buffering",
                ));
            }
        };

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        if let Some(ref mut rc) = rate_checker {
            rc.add(n);
            if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                return Err(rate.to_timeout_io_error(format_args!(" for upstream")));
            }
        }
    }

    Ok(body)
}

/// Dechunk a chunked-encoded body from upstream into a `Vec<u8>`, up to `max_bytes`
/// of decoded payload.
///
/// On success the closing `\r\n` after the `0\r\n` terminator has been fully
/// consumed from the upstream socket buffer, so the connection can be safely
/// returned to the pool (the streaming variant
/// [`forward_upstream_chunked_body`] shares the [`ChunkDecoder`] and
/// therefore the terminator policy). On error the connection state is
/// indeterminate -- callers must mark the upstream non-poolable.
async fn read_dechunk_body_to_vec(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let config = global_config();
    let mut body = Vec::with_capacity(4096);
    let mut rate_checker = RateChecker::from_config(config);
    let mut decoder = ChunkDecoder::new(max_bytes);
    let mut read_buf = BytesMut::with_capacity(TLS_READ_BUF_SIZE);

    // Process the prefix first, then read from upstream.
    let pending: &[u8] = prefix;
    let mut need_read = prefix.is_empty();

    loop {
        let data = if need_read {
            read_buf.clear();
            let n =
                match tokio::time::timeout(config.http_timeout, upstream.read_buf(&mut read_buf))
                    .await
                {
                    Ok(Ok(0)) => {
                        return Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "upstream closed during chunked body buffering",
                        ));
                    }
                    Ok(Ok(n)) => n,
                    Ok(Err(err)) => return Err(err),
                    Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                        metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                        return Err(std::io::Error::new(
                            ErrorKind::TimedOut,
                            format!(
                                "upstream read timed out during chunked body buffering after {}",
                                HumanFmt::Time(config.http_timeout)
                            ),
                        ));
                    }
                };
            metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);
            if let Some(ref mut rc) = rate_checker {
                rc.add(n);
                if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                    return Err(rate.to_timeout_io_error(format_args!(" for upstream")));
                }
            }
            &read_buf[..n]
        } else {
            need_read = true;
            pending
        };

        let consumed = match decoder.feed(data, |payload| body.extend_from_slice(&data[payload])) {
            Ok(consumed) => consumed,
            Err(ChunkDecodeError::SizeCap { max_bytes }) => {
                warn_once_or_info!(
                    "splice proxy: chunked volatile body exceeded {max_bytes} byte cap; aborting the download"
                );
                return Err(std::io::Error::other(
                    "chunked volatile body exceeded size cap",
                ));
            }
            Err(ChunkDecodeError::Framing(err)) => return Err(err),
        };

        if consumed.done {
            consumed.ensure_no_trailing_bytes(data.len())?;
            break;
        }
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_upstream_response() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 12345\r\n\
                        Content-Type: application/vnd.debian.binary-package\r\n\
                        Last-Modified: Thu, 01 Jan 2025 00:00:00 GMT\r\n\
                        \r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
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
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length(), None);
        assert_eq!(resp.framing, BodyFraming::Chunked);
    }

    #[test]
    fn test_parse_upstream_response_not_chunked() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
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
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.framing, BodyFraming::Chunked);
        assert_eq!(resp.content_length(), None);
    }

    #[test]
    fn parse_upstream_response_close_delimited_without_framing_headers() {
        let headers = b"HTTP/1.1 200 OK\r\n\r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.framing, BodyFraming::CloseDelimited);
        assert_eq!(resp.content_length(), None);
    }

    #[test]
    fn parse_upstream_response_304_is_bodyless() {
        // RFC 9112 §6.3: a 304 never carries a body even with Content-Length.
        let headers = b"HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.framing, BodyFraming::ContentLength(0));
        assert_eq!(resp.content_length(), Some(0));
    }

    #[test]
    fn parse_upstream_response_204_is_bodyless() {
        // RFC 9112 §6.3: a 204 never carries a body even with chunked framing.
        let headers = b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.framing, BodyFraming::ContentLength(0));
    }

    #[test]
    fn test_parse_upstream_response_404() {
        let headers = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.status_code, 404);
    }

    #[test]
    fn test_parse_upstream_response_etag() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        ETag: \"abc123\"\r\n\
                        \r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
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
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.etag.as_deref(), Some("not-a-valid-etag"));
        assert_eq!(resp.last_modified.as_deref(), Some("not a date"));
    }

    #[test]
    fn test_parse_upstream_response_content_range() {
        let headers = b"HTTP/1.1 206 Partial Content\r\n\
                        Content-Length: 500\r\n\
                        Content-Range: bytes 100-599/1000\r\n\
                        \r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.status_code, 206);
        assert_eq!(resp.content_range.as_deref(), Some("bytes 100-599/1000"));
    }

    #[test]
    fn test_parse_upstream_response_connection_close() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        Connection: close\r\n\
                        \r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert!(resp.connection_close);
    }

    #[test]
    fn test_parse_upstream_response_connection_keep_alive() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        Connection: keep-alive\r\n\
                        \r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert!(!resp.connection_close);
    }

    #[test]
    fn test_parse_upstream_response_no_connection_header() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
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
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        assert_eq!(resp.content_length(), Some(42));
        assert_eq!(resp.content_type.as_deref(), Some("text/plain"));
        assert_eq!(
            resp.last_modified.as_deref(),
            Some("Mon, 01 Jan 2024 00:00:00 GMT")
        );
        assert_eq!(resp.etag.as_deref(), Some("\"xyz\""));
    }

    #[test]
    fn test_parse_upstream_response_malformed() {
        let garbage = b"not an http response at all";
        assert!(parse_upstream_response(garbage, garbage.len(), "test.mirror").is_err());
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
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
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
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
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
        let result = parse_upstream_response(&buf, buf.len(), "test.mirror");
        assert!(
            result.is_ok(),
            "expected Ok for response at exact cap, got Err"
        );
    }

    /// `parse_upstream_response` does not panic on a response one byte over
    /// `MAX_UPSTREAM_HEADER_SIZE` (the read-loop would have rejected it first,
    /// but the parser itself must be robust).
    #[test]
    fn test_parse_upstream_response_one_over_max_header_size() {
        let preamble = b"HTTP/1.1 200 OK\r\nX-Pad: \r\n\r\n";
        let pad_len = MAX_UPSTREAM_HEADER_SIZE - preamble.len() + 1;
        let buf = make_padded_response(pad_len);
        assert_eq!(buf.len(), MAX_UPSTREAM_HEADER_SIZE + 1);
        // Must not panic; Ok or Err both acceptable.
        match parse_upstream_response(&buf, buf.len(), "test.mirror") {
            Ok(_) | Err(_) => {}
        }
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
            matches!(err, ChunkDecodeError::Framing(io_err) if io_err.kind() == ErrorKind::InvalidData),
            "expected an InvalidData framing error, got {err:?}",
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
        let err = consumed
            .ensure_no_trailing_bytes(input.len())
            .expect_err("trailing bytes after the terminator must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
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
        // wrappers can word their own log line.
        let input: &[u8] = b"3\r\nfoo\r\n3\r\nbar\r\n0\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 6).expect("exactly at the cap is fine");
        assert_eq!(body, b"foobar");
        assert!(consumed.done);

        let err = dechunk_once(input, 5).expect_err("one byte over the cap must be refused");
        assert!(
            matches!(err, ChunkDecodeError::SizeCap { max_bytes: 5 }),
            "expected SizeCap, got {err:?}",
        );
    }
}
