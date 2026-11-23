//! HTTP/1.1 wire handling between the splice proxy and upstream:
//! [`format_http_request`]/[`send_and_read_headers`] on the request side,
//! [`parse_upstream_response`] into [`UpstreamResponse`] on the response
//! side, and the body relays hanging off the shared [`BodyFraming`]
//! (`relay_to_client`, `read_to_vec`) that stream or buffer a body according
//! to its framing. A relayed chunked body reaches an HTTP/1.1 client in its
//! raw encoding but an HTTP/1.0 client de-chunked and close-delimited
//! ([`ChunkedRelay`]).

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
use crate::config::Config;
use crate::http_helpers::{
    ConnectionAction, ConnectionVersion, HeadEnd, OptHeader, capped_header_end, find_header,
};
use crate::http_range::{ContentRange, parse_content_range};
use crate::humanfmt::HumanFmt;
use crate::limits::{MAX_UPSTREAM_HEADER_SIZE, MAX_UPSTREAM_HEADERS};
use crate::precise_instant::PreciseInstant;
use crate::rate_checker::RateChecker;
use crate::sendfile_conn::write_all_to_stream_rated;
use crate::transfer_error::{ClientError, DeliveryFailure, UpstreamError};
use crate::upstream_head::{
    BodyFraming, RejectReason, UpstreamHead, is_followed_redirect, resolve_body_framing,
    well_formed_etag,
};
use crate::{
    build_info::{APP_USER_AGENT, APP_VIA},
    cache_metadata::{self, ValidatorGates},
    global_config, log_once, metrics,
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

/// Exactly one upstream request mode, shared with the response planner.
pub(super) type RequestConditions<'a> =
    crate::upstream_head::FetchMode<'a, &'a VolatileCondHeaders>;

#[derive(Clone, Copy)]
pub(super) struct UpstreamRequest<'a> {
    pub(super) authority: &'a str,
    pub(super) path: &'a str,
    pub(super) conditions: RequestConditions<'a>,
}

impl<'a> UpstreamRequest<'a> {
    /// A plain, unconditional `GET` of `path` from `authority`.
    pub(super) fn plain(authority: &'a str, path: &'a str) -> Self {
        Self {
            authority,
            path,
            conditions: RequestConditions::Fresh(crate::cache_layout::CachedFlavor::Permanent),
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
fn format_http_request(request: UpstreamRequest<'_>) -> String {
    let UpstreamRequest {
        authority: host_authority,
        path,
        conditions,
    } = request;
    let range_header = std::fmt::from_fn(|f| {
        if let RequestConditions::Resume(resume) = conditions {
            let resume_offset = resume.offset();
            let resume_if_range = Some(resume.if_range());
            write!(
                f,
                "Range: bytes={resume_offset}-\r\n{}",
                OptHeader("If-Range", resume_if_range)
            )?;
        }
        Ok(())
    });
    let volatile_headers = std::fmt::from_fn(|f| {
        if let RequestConditions::Revalidate(vc) = conditions {
            write!(
                f,
                "{}Cache-Control: max-age=300\r\n{}",
                OptHeader("If-Modified-Since", vc.if_modified_since.as_deref()),
                OptHeader("If-None-Match", vc.if_none_match.as_deref())
            )?;
        }
        Ok(())
    });

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

async fn send_upstream_request(
    upstream: &mut UpstreamConn,
    request: UpstreamRequest<'_>,
) -> std::io::Result<()> {
    let request = format_http_request(request);
    let write_and_flush = async {
        upstream.write_all(request.as_bytes()).await?;
        upstream.flush().await
    };

    let http_timeout = global_config().http_timeout;
    match tokio::time::timeout(http_timeout, write_and_flush).await {
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

/// Returns the byte index where the body starts.
async fn read_upstream_response_headers(
    upstream: &mut UpstreamConn,
    buf: &mut BytesMut,
) -> Result<usize, HeadError> {
    let http_timeout = global_config().http_timeout;
    let deadline = tokio::time::sleep(http_timeout);
    tokio::pin!(deadline);

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
        //
        // The cap applies to the head alone, wherever the read boundaries
        // fall: a terminator in the read that also carries the overflow is
        // still too large, and body bytes behind a complete head are not
        // counted.
        let scan_from = search_offset.saturating_sub(3);
        match capped_header_end(buf, scan_from, MAX_UPSTREAM_HEADER_SIZE) {
            HeadEnd::Complete(end) => return Ok(end),
            HeadEnd::TooLarge(size) => {
                // Every `HeadError::Protocol` is one
                // `UPSTREAM_PROTOCOL_VIOLATION`, bumped where it was detected.
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                return Err(HeadError::Protocol(format!(
                    "upstream response header size of {size} bytes exceeds {MAX_UPSTREAM_HEADER_SIZE} byte cap"
                )));
            }
            HeadEnd::Incomplete => search_offset = buf.len(),
        }
    }
}

/// The splice side of [`BodyFraming`], which `upstream_head` shares with
/// hyper.
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
    ) -> impl std::fmt::Display {
        std::fmt::from_fn(move |f| {
            if is_bodyless_status(status) {
                return Ok(());
            }
            match self {
                Self::ContentLength(len) => write!(f, "Content-Length: {len}\r\n"),
                Self::Chunked if matches!(ChunkedRelay::for_client(client), ChunkedRelay::Raw) => {
                    f.write_str("Transfer-Encoding: chunked\r\n")
                }
                Self::Chunked | Self::CloseDelimited => Ok(()),
            }
        })
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
                let forwarded =
                    forward_upstream_body(&mut upstream, client_stream, Some(remaining), max_bytes)
                        .await?;
                upstream.complete();
                Ok(prefix_len + forwarded)
            }
            Self::Chunked => {
                // The helper consumes and strips trailers so the upstream
                // connection stays reusable on success.
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
                // Unlike the chunked arm, `max_bytes` caps only what follows
                // `body_prefix`, so the relay may forward up to the prefix's
                // length past it. Accepted: the prefix is what the head read
                // pulled in behind the head (a few KiB, never more than one
                // read), and the body streams through a fixed buffer, so the
                // cap bounds how long a relay runs, not what it holds.
                write_prefix(client_stream, body_prefix).await?;
                let forwarded =
                    forward_upstream_body(&mut upstream, client_stream, None, max_bytes).await?;
                Ok(prefix_len + forwarded)
            }
        }
    }

    /// Read the whole response body into memory, framed per `self`, up to
    /// `max_bytes` of payload (`body_prefix` included).
    ///
    /// Same poolability contract as [`Self::relay_to_client`].
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

pub(super) struct UpstreamResponse {
    pub(super) status_code: StatusCode,
    pub(super) framing: BodyFraming,
    pub(super) content_type: Option<String>,
    pub(super) last_modified: Option<String>,
    pub(super) etag: Option<String>,
    content_range: Option<ContentRange>,
    pub(super) location: Option<String>,
    pub(super) connection_close: bool,
    /// Instant the upstream request was sent - start of the upstream-rate
    /// window.
    pub(super) request_sent_at: PreciseInstant,
    /// Instant the head was parsed: the end of the time to first byte and
    /// the start of the throughput window (`mirror_perf`).
    pub(super) head_at: PreciseInstant,
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

    /// A 3xx the drive follows when the `Location` target is allowed.
    pub(super) fn is_redirect(&self) -> bool {
        is_followed_redirect(self.status_code)
    }

    fn content_length(&self) -> Option<u64> {
        match self.framing {
            BodyFraming::ContentLength(n) => Some(n),
            BodyFraming::Chunked | BodyFraming::CloseDelimited => None,
        }
    }

    /// The backend-neutral projection consumed by
    /// `upstream_head::plan_download`. Its `ETag` goes through the same
    /// `well_formed_etag` filter as hyper's projection, so the planner's
    /// input does not depend on whether
    /// [`Self::discard_invalid_validators`] ran first.
    pub(super) fn head(&self) -> UpstreamHead<'_> {
        UpstreamHead {
            status: self.status_code,
            content_length: self.content_length(),
            content_range: self.content_range,
            etag: well_formed_etag(self.etag.as_deref()),
        }
    }

    /// Discard malformed `ETag`/`Last-Modified` values before they reach a
    /// client response header, an `If-Range` comparison or an xattr.
    ///
    /// The warn's wording mirrors `hyper_conn.rs::serve_new_file_worker`
    /// modulo the subsystem prefix.
    pub(super) fn discard_invalid_validators(&mut self, conn_details: &ConnectionDetails) {
        let (etag, last_modified) = cache_metadata::check_upstream_validators(
            self.etag.take(),
            self.last_modified.take(),
            |invalid| {
                static GATES: ValidatorGates = ValidatorGates::new();
                log_once::warn_once_or_info_gated(
                    GATES.for_validator(&invalid),
                    format_args!(
                        "splice proxy: upstream mirror {} {} for {}; discarding it",
                        conn_details.mirror,
                        invalid.detail(),
                        conn_details.debname
                    ),
                );
            },
        );
        self.etag = etag;
        self.last_modified = last_modified;
    }
}

/// Whether a response with `status` never carries a body, whatever its
/// framing headers claim (RFC 9112 §6.3: 1xx, 204 and 304).
fn is_bodyless_status(status: StatusCode) -> bool {
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
fn parse_upstream_response(
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

    let content_range = find_header(headers, &CONTENT_RANGE).and_then(parse_content_range);

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
        head_at: PreciseInstant::now(),
    })
}

pub(super) async fn send_and_read_headers(
    up: &mut UpstreamConn,
    request: UpstreamRequest<'_>,
) -> Result<(UpstreamResponse, BytesMut, usize), HeadError> {
    send_upstream_request(up, request)
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

fn upstream_read_timeout(timeout: Duration) -> UpstreamError {
    metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
    UpstreamError::timeout("upstream read timed out", timeout)
}

/// The upstream half of every body reader below: one read under the
/// `http_timeout` deadline, counted, optionally capped ([`Self::capped`]) and
/// gated on the mirror rate. A `0` (EOF) passes no check and is the caller's
/// to interpret.
struct UpstreamReader {
    /// `None` when `min_download_rate` is disabled.
    rate_checker: Option<RateChecker>,
    http_timeout: Duration,
    phase: &'static str,
    cap: Option<RelayCap>,
}

struct RelayCap {
    max_bytes: usize,
    total: u64,
}

impl UpstreamReader {
    fn new(config: &Config, phase: &'static str) -> Self {
        Self {
            rate_checker: RateChecker::from_config(config),
            http_timeout: config.http_timeout,
            phase,
            cap: None,
        }
    }

    /// Fail the read that takes the body past `max_bytes`. Checked before
    /// the rate gate, so a read crossing both reports the cap.
    fn capped(self, max_bytes: usize) -> Self {
        Self {
            cap: Some(RelayCap {
                max_bytes,
                total: 0,
            }),
            ..self
        }
    }

    async fn read(
        &mut self,
        read: impl Future<Output = std::io::Result<usize>>,
    ) -> Result<usize, UpstreamError> {
        let n = match tokio::time::timeout(self.http_timeout, read).await {
            Ok(result) => result.map_err(|error| UpstreamError::io(self.phase, error))?,
            Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                return Err(upstream_read_timeout(self.http_timeout));
            }
        };
        if n == 0 {
            return Ok(0);
        }

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        if let Some(RelayCap { max_bytes, total }) = &mut self.cap {
            *total += n as u64;
            if *total > *max_bytes as u64 {
                return Err(UpstreamError::body_limit(format!(
                    "upstream error response body exceeded {max_bytes} byte cap (size={total} bytes)"
                )));
            }
        }

        if let Some(rate_checker) = self.rate_checker.as_mut() {
            rate_checker.add(n);
            if let Some(rate) = rate_checker.check_fail() {
                return Err(UpstreamError::rate(rate));
            }
        }
        Ok(n)
    }
}

/// Forward the rest of a relayed body from upstream to client (no
/// caching): `length` more bytes of a length-delimited body, else
/// everything up to EOF, capped at `max_bytes`. Returns the bytes forwarded.
/// On error the connection state is indeterminate -- callers must not pool
/// the upstream.
async fn forward_upstream_body(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    length: Option<u64>,
    max_bytes: usize,
) -> Result<u64, DeliveryFailure> {
    let config = global_config();
    let mut reader = UpstreamReader::new(config, "body forward");
    if length.is_none() {
        reader = reader.capped(max_bytes);
    }
    // No larger than the body when its length is known: most relayed bodies
    // are small error pages, which need no full read buffer.
    let buf_size = length.map_or(TLS_READ_BUF_SIZE, |length| {
        usize::try_from(length).map_or(TLS_READ_BUF_SIZE, |length| length.min(TLS_READ_BUF_SIZE))
    });
    let mut buf: Vec<u8> = Vec::with_capacity(buf_size);
    let mut total: u64 = 0;
    let mut client_rate_checker = RateChecker::from_config(config);

    loop {
        let to_read = match length {
            Some(length) if total == length => break,
            Some(length) => (length - total).min(buf_size as u64),
            None => buf_size as u64,
        };
        debug_assert_eq!(
            buf.capacity(),
            buf_size,
            "buffer capacity should remain constant"
        );
        buf.clear();
        let n = reader
            .read((&mut *upstream).take(to_read).read_buf(&mut buf))
            .await?;
        if n == 0 {
            if length.is_none() {
                break;
            }
            return Err(DeliveryFailure::from(UpstreamError::protocol(
                "upstream closed before sending complete body",
            )));
        }

        write_all_to_stream_rated(client, &buf, &mut client_rate_checker, config.http_timeout)
            .await?;
        metrics::BYTES_SERVED_PASSTHROUGH.increment_by(n as u64);
        total += n as u64;
    }

    Ok(total)
}

/// Framing position of a [`ChunkDecoder`].
enum ChunkedState {
    /// Accumulating the hex chunk-size line (up to `\r\n`).
    ReadingSize,
    /// Inside chunk data; `remaining` counts undecoded payload bytes.
    ReadingData {
        remaining: usize,
    },
    /// Expecting the `\r\n` trailer after chunk data.
    ReadingTrailer {
        seen_cr: bool,
    },
    /// Collect and validate the bounded trailer section after the last chunk.
    Trailers,
    Done,
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

impl ChunkDecodeError {
    /// The upstream failure this stop is, a cap naming the capped body as
    /// `what`.
    fn into_upstream(self, what: &str) -> UpstreamError {
        match self {
            Self::SizeCap {
                max_bytes,
                declared_bytes,
            } => UpstreamError::body_limit(format!(
                "{what} exceeded {max_bytes} byte cap (declared payload={declared_bytes} bytes)"
            )),
            Self::Framing(reason) => UpstreamError::protocol(reason),
        }
    }
}

/// What one [`ChunkDecoder::feed`] call took from its input.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Consumed {
    /// Raw bytes (framing and payload) consumed from the input. Equals the
    /// input length unless `done` is set: then the decoder stopped right
    /// after the closing CRLF and left everything past it untouched.
    raw: usize,
    /// Prefix containing chunk framing and data, excluding the trailer
    /// section (including its closing CRLF). The raw relay forwards this
    /// prefix and emits an empty trailer section once `done` is set.
    framed: usize,
    /// The last chunk and complete trailer section have been consumed.
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
    /// forward the validated chunk prefix and empty trailer section before
    /// failing the connection.
    fn ensure_no_trailing_bytes(self, data_len: usize) -> Result<(), &'static str> {
        let Self { raw, done, .. } = self;
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
/// Chunk-size lines are held to RFC 9112's grammar ([`parse_chunk_size_line`])
/// and chunk extensions after `;` are ignored; trailer fields between `0\r\n`
/// and the final `\r\n` are validated with the header parser. The declared
/// payload total is checked against `max_bytes` at every chunk-size line.
///
/// On success the closing `\r\n` after the `0\r\n` has been fully consumed
/// from the upstream socket buffer, so the connection can be returned to the
/// pool. On error the connection state is indeterminate and the caller must
/// not pool the upstream.
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
        let mut i = 0usize;
        let mut trailer_start = None;
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
                            return Err(ChunkDecodeError::Framing(
                                "chunked encoding: bare LF in chunk-size line",
                            ));
                        };
                        let chunk_size =
                            parse_chunk_size_line(line).map_err(ChunkDecodeError::Framing)?;
                        self.size_buf.clear();
                        if chunk_size == 0 {
                            self.state = ChunkedState::Trailers;
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
                        return Err(ChunkDecodeError::Framing(
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
                        return Err(ChunkDecodeError::Framing(
                            "chunked encoding: expected CRLF after chunk data",
                        ));
                    }
                }
                ChunkedState::Trailers => {
                    trailer_start.get_or_insert(i);
                    let byte = data[i];
                    i += 1;
                    self.size_buf.push(byte);
                    if self.size_buf.len() > MAX_UPSTREAM_HEADER_SIZE {
                        return Err(ChunkDecodeError::Framing(
                            "chunked encoding: trailer section too large",
                        ));
                    }
                    if byte == b'\n' {
                        if !self.size_buf.ends_with(b"\r\n") {
                            return Err(ChunkDecodeError::Framing(
                                "chunked encoding: bare LF in trailers",
                            ));
                        }
                        let mut headers = [httparse::EMPTY_HEADER; MAX_UPSTREAM_HEADERS];
                        match httparse::parse_headers(&self.size_buf, &mut headers) {
                            Ok(httparse::Status::Complete(_)) => {
                                self.state = ChunkedState::Done;
                                break;
                            }
                            Ok(httparse::Status::Partial) => {}
                            Err(_) => {
                                return Err(ChunkDecodeError::Framing(
                                    "chunked encoding: invalid trailers",
                                ));
                            }
                        }
                    }
                }
                ChunkedState::Done => break,
            }
        }
        Ok(Consumed {
            raw: i,
            framed: trailer_start.unwrap_or(i),
            done: matches!(self.state, ChunkedState::Done),
        })
    }
}

/// What [`forward_upstream_chunked_body`] hands the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChunkedRelay {
    /// Original chunk framing and data with trailer fields stripped:
    /// an HTTP/1.1 client decodes it itself. We do not negotiate downstream
    /// trailer support, so always replace trailers with an empty section.
    Raw,
    /// The decoded payload only, for an HTTP/1.0 client, which knows no
    /// transfer coding (RFC 9112 §6.1): the relayed body is close-delimited.
    Decoded,
}

impl ChunkedRelay {
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
/// receives bytes past a detected framing error. When the terminator is
/// consumed only the chunk prefix `data[..framed]` goes out in raw mode,
/// followed by an empty trailer section; bytes past the upstream's closing
/// `\r\n` are rejected afterwards by [`Consumed::ensure_no_trailing_bytes`].
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
    let consumed = fed.map_err(|err| err.into_upstream("chunked response body"))?;
    let forward_slice = match relay {
        ChunkedRelay::Raw => &data[..consumed.framed],
        ChunkedRelay::Decoded => payload.as_slice(),
    };
    let closing_crlf: &[u8] = if relay == ChunkedRelay::Raw && consumed.done {
        b"\r\n"
    } else {
        b""
    };
    for bytes in [forward_slice, closing_crlf] {
        if !bytes.is_empty() {
            write_all_to_stream_rated(client, bytes, client_rate_checker, http_timeout).await?;
            metrics::BYTES_SERVED_PASSTHROUGH.increment_by(bytes.len() as u64);
            *client_total += bytes.len() as u64;
        }
    }
    consumed
        .ensure_no_trailing_bytes(data.len())
        .map_err(UpstreamError::protocol)?;
    Ok(consumed.done)
}

/// Forward a chunked transfer-encoded body from upstream to client.
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
    let mut reader = UpstreamReader::new(config, "chunked body forward");
    let mut client_rate_checker = RateChecker::from_config(config);

    let mut decoder = ChunkDecoder::new(max_bytes);
    // The decoded payload of the current buffer; stays empty for `Raw`.
    let mut payload = Vec::new();
    let mut client_total: u64 = 0;

    // The bytes that arrived with the response headers go first.
    let mut pending = body_prefix;
    let mut buf = BytesMut::new();
    loop {
        let data = if pending.is_empty() {
            buf.clear();
            buf.reserve(TLS_READ_BUF_SIZE);
            let n = reader.read(upstream.read_buf(&mut buf)).await?;
            if n == 0 {
                return Err(DeliveryFailure::from(UpstreamError::protocol(
                    "upstream closed during chunked body transfer",
                )));
            }
            &buf[..n]
        } else {
            std::mem::take(&mut pending)
        };

        if forward_chunked_buf(
            &mut decoder,
            data,
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

/// Reads until EOF, so the connection is not poolable afterwards.
async fn read_body_to_vec_until_eof(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, UpstreamError> {
    let size = (prefix.len() + 4096).min(max_bytes.saturating_add(1));
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(prefix);
    let mut reader = UpstreamReader::new(global_config(), "volatile body buffering");

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
        body.reserve(TLS_READ_BUF_SIZE.min(remaining));

        let n = reader
            .read((&mut *upstream).take(remaining as u64).read_buf(&mut body))
            .await?;
        if n == 0 {
            break;
        }
    }

    Ok(body)
}

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

    // Allocate incrementally (the per-iteration `reserve` below), like
    // `read_body_to_vec_until_eof`: `content_length` is an untrusted upstream
    // header and must not size an up-front allocation.
    let mut body = Vec::with_capacity((prefix.len() + 32 * 1024).min(content_length));
    body.extend_from_slice(prefix);
    let mut reader = UpstreamReader::new(global_config(), "length-delimited body buffering");

    while body.len() < content_length {
        let remaining = content_length - body.len();
        body.reserve(TLS_READ_BUF_SIZE.min(remaining));
        let n = reader
            .read((&mut *upstream).take(remaining as u64).read_buf(&mut body))
            .await?;
        if n == 0 {
            return Err(UpstreamError::protocol(
                "upstream closed before content-length body completed",
            ));
        }
    }

    Ok(body)
}

/// `max_bytes` caps the decoded payload. Terminator and pool-safety policy:
/// [`ChunkDecoder`].
async fn read_dechunk_body_to_vec(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    max_bytes: usize,
) -> Result<Vec<u8>, UpstreamError> {
    let mut body = Vec::with_capacity(4096);
    let mut reader = UpstreamReader::new(global_config(), "chunked body buffering");
    let mut decoder = ChunkDecoder::new(max_bytes);
    // Allocated by the first upstream read: a small body (a drained redirect
    // or error page) often arrives whole with the head. Sized down to a small
    // payload cap: a drain capped at 64 KiB needs no full read buffer.
    let mut read_buf = BytesMut::new();

    // The bytes that arrived with the headers are decoded first; every later
    // iteration reads from upstream (`take` leaves an empty slice behind).
    let mut pending: &[u8] = prefix;

    loop {
        let data = if pending.is_empty() {
            read_buf.clear();
            read_buf.reserve(TLS_READ_BUF_SIZE.min(max_bytes));
            let n = reader.read(upstream.read_buf(&mut read_buf)).await?;
            if n == 0 {
                return Err(UpstreamError::protocol(
                    "upstream closed during chunked body buffering",
                ));
            }
            &read_buf[..n]
        } else {
            std::mem::take(&mut pending)
        };

        let consumed = decoder
            .feed(data, |payload| body.extend_from_slice(&data[payload]))
            .map_err(|err| err.into_upstream("chunked volatile body"))?;

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
    use std::num::NonZero;

    #[test]
    fn request_wire_preserves_optional_header_conditions_and_order() {
        let empty = VolatileCondHeaders {
            if_modified_since: None,
            if_none_match: None,
        };
        let modified = VolatileCondHeaders {
            if_modified_since: Some("Wed, 21 Oct 2015 07:28:00 GMT".into()),
            if_none_match: None,
        };
        let tagged = VolatileCondHeaders {
            if_modified_since: None,
            if_none_match: <crate::http_etag::ETag as crate::xattr_helpers::XattrValue>::parse(
                "\"index-v2\"",
            ),
        };
        let both = VolatileCondHeaders {
            if_modified_since: modified.if_modified_since.clone(),
            if_none_match: tagged.if_none_match.clone(),
        };
        let preamble = format!(
            "GET /debian/dists/stable/InRelease?mirror=1 HTTP/1.1\r\n\
             Host: [2001:db8::1]:8080\r\n\
             User-Agent: {APP_USER_AGENT}\r\n\
             Via: {APP_VIA}\r\n\
             Accept-Encoding: identity\r\n\
             Connection: keep-alive\r\n"
        );
        let validator =
            <crate::http_etag::ETag as crate::xattr_helpers::XattrValue>::parse("\"resume-v1\"")
                .unwrap()
                .into_strong()
                .unwrap();
        let resume =
            crate::upstream_head::ResumeState::new(NonZero::new(7).unwrap(), None, &validator);
        for (case, conditions, headers) in [
            (
                "unconditional",
                RequestConditions::Fresh(crate::cache_layout::CachedFlavor::Permanent),
                "",
            ),
            (
                "resume with validator",
                RequestConditions::Resume(resume),
                "Range: bytes=7-\r\nIf-Range: \"resume-v1\"\r\n",
            ),
            (
                "volatile without validators",
                RequestConditions::Revalidate(&empty),
                "Cache-Control: max-age=300\r\n",
            ),
            (
                "volatile modified only",
                RequestConditions::Revalidate(&modified),
                "If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\nCache-Control: max-age=300\r\n",
            ),
            (
                "volatile tag only",
                RequestConditions::Revalidate(&tagged),
                "Cache-Control: max-age=300\r\nIf-None-Match: \"index-v2\"\r\n",
            ),
            (
                "volatile both validators",
                RequestConditions::Revalidate(&both),
                "If-Modified-Since: Wed, 21 Oct 2015 07:28:00 GMT\r\nCache-Control: max-age=300\r\nIf-None-Match: \"index-v2\"\r\n",
            ),
        ] {
            let request = format_http_request(UpstreamRequest {
                authority: "[2001:db8::1]:8080",
                path: "/debian/dists/stable/InRelease?mirror=1",
                conditions,
            });
            let expected = format!("{preamble}{headers}\r\n");
            assert_eq!(request.as_bytes(), expected.as_bytes(), "{case}");
        }
    }

    #[tokio::test]
    async fn chunked_relay_write_failure_keeps_client_side_and_os_error() {
        let (mut client, _peer) = crate::test_support::connected_tcp_pair().await;
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
        let (client, mut peer) = crate::test_support::connected_tcp_pair().await;

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

    #[tokio::test]
    async fn chunked_relay_strips_trailers_at_every_split() {
        for input in [
            &b"3\r\nabc\r\n0\r\nX-Trailer: \xff\r\nX-Another: yes\r\n\r\n"[..],
            b"3\r\nabc\r\n0\r\n\r\n",
            b"0\r\nX-Trailer: yes\r\n\r\n",
        ] {
            for relay in [ChunkedRelay::Raw, ChunkedRelay::Decoded] {
                // Also exercise one-byte reads, which fragment every trailer line.
                for split in 1..input.len() {
                    let (client, mut peer) = crate::test_support::connected_tcp_pair().await;
                    let mut decoder = ChunkDecoder::new(1024);
                    let mut payload = Vec::new();
                    let mut total = 0;
                    for (index, part) in input.chunks(split).enumerate() {
                        let done = forward_chunked_buf(
                            &mut decoder,
                            part,
                            relay,
                            &mut payload,
                            &client,
                            &mut None,
                            &mut total,
                            Duration::from_secs(1),
                        )
                        .await
                        .expect("valid chunked input");
                        assert_eq!(done, (index + 1) * split >= input.len());
                    }
                    let has_payload = input.starts_with(b"3");
                    let expected: &[u8] = match (relay, has_payload) {
                        (ChunkedRelay::Raw, true) => b"3\r\nabc\r\n0\r\n\r\n",
                        (ChunkedRelay::Raw, false) => b"0\r\n\r\n",
                        (ChunkedRelay::Decoded, true) => b"abc",
                        (ChunkedRelay::Decoded, false) => b"",
                    };
                    drop(client);
                    let mut received = Vec::new();
                    peer.read_to_end(&mut received).await.unwrap();
                    assert_eq!(received, expected, "relay={relay:?}, split={split}");
                    assert_eq!(total, expected.len() as u64);
                }
            }
        }
    }

    #[tokio::test]
    async fn raw_chunked_relay_rejects_bytes_after_trailers_without_forwarding_them() {
        let (client, mut peer) = crate::test_support::connected_tcp_pair().await;
        let mut total = 0;
        let result = forward_chunked_buf(
            &mut ChunkDecoder::new(1024),
            b"3\r\nabc\r\n0\r\nX-Trailer: yes\r\n\r\nGARBAGE",
            ChunkedRelay::Raw,
            &mut Vec::new(),
            &client,
            &mut None,
            &mut total,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_err(), "bytes beyond the terminator must fail");
        drop(client);
        let mut received = Vec::new();
        peer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"3\r\nabc\r\n0\r\n\r\n");
        assert_eq!(total, received.len() as u64);
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
        let headers = b"HTTP/1.1 206 Partial Content\r\n\
                        Content-Length: 500\r\n\
                        Content-Type: application/octet-stream\r\n\
                        Last-Modified: Sat, 15 Mar 2025 12:00:00 GMT\r\n\
                        ETag: \"full-test\"\r\n\
                        Content-Range: bytes 100-599/1000\r\n\
                        Connection: close\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len(), PreciseInstant::now())
            .expect("should parse");
        assert_eq!(resp.status_code, 206);
        assert_eq!(resp.content_length(), Some(500));
        assert_eq!(
            resp.content_type.as_deref(),
            Some("application/octet-stream")
        );
        assert_eq!(
            resp.last_modified.as_deref(),
            Some("Sat, 15 Mar 2025 12:00:00 GMT")
        );
        assert_eq!(resp.etag.as_deref(), Some("\"full-test\""));
        assert_eq!(
            resp.content_range
                .map(|r| (r.start(), r.span().get(), r.total().get())),
            Some((100, 500, 1000))
        );
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

    /// The byte cap is enforced by `read_upstream_response_headers`, not by
    /// the parser: a head of exactly `MAX_UPSTREAM_HEADER_SIZE` bytes and one
    /// a byte over both parse.
    #[test]
    fn test_parse_upstream_response_is_not_size_capped() {
        for size in [MAX_UPSTREAM_HEADER_SIZE, MAX_UPSTREAM_HEADER_SIZE + 1] {
            let mut buf = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
            buf.resize(size - 4, b'a');
            buf.extend_from_slice(b"\r\n\r\n");
            let resp = parse_upstream_response(&buf, buf.len(), PreciseInstant::now())
                .expect("the parser itself applies no size cap");
            assert_eq!(resp.status_code, StatusCode::OK, "{size} bytes");
        }
    }

    /// The framing and connection fate the parser resolves itself: identical
    /// `Content-Length` duplicates (folded or on separate lines) collapse to
    /// one value, a 1xx, 204 or 304 head is bodyless whatever it claims (RFC
    /// 9112 §6.3), no framing header at all is close-delimited, a lone
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
                head: b"HTTP/1.1 200 OK\r\n\r\n",
                framing: BodyFraming::CloseDelimited,
                connection_close: false,
            },
            Case {
                head: b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                framing: BodyFraming::Chunked,
                connection_close: false,
            },
            Case {
                head: b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\nTransfer-Encoding: chunked\r\n\r\n",
                framing: BodyFraming::Chunked,
                connection_close: false,
            },
            Case {
                head: b"HTTP/1.1 304 Not Modified\r\nContent-Length: 500\r\n\r\n",
                framing: BodyFraming::ContentLength(0),
                connection_close: false,
            },
            Case {
                head: b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: chunked\r\n\r\n",
                framing: BodyFraming::ContentLength(0),
                connection_close: false,
            },
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
                head: b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: keep-alive\r\n\r\n",
                framing: BodyFraming::ContentLength(7),
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

        // A literal, not the constant: a mirror behind a CDN and an
        // application server sends more than a few dozen fields, so
        // lowering the cap below this must fail here.
        let hundred = build(100);
        assert!(
            parse_upstream_response(&hundred, hundred.len(), PreciseInstant::now()).is_ok(),
            "100 header fields must parse"
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
    // consumption report (including the prefix safe for the raw relay).
    fn feed_collect(
        decoder: &mut ChunkDecoder,
        input: &[u8],
    ) -> Result<(Vec<u8>, Consumed), ChunkDecodeError> {
        let mut body = Vec::new();
        let consumed = decoder.feed(input, |payload| body.extend_from_slice(&input[payload]))?;
        Ok((body, consumed))
    }

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

    /// A whole frame in one buffer decodes to its payload, chunk extensions
    /// ignored, and is consumed to its last byte: the closing CRLF must not
    /// stay on the upstream socket of a connection returning to the pool.
    #[test]
    fn test_chunk_decoder_decodes_whole_frames() {
        for (input, payload) in [
            (&b"5\r\nhello\r\n0\r\n\r\n"[..], &b"hello"[..]),
            (b"0\r\n\r\n", b""),
            (b"3\r\nfoo\r\n4\r\nbarz\r\n0\r\n\r\n", b"foobarz"),
            (b"5;ext=foo\r\nhello\r\n0;final\r\n\r\n", b"hello"),
        ] {
            let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
            assert_eq!(body, payload, "{:?}", input.escape_ascii().to_string());
            assert_eq!(
                consumed,
                Consumed {
                    raw: input.len(),
                    framed: input.len() - 2,
                    done: true
                },
                "{:?}",
                input.escape_ascii().to_string()
            );
        }
    }

    #[test]
    fn test_chunk_decoder_accepts_fragmented_trailer_fields() {
        let input = b"3\r\nabc\r\n0\r\nX-Trailer: \xff\r\nX-Another: yes\r\n\r\n";
        for split in 0..=input.len() {
            let mut decoder = ChunkDecoder::new(1024);
            let (mut body, _) = feed_collect(&mut decoder, &input[..split]).unwrap();
            let (rest, consumed) = feed_collect(&mut decoder, &input[split..]).unwrap();
            body.extend(rest);
            assert_eq!(body, b"abc");
            assert!(consumed.done);
        }
        let oversized = format!("0\r\nX: {}\r\n\r\n", "x".repeat(MAX_UPSTREAM_HEADER_SIZE));
        assert!(dechunk_once(oversized.as_bytes(), 1024).is_err());
    }

    #[test]
    fn test_chunk_decoder_rejects_garbage_after_zero_chunk() {
        // The bytes following `0\r\n` must be valid trailer fields or
        // the closing CRLF.
        let input: &[u8] = b"0\r\nXY\r\n";
        let err = dechunk_once(input, 1024).expect_err("garbage after 0-chunk must be rejected");
        assert_framing_error(&err);
    }

    #[test]
    fn test_chunk_decoder_split_closing_crlf() {
        let mut decoder = ChunkDecoder::new(1024);

        let part1: &[u8] = b"5\r\nhello\r\n0\r\n\r";
        let (body1, c1) = feed_collect(&mut decoder, part1).expect("part1 decode");
        assert_eq!(body1, b"hello");
        assert_eq!(
            c1,
            Consumed {
                raw: part1.len(),
                framed: part1.len() - 1,
                done: false
            },
            "after part1 the decoder must still be waiting for one more byte (the LF)",
        );
        assert!(matches!(decoder.state, ChunkedState::Trailers));

        let part2: &[u8] = b"\n";
        let (body2, c2) = feed_collect(&mut decoder, part2).expect("part2 decode");
        assert_eq!(body2, b"");
        assert_eq!(
            c2,
            Consumed {
                raw: 1,
                framed: 0,
                done: true
            }
        );
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
            Consumed {
                raw: 5,
                framed: 3,
                done: true
            },
            "decoder must stop right after the closing CRLF, not swallow trailing bytes",
        );
        let reason = consumed
            .ensure_no_trailing_bytes(input.len())
            .expect_err("trailing bytes after the terminator must be rejected");
        assert_eq!(
            reason,
            "chunked encoding: trailing bytes after 0-length chunk"
        );
        consumed
            .ensure_no_trailing_bytes(5)
            .expect("no trailing bytes when the input ends at the terminator");
        Consumed {
            raw: 3,
            framed: 3,
            done: false,
        }
        .ensure_no_trailing_bytes(3)
        .expect("unfinished frames are not checked for trailing bytes");
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
                    framed: 1,
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
                framed: 15,
                done: true
            }
        );
    }

    #[test]
    fn test_chunk_decoder_chunk_data_split_across_reads() {
        // Chunk data and the CRLF after it straddle read boundaries; every
        // feed that does not finish the frame must consume its whole input
        // (the streaming relay forwards its chunk prefix), and
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
                    framed: if last { part.len() - 2 } else { part.len() },
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
                framed: input.len() - 2,
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
                framed: 64,
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
