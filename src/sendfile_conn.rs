//! Zero-copy client backend: parses requests with httparse, serves cached
//! files via sendfile(2), fetches misses through `splice` (with
//! `splice`) and hands everything else to hyper.
//!
//! Handoff contract: `ZeroCopyResult::NotApplicable` gives the connection to
//! hyper for the current and every later request.  The buffered bytes are
//! prepended to hyper's stream (`MaybePrependedStream`) and the work already
//! done for that first request travels alongside as `hyper_conn::HandoffPlan`,
//! so hyper resumes the pipeline (`serve_cache_miss`,
//! `serve_downloading_file` or the simple proxy) instead of re-parsing,
//! re-dispatching and re-looking up.  Every `NotApplicable` site builds the
//! plan variant matching what it has already run and accounted for; the
//! accounting rules are on `HandoffPlan` and `cache_layout::CacheMiss`.

use std::{
    io::ErrorKind,
    num::NonZero,
    os::{fd::AsFd as _, unix::fs::MetadataExt as _},
    path::Path,
    sync::Arc,
};
#[cfg(feature = "hyper")]
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{BytesMut, buf::Buf as _};
use http::{
    StatusCode,
    header::{CONNECTION, HOST, VIA},
};
use nix::sys::sendfile::sendfile;
#[cfg(feature = "hyper")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::{AsyncWriteExt as _, Interest};
use tokio::net::TcpStream;
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "hyper")]
use crate::hyper_conn::{HandoffPlan, handle_hyper_connection};
#[cfg(feature = "splice")]
use crate::splice::SpliceProxyError;
use crate::{
    AppState, Never,
    active_downloads::{
        AbortReason, ActiveDownloadStatus, JoinFailure, Serveable, await_serveable,
    },
    build_info::APP_NAME,
    cache_conditional::{CacheInfo, RangeRequestHeaders, ServeParams, ServePlan},
    cache_layout::{CacheMiss, CachedFlavor, ConnectionDetails},
    cache_metadata::{self},
    client_counter,
    client_info::ClientInfo,
    connect_tunnel::{
        ConnectReject, copy_bidirectional_idle, report_tunnel_outcome, validate_connect_target,
    },
    content_type::content_type_for_cached_file,
    database_task::{DatabaseCommand, send_db_command},
    delivery::{AbortCause, Mechanism, Role, ServeOutcome, finish_cached_serve},
    error::{ErrorReport, errno_to_io_error, is_peer_disconnect},
    fs_open::{
        CacheAccessFailure, hint_sequential_read, regular_file_metadata, tokio_nofollow_options,
    },
    global_config,
    http_helpers::{
        ConnectionAction, ConnectionVersion, ResponseHeaders, WritePhase, find_header,
        find_header_end, write_304_response, write_416_response, write_all_to_stream,
        write_invalid_response, write_response_headers,
    },
    http_range::format_http_date,
    humanfmt::HumanFmt,
    limits::VOLATILE_CACHE_MAX_AGE,
    metrics,
    permitted_host_cache::authorize_cache_access,
    precise_instant::PreciseInstant,
    rate_checker::{InsufficientRate, RateCheckDirection, RateChecker},
    request_dispatch::{
        ClientAcls, DispatchOutcome, RejectReason, RequestKind, RequestTarget, dispatch_request,
        preflight_method, preflight_target, preflight_via,
    },
    response_head::{ResponseHead, WireBody},
    static_assert, swrite, tunnel_limiter,
    upstream_head::ContentLength,
    warn_once, warn_once_or_debug, warn_once_or_info,
    web::{WebResponse, serve_web_interface},
};

/// Maximum size for HTTP request headers buffer (matches hyper's default of 8192).
const MAX_HEADER_SIZE: usize = 8192;

/// Upper bound for `async_sendfile`'s inline single-syscall fast path.
///
/// The fast path runs `sendfile(2)` on the tokio worker (not the blocking
/// pool), so a cold-page-cache serve blocks the worker on disk I/O, and the
/// transfer only *completes* inline when the file fits the socket's autotuned
/// `SO_SNDBUF` (cold start ~16 KiB, grows to `wmem_max`). This bound caps that
/// worker-blocking exposure; raising it widens it. Pinning `SO_SNDBUF` to force
/// larger inline completions is a net loss: it disables autotuning, wasting
/// memory on the dominant localhost/LAN clients while capping WAN throughput.
const SMALL_SERVE_INLINE_MAX: u64 = 256 * 1024;
/// Initial size for HTTP request headers buffer.
const INITIAL_HEADER_SIZE: usize = 2048;
/// Maximum number of HTTP headers to parse (matches hyper's default of 100).
const MAX_HEADERS: usize = 100;

/// Represents the result of a sendfile operation.
// Only the `CacheMiss` handoff plan (carrying the stale copy) pushes the
// variant-size gap over clippy's threshold.
#[cfg_attr(
    feature = "hyper",
    expect(
        clippy::large_enum_variant,
        reason = "transient value: returned by try_sendfile_request and matched once by the \
                  connection loop, never stored or collected; boxing the handoff plan would \
                  add a heap alloc per default-build cache miss"
    )
)]
pub(crate) enum ZeroCopyResult {
    /// Request was served via sendfile
    Served(ConnectionAction),

    /// Request is not applicable for sendfile, fall back to hyper for this
    /// and every later request on the connection.  `plan` carries the work
    /// already done (pre-flight, dispatch, cache lookup / late-joiner
    /// attach) so hyper resumes the pipeline instead of restarting it; see
    /// `hyper_conn::HandoffPlan`.  Without hyper the request is refused.
    NotApplicable {
        reason: &'static str,
        #[cfg(feature = "hyper")]
        plan: HandoffPlan,
    },

    /// Request is invalid, reject and close the connection
    Invalid {
        status: StatusCode,
        msg: &'static str,
    },

    /// Request should be rejected, but the connection might be kept alive
    Rejection {
        status: StatusCode,
        conn_action: ConnectionAction,
        msg: &'static str,
    },

    /// Request is a policy-accepted CONNECT: hand the whole connection to
    /// [`run_connect_tunnel`], which sends `200` and relays bytes bidirectionally.
    /// The guards are held for the tunnel's lifetime.
    Tunnel {
        host: String,
        port: NonZero<u16>,
        tunnel_guard: Option<tunnel_limiter::TunnelGuard>,
        active_guard: tunnel_limiter::ActiveTunnelGuard,
    },

    /// Sending a message to the client failed.
    /// Close the connection without any further action.
    ClientError,

    /// An error occurred after successfully sending the http header.
    /// Close the connection without any further action.
    AfterHeaderError,
}

impl From<SendfileResult> for ZeroCopyResult {
    fn from(value: SendfileResult) -> Self {
        match value {
            SendfileResult::Served(ca) => Self::Served(ca),
            SendfileResult::Invalid { status, msg } => Self::Invalid { status, msg },
            SendfileResult::ClientError => Self::ClientError,
            SendfileResult::AfterHeaderError => Self::AfterHeaderError,
        }
    }
}

/// Handle a client connection using sendfile(2) for cached file delivery.
///
/// For each request on the connection:
/// - If it's a GET for a cached file (permanent, or volatile within its
///   freshness window), serve it using sendfile(2)
/// - Web-interface and splice-proxy-eligible requests are handled in place
/// - Otherwise, fall back to the standard hyper-based handler
pub(crate) async fn handle_sendfile_connection(
    stream: TcpStream,
    client: ClientInfo,
    appstate: AppState,
) {
    let mut buf = BytesMut::with_capacity(INITIAL_HEADER_SIZE);

    trace!("Using sendfile(2) backend to handle request from client {client}...");

    let mut req_num = 0;
    let mut conn_version = ConnectionVersion::Http11; // assume more recent version 1.1 if not yet parsed from any request

    loop {
        // Try to peek and find the next request headers to determine if sendfile is applicable
        let next_header_index = match read_request_headers(&stream, &mut buf).await {
            Ok(None) if req_num == 0 => {
                info!("Connection from client {client} closed before receiving any request");
                return;
            }
            Ok(None) => {
                debug!(
                    "No more requests from client {client}, ending connection after {req_num} requests"
                );
                return;
            }
            Ok(Some(index)) => {
                req_num += 1;
                index
            }
            Err(err) => {
                if err.kind() == ErrorKind::TimedOut {
                    // Web UI connections from browsers tend to idle out;
                    // the client is gone, so don't bother writing a 400.
                    debug!(
                        "Client {client} timed out before request number {} was received:  {}",
                        req_num + 1,
                        ErrorReport(&err),
                    );
                    return;
                }
                if is_peer_disconnect(&err) {
                    metrics::REQUEST_READ_PEER_DISCONNECT.increment();
                    info!(
                        "Client {client} disconnected before request number {} was received:  {}",
                        req_num + 1,
                        ErrorReport(&err),
                    );
                    return;
                }
                metrics::REQUEST_READ_PROTOCOL_ERROR.increment();
                warn_once_or_info!(
                    "Failed to read request number {} from client {client}; returning 400 and closing the connection:  {}",
                    req_num + 1,
                    ErrorReport(&err),
                );
                // Count the attempted request so REQUESTS_TOTAL stays >=
                // CLIENT_STATUS_*: write_invalid_response below bumps
                // CLIENT_STATUS_400 even though parsing failed.
                metrics::REQUESTS_TOTAL.increment();
                let _ignore = write_invalid_response(
                    &stream,
                    conn_version,
                    ConnectionAction::Close,
                    StatusCode::BAD_REQUEST,
                    "Error reading request headers",
                    None,
                )
                .await;
                graceful_close(&stream).await;
                return;
            }
        };

        let result =
            try_sendfile_request(&buf, &stream, client, &appstate, &mut conn_version).await;

        // Proxy entry for every request this backend parsed, including the
        // ones handed to hyper (which skips its own bump for a handoff), so
        // REQUESTS_TOTAL >= CLIENT_STATUS_* holds as on the parse-error path
        // above.
        metrics::REQUESTS_TOTAL.increment();

        // Parse the request and try to handle it with sendfile
        #[expect(clippy::match_same_arms, reason = "keep separate for clarity")]
        let _: Never = match result {
            ZeroCopyResult::Served(ConnectionAction::KeepAlive) => {
                // Request served via sendfile with keep-alive; continue to next request
                buf.advance(next_header_index);
                continue;
            }
            ZeroCopyResult::Served(ConnectionAction::Close) => {
                // Request served via sendfile; close the connection as requested
                return;
            }
            ZeroCopyResult::NotApplicable {
                reason,
                #[cfg(feature = "hyper")]
                plan,
            } => {
                #[cfg(feature = "hyper")]
                {
                    // Fall back to hyper for this and all subsequent requests.
                    // `buf` starts with the request `plan` describes; any
                    // pipelined successors behind it are hyper's to parse.
                    debug!(
                        "Falling back to hyper for client {client} on request #{req_num} due to: {reason} ({} bytes buffered)",
                        buf.len()
                    );

                    let stream = MaybePrependedStream::new(buf, stream);

                    return handle_hyper_connection(stream, client, appstate, Some(plan)).await;
                }
                #[cfg(not(feature = "hyper"))]
                {
                    warn_once_or_info!(
                        "Rejecting request from client {client} in the splice-only backend: unsupported sendfile fallback path ({reason}); returning 503"
                    );
                    let _ignore = write_invalid_response(
                        &stream,
                        conn_version,
                        ConnectionAction::Close,
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Request not supported by splice backend",
                        None,
                    )
                    .await;
                    return;
                }
            }
            ZeroCopyResult::Invalid { status, msg } => {
                if let Err(err) = write_invalid_response(
                    &stream,
                    conn_version,
                    ConnectionAction::Close,
                    status,
                    msg,
                    None,
                )
                .await
                {
                    if is_peer_disconnect(&err) {
                        info!(
                            "Failed to write error response to client {client}; closing the connection:  {}",
                            ErrorReport(&err)
                        );
                    } else {
                        warn!(
                            "Failed to write error response to client {client}; closing the connection:  {}",
                            ErrorReport(&err)
                        );
                    }
                }

                graceful_close(&stream).await;
                return;
            }
            ZeroCopyResult::Rejection {
                status,
                conn_action,
                msg,
            } => {
                if let Err(err) =
                    write_invalid_response(&stream, conn_version, conn_action, status, msg, None)
                        .await
                {
                    if is_peer_disconnect(&err) {
                        info!(
                            "Failed to write rejection response to client {client}; closing the connection:  {}",
                            ErrorReport(&err)
                        );
                    } else {
                        warn!(
                            "Failed to write rejection response to client {client}; closing the connection:  {}",
                            ErrorReport(&err)
                        );
                    }
                    return;
                }

                match conn_action {
                    ConnectionAction::KeepAlive => {
                        buf.advance(next_header_index);
                        continue;
                    }
                    ConnectionAction::Close => {
                        graceful_close(&stream).await;
                        return;
                    }
                }
            }
            ZeroCopyResult::Tunnel {
                host,
                port,
                tunnel_guard,
                active_guard,
            } => {
                // CONNECT tunnel consumes the whole connection.
                run_connect_tunnel(
                    stream,
                    buf,
                    next_header_index,
                    conn_version,
                    client,
                    host,
                    port,
                    tunnel_guard,
                    active_guard,
                )
                .await;
                return;
            }
            ZeroCopyResult::AfterHeaderError | ZeroCopyResult::ClientError => {
                // Error occurred, should have been already logged.
                // The connection should be closed
                return;
            }
        };
    }
}

/// Read HTTP request headers from the stream into the buffer.
/// Returns when a complete set of headers has been received (terminated by \r\n\r\n) or there is no more data to read.
async fn read_request_headers(
    stream: &TcpStream,
    buf: &mut BytesMut,
) -> std::io::Result<Option<usize>> {
    // Check if we already have the complete headers from the previous read
    if let Some(next_index) = find_header_end(buf) {
        return Ok(Some(next_index));
    }

    let client_idle_timeout = global_config().client_idle_timeout;
    let deadline = tokio::time::sleep(client_idle_timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            biased;
            ready = stream.readable() => {
                ready?;
                match stream.try_read_buf(buf) {
                    Ok(0) => {
                        if buf.is_empty() {
                            // Clean close between requests.
                            return Ok(None);
                        }
                        // Peer closed its write side mid-request, leaving a
                        // partial header block buffered — a truncated request,
                        // not a clean close. Surface it as a disconnect (the
                        // caller's is_peer_disconnect branch handles UnexpectedEof).
                        return Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "connection closed mid-request",
                        ));
                    }
                    Ok(n) => {
                        if let Some(next_index) = find_header_end(buf) {
                            trace!("Read {n} bytes from client, found header end at {next_index}");
                            return Ok(Some(next_index));
                        }
                        if buf.len() > MAX_HEADER_SIZE {
                            return Err(std::io::Error::new(
                                ErrorKind::InvalidInput,
                                "request headers too large",
                            ));
                        }
                        trace!("Read {n} bytes from client, did not find header end");
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        // Race: readable() returned ready but try_read_buf got
                        // WouldBlock.  Looping iterates select! which will
                        // re-poll readable() and naturally pend if the socket
                        // really isn't ready.
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => {}
                    Err(err) => return Err(err),
                }
            }
            () = &mut deadline => {
                metrics::HTTP_TIMEOUT_CLIENT_HEADER.increment();
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "reading TCP stream request headers timed out after {}",
                        HumanFmt::Time(client_idle_timeout)
                    ),
                ));
            }
        }
    }
}

/// Best-effort graceful close after writing an error/rejection response on a
/// connection we are about to drop.  Half-closes the write side (FIN, which
/// flushes the queued response) then briefly drains pending client input, so
/// the final `close(2)` emits a FIN rather than an RST.  An RST can make the
/// peer discard the response it has not read yet — e.g. a request that carried
/// an unread body, which `compute_conn_action` deliberately does not drain.
/// Bounded in both time and bytes so a slow or hostile client cannot pin the
/// task here.
async fn graceful_close(stream: &TcpStream) {
    use std::os::fd::AsRawFd as _;

    const DRAIN_BUDGET: usize = 64 * 1024;

    // FIN out: response bytes flush; the read half stays open to drain.
    if nix::sys::socket::shutdown(stream.as_raw_fd(), nix::sys::socket::Shutdown::Write).is_err() {
        return;
    }

    let mut scratch = [0u8; 4096];
    let mut drained = 0usize;
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(1));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            biased;
            ready = stream.readable() => {
                if ready.is_err() {
                    return;
                }
                match stream.try_read(&mut scratch) {
                    Ok(0) => return, // peer FIN: recv queue drained
                    Ok(n) => {
                        drained = drained.saturating_add(n);
                        if drained >= DRAIN_BUDGET {
                            return;
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                    Err(err) if err.kind() == ErrorKind::Interrupted => {}
                    Err(_) => return,
                }
            }
            () = &mut deadline => return,
        }
    }
}

/// Serve a local web-interface request directly from the sendfile path.
///
/// The web-interface ACL has already been enforced by `preflight_target`.
/// The hyper-based handler exists in `web::serve_web_interface`; this
/// wrapper invokes it and serializes the resulting `WebResponse`
/// onto the raw `TcpStream` with handwritten headers, so webui responses look
/// the same regardless of which connection backend served them.
async fn serve_webui(
    stream: &TcpStream,
    uri: &http::Uri,
    appstate: &AppState,
    client: &ClientInfo,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
) -> ZeroCopyResult {
    let response = serve_web_interface(uri, appstate).await;

    if let Err(err) = write_webui_response(stream, conn_version, conn_action, response).await {
        if is_peer_disconnect(&err) {
            info!(
                "Failed to write web-interface response to client {client}; closing the connection:  {}",
                ErrorReport(&err)
            );
        } else {
            warn!(
                "Failed to write web-interface response to client {client}; closing the connection:  {}",
                ErrorReport(&err)
            );
        }
        return ZeroCopyResult::AfterHeaderError;
    }
    // `SERVED_*` means "fully delivered": bump only after the synchronous
    // write completed (the hyper path gates via `WebUiCountedBody`).
    metrics::SERVED_WEBUI.increment();
    metrics::SERVED_TOTAL.increment();
    ZeroCopyResult::Served(conn_action)
}

/// Format and write a [`WebResponse`] onto the raw stream.
///
/// Deliberately not a `ResponseHead`: web-interface responses are
/// origin-server responses (no `Via:`), so a single `format!` builds the
/// status-line + headers block with named substitutions, mirroring the
/// hyper-side `WebResponse::into_hyper_response` constructor.
async fn write_webui_response(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    response: WebResponse,
) -> std::io::Result<()> {
    let date = format_http_date();
    let content_type = response.content_type();
    let body_len = response.body.len();
    let status = response.status;

    let mut extra_headers = String::new();
    for &(name, value) in response.extra_headers() {
        swrite!(extra_headers, "{name}: {value}\r\n");
    }

    let header = format!(
        "{conn_version} {status}\r\n\
         Server: {APP_NAME}\r\n\
         Date: {date}\r\n\
         Connection: {conn_action}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {body_len}\r\n\
         {extra_headers}\
         \r\n",
    );

    trace!("Outgoing web-interface response headers:\n{header}");
    metrics::record_client_status(status);
    write_all_to_stream(stream, header.as_bytes(), WritePhase::Header).await?;
    write_all_to_stream(stream, &response.body, WritePhase::Body).await
}

/// Map a shared pre-flight/dispatch rejection onto the sendfile result type.
///
/// Diff-request and web-interface ACL rejections keep the connection alive
/// (per the request's own `Connection` semantics); the CONNECT ACL rejection
/// closes it; every other 4xx closes to defend against header smuggling.
/// `conn_action` is a closure because `compute_conn_action` logs a warning
/// for requests carrying a body, which the closing variants never did.
#[must_use]
fn reject_result(
    reason: RejectReason,
    conn_action: impl FnOnce() -> ConnectionAction,
) -> ZeroCopyResult {
    let (status, msg) = reason.response_parts();
    match reason {
        RejectReason::DiffRequest | RejectReason::UnauthorizedWebUi => ZeroCopyResult::Rejection {
            status,
            conn_action: conn_action(),
            msg,
        },
        RejectReason::UnauthorizedClient => ZeroCopyResult::Rejection {
            status,
            conn_action: ConnectionAction::Close,
            msg,
        },
        RejectReason::BadEncoding
        | RejectReason::InvalidValue
        | RejectReason::UnsafePath
        | RejectReason::UnsupportedMethod
        | RejectReason::UnsupportedScheme
        | RejectReason::MissingHost
        | RejectReason::InvalidPort
        | RejectReason::LoopDetected => ZeroCopyResult::Invalid { status, msg },
    }
}

/// Compute the connection action based on the request headers.
#[must_use]
fn compute_conn_action(
    req: &httparse::Request<'_, '_>,
    version: ConnectionVersion,
    client: &ClientInfo,
) -> ConnectionAction {
    // If the client sends a body, just close the connection afterwards
    // to avoid computing the length of the body.
    if req.headers.iter().any(|h| {
        (h.name.eq_ignore_ascii_case("content-length")
            && str::from_utf8(h.value)
                .ok()
                .is_none_or(|hval| hval.trim() != "0"))
            || h.name.eq_ignore_ascii_case("transfer-encoding")
    }) {
        warn_once_or_info!(
            "Request with body detected from client {client}; closing the connection after the response"
        );
        return ConnectionAction::Close;
    }

    if let Some(hvalue) = find_header(req.headers, &CONNECTION) {
        for p in hvalue.split(',') {
            let p = p.trim();

            if p.eq_ignore_ascii_case("close") {
                return ConnectionAction::Close;
            }
            if p.eq_ignore_ascii_case("keep-alive") {
                return ConnectionAction::KeepAlive;
            }

            warn_once_or_debug!(
                "Ignoring unrecognized Connection header value `{p}` from client {client}"
            );
        }
    }

    // Use the protocol default
    match version {
        ConnectionVersion::Http10 => ConnectionAction::Close,
        ConnectionVersion::Http11 => ConnectionAction::KeepAlive,
    }
}

/// Validate a CONNECT request against tunnel policy and, on success, acquire
/// the concurrency guards. Writes nothing to the socket — the outer connection
/// loop owns the stream and drives [`run_connect_tunnel`] on the returned
/// [`ZeroCopyResult::Tunnel`].
///
/// The proxy-client ACL (`allowed_proxy_clients`) has already been enforced
/// by `preflight_method`, which both backends run before reaching here.
#[must_use]
fn handle_connect(client: ClientInfo, target: &str) -> ZeroCopyResult {
    let config = global_config();

    // A CONNECT request target is authority-form ("host:port"); parse it into a
    // URI so the shared validator sees the same `authority()` the hyper backend
    // gets from its pre-parsed request.
    let uri = match target.parse::<http::uri::Uri>() {
        Ok(uri) => uri,
        Err(err) => {
            warn_once_or_info!(
                "Invalid CONNECT address `{}` from client {client}; rejecting the tunnel request with 400:  {}",
                target.escape_debug(),
                ErrorReport(&err)
            );
            return ZeroCopyResult::Rejection {
                status: StatusCode::BAD_REQUEST,
                conn_action: ConnectionAction::Close,
                msg: "Invalid CONNECT address",
            };
        }
    };

    let (host, port) = match validate_connect_target(config, &client, &uri) {
        Ok(hp) => hp,
        Err(ConnectReject { status, msg }) => {
            return ZeroCopyResult::Rejection {
                status,
                conn_action: ConnectionAction::Close,
                msg,
            };
        }
    };

    let tunnel_guard = if let Some(max) = config.https_tunnel_max_connections_per_client {
        let Some(guard) = tunnel_limiter::try_acquire(client.ip(), max) else {
            info!(
                "Rejecting https tunnel request for client {client}: \
                 concurrent connection limit ({max}) reached"
            );
            metrics::TUNNEL_REJECTED_CAPACITY.increment();
            return ZeroCopyResult::Rejection {
                status: StatusCode::TOO_MANY_REQUESTS,
                conn_action: ConnectionAction::Close,
                msg: "Too many concurrent HTTPS tunnel connections",
            };
        };
        Some(guard)
    } else {
        None
    };

    // Account for the active tunnel regardless of whether the per-IP cap is
    // configured, so the dashboard's active/peak counts stay accurate.
    let active_guard = tunnel_limiter::ActiveTunnelGuard::new();

    ZeroCopyResult::Tunnel {
        host,
        port,
        tunnel_guard,
        active_guard,
    }
}

/// Write a `502 Bad Gateway` (`"Upstream Error"`) for a CONNECT whose upstream
/// connect failed *before* `200 Connection Established` was sent, then close.
/// A write failure is logged and swallowed — the connection is being dropped.
async fn write_tunnel_upstream_error(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    client: ClientInfo,
) {
    if let Err(err) = write_invalid_response(
        stream,
        conn_version,
        ConnectionAction::Close,
        StatusCode::BAD_GATEWAY,
        "Upstream Error",
        None,
    )
    .await
    {
        if is_peer_disconnect(&err) {
            info!(
                "Failed to write tunnel 502 response to client {client}; closing the connection:  {}",
                ErrorReport(&err)
            );
        } else {
            warn!(
                "Failed to write tunnel 502 response to client {client}; closing the connection:  {}",
                ErrorReport(&err)
            );
        }
        return;
    }
    graceful_close(stream).await;
}

/// Drive a policy-accepted CONNECT tunnel to completion.
///
/// Consumes the connection. This DELIBERATELY diverges from the hyper backend:
/// hyper emits `200 Connection Established` through its upgrade machinery
/// *before* dialing upstream, so a failed upstream connect can only reach the
/// client as `200` followed by an immediate close. Owning the raw socket here
/// lets us connect upstream FIRST and, on an unreachable/refused/timed-out
/// upstream, return a real `502 Bad Gateway` (per the 5xx convention) instead.
/// This is also why the CONNECT integration tests dial a mock upstream rather
/// than a real host: the connect must succeed for a `200` to be produced.
///
/// On a successful connect it writes `200 Connection Established`, forwards any
/// pipelined bytes already buffered past the request header, then relays bytes
/// bidirectionally. The guards are held for the whole tunnel lifetime.
///
/// `TUNNEL_CONNECTS_TOTAL` is bumped up front (the CONNECT was accepted), so a
/// connect failure's `TUNNEL_TRANSFER_FAILED` bump stays a subset of it — the
/// invariant documented on those counters in `metrics.rs`.
#[expect(
    clippy::too_many_arguments,
    reason = "tunnel relay threads the stream, buffered prefix, target and guards through one call"
)]
async fn run_connect_tunnel(
    stream: TcpStream,
    buf: BytesMut,
    next_header_index: usize,
    conn_version: ConnectionVersion,
    client: ClientInfo,
    host: String,
    port: NonZero<u16>,
    tunnel_guard: Option<tunnel_limiter::TunnelGuard>,
    active_guard: tunnel_limiter::ActiveTunnelGuard,
) {
    let _tunnel_guard = tunnel_guard;
    let _active_guard = active_guard;

    let config = global_config();

    metrics::TUNNEL_CONNECTS_TOTAL.increment();

    // Connect upstream BEFORE sending `200`: owning the raw socket lets a failed
    // connect surface as a real 502 (see the fn doc-comment).
    let mut upstream = match tokio::time::timeout(
        config.http_timeout,
        TcpStream::connect((host.as_str(), port.get())),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(err)) => {
            metrics::TUNNEL_TRANSFER_FAILED.increment();
            warn_once_or_info!(
                "Failed to connect the tunnel to {host}:{port} for client {client}; returning 502:  {}",
                ErrorReport(&err)
            );
            write_tunnel_upstream_error(&stream, conn_version, client).await;
            return;
        }
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
            metrics::TUNNEL_TRANSFER_FAILED.increment();
            info!(
                "Tunnel connect to {host}:{port} for client {client} timed out after {}; returning 502",
                HumanFmt::Time(config.http_timeout)
            );
            write_tunnel_upstream_error(&stream, conn_version, client).await;
            return;
        }
    };

    // Disable Nagle on the tunnel: TLS handshake records and HTTP request
    // headers are interactive, and a tunnel cannot coalesce them on our behalf.
    if config.upstream_tcp_nodelay
        && let Err(err) = upstream.set_nodelay(true)
    {
        warn_once_or_debug!(
            "Failed to set TCP_NODELAY on the upstream tunnel to {host}:{port}; continuing with Nagle enabled:  {}",
            ErrorReport(&err)
        );
    }

    // Upstream is connected: send `200 Connection Established` so the client may
    // begin its TLS handshake. The head is the same `TunnelEstablished` shape
    // the hyper backend renders for its CONNECT response; a tunnel head
    // carries no `Connection:` header, so the action passed is not rendered.
    if let Err(err) = ResponseHead::tunnel_established()
        .write_to(
            &stream,
            conn_version,
            ConnectionAction::Close,
            WireBody::None,
        )
        .await
    {
        if is_peer_disconnect(&err) {
            info!(
                "Failed to send tunnel established response to client {client}; tearing down the tunnel:  {}",
                ErrorReport(&err)
            );
        } else {
            warn!(
                "Failed to send tunnel established response to client {client}; tearing down the tunnel:  {}",
                ErrorReport(&err)
            );
        }
        return;
    }

    info!("Using uncached tunnel for client {client} to {host}:{port}");

    // Flush any client bytes already buffered past the CONNECT header (a
    // pipelined TLS ClientHello); dropping them would stall the handshake.
    if next_header_index < buf.len()
        && let Err(err) = upstream.write_all(&buf[next_header_index..]).await
    {
        metrics::TUNNEL_TRANSFER_FAILED.increment();
        warn_once_or_info!(
            "Failed to forward buffered tunnel bytes to {host}:{port} for client {client}; closing the tunnel:  {}",
            ErrorReport(&err)
        );
        return;
    }

    let start = PreciseInstant::now();
    let outcome = copy_bidirectional_idle(
        stream,
        &mut upstream,
        config.buffer_size,
        config.client_idle_timeout,
    )
    .await;
    report_tunnel_outcome(&outcome, &client, &host, port, start.elapsed());
}

/// Try to serve a request using sendfile(2).
/// Returns a [`ZeroCopyResult`] telling the caller how the request was (or
/// was not) handled.
async fn try_sendfile_request(
    buf: &[u8],
    stream: &TcpStream,
    client: ClientInfo,
    appstate: &AppState,
    conn_version: &mut ConnectionVersion,
) -> ZeroCopyResult {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    static_assert!(
        size_of::<httparse::Header<'_>>() <= 32 && MAX_HEADERS == 100,
        "stack usage of at most 3200 bytes for headers"
    );

    let mut req = httparse::Request::new(&mut headers);

    match req.parse(buf) {
        Ok(httparse::Status::Complete(_)) => match req.version.expect("complete header parsed") {
            1 => *conn_version = ConnectionVersion::Http11,
            0 => *conn_version = ConnectionVersion::Http10,
            v => {
                warn_once_or_info!("Unsupported HTTP/1.{v} from client {client}; returning 505");
                return ZeroCopyResult::Invalid {
                    status: StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                    msg: "HTTP version not supported",
                };
            }
        },
        Ok(httparse::Status::Partial) => {
            match req.version {
                Some(1) => *conn_version = ConnectionVersion::Http11,
                Some(0) => *conn_version = ConnectionVersion::Http10,
                _ => {}
            }

            warn_once_or_info!("Incomplete HTTP request from client {client}; returning 400");
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Incomplete request header",
            };
        }
        Err(httparse::Error::Version) => {
            warn_once_or_info!("Unsupported HTTP version from client {client}; returning 505");
            return ZeroCopyResult::Invalid {
                status: StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                msg: "HTTP version not supported",
            };
        }
        Err(err) => {
            warn_once_or_info!(
                "Failed to parse HTTP request from client {client}; returning 400:  {}",
                ErrorReport(&err)
            );
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Invalid request header",
            };
        }
    }
    let req = req; // mark immutable

    trace!("Parsed client request:\n{req:?}");

    let acls = ClientAcls::from(global_config());

    // Only handle GET requests via sendfile
    match preflight_method(req.method.expect("complete header parsed"), &client, &acls) {
        Ok(RequestKind::Get) => {}
        Ok(RequestKind::Connect) => {
            return handle_connect(client, req.path.expect("complete header parsed"));
        }
        Err(reason) => {
            return reject_result(reason, || compute_conn_action(&req, *conn_version, &client));
        }
    }

    let via_values = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(VIA.as_str()))
        .filter_map(|h| str::from_utf8(h.value).ok());
    if let Err(reason) = preflight_via(via_values, &client) {
        return reject_result(reason, || compute_conn_action(&req, *conn_version, &client));
    }

    let uri = match req
        .path
        .expect("complete header parsed")
        .parse::<http::uri::Uri>()
    {
        Ok(uri) => uri,
        Err(err) => {
            warn_once_or_info!(
                "Failed to parse URI from client {client}; returning 400:  {}",
                ErrorReport(&err)
            );
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Invalid URI",
            };
        }
    };

    let (requested_host, requested_port) = match preflight_target(
        &uri,
        *conn_version == ConnectionVersion::Http11,
        || find_header(req.headers, &HOST).is_some(),
        &client,
        &acls,
    ) {
        Ok(RequestTarget::Proxy { host, port }) => (host, port),
        Ok(RequestTarget::WebUi) => {
            let conn_action = compute_conn_action(&req, *conn_version, &client);
            return serve_webui(stream, &uri, appstate, &client, *conn_version, conn_action).await;
        }
        Err(reason) => {
            return reject_result(reason, || compute_conn_action(&req, *conn_version, &client));
        }
    };

    let requested_host = match authorize_cache_access(&client, requested_host) {
        Ok(rh) => rh,
        Err((status, msg)) => return ZeroCopyResult::Invalid { status, msg },
    };

    let conn_action = compute_conn_action(&req, *conn_version, &client);

    // Unified dispatch shared with hyper_conn.rs: diff-reject -> normalize
    // -> parse -> classify -> flat-blocklist -> deferred-Origin-DB ->
    // unsafe-path gate.  Logging, metric bumping, the deferred Origin DB
    // write and `record_uncacheable` happen inside `dispatch_request`, which
    // runs once per request: a handoff carries its outcome to hyper.  This
    // match only maps outcomes to ZeroCopyResult.
    let uri_path = uri.path();
    let conn_details =
        match dispatch_request(uri_path, requested_host, requested_port, &client).await {
            DispatchOutcome::Cache(conn_details) => conn_details,
            DispatchOutcome::Reject(reason) => return reject_result(reason, || conn_action),
            #[cfg(feature = "splice")]
            DispatchOutcome::Passthrough {
                reason,
                requested_host,
                request_received_at,
            } => {
                use crate::{
                    deb_mirror::{Mirror, MirrorKind},
                    splice::splice_simple_proxy,
                };

                warn_once_or_info!(
                    "Proxying (without caching) request {uri} for client {client} ({})",
                    reason.label()
                );

                // Simple-proxy path: this Mirror is used only for upstream
                // dispatch/formatting and is never persisted; kind is arbitrary.
                let mirror = Mirror::new(
                    requested_host,
                    requested_port,
                    String::new(),
                    MirrorKind::Structured,
                );

                return match splice_simple_proxy(
                    stream,
                    *conn_version,
                    conn_action,
                    &mirror,
                    uri.path_and_query().map_or(uri_path, |pq| pq.as_str()),
                    client,
                    request_received_at,
                )
                .await
                {
                    Ok(()) => ZeroCopyResult::Served(conn_action),
                    Err(err) => splice_error_outcome(
                        err,
                        "simple proxy",
                        format_args!("{uri_path} from host {}", mirror.format_authority()),
                    ),
                };
            }
            #[cfg(not(feature = "splice"))]
            DispatchOutcome::Passthrough {
                reason,
                requested_host,
                request_received_at,
            } => {
                // Without splice this backend has no uncached forwarder; hyper
                // continues from the dispatch verdict.
                return ZeroCopyResult::NotApplicable {
                    reason: reason.label(),
                    plan: HandoffPlan::Passthrough {
                        reason,
                        requested_host,
                        requested_port,
                        request_received_at,
                    },
                };
            }
        };

    let aliased = conn_details.alias_suffix();

    // Check if the file is currently being downloaded - if so, serve it via
    // sendfile from the growing partial file.  `attach()` atomically records
    // the late joiner under the same write lock as the lookup; should the
    // response turn out unframeable here (no Content-Length), the attached
    // status travels to hyper in the `NotApplicable` plan, so the joiner is
    // never registered twice.
    if let Some(dl_status) = appstate.active_downloads.attach(conn_details.key()) {
        // Coalesced permanent late-joiners count as `CACHE_MISSES`: the file
        // was not yet fully on disk so we would have fetched upstream if not
        // for the in-flight originator. `LATE_JOINERS_TOTAL` is the subset of
        // misses that attached; `attach()` already bumped that counter. The
        // volatile case is accounted for via `VOLATILE_REFETCHED` by the
        // originator.
        if conn_details.cached_flavor() == CachedFlavor::Permanent {
            metrics::CACHE_MISSES.increment();
        }

        return serve_unfinished_sendfile(
            stream,
            conn_details,
            &aliased,
            dl_status,
            *conn_version,
            conn_action,
            RangeRequestHeaders::extract(req.headers),
        )
        .await;
    }

    let cache_path = conn_details.cache_file_path();

    // This is the lookup site for every request that gets here, so the
    // hit/miss/refetch counters are bumped exactly here - whether the miss is
    // then fetched by splice below or handed to hyper, which enters its
    // pipeline past its own lookup (`HandoffPlan::CacheMiss`).

    // Try to open the cached file; for volatile resources, treat stale files as cache misses.
    let cached_file = 'cache_lookup: {
        let file = match tokio_nofollow_options().read(true).open(&cache_path).await {
            Ok(f) => f,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                break 'cache_lookup Err(CacheMiss::NotFound);
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to open cached file `{}` for client {client}; returning 500:  {}",
                    cache_path.display(),
                    ErrorReport(&err)
                );
                return ZeroCopyResult::Invalid {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    msg: "Cache Access Failure",
                };
            }
        };

        // Volatile staleness: if file is older than VOLATILE_CACHE_MAX_AGE,
        // treat as cache miss so splice/hyper can fetch a fresh copy from
        // upstream. Keep the metadata for the serve path so it doesn't
        // fstat a second time.
        if conn_details.cached_flavor() == CachedFlavor::Volatile {
            match regular_file_metadata(&file, &cache_path) {
                Ok(md) => {
                    let last_modified = md
                        .modified()
                        .expect("Platform should support modification timestamps via setup check");
                    if let Ok(elapsed) = last_modified.elapsed() {
                        if elapsed >= VOLATILE_CACHE_MAX_AGE {
                            break 'cache_lookup Err(CacheMiss::StaleVolatile {
                                file,
                                modified: last_modified,
                                size: md.size(),
                            });
                        }

                        debug!(
                            "Volatile file `{}` age {} is within the {} freshness window, serving cached version...",
                            cache_path.display(),
                            HumanFmt::Time(elapsed),
                            HumanFmt::Time(VOLATILE_CACHE_MAX_AGE)
                        );
                    } else {
                        // Served from cache all the same - keep the
                        // hit/miss metrics complete via the shared bump below.
                        warn_once_or_info!(
                            "Volatile file `{}` was modified in the future; serving the cached copy anyway",
                            cache_path.display()
                        );
                    }
                    metrics::VOLATILE_HIT.increment();
                    break 'cache_lookup Ok((file, Some(md)));
                }
                Err(CacheAccessFailure(_)) => {
                    return ZeroCopyResult::Invalid {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        msg: "Cache Access Failure",
                    };
                }
            }
        }

        Ok((file, None))
    };

    let miss = match cached_file {
        Ok((file, mdata)) => {
            // CACHE_HITS only counts permanent-file hits; fresh volatile hits
            // were already bumped as VOLATILE_HIT in the cache_lookup block.
            if conn_details.cached_flavor() == CachedFlavor::Permanent {
                metrics::CACHE_HITS.increment();
            }
            conn_details.record_origin();

            return serve_file_via_sendfile(
                stream,
                &conn_details,
                &aliased,
                (file, mdata, &cache_path),
                (*conn_version, conn_action),
                RangeRequestHeaders::extract(req.headers),
                None,
            )
            .await
            .into();
        }
        Err(miss) => miss,
    };

    // Cache miss or stale volatile file: a permanent file not found is a real
    // cache miss; a volatile file not found or stale is a refetch.
    match &miss {
        CacheMiss::NotFound => match conn_details.cached_flavor() {
            CachedFlavor::Permanent => metrics::CACHE_MISSES.increment(),
            CachedFlavor::Volatile => metrics::VOLATILE_REFETCHED.increment(),
        },
        CacheMiss::StaleVolatile { .. } => metrics::VOLATILE_REFETCHED.increment(),
    }

    #[cfg(feature = "splice")]
    {
        use crate::splice::{SpliceProxyOutcome, splice_proxy};

        // Splice fetches on its own path and re-opens a stale copy itself.
        drop(miss);

        let outcome = splice_proxy(
            stream,
            *conn_version,
            conn_action,
            &conn_details,
            uri.path_and_query().map_or(uri_path, |pq| pq.as_str()),
            appstate,
            RangeRequestHeaders::extract(req.headers),
        )
        .await;
        match outcome {
            Ok(SpliceProxyOutcome::Served) => ZeroCopyResult::Served(conn_action),
            Ok(SpliceProxyOutcome::ClientLost) => ZeroCopyResult::AfterHeaderError,
            Ok(SpliceProxyOutcome::Concurrent { status: dl_status }) => {
                // Race-loser path: another connection registered the
                // download between our earlier `attach()` (which saw
                // nothing) and `splice_proxy`'s `originate()`. The
                // existing download's status was handed back by
                // `originate()` and is held alive by the Arc, so we can
                // serve from the partial via sendfile directly - no
                // re-attach, no race-of-races fall-back. `CACHE_MISSES`
                // (permanent) or `VOLATILE_REFETCHED` (volatile) was bumped
                // above when the cache lookup found no usable file;
                // `LATE_JOINERS_TOTAL` was bumped inside `originate()`.
                serve_unfinished_sendfile(
                    stream,
                    conn_details,
                    &aliased,
                    dl_status,
                    *conn_version,
                    conn_action,
                    RangeRequestHeaders::extract(req.headers),
                )
                .await
            }
            Ok(SpliceProxyOutcome::AtCapacity { max }) => {
                // Same log line and canonical 503 as the hyper backend's
                // `upstream_cap_rejection`; the metric bump happened inside
                // `ActiveDownloads::lookup_or_insert`.
                warn_once_or_info!(
                    "Max upstream downloads ({max}) exceeded for {} from client {client}; returning 503",
                    conn_details.debname,
                );
                ZeroCopyResult::Rejection {
                    status: StatusCode::SERVICE_UNAVAILABLE,
                    conn_action,
                    msg: "Too many concurrent upstream downloads",
                }
            }
            Err(err) => splice_error_outcome(
                err,
                "splice proxy",
                format_args!(
                    "{} from mirror {}{}",
                    conn_details.debname, conn_details.mirror, aliased
                ),
            ),
        }
    }

    #[cfg(not(feature = "splice"))]
    {
        let reason = match miss {
            CacheMiss::NotFound => "file not found in cache",
            CacheMiss::StaleVolatile { .. } => "stale volatile file in cache",
        };
        ZeroCopyResult::NotApplicable {
            reason,
            plan: HandoffPlan::CacheMiss {
                conn_details,
                cache_path,
                miss,
            },
        }
    }
}

/// The single outer arm for [`SpliceProxyError`]: maps every variant to its
/// connection-level outcome and writes the log lines the variants delegate
/// to it. The policy -- which variants are logged here and at what
/// severity, which arrive with a `Logged` proof and map silently -- is
/// documented on the variants themselves; this `match` only implements it,
/// and is exhaustive so a new variant lands here as a compile error.
///
/// `prefix` is the registered subsystem prefix,
/// `subject` names the resource the way that path's other lines do.
///
/// `AfterHeaderSide::Upstream` is not reachable from `splice_simple_proxy`
/// today (it relays the body itself rather than through
/// `splice_proxy_body{,_tls}`, the only producers); it is handled uniformly
/// rather than as a panic so wiring the split into the passthrough relay is
/// not a production hazard.
#[cfg(feature = "splice")]
fn splice_error_outcome(
    err: SpliceProxyError,
    prefix: &str,
    subject: std::fmt::Arguments<'_>,
) -> ZeroCopyResult {
    use crate::splice::{AfterHeaderSide, UpstreamFailure};

    match err {
        SpliceProxyError::Upstream(UpstreamFailure {
            err: _,
            logged: _logged,
        }) => ZeroCopyResult::Invalid {
            status: StatusCode::BAD_GATEWAY,
            msg: "Upstream Error",
        },
        SpliceProxyError::Cache(_logged) => ZeroCopyResult::Invalid {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            msg: "Cache Access Failure",
        },
        SpliceProxyError::Client { phase, err } => {
            if is_peer_disconnect(&err) {
                info!(
                    "{prefix}: client error writing {phase} (peer disconnect) for {subject}; closing the connection:  {}",
                    ErrorReport(&err)
                );
            } else {
                warn!(
                    "{prefix}: client error writing {phase} for {subject}; closing the connection:  {}",
                    ErrorReport(&err)
                );
            }
            ZeroCopyResult::ClientError
        }
        SpliceProxyError::AfterHeader { phase, side } => {
            match side {
                AfterHeaderSide::Client(err) => {
                    if is_peer_disconnect(&err) {
                        info!(
                            "{prefix}: client response delivery aborted in {phase} (peer disconnect) for {subject}; closing the connection:  {}",
                            ErrorReport(&err)
                        );
                    } else {
                        warn!(
                            "{prefix}: client response delivery failed in {phase} for {subject}; closing the connection:  {}",
                            ErrorReport(&err)
                        );
                    }
                }
                // No peer-hung-up case to demote (see the variant doc): every
                // way here means this mirror failed to deliver a body it had
                // already promised, and the operator wants to see which
                // mirror. Counter-backed and bounded to one line per
                // connection, so it takes the same once-gating exemption as
                // the delivery split.
                AfterHeaderSide::Upstream(err) => {
                    warn!(
                        "{prefix}: upstream failed in {phase} for {subject}; closing the connection:  {}",
                        ErrorReport(&err)
                    );
                }
                AfterHeaderSide::Cache(_logged) | AfterHeaderSide::Proxy(_logged) => {}
            }
            ZeroCopyResult::AfterHeaderError
        }
    }
}

/// Outcome of [`evaluate_conditional_and_range`].
enum ConditionalOutcome {
    /// The 304 Not Modified response has already been written to the stream;
    /// the caller should report the request as served using this `ConnectionAction`.
    NotModified(ConnectionAction),
    /// The 416 Range Not Satisfiable response has already been written to the stream;
    /// the caller should report the request as served using this `ConnectionAction`.
    RangeNotSatisfiable(ConnectionAction),
    /// Proceed with serving the file using these range parameters.
    Serve(ServeParams),
}

/// Evaluate conditional request headers (If-None-Match, If-Modified-Since) and
/// Range headers via [`CacheInfo::plan`], writing 304 or 416 responses
/// directly to the stream when the plan says so.
///
/// Returns [`ConditionalOutcome::Serve`] with the resolved range parameters
/// when the caller should proceed with sending the file body.
async fn evaluate_conditional_and_range(
    stream: &TcpStream,
    client: &ClientInfo,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    cache_info: &CacheInfo,
    file_size: u64,
    headers: RangeRequestHeaders<'_>,
) -> Result<ConditionalOutcome, SendfileResult> {
    let params = match cache_info.plan(file_size, &headers, client) {
        ServePlan::Serve(params) => params,
        ServePlan::NotModified => {
            if let Err(err) = write_304_response(
                stream,
                conn_version,
                conn_action,
                &cache_info.last_modified_str,
                cache_info.age,
                cache_info.file_etag.as_deref(),
            )
            .await
            {
                if is_peer_disconnect(&err) {
                    info!(
                        "Failed to write 304 response to client {client}; closing the connection:  {}",
                        ErrorReport(&err)
                    );
                } else {
                    warn!(
                        "Failed to write 304 response to client {client}; closing the connection:  {}",
                        ErrorReport(&err)
                    );
                }
                return Err(SendfileResult::ClientError);
            }

            return Ok(ConditionalOutcome::NotModified(conn_action));
        }
        ServePlan::NotSatisfiable => {
            if let Err(err) = write_416_response(stream, conn_version, conn_action, file_size).await
            {
                if is_peer_disconnect(&err) {
                    info!(
                        "Failed to write 416 response to client {client}; closing the connection:  {}",
                        ErrorReport(&err)
                    );
                } else {
                    warn!(
                        "Failed to write 416 response to client {client}; closing the connection:  {}",
                        ErrorReport(&err)
                    );
                }
                return Err(SendfileResult::ClientError);
            }

            return Ok(ConditionalOutcome::RangeNotSatisfiable(conn_action));
        }
    };

    Ok(ConditionalOutcome::Serve(params))
}

pub(crate) enum SendfileResult {
    Invalid {
        status: StatusCode,
        msg: &'static str,
    },
    Served(ConnectionAction),
    AfterHeaderError,
    ClientError,
}

/// Serve a file via sendfile(2), handling conditional requests (304),
/// range requests, and database delivery tracking.
///
/// Shared implementation used for both already-cached files and files
/// that finished downloading while a joining client was waiting.
pub(crate) async fn serve_file_via_sendfile(
    stream: &TcpStream,
    conn_details: &ConnectionDetails,
    aliased: &str,
    source: (tokio::fs::File, Option<std::fs::Metadata>, &Path),
    conn_settings: (ConnectionVersion, ConnectionAction),
    headers: RangeRequestHeaders<'_>,
    prefetched_upstream_metadata: Option<&cache_metadata::UpstreamMetadata>,
) -> SendfileResult {
    let (file, prefetched_mdata, file_path) = source;
    let (conn_version, conn_action) = conn_settings;

    // The volatile-hit path already fetched (and is_file-validated) the
    // metadata for its staleness check; don't pay a second fstat here.
    let mdata = if let Some(m) = prefetched_mdata {
        m
    } else {
        match regular_file_metadata(&file, file_path) {
            Ok(m) => m,
            Err(CacheAccessFailure(_)) => {
                return SendfileResult::Invalid {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    msg: "Cache Access Failure",
                };
            }
        }
    };

    let file_size = mdata.len();

    let cache_info = if let Some(meta) = prefetched_upstream_metadata {
        CacheInfo::with_meta(&mdata, meta)
    } else {
        let key = conn_details.key();
        CacheInfo::resolve(&file, file_path, &mdata, &key)
    };

    let params = match evaluate_conditional_and_range(
        stream,
        &conn_details.client,
        conn_version,
        conn_action,
        &cache_info,
        file_size,
        headers,
    )
    .await
    {
        Ok(ConditionalOutcome::NotModified(ca)) => {
            info!(
                "Serving 304 Not Modified for cached file {} from mirror {}{aliased} for client {} via sendfile",
                conn_details.debname, conn_details.mirror, conn_details.client
            );
            return SendfileResult::Served(ca);
        }
        Ok(ConditionalOutcome::RangeNotSatisfiable(ca)) => {
            return SendfileResult::Served(ca);
        }
        Ok(ConditionalOutcome::Serve(params)) => params,
        Err(result) => return result,
    };
    let partial = params.is_partial();
    let http_status = params.http_status();
    let ServeParams {
        content_start,
        content_length,
        content_range,
    } = params;

    debug!(
        "Serving cached file {} from mirror {}{aliased} for client {} via sendfile...",
        conn_details.debname, conn_details.mirror, conn_details.client,
    );

    // sendfile streams the file linearly through the kernel, so help the
    // page-cache readahead window grow before the splice loop starts.
    hint_sequential_read(&file, content_length, file_path);

    // Headers are sent with MSG_MORE (see write_response_headers), so the
    // kernel coalesces them with the first sendfile body bytes — no
    // TCP_CORK setsockopt pair needed.

    // Write HTTP response headers
    let headers = ResponseHeaders {
        conn_version,
        status: http_status,
        conn_action,
        content_length,
        content_type: content_type_for_cached_file(&conn_details.debname),
        last_modified_str: &cache_info.last_modified_str,
        age: cache_info.age,
        content_range: content_range.as_deref(),
        etag: cache_info.file_etag.as_deref(),
    };
    if let Err(err) = write_response_headers(stream, headers).await {
        if is_peer_disconnect(&err) {
            info!(
                "Failed to write response headers to client {}; closing the connection:  {}",
                conn_details.client,
                ErrorReport(&err)
            );
        } else {
            warn!(
                "Failed to write response headers to client {}; closing the connection:  {}",
                conn_details.client,
                ErrorReport(&err)
            );
        }
        return SendfileResult::ClientError;
    }

    let start = PreciseInstant::now();

    // Use sendfile(2) to transfer the file body
    metrics::REQUESTS_SENDFILE.increment();
    let transfer_result = async_sendfile(stream, &file, content_start, content_length).await;

    let elapsed = start.elapsed();
    let (complete, transferred, failure) = match &transfer_result {
        Ok(transferred) => (true, *transferred, None),
        Err((transferred, err)) => (
            false,
            *transferred,
            Some((ErrorReport(err), is_peer_disconnect(err))),
        ),
    };
    let outcome = ServeOutcome {
        size: content_length,
        transferred,
        complete,
        partial,
        elapsed,
        abort: failure
            .as_ref()
            .map(|(reason, peer_disconnect)| AbortCause {
                reason,
                peer_disconnect: *peer_disconnect,
            }),
    };
    if let Some(cmd) = finish_cached_serve(conn_details, Mechanism::Sendfile, Role::Cached, outcome)
    {
        send_db_command(DatabaseCommand::Transfer(cmd)).await;
    }
    if complete {
        SendfileResult::Served(conn_action)
    } else {
        SendfileResult::AfterHeaderError
    }
}

/// Format an `InsufficientRate` into a timeout `std::io::Error`, tagging
/// which side of the proxy the slow transfer was observed on.
#[must_use]
fn rate_timeout_error(rate: &InsufficientRate, direction: RateCheckDirection) -> std::io::Error {
    let context = match direction {
        RateCheckDirection::Client => " for client",
        RateCheckDirection::Upstream => " for upstream",
    };
    rate.to_timeout_io_error(format_args!("{context}"))
}

/// Whether the helper waits for read-readiness or write-readiness.
#[derive(Copy, Clone)]
enum SocketReadiness {
    #[cfg_attr(
        not(feature = "splice"),
        expect(dead_code, reason = "sendfile backend does not read from any upstream")
    )]
    Readable,
    Writable,
}

/// Cadence for the rate-check tick, derived from the configured
/// `rate_check_timeframe`.  Aim for roughly five samples per window so
/// `check_fail` fires well within the window on stalled sockets, then
/// clamp to `[1 s, 5 s]`: the upper bound caps timer churn for the
/// default 30 s window, and the lower bound preserves the original 1 s
/// granularity for the warned-but-allowed sub-5 s configurations.
///
/// Worst-case detection latency is `timeframe + rate_check_tick`.  For
/// the default 30 s window that is 35 s (~1.17× the window); the prior
/// fixed-1 s tick gave 31 s (~1.03×) at the cost of one inner timer
/// per second on every stalled socket.  Trade is intentional: the
/// extra ~4 s of detection lag is negligible against a window measured
/// in tens of seconds, and timer churn on the fast path drops 5×.
fn rate_check_tick(rc: &RateChecker) -> std::time::Duration {
    let secs = (rc.timeframe().get() / 5).clamp(1, 5);
    std::time::Duration::from_secs(secs as u64)
}

/// Wait for the socket to become readable or writable, bounded by
/// `http_timeout`.  When a `RateChecker` is supplied, also wakes up
/// every [`rate_check_tick`] so a stalled socket trips the configured
/// rate-check window.  `RateChecker::add` back-fills gaps on the next
/// sample on its own; the `rc.add(0)` calls here only exist to drive
/// `check_fail` on each tick.
///
/// Implementation note: the previous version constructed two
/// `tokio::time::Timeout` futures per call (outer `http_timeout` plus a
/// fresh inner 1 s timer per loop iteration), allocating even on the
/// fast path where `wait_once` returns instantly.  This version pins
/// one outer `Sleep` and one re-armable inner `Sleep`, then drives them
/// with `tokio::select!` — no per-iteration allocation.
async fn wait_socket_rated(
    socket: &TcpStream,
    op: SocketReadiness,
    rate_checker: &mut Option<RateChecker>,
    direction: RateCheckDirection,
    http_timeout: std::time::Duration,
) -> std::io::Result<()> {
    // The timeout-metric branch below maps `Upstream → HTTP_TIMEOUT_UPSTREAM_READ`
    // unconditionally, so passing `(Writable, Upstream)` here would mislabel an
    // upstream-write stall as an upstream-read stall. No caller does this today.
    // If you need to wait on an upstream write, introduce a dedicated
    // `HTTP_TIMEOUT_UPSTREAM_WRITE` metric and extend the match below first.
    debug_assert!(
        !matches!(
            (op, direction),
            (SocketReadiness::Writable, RateCheckDirection::Upstream)
        ),
        "wait_socket_rated has no metric for upstream-write timeouts; add HTTP_TIMEOUT_UPSTREAM_WRITE before introducing a caller"
    );

    let timeout_msg = match (op, direction) {
        (SocketReadiness::Readable, RateCheckDirection::Client) => "client read timed out",
        (SocketReadiness::Writable, RateCheckDirection::Client) => "client write timed out",
        (SocketReadiness::Readable, RateCheckDirection::Upstream) => "upstream read timed out",
        (SocketReadiness::Writable, RateCheckDirection::Upstream) => "upstream write timed out",
    };

    let bump_timeout = || match direction {
        RateCheckDirection::Client => metrics::HTTP_TIMEOUT_CLIENT_BODY.increment(),
        RateCheckDirection::Upstream => metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment(),
    };

    let outer = tokio::time::sleep(http_timeout);
    tokio::pin!(outer);

    if let Some(rc) = rate_checker {
        let tick_period = rate_check_tick(rc);
        let tick = tokio::time::sleep(tick_period);
        tokio::pin!(tick);

        loop {
            tokio::select! {
                biased;
                result = async {
                    match op {
                        SocketReadiness::Readable => socket.readable().await,
                        SocketReadiness::Writable => socket.writable().await,
                    }
                } => return result,
                () = &mut tick => {
                    rc.add(0);
                    if let Some(rate) = rc.check_fail(direction) {
                        return Err(rate_timeout_error(&rate, direction));
                    }
                    tick.as_mut().reset(tokio::time::Instant::now() + tick_period);
                }
                () = &mut outer => {
                    bump_timeout();
                    return Err(std::io::Error::new(
                        ErrorKind::TimedOut,
                        format!("{timeout_msg} after {}", HumanFmt::Time(http_timeout)),
                    ));
                }
            }
        }
    }

    tokio::select! {
        biased;
        result = async {
            match op {
                SocketReadiness::Readable => socket.readable().await,
                SocketReadiness::Writable => socket.writable().await,
            }
        } => result,
        () = &mut outer => {
            bump_timeout();
            Err(std::io::Error::new(
                ErrorKind::TimedOut,
                format!("{timeout_msg} after {}", HumanFmt::Time(http_timeout)),
            ))
        }
    }
}

// Force-clear Tokio's cached readiness on a TCP socket.
//
// `sendfile`/`splice`/`tee` operate on raw fds and can return `EAGAIN`;
// Tokio doesn't see those errors so its cache stays "ready" and the next
// `readable()`/`writable()` returns instantly instead of parking — a
// busy-spin. We invoke `try_io` with a no-op closure that returns
// `WouldBlock` to trigger `clear_readiness` and force the next wait to
// actually park until a fresh epoll event arrives.

#[cfg(feature = "splice")]
pub(crate) fn clear_tcp_readable_cache(socket: &TcpStream) {
    let _ignore = socket.try_io(Interest::READABLE, || -> std::io::Result<()> {
        Err(ErrorKind::WouldBlock.into())
    });
}

#[cfg(feature = "splice")]
pub(crate) fn clear_tcp_writable_cache(socket: &TcpStream) {
    let _ignore = socket.try_io(Interest::WRITABLE, || -> std::io::Result<()> {
        Err(ErrorKind::WouldBlock.into())
    });
}

pub(crate) async fn wait_writable_rated(
    socket: &TcpStream,
    rate_checker: &mut Option<RateChecker>,
    direction: RateCheckDirection,
    http_timeout: std::time::Duration,
) -> std::io::Result<()> {
    wait_socket_rated(
        socket,
        SocketReadiness::Writable,
        rate_checker,
        direction,
        http_timeout,
    )
    .await
}

#[cfg(feature = "splice")]
pub(crate) async fn wait_readable_rated(
    socket: &TcpStream,
    rate_checker: &mut Option<RateChecker>,
    direction: RateCheckDirection,
    http_timeout: std::time::Duration,
) -> std::io::Result<()> {
    wait_socket_rated(
        socket,
        SocketReadiness::Readable,
        rate_checker,
        direction,
        http_timeout,
    )
    .await
}

/// Like [`crate::http_helpers::write_all_to_stream`], but additionally enforces
/// the configured minimum download rate via `rate_checker` (when supplied).
///
/// Used for payload-carrying writes; header-only writes should keep using the
/// non-rated variant since rate-limiting is not meaningful for small fixed
/// control frames.
#[cfg(feature = "splice")]
pub(crate) async fn write_all_to_stream_rated(
    socket: &TcpStream,
    mut data: &[u8],
    rate_checker: &mut Option<RateChecker>,
    direction: RateCheckDirection,
    http_timeout: std::time::Duration,
) -> std::io::Result<()> {
    let error_msg = match direction {
        RateCheckDirection::Client => "client write failed",
        RateCheckDirection::Upstream => "upstream write failed",
    };

    while !data.is_empty() {
        wait_writable_rated(socket, rate_checker, direction, http_timeout).await?;

        let _: Never = match socket.try_write(data) {
            Ok(0) => {
                return Err(std::io::Error::new(ErrorKind::WriteZero, error_msg));
            }
            Ok(n) => {
                if let Some(rc) = rate_checker.as_mut() {
                    rc.add(n);
                }
                data = &data[n..];
                continue;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => continue,
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
    }

    Ok(())
}

/// Outcome of [`sendfile_chunk_loop`]: [`ChunkLoopOutcome::Complete`] when
/// all `amount` bytes were transferred, [`ChunkLoopOutcome::Eof`] if
/// sendfile(2) reported EOF (returned 0) before completion — the caller
/// decides whether that is an error.
enum ChunkLoopOutcome {
    Complete,
    Eof { transferred: u64 },
}

/// Reason the inner blocking sendfile loop returned to async context.
enum SendfileBatchStop {
    /// Inner loop transferred all `count` requested bytes.
    Done,
    /// `sendfile(2)` returned 0 — caller treats as EOF.
    Eof,
    /// `sendfile(2)` returned `EAGAIN` — caller must wait for the socket
    /// to become writable before re-entering the blocking loop.
    NeedsWritable,
    /// `sendfile(2)` returned an error other than `EAGAIN`/`EINTR`.
    Error(nix::errno::Errno),
}

struct SendfileBatch {
    /// Total bytes transferred during this batch.
    transferred: usize,
    /// Updated file offset after the last successful sendfile call.
    new_offset: i64,
    stop: SendfileBatchStop,
}

/// Dup'd socket + file descriptor pair threaded through the blocking
/// sendfile batches.
///
/// The descriptors are dup'd once per transfer and passed by ownership
/// through each `spawn_blocking`, coming back via the closure return
/// value.  If the outer future is cancelled mid-batch (client disconnect,
/// runtime shutdown), tokio cannot abort `spawn_blocking` — it merely
/// detaches the `JoinHandle`.  The detached closure still owns the
/// `OwnedFd`s, so the kernel descriptors stay open until it returns and
/// cannot be reassigned to an unrelated FD by a parent's
/// `TcpStream`/`File` Drop.  One dup pair per transfer amortises across
/// many EAGAIN cycles and, for unfinished-file serves, across many
/// availability windows.
pub(crate) struct SendfileFds {
    socket: std::os::fd::OwnedFd,
    file: std::os::fd::OwnedFd,
}

impl SendfileFds {
    pub(crate) fn dup(socket: &TcpStream, file: &tokio::fs::File) -> std::io::Result<Self> {
        Ok(Self {
            socket: nix::unistd::dup(socket.as_fd())
                .map_err(|errno| errno_to_io_error(errno, "dup of socket fd failed"))?,
            file: nix::unistd::dup(file.as_fd())
                .map_err(|errno| errno_to_io_error(errno, "dup of file fd failed"))?,
        })
    }
}

/// Transfer up to `amount` bytes from `fds.file` at `*file_offset` to
/// `fds.socket` using sendfile(2), handling rate checking and writability
/// polling.  Returns the fd pair for reuse by the next call; on error the
/// transfer is over and the pair is dropped.
async fn sendfile_chunk_loop(
    socket: &TcpStream,
    mut fds: SendfileFds,
    file_offset: &mut i64,
    amount: u64,
    rate_checker: &mut Option<RateChecker>,
) -> std::io::Result<(ChunkLoopOutcome, SendfileFds)> {
    // Per-syscall cap to avoid exceeding system limits.  Always within
    // usize range since it fits in 31 bits.
    const MAX_PER_SYSCALL: usize = 0x7fff_f000;
    static_assert!(MAX_PER_SYSCALL < usize::MAX);

    let config = global_config();
    let mut remaining = amount;

    while remaining > 0 {
        if let Some(rc) = rate_checker.as_ref()
            && let Some(rate) = rc.check_fail(RateCheckDirection::Client)
        {
            return Err(rate_timeout_error(&rate, RateCheckDirection::Client));
        }

        wait_writable_rated(
            socket,
            rate_checker,
            RateCheckDirection::Client,
            config.http_timeout,
        )
        .await?;

        // Hand the entire "transfer up to `count` bytes" loop to one
        // spawn_blocking so consecutive sendfile() syscalls run on the same
        // blocking-pool thread without bouncing back through the tokio
        // scheduler each time.  The blocking task only returns when the
        // kernel socket buffer fills (EAGAIN), the file ends, or all
        // requested bytes have moved — sharply reducing the per-request
        // spawn_blocking count for large cached-file serves.
        let count: usize = remaining.try_into().unwrap_or(usize::MAX);
        let off_in = *file_offset;

        let SendfileFds { socket: s, file: f } = fds;

        let (batch, s, f) = tokio::task::spawn_blocking(move || {
            let mut transferred: usize = 0;
            let mut off = off_in;
            let mut left = count;
            let stop = loop {
                if left == 0 {
                    break SendfileBatchStop::Done;
                }
                let chunk_size = std::cmp::min(left, MAX_PER_SYSCALL);
                match sendfile(s.as_fd(), f.as_fd(), Some(&mut off), chunk_size) {
                    Ok(0) => break SendfileBatchStop::Eof,
                    Ok(n) => {
                        transferred += n;
                        left -= n;
                    }
                    Err(nix::errno::Errno::EAGAIN) => {
                        break SendfileBatchStop::NeedsWritable;
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(e) => break SendfileBatchStop::Error(e),
                }
            };
            (
                SendfileBatch {
                    transferred,
                    new_offset: off,
                    stop,
                },
                s,
                f,
            )
        })
        .await
        .expect("task should not panic");

        fds = SendfileFds { socket: s, file: f };

        // Apply state changes from whatever progress the batch made before
        // it stopped (success or EAGAIN both leave us with bytes to credit).
        *file_offset = batch.new_offset;
        remaining = remaining
            .checked_sub(batch.transferred as u64)
            .expect("sendfile(2) should not transfer more bytes than requested");
        metrics::BYTES_SERVED_SENDFILE.increment_by(batch.transferred as u64);
        if let Some(rc) = rate_checker
            && batch.transferred > 0
        {
            rc.add(batch.transferred);
        }

        match batch.stop {
            SendfileBatchStop::Done => return Ok((ChunkLoopOutcome::Complete, fds)),
            SendfileBatchStop::Eof => {
                warn_once_or_debug!(
                    "sendfile: returned 0 at offset {file_offset} with {remaining}/{amount} bytes remaining; stopping the transfer at that offset"
                );
                return Ok((
                    ChunkLoopOutcome::Eof {
                        transferred: amount - remaining,
                    },
                    fds,
                ));
            }
            SendfileBatchStop::NeedsWritable => {
                // The raw sendfile(2) EAGAIN inside the blocking batch is
                // invisible to Tokio, so its cached WRITABLE readiness would
                // make the next `wait_writable_rated` return instantly — a
                // busy-spin for as long as the client's socket buffer stays
                // full.  A bare no-op `try_io` clear would race a wakeup
                // delivered between the batch's EAGAIN and the clear
                // (wiping it stalls the transfer until http_timeout), so
                // retry one sendfile *inside* `try_io`: tokio's readiness
                // tick makes the EAGAIN observation and the cache clear
                // atomic, and a wakeup arriving during the syscall survives.
                // Bounded like the inline fast path: if a wakeup drained the
                // socket between the batch's EAGAIN and this probe, the call
                // below is no longer a cheap readiness observation but a real
                // transfer running on the worker thread, and an unbounded
                // chunk would move a full autotuned send buffer out of a
                // possibly cold file there -- exactly the exposure
                // `SMALL_SERVE_INLINE_MAX` exists to cap.
                let chunk_size = usize::try_from(std::cmp::min(remaining, SMALL_SERVE_INLINE_MAX))
                    .unwrap_or(MAX_PER_SYSCALL);
                let mut off = *file_offset;
                match socket.try_io(Interest::WRITABLE, || {
                    loop {
                        match sendfile(
                            fds.socket.as_fd(),
                            fds.file.as_fd(),
                            Some(&mut off),
                            chunk_size,
                        ) {
                            Ok(n) => return Ok(n),
                            Err(nix::errno::Errno::EAGAIN) => {
                                return Err(std::io::Error::from(ErrorKind::WouldBlock));
                            }
                            Err(nix::errno::Errno::EINTR) => {}
                            Err(errno) => return Err(errno_to_io_error(errno, "sendfile failed")),
                        }
                    }
                }) {
                    Ok(0) => {
                        warn_once_or_debug!(
                            "sendfile: returned 0 at offset {off} with {remaining}/{amount} bytes remaining; stopping the transfer at that offset"
                        );
                        return Ok((
                            ChunkLoopOutcome::Eof {
                                transferred: amount - remaining,
                            },
                            fds,
                        ));
                    }
                    Ok(n) => {
                        *file_offset = off;
                        remaining = remaining
                            .checked_sub(n as u64)
                            .expect("sendfile(2) should not transfer more bytes than requested");
                        metrics::BYTES_SERVED_SENDFILE.increment_by(n as u64);
                        if let Some(rc) = rate_checker {
                            rc.add(n);
                        }
                    }
                    // Readiness cleared race-free; the next loop iteration
                    // parks in `wait_writable_rated` until a fresh event.
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                    Err(err) => return Err(err),
                }
            }
            SendfileBatchStop::Error(errno) => {
                return Err(errno_to_io_error(errno, "sendfile failed"));
            }
        }
    }

    Ok((ChunkLoopOutcome::Complete, fds))
}

/// Perform an async sendfile(2) operation, transferring `count` bytes from `file`
/// starting at `offset` to the TCP socket.
///
/// Returns `Ok(n)` when all `n` bytes were transferred.  Returns `Err((n, e))`
/// when an error occurred after `n` bytes had been transferred.
pub(crate) async fn async_sendfile(
    socket: &TcpStream,
    file: &tokio::fs::File,
    offset: u64,
    count: u64,
) -> Result<u64, (u64, std::io::Error)> {
    let _counter = client_counter::ClientDownload::new();

    // Nothing to transfer: skip the fd dup and the blocking-pool round-trip.
    if count == 0 {
        return Ok(0);
    }

    let Ok(mut file_offset) = i64::try_from(offset) else {
        return Err((
            0,
            std::io::Error::new(ErrorKind::InvalidInput, "sendfile: offset exceeds i64::MAX"),
        ));
    };

    let config = global_config();

    let mut rate_checker = RateChecker::from_config(config);

    let mut remaining = count;

    // Fast path for the dominant request class (small hot cached files):
    // one sendfile(2) into a usually-empty socket buffer completes the
    // whole transfer on the request task — no fd dup pair, no
    // blocking-pool round-trip.  `try_io` keeps tokio's readiness cache
    // honest on EAGAIN; any partial/blocked outcome falls through to the
    // batched loop below.  The dup-based cancellation-safety argument
    // doesn't apply here: the syscall runs synchronously on this task
    // while `socket`/`file` are borrowed.
    if count > 0 && count <= SMALL_SERVE_INLINE_MAX {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "count is bounded by SMALL_SERVE_INLINE_MAX which fits in usize"
        )]
        let want = count as usize;
        match socket.try_io(Interest::WRITABLE, || {
            loop {
                match sendfile(socket.as_fd(), file.as_fd(), Some(&mut file_offset), want) {
                    Ok(n) => return Ok(n),
                    Err(nix::errno::Errno::EAGAIN) => {
                        return Err(std::io::Error::from(ErrorKind::WouldBlock));
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(errno) => return Err(errno_to_io_error(errno, "sendfile failed")),
                }
            }
        }) {
            Ok(0) => {
                return Err((
                    0,
                    std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        format!(
                            "sendfile: unexpected end of file (transferred 0/{count} at offset {file_offset})"
                        ),
                    ),
                ));
            }
            Ok(n) => {
                metrics::BYTES_SERVED_SENDFILE.increment_by(n as u64);
                if let Some(rc) = &mut rate_checker {
                    rc.add(n);
                }
                remaining -= n as u64;
                if remaining == 0 {
                    return Ok(count);
                }
            }
            // Socket buffer full — the batched loop below parks properly.
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(err) => return Err((0, err)),
        }
    }

    let fds = SendfileFds::dup(socket, file).map_err(|e| {
        (
            u64::try_from(file_offset)
                .unwrap_or(0)
                .saturating_sub(offset),
            e,
        )
    })?;

    match sendfile_chunk_loop(socket, fds, &mut file_offset, remaining, &mut rate_checker)
        .await
        .map_err(|e| {
            (
                u64::try_from(file_offset)
                    .unwrap_or(0)
                    .saturating_sub(offset),
                e,
            )
        })? {
        (ChunkLoopOutcome::Complete, _fds) => Ok(count),
        (ChunkLoopOutcome::Eof { transferred }, _fds) => {
            let transferred = (count - remaining) + transferred;
            Err((
                transferred,
                std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!(
                        "sendfile: unexpected end of file (transferred {transferred}/{count} at offset {file_offset})"
                    ),
                ),
            ))
        }
    }
}

/// Like [`async_sendfile`], but for a file that is still being written to by
/// a concurrent download task.  Waits for `watch::Receiver` pings to learn
/// about new data.  The sender batches notifications (see
/// [`crate::guards::DownloadBarrier::ping_batched`]), so each ping indicates a meaningful
/// amount of new data on disk.
///
/// `content_start` / `content_length` may describe a sub-range (HTTP Range).
///
/// Returns `Ok(n)` when all `n` bytes were transferred.  Returns `Err((n, e))`
/// when an error occurred after `n` bytes had been transferred.
///
/// The caller is responsible for bumping the appropriate request-count metric
/// (`REQUESTS_SENDFILE` for the sendfile late-joiner path, no bump for the
/// splice demoted-client path which already counted as `REQUESTS_SPLICE`).
pub(crate) async fn async_sendfile_unfinished(
    socket: &TcpStream,
    file: &tokio::fs::File,
    file_path: &Path,
    content_start: u64,
    content_length: u64,
    mut receiver: tokio::sync::watch::Receiver<()>,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
) -> Result<u64, (u64, std::io::Error)> {
    let _counter = client_counter::ClientDownload::new();

    let Ok(mut file_offset) = i64::try_from(content_start) else {
        return Err((
            0,
            std::io::Error::new(ErrorKind::InvalidInput, "sendfile: offset exceeds i64::MAX"),
        ));
    };

    let config = global_config();

    let mut rate_checker = RateChecker::from_config(config);

    let mut remaining = content_length;
    let mut finished = false;

    // A persistently failing fstat would otherwise log + bump the metric on
    // every availability window; report it once per request.
    let mut fstat_error_logged = false;

    // One dup pair for the whole transfer, reused across availability
    // windows (each window is one `sendfile_chunk_loop` call).
    let mut fds = SendfileFds::dup(socket, file).map_err(|e| (0, e))?;

    while remaining > 0 {
        // Determine how many bytes the file currently has available past our offset.
        let offset_u64: u64 = file_offset
            .try_into()
            .expect("file_offset is non-negative by construction");

        // Deliberately NOT `block_in_place`: this runs once (usually twice)
        // per availability window, and `block_in_place` demotes the worker
        // thread — orders of magnitude dearer than the fstat it would wrap.
        // fstat on a regular file reads the in-memory inode; the writer task
        // keeps the inode hot, so there is no disk wait to shield against.
        let file_size = match nix::sys::stat::fstat(file.as_fd()) {
            Ok(stat) if stat.st_mode & nix::libc::S_IFMT == nix::libc::S_IFREG => stat
                .st_size
                .try_into()
                .expect("file size is non-negative by construction"),
            Ok(_) => {
                metrics::CACHE_NON_REGULAR.increment();
                error!(
                    "Cache file `{}` is not a regular file; aborting the transfer",
                    file_path.display()
                );
                let transferred = content_length - remaining;
                return Err((
                    transferred,
                    std::io::Error::new(ErrorKind::InvalidData, "Not a regular file"),
                ));
            }
            Err(errno) => {
                if !fstat_error_logged {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to query metadata of downloading file `{}` during sendfile; assuming no further data is available yet:  {}",
                        file_path.display(),
                        ErrorReport(&errno)
                    );
                    fstat_error_logged = true;
                }
                offset_u64
            }
        };

        let available = file_size.saturating_sub(offset_u64);

        // Clamp to what is actually available on disk and to what we still need.
        let sendable = std::cmp::min(available, remaining);
        if sendable == 0 {
            if finished {
                // The download claims to be done but the file is shorter than
                // expected — treat as unexpected EOF.
                let transferred = content_length - remaining;
                return Err((
                    transferred,
                    std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "sendfile: file shorter than expected after download finished",
                    ),
                ));
            }
            // Wait for the sender to notify us of new data on disk.
            // The sender handles timeouts, so we *should* never stall here.
            let _: Never = match receiver.changed().await {
                Ok(()) => continue,
                Err(_err @ tokio::sync::watch::error::RecvError { .. }) => {
                    // Sender dropped — download finished, verifying, or
                    // aborted. Verifying means all bytes are on disk and the
                    // writer is hashing on a blocking thread; the open file
                    // handle stays valid across the upcoming rename, so drain
                    // like Finished.
                    let st = status.read().await;
                    match *st {
                        ActiveDownloadStatus::Finished { .. }
                        | ActiveDownloadStatus::Verifying { .. }
                        | ActiveDownloadStatus::Aborted(AbortReason::Discarded {
                            checksum_mismatch: _,
                        }) => {
                            drop(st);
                            finished = true;
                            continue;
                        }
                        ActiveDownloadStatus::Aborted(
                            AbortReason::MirrorDownloadRate(_) | AbortReason::AlreadyLoggedJustFail,
                        ) => {
                            drop(st);
                            let transferred = content_length - remaining;
                            return Err((
                                transferred,
                                std::io::Error::other("sendfile: upstream download aborted"),
                            ));
                        }
                        ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download { .. } => {
                            drop(st);
                            let transferred = content_length - remaining;
                            return Err((
                                transferred,
                                std::io::Error::other(
                                    "sendfile: unexpected download state for demoted client file-serve",
                                ),
                            ));
                        }
                    }
                }
            };
        }

        // Transfer what is currently available via the shared sendfile loop.
        let (outcome, fds_back) =
            sendfile_chunk_loop(socket, fds, &mut file_offset, sendable, &mut rate_checker)
                .await
                .map_err(|e| {
                    (
                        u64::try_from(file_offset)
                            .unwrap_or(0)
                            .saturating_sub(content_start),
                        e,
                    )
                })?;
        fds = fds_back;
        let sent = match outcome {
            ChunkLoopOutcome::Complete => sendable,
            ChunkLoopOutcome::Eof { transferred } => {
                // sendfile(2) hit EOF mid-chunk even though fstat reported the
                // bytes as available.  Re-check the download status directly
                // rather than relying on another fstat round-trip that could
                // race with the writer task dropping the watch sender.
                let (is_finished, is_aborted) = {
                    let st = status.read().await;
                    match *st {
                        ActiveDownloadStatus::Finished { .. }
                        | ActiveDownloadStatus::Verifying { .. }
                        | ActiveDownloadStatus::Aborted(AbortReason::Discarded {
                            checksum_mismatch: _,
                        }) => (true, false),
                        ActiveDownloadStatus::Aborted(
                            AbortReason::MirrorDownloadRate(_) | AbortReason::AlreadyLoggedJustFail,
                        ) => (false, true),
                        ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download { .. } => {
                            (false, false)
                        }
                    }
                };
                if is_aborted {
                    let already_sent = content_length - remaining;
                    return Err((
                        already_sent + transferred,
                        std::io::Error::other("sendfile: upstream download aborted"),
                    ));
                }
                if is_finished {
                    finished = true;
                } else if transferred < sendable {
                    // Neither finished nor aborted: the writer still claims
                    // the download is in flight while the file is shorter
                    // than the fstat two lines above reported. The loop
                    // re-runs with the same inputs, so a stuck writer shows
                    // up as a spin, not as an error.
                    warn_once!(
                        "sendfile: EOF at offset {file_offset} for `{}` while the download is still in progress ({} bytes owed), retrying",
                        file_path.display(),
                        sendable - transferred
                    );
                }
                transferred
            }
        };
        remaining = remaining
            .checked_sub(sent)
            .expect("should not have transferred more bytes than requested");
    }

    Ok(content_length)
}

/// Serve a file that is currently being downloaded by another task, using
/// sendfile(2) for zero-copy delivery to the joining client.
///
/// Takes `conn_details` by value because an in-flight download without a
/// known `Content-Length` cannot be framed here and is handed to hyper
/// together with the attached `dl_status` (`HandoffPlan::JoinDownload`).
async fn serve_unfinished_sendfile(
    stream: &TcpStream,
    conn_details: ConnectionDetails,
    aliased: &str,
    dl_status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    headers: RangeRequestHeaders<'_>,
) -> ZeroCopyResult {
    // Wait for the download to leave the Init state; a complete copy
    // (Verifying/Finished) is served like any cached file, an in-progress
    // one below via the partial file plus the progress receiver.
    let (file, file_path, total_size, receiver, status_meta) =
        match await_serveable(&dl_status, &conn_details).await {
            Ok(Serveable::InProgress {
                file,
                path,
                content_length,
                rx,
                meta,
            }) => (file, path, content_length, rx, meta),
            Ok(Serveable::Complete { file, path, meta }) => {
                return serve_file_via_sendfile(
                    stream,
                    &conn_details,
                    aliased,
                    (file, None, &path),
                    (conn_version, conn_action),
                    headers,
                    meta.as_deref(),
                )
                .await
                .into();
            }
            Err(failure @ JoinFailure::VerifyThrottled { remaining: _ }) => {
                // Same answer and keep-alive handling as the pre-upstream
                // throttle gate (`splice_proxy`).
                let (status, msg) = failure.response_parts();
                return match write_invalid_response(
                    stream,
                    conn_version,
                    conn_action,
                    status,
                    msg,
                    failure.retry_after(),
                )
                .await
                {
                    Ok(()) => ZeroCopyResult::Served(conn_action),
                    Err(err) => {
                        debug!(
                            "Failed to write verify-throttle response to client {}:  {}",
                            conn_details.client,
                            ErrorReport(&err)
                        );
                        ZeroCopyResult::ClientError
                    }
                };
            }
            Err(
                failure @ (JoinFailure::Aborted { rate_timeout: _ }
                | JoinFailure::StateCorrupted
                | JoinFailure::CacheAccess),
            ) => {
                let (status, msg) = failure.response_parts();
                return ZeroCopyResult::Invalid { status, msg };
            }
        };

    // We need an exact content length to write a Content-Length header.
    let ContentLength::Exact(exact_size) = total_size else {
        warn_once_or_debug!(
            "Unknown content length for in-progress download of {} from mirror {}{aliased}; not serving the joining client via sendfile",
            conn_details.debname,
            conn_details.mirror,
        );
        return ZeroCopyResult::NotApplicable {
            reason: "unknown content length for in-progress download",
            #[cfg(feature = "hyper")]
            plan: HandoffPlan::JoinDownload {
                conn_details,
                status: dl_status,
            },
        };
    };

    let metadata = match regular_file_metadata(&file, &file_path) {
        Ok(m) => m,
        Err(CacheAccessFailure(_)) => {
            return ZeroCopyResult::Invalid {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                msg: "Cache Access Failure",
            };
        }
    };

    // Late-joiner: use the in-flight metadata captured from the active-
    // downloads status (no xattr reads — the temp file may still be
    // having its xattrs written concurrently).
    let cache_info = CacheInfo::with_meta(&metadata, &status_meta);

    // Range handling uses the total upstream size (not the current partial size on disk).
    let params = match evaluate_conditional_and_range(
        stream,
        &conn_details.client,
        conn_version,
        conn_action,
        &cache_info,
        exact_size.get(),
        headers,
    )
    .await
    {
        Ok(ConditionalOutcome::NotModified(ca)) => {
            info!(
                "Serving 304 Not Modified for downloading file {} from mirror {}{aliased} for joining client {} via sendfile",
                conn_details.debname, conn_details.mirror, conn_details.client
            );
            return ZeroCopyResult::Served(ca);
        }
        Ok(ConditionalOutcome::RangeNotSatisfiable(ca)) => {
            return ZeroCopyResult::Served(ca);
        }
        Ok(ConditionalOutcome::Serve(params)) => params,
        Err(result) => return result.into(),
    };
    let partial = params.is_partial();
    let http_status = params.http_status();
    let ServeParams {
        content_start,
        content_length,
        content_range,
    } = params;

    debug!(
        "Serving downloading file {} from mirror {}{aliased} for joining client {} via sendfile...",
        conn_details.debname, conn_details.mirror, conn_details.client
    );

    // Joining clients also stream the partial cache file linearly via sendfile,
    // so warm the kernel readahead window before the loop starts.  The final
    // size is unknown (file still growing), so always hint.
    hint_sequential_read(&file, u64::MAX, &file_path);

    // Headers go out with MSG_MORE (see write_response_headers); the first
    // sendfile body bytes complete the held segment — no TCP_CORK pair.

    let headers = ResponseHeaders {
        conn_version,
        status: http_status,
        conn_action,
        content_length,
        content_type: content_type_for_cached_file(&conn_details.debname),
        last_modified_str: &cache_info.last_modified_str,
        age: cache_info.age,
        content_range: content_range.as_deref(),
        etag: cache_info.file_etag.as_deref(),
    };
    if let Err(err) = write_response_headers(stream, headers).await {
        if is_peer_disconnect(&err) {
            info!(
                "Failed to write response headers to joining client {}; closing the connection:  {}",
                conn_details.client,
                ErrorReport(&err)
            );
        } else {
            warn!(
                "Failed to write response headers to joining client {}; closing the connection:  {}",
                conn_details.client,
                ErrorReport(&err)
            );
        }
        return ZeroCopyResult::ClientError;
    }

    let start = PreciseInstant::now();

    metrics::REQUESTS_SENDFILE.increment();

    let transfer_result = async_sendfile_unfinished(
        stream,
        &file,
        &file_path,
        content_start,
        content_length,
        receiver,
        dl_status,
    )
    .await;

    let elapsed = start.elapsed();
    let (complete, transferred, failure) = match &transfer_result {
        Ok(transferred) => (true, *transferred, None),
        Err((transferred, err)) => (
            false,
            *transferred,
            Some((ErrorReport(err), is_peer_disconnect(err))),
        ),
    };
    let outcome = ServeOutcome {
        size: content_length,
        transferred,
        complete,
        partial,
        elapsed,
        abort: failure
            .as_ref()
            .map(|(reason, peer_disconnect)| AbortCause {
                reason,
                peer_disconnect: *peer_disconnect,
            }),
    };
    if let Some(cmd) = finish_cached_serve(
        &conn_details,
        Mechanism::Sendfile,
        Role::LateJoiner,
        outcome,
    ) {
        send_db_command(DatabaseCommand::Transfer(cmd)).await;
    }
    if complete {
        ZeroCopyResult::Served(conn_action)
    } else {
        ZeroCopyResult::AfterHeaderError
    }
}

/// A stream that may have prepended data from a previous read.
/// When all prepended data is consumed, the buffer is dropped and
/// subsequent reads go straight to the inner TCP stream.
#[cfg(feature = "hyper")]
struct MaybePrependedStream {
    prepend: Option<BytesMut>,
    stream: TcpStream,
}

#[cfg(feature = "hyper")]
impl MaybePrependedStream {
    fn new(prepend: BytesMut, stream: TcpStream) -> Self {
        let prepend = if prepend.is_empty() {
            None
        } else {
            Some(prepend)
        };

        Self { prepend, stream }
    }
}

#[cfg(feature = "hyper")]
impl AsyncRead for MaybePrependedStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(prepend) = &mut this.prepend {
            let n = std::cmp::min(prepend.len(), buf.remaining());
            buf.put_slice(&prepend[..n]);
            prepend.advance(n);
            if prepend.is_empty() {
                this.prepend = None;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

#[cfg(feature = "hyper")]
impl AsyncWrite for MaybePrependedStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
