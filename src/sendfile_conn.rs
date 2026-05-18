use std::io::ErrorKind;
use std::num::NonZero;
use std::os::fd::AsFd as _;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use bytes::buf::Buf as _;
use coarsetime::Instant;
use http::StatusCode;
use http::header::{CONNECTION, HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, RANGE};
use log::{debug, error, info, trace, warn};
use nix::sys::sendfile::sendfile;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::cache_conditional::CacheInfo;
use crate::cache_layout::{self, CachedFlavor, ConnectionDetails};
use crate::cache_metadata::{self, CacheMetadataKeyRef};
use crate::config::{CacheHost, resolve_alias};
use crate::database_task::{DatabaseCommand, DbCmdDelivery, DbCmdOrigin, send_db_command};
use crate::deb_mirror::{
    Mirror, Origin, is_unsafe_proxy_path, normalize_uri_path, parse_request_path,
};
use crate::error::{ErrorReport, errno_to_io_error};
use crate::flat_blocklist;
use crate::http_helpers::{
    ConnectionAction, ConnectionVersion, ResponseHeaders, WritePhase, find_header, find_header_end,
    write_304_response, write_416_response, write_all_to_stream, write_invalid_response,
    write_response_headers,
};
use crate::http_range::{ParsedRange, format_http_date, http_parse_range};
use crate::humanfmt::HumanFmt;
use crate::rate_checked_body::{InsufficientRate, RateCheckDirection, RateChecker};
use crate::tcp_cork_guard::CorkGuard;
use crate::utils::{hint_sequential_read, is_peer_disconnect};
use crate::{
    APP_NAME, ActiveDownloadStatus, AppState, ClientInfo, ContentLength, Never,
    VOLATILE_CACHE_MAX_AGE, authorize_cache_access, client_counter, content_type_for_cached_file,
    global_config, handle_hyper_connection, is_diff_request_path, metrics, static_assert,
    warn_once_or_debug, warn_once_or_info,
    web_interface::{HTML_CSP, WebResponse, WebResponseKind, serve_web_interface},
};

/// Maximum size for HTTP request headers buffer (matches hyper's default of 8192).
const MAX_HEADER_SIZE: usize = 8192;
/// Initial size for HTTP request headers buffer.
const INITIAL_HEADER_SIZE: usize = 2048;
/// Maximum number of HTTP headers to parse (matches hyper's default of 100).
const MAX_HEADERS: usize = 100;

/// Represents the result of a sendfile operation.
pub(crate) enum ZeroCopyResult {
    /// Request was served via sendfile
    Served(ConnectionAction),

    /// Request is not applicable for sendfile, fall back to hyper
    NotApplicable(&'static str),

    /// Request is invalid, reject and close the connection
    Invalid {
        status: http::StatusCode,
        msg: &'static str,
    },

    /// Request should be rejected, but the connection might be kept alive
    Rejection {
        status: http::StatusCode,
        conn_action: ConnectionAction,
        msg: &'static str,
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
/// - If it's a GET for a permanently cached file, serve it using sendfile(2)
/// - Otherwise, fall back to the standard hyper-based handler
pub(crate) async fn handle_sendfile_connection(
    stream: TcpStream,
    client: ClientInfo,
    appstate: AppState,
) {
    let mut buf = BytesMut::with_capacity(INITIAL_HEADER_SIZE);

    trace!("Using sendfile(2) backend to handle request from client {client} ...");

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
                    "Failed to read request number {} from client {client}:  {}",
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
                )
                .await;
                return;
            }
        };

        let result =
            try_sendfile_request(&buf, &stream, client, &appstate, &mut conn_version).await;

        if !matches!(result, ZeroCopyResult::NotApplicable(_)) {
            metrics::REQUESTS_TOTAL.increment();
        }

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
            ZeroCopyResult::NotApplicable(reason) => {
                // Fall back to hyper for this and all subsequent requests
                debug!(
                    "Falling back to hyper for client {client} after {req_num} requests due to: {reason} ({} bytes buffered)",
                    buf.len()
                );

                let stream = MaybePrependedStream::new(buf, stream);

                return handle_hyper_connection(stream, client, appstate).await;
            }
            ZeroCopyResult::Invalid { status, msg } => {
                if let Err(err) = write_invalid_response(
                    &stream,
                    conn_version,
                    ConnectionAction::Close,
                    status,
                    msg,
                )
                .await
                {
                    info!("Failed to write error response to client {client}:  {err}");
                }

                return;
            }
            ZeroCopyResult::Rejection {
                status,
                conn_action,
                msg,
            } => {
                if let Err(err) =
                    write_invalid_response(&stream, conn_version, conn_action, status, msg).await
                {
                    info!("Failed to write rejection response to client {client}:  {err}");
                    return;
                }

                match conn_action {
                    ConnectionAction::KeepAlive => {
                        buf.advance(next_header_index);
                        continue;
                    }
                    ConnectionAction::Close => return,
                }
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

    let deadline = tokio::time::sleep(global_config().http_timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            biased;
            ready = stream.readable() => {
                ready?;
                match stream.try_read_buf(buf) {
                    Ok(0) => return Ok(None),
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
                    "reading TCP stream request headers timed out",
                ));
            }
        }
    }
}

/// Serve a local web-interface request directly from the sendfile path.
///
/// The hyper-based handler exists in `web_interface::serve_web_interface`; this
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
    let cfg = global_config();
    let allowed_webif_clients = cfg
        .allowed_webif_clients
        .as_ref()
        .unwrap_or(&cfg.allowed_proxy_clients);
    let client_ip = client.ip();
    if !allowed_webif_clients.is_empty()
        && !allowed_webif_clients
            .iter()
            .any(|ac| ac.contains(&client_ip))
    {
        warn_once_or_info!("Unauthorized web-interface access by client {client}");
        metrics::AUTHZ_REJECTED_WEBUI.increment();
        return ZeroCopyResult::Rejection {
            status: StatusCode::FORBIDDEN,
            conn_action,
            msg: "Unauthorized client",
        };
    }

    let response = serve_web_interface(uri, appstate).await;

    if let Err(err) = write_webui_response(stream, conn_version, conn_action, response).await {
        info!("Failed to write web-interface response to client {client}:  {err}");
        return ZeroCopyResult::AfterHeaderError;
    }
    ZeroCopyResult::Served(conn_action)
}

/// Format and write a [`WebResponse`] onto the raw stream.
///
/// Mirrors the layout used by [`crate::http_helpers::write_response_headers`]:
/// a single `format!` builds the entire status-line + headers block with named
/// substitutions, so the wire bytes are easy to read alongside the hyper-side
/// `WebResponse::into_hyper_response` constructor.
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

    // Per-kind extra headers, kept in lockstep with `WebResponse::into_hyper_response`.
    let extra_headers: String = match response.kind {
        WebResponseKind::Html => format!(
            "Cache-Control: no-store\r\n\
             Content-Security-Policy: {HTML_CSP}\r\n\
             X-Content-Type-Options: nosniff\r\n\
             X-Frame-Options: DENY\r\n\
             X-Robots-Tag: noindex\r\n\
             Referrer-Policy: no-referrer\r\n",
        ),
        WebResponseKind::Static { .. } => String::from(
            "Cache-Control: public, max-age=86400\r\n\
             X-Content-Type-Options: nosniff\r\n",
        ),
        WebResponseKind::Error => String::new(),
    };

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
            "Request with body detected from client {client}, closing connection after response"
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

/// Try to serve a request using sendfile(2).
/// Return whether the request was handled.
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
                warn_once_or_info!("Unsupported HTTP/1.{v} from client {client}");
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

            warn_once_or_info!("Incomplete HTTP request from client {client}");
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Incomplete request header",
            };
        }
        Err(httparse::Error::Version) => {
            warn_once_or_info!("Unsupported HTTP version from client {client}");
            return ZeroCopyResult::Invalid {
                status: StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                msg: "HTTP version not supported",
            };
        }
        Err(err) => {
            warn_once_or_info!("Failed to parse HTTP request from client {client}:  {err}");
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Invalid request header",
            };
        }
    }
    let req = req; // mark immutable

    trace!("Parsed client request:\n{req:?}");

    // Only handle GET requests via sendfile
    match req.method.expect("complete header parsed") {
        "GET" => {}
        "CONNECT" => return ZeroCopyResult::NotApplicable("CONNECT method not supported"),
        m => {
            warn_once_or_info!(
                "Unsupported request method from client {client}: {}",
                m.escape_debug(),
            );
            return ZeroCopyResult::Invalid {
                status: StatusCode::METHOD_NOT_ALLOWED,
                msg: "Method not supported",
            };
        }
    }

    let uri = match req
        .path
        .expect("complete header parsed")
        .parse::<http::uri::Uri>()
    {
        Ok(uri) => uri,
        Err(err) => {
            info!("Failed to parse URI from client {client}:  {err}");
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Invalid URI",
            };
        }
    };

    // Proxy GET requests always use http://, HTTPS goes through CONNECT.
    // Reject any other scheme (e.g. ftp://, file://).
    if let Some(scheme) = uri.scheme()
        && *scheme != http::uri::Scheme::HTTP
    {
        warn_once_or_info!("Unsupported URI scheme from client {client}: {scheme}");
        return ZeroCopyResult::Invalid {
            status: StatusCode::BAD_REQUEST,
            msg: "Unsupported URI scheme",
        };
    }

    let Some(authority) = uri.authority() else {
        // RFC 7230 §5.4: A server MUST respond with a 400 status code to any
        // HTTP/1.1 request that lacks a Host header field.
        if *conn_version == ConnectionVersion::Http11 && find_header(req.headers, &HOST).is_none() {
            debug!("Missing Host header from HTTP/1.1 request from client {client}");
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Missing Host header",
            };
        }
        // No authority means it's a direct request to the local web interface.
        let conn_action = compute_conn_action(&req, *conn_version, &client);
        return serve_webui(stream, &uri, appstate, &client, *conn_version, conn_action).await;
    };

    let requested_host = match authorize_cache_access(&client, authority.host()) {
        Ok(rh) => rh,
        Err((status, msg)) => return ZeroCopyResult::Invalid { status, msg },
    };
    let requested_port = match authority.port_u16() {
        Some(port) => {
            let Some(port) = NonZero::new(port) else {
                warn_once_or_info!("Unsupported request port 0 from client {client}");
                return ZeroCopyResult::Invalid {
                    status: StatusCode::BAD_REQUEST,
                    msg: "Invalid port",
                };
            };
            Some(port)
        }
        None => None,
    };

    let conn_action = compute_conn_action(&req, *conn_version, &client);

    // Match all cacheable resource types for sendfile/splice serving.
    // Collapse `//` runs before parsing — clients with a trailing slash in
    // their `sources.list` URI emit `/debian//dists/...`; raw `uri_path` is
    // preserved for logs and upstream simple-proxy passthrough so the
    // client request still flows verbatim when the parser declines it.
    let uri_path = uri.path();
    let normalized_uri_path = normalize_uri_path(uri_path);
    let Some(resource) = parse_request_path(&normalized_uri_path) else {
        if global_config().reject_pdiff_requests && is_diff_request_path(uri_path) {
            info!("Rejecting diff request {uri_path} for client {client}");

            metrics::PDIFF_REJECTED.increment();
            return ZeroCopyResult::Rejection {
                status: StatusCode::GONE,
                conn_action,
                msg: "Diff requests are not supported",
            };
        }

        warn_once_or_debug!("Unrecognized resource path from client {client}: {uri_path}");

        // Reject paths with traversal sequences, control characters, or invalid encoding.
        if is_unsafe_proxy_path(uri_path) {
            metrics::UNSAFE_PATH_REJECTED.increment();
            warn_once_or_info!(
                "Rejecting unsafe unrecognized path from client {client}: {uri_path}"
            );
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported request",
            };
        }

        #[cfg(feature = "splice")]
        {
            use crate::{
                deb_mirror::MirrorKind,
                splice_conn::{SpliceProxyError, splice_simple_proxy},
                uncacheables::record_uncacheable,
            };

            record_uncacheable(&requested_host, uri_path);

            // Simple-proxy path: this Mirror is used only for upstream
            // dispatch/formatting and is never persisted; kind is arbitrary.
            let mirror = Mirror::new(
                requested_host,
                requested_port,
                String::new(),
                MirrorKind::Structured,
            );

            return match splice_simple_proxy(stream, *conn_version, conn_action, &mirror, uri_path)
                .await
            {
                Ok(()) => ZeroCopyResult::Served(conn_action),
                Err(SpliceProxyError::Upstream) => ZeroCopyResult::Invalid {
                    status: StatusCode::BAD_GATEWAY,
                    msg: "Upstream Error",
                },
                Err(SpliceProxyError::Client(err, location)) => {
                    if is_peer_disconnect(&err) {
                        info!(
                            "simple proxy: client error writing {location} (peer disconnect) for {uri_path} from host {}:  {}",
                            mirror.format_authority(),
                            ErrorReport(&err)
                        );
                    } else {
                        warn!(
                            "simple proxy: client error writing {location} for {uri_path} from host {}:  {}",
                            mirror.format_authority(),
                            ErrorReport(&err)
                        );
                    }
                    ZeroCopyResult::ClientError
                }
                Err(SpliceProxyError::AfterHeaderClient(err, location)) => {
                    if is_peer_disconnect(&err) {
                        info!(
                            "simple proxy: client response delivery aborted in {location} (peer disconnect) for {uri_path} from host {}:  {}",
                            mirror.format_authority(),
                            ErrorReport(&err)
                        );
                    } else {
                        warn!(
                            "simple proxy: client response delivery failed in {location} for {uri_path} from host {}:  {}",
                            mirror.format_authority(),
                            ErrorReport(&err)
                        );
                    }
                    ZeroCopyResult::AfterHeaderError
                }
                Err(SpliceProxyError::AfterHeaderIo) => ZeroCopyResult::AfterHeaderError,
                Err(SpliceProxyError::Cache) => ZeroCopyResult::Invalid {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    msg: "Cache Access Failure",
                },
            };
        }

        #[cfg(not(feature = "splice"))]
        return ZeroCopyResult::NotApplicable("unrecognized resource path");
    };

    let class = match cache_layout::classify_request(&resource, &client) {
        Ok(class) => class,
        Err(cache_layout::ClassifyError::BadEncoding { kind, raw, source }) => {
            warn_once_or_info!(
                "Failed to decode {kind} `{}` from client {client}:  {source}",
                raw.escape_debug()
            );
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported URL encoding",
            };
        }
        Err(cache_layout::ClassifyError::InvalidValue { kind, decoded }) => {
            warn_once_or_info!("Unsupported {kind} `{decoded}` from client {client}");
            return ZeroCopyResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported request",
            };
        }
        Err(cache_layout::ClassifyError::NonDebPool { filename: _ }) => {
            // Pool filename failed the deb extension check (structured
            // Pool) or the strict flat-pool shape check; hand back to
            // hyper so the simple proxy can handle it without caching.
            return ZeroCopyResult::NotApplicable("unsupported pool filename");
        }
    };

    let aliased_host = resolve_alias(&global_config().aliases, &requested_host);

    // Per-host flat collision: a structured mirror with
    // `mirror_path == "flat"` (or `"flat/..."`) has already claimed the
    // host-level `flat/` anchor; hand back to hyper which will pass the
    // request through uncached. The blocklist is keyed on the alias-resolved
    // host (matching the on-disk host directory) so sibling aliases share it.
    let cache_id: &CacheHost = match aliased_host {
        Some(cache) => cache,
        None => requested_host.as_cache_host(),
    };
    if class.layout.is_flat() && flat_blocklist::is_blocked(cache_id, requested_port) {
        return ZeroCopyResult::NotApplicable("flat host blocked by structured collision");
    }

    let aliased = match aliased_host {
        Some(alias) => format!(" aliased to host {alias}"),
        None => String::new(),
    };

    let conn_details = ConnectionDetails {
        client,
        mirror: Mirror::new(
            requested_host,
            requested_port,
            class.mirror_path,
            class.layout.mirror_kind(),
        ),
        aliased_host,
        debname: class.debname,
        cached_flavor: class.cached_flavor,
        layout: class.layout,
    };

    // Record origin for Packages requests (mirrors main.rs behavior)
    if let Some(fields) = class.origin_fields {
        let origin = Origin {
            mirror: conn_details.mirror.clone(),
            distribution: fields.distribution,
            component: fields.component,
            architecture: fields.architecture,
        };
        let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
        send_db_command(cmd).await;
    }

    // Check if the file is currently being downloaded — if so, serve it via
    // sendfile from the growing partial file instead of falling back to hyper.
    // `attach()` atomically records the late joiner under the same write lock
    // as the lookup; on `NotApplicable` we fall back to hyper, whose
    // `insert()` may count this client a second time (rare, only when
    // upstream omits Content-Length).
    if let Some(dl_status) = appstate.active_downloads.attach(
        &conn_details.mirror,
        &conn_details.debname,
        conn_details.layout,
    ) {
        let result = serve_unfinished_sendfile(
            stream,
            &conn_details,
            &aliased,
            dl_status,
            *conn_version,
            conn_action,
            RangeRequestHeaders::extract(req.headers),
        )
        .await;

        // Coalesced permanent late-joiners count as `CACHE_MISSES`: the file
        // was not yet fully on disk so we would have fetched upstream if not
        // for the in-flight originator. `LATE_JOINERS_TOTAL` is the subset of
        // misses that attached. `attach()` already bumped that counter.
        // `NotApplicable` falls back to hyper, which bumps `CACHE_MISSES`
        // itself on its own miss path; the volatile case is accounted for via
        // `VOLATILE_REFETCHED` by the originator.
        if !matches!(result, ZeroCopyResult::NotApplicable(_))
            && conn_details.cached_flavor == CachedFlavor::Permanent
        {
            metrics::CACHE_MISSES.increment();
        }

        return result;
    }

    let cache_path = {
        let mut p = conn_details.cache_dir_path();
        let filename = Path::new(&conn_details.debname);
        assert!(
            filename.is_relative(),
            "path construction must not contain absolute components"
        );
        p.push(filename);
        p
    };

    // Try to open the cached file; for volatile resources, treat stale files as cache misses.
    let mut cache_miss_was_volatile_notfound = false;
    let cached_file = 'cache_lookup: {
        let file = match tokio::fs::File::options()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&cache_path)
            .await
        {
            Ok(f) => f,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                if conn_details.cached_flavor == CachedFlavor::Volatile {
                    cache_miss_was_volatile_notfound = true;
                }
                break 'cache_lookup None;
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to open cached file `{}` for client {client}:  {err}",
                    cache_path.display()
                );
                return ZeroCopyResult::Invalid {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    msg: "Cache Access Failure",
                };
            }
        };

        // Volatile staleness: if file is older than 30s, treat as cache miss
        // so splice/hyper can fetch a fresh copy from upstream.
        if conn_details.cached_flavor == CachedFlavor::Volatile {
            match file.metadata().await {
                Ok(md) if md.file_type().is_file() => {
                    let last_modified = md
                        .modified()
                        .expect("Platform should support modification timestamps via setup check");
                    if let Ok(elapsed) = last_modified.elapsed() {
                        if elapsed >= VOLATILE_CACHE_MAX_AGE {
                            metrics::VOLATILE_REFETCHED.increment();
                            break 'cache_lookup None;
                        }

                        debug!(
                            "Volatile file `{}` is just {} old (limit: {}s), serving cached version...",
                            cache_path.display(),
                            HumanFmt::Time(elapsed),
                            VOLATILE_CACHE_MAX_AGE.as_secs()
                        );
                        metrics::VOLATILE_HIT.increment();
                    } else {
                        warn!(
                            "Volatile file `{}` was modified in the future, ignoring modification time",
                            cache_path.display()
                        );
                    }
                }
                Ok(_) => {
                    metrics::CACHE_NON_REGULAR.increment();
                    error!(
                        "Cache file `{}` is not a regular file",
                        cache_path.display()
                    );
                    return ZeroCopyResult::Invalid {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        msg: "Cache Access Failure",
                    };
                }
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to get metadata of cached file `{}` for client {client}:  {err}",
                        cache_path.display()
                    );
                    return ZeroCopyResult::Invalid {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        msg: "Cache Access Failure",
                    };
                }
            }
        }

        Some(file)
    };

    if let Some(file) = cached_file {
        // CACHE_HITS only counts permanent-file hits; fresh volatile hits
        // were already bumped as VOLATILE_HIT in the cache_lookup block.
        if conn_details.cached_flavor == CachedFlavor::Permanent {
            metrics::CACHE_HITS.increment();
        }

        return serve_file_via_sendfile(
            stream,
            &conn_details,
            &aliased,
            (file, &cache_path),
            (*conn_version, conn_action),
            RangeRequestHeaders::extract(req.headers),
            None,
        )
        .await
        .into();
    }

    // Cache miss or stale volatile file — try splice proxy, then hyper fallback.
    // The stale-volatile case has already bumped VOLATILE_REFETCHED above; bump
    // it for the volatile-not-found case too. Permanent-not-found is a real
    // cache miss.
    if cache_miss_was_volatile_notfound {
        metrics::VOLATILE_REFETCHED.increment();
    } else if conn_details.cached_flavor == CachedFlavor::Permanent {
        metrics::CACHE_MISSES.increment();
    }

    #[cfg(feature = "splice")]
    {
        use crate::splice_conn::{SpliceProxyError, SpliceProxyOutcome, splice_proxy};

        match splice_proxy(
            stream,
            *conn_version,
            conn_action,
            &conn_details,
            uri.path(),
            appstate,
            RangeRequestHeaders::extract(req.headers),
        )
        .await
        {
            Ok(SpliceProxyOutcome::Served) => ZeroCopyResult::Served(conn_action),
            Ok(SpliceProxyOutcome::Concurrent { status: dl_status }) => {
                // Race-loser path: another connection registered the
                // download between our earlier `attach()` (which saw
                // nothing) and `splice_proxy`'s `originate()`. The
                // existing download's status was handed back by
                // `originate()` and is held alive by the Arc, so we can
                // serve from the partial via sendfile directly — no
                // re-attach, no race-of-races fall-back. `CACHE_MISSES` was
                // bumped above when the cache lookup found no usable file;
                // `LATE_JOINERS_TOTAL` was bumped inside `originate()`.
                serve_unfinished_sendfile(
                    stream,
                    &conn_details,
                    &aliased,
                    dl_status,
                    *conn_version,
                    conn_action,
                    RangeRequestHeaders::extract(req.headers),
                )
                .await
            }
            Err(SpliceProxyError::Upstream) => ZeroCopyResult::Invalid {
                status: StatusCode::BAD_GATEWAY,
                msg: "Upstream Error",
            },
            Err(SpliceProxyError::Cache) => ZeroCopyResult::Invalid {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                msg: "Cache Access Failure",
            },
            Err(SpliceProxyError::Client(err, location)) => {
                if is_peer_disconnect(&err) {
                    info!(
                        "splice proxy: client error writing {location} (peer disconnect) for {} from mirror {}{}:  {}",
                        conn_details.debname,
                        conn_details.mirror,
                        aliased,
                        ErrorReport(&err)
                    );
                } else {
                    warn!(
                        "splice proxy: client error writing {location} for {} from mirror {}{}:  {}",
                        conn_details.debname,
                        conn_details.mirror,
                        aliased,
                        ErrorReport(&err)
                    );
                }
                ZeroCopyResult::ClientError
            }
            Err(SpliceProxyError::AfterHeaderClient(err, location)) => {
                if is_peer_disconnect(&err) {
                    info!(
                        "splice proxy: client response delivery aborted in {location} (peer disconnect) for {} from mirror {}{}:  {}",
                        conn_details.debname,
                        conn_details.mirror,
                        aliased,
                        ErrorReport(&err)
                    );
                } else {
                    warn!(
                        "splice proxy: client response delivery failed in {location} for {} from mirror {}{}:  {}",
                        conn_details.debname,
                        conn_details.mirror,
                        aliased,
                        ErrorReport(&err)
                    );
                }
                ZeroCopyResult::AfterHeaderError
            }
            Err(SpliceProxyError::AfterHeaderIo) => ZeroCopyResult::AfterHeaderError,
        }
    }

    #[cfg(not(feature = "splice"))]
    ZeroCopyResult::NotApplicable("file not found in cache")
}

/// Range and status parameters for a successful conditional evaluation.
struct ServeParams {
    http_status: StatusCode,
    content_start: u64,
    content_length: u64,
    content_range: Option<String>,
    partial: bool,
}

/// Outcome of [`evaluate_conditional_and_range`].
enum ConditionalOutcome {
    /// Caller should send a 304 Not Modified (already written to the stream).
    NotModified(ConnectionAction),
    /// Caller should send a 416 Range Not Satisfiable (already written to the stream).
    RangeNotSatisfiable(ConnectionAction),
    /// Proceed with serving the file using these range parameters.
    Serve(ServeParams),
}

/// Raw Range / If-Range / conditional headers from a http client request.
pub(crate) struct RangeRequestHeaders<'a> {
    pub(crate) range: Option<&'a str>,
    pub(crate) if_range: Option<&'a str>,
    pub(crate) if_none_match: Option<&'a str>,
    pub(crate) if_modified_since: Option<&'a str>,
}

impl<'a> RangeRequestHeaders<'a> {
    fn extract(headers: &[httparse::Header<'a>]) -> Self {
        Self {
            range: find_header(headers, &RANGE),
            if_range: find_header(headers, &IF_RANGE),
            if_none_match: find_header(headers, &IF_NONE_MATCH),
            if_modified_since: find_header(headers, &IF_MODIFIED_SINCE),
        }
    }
}

/// Evaluate conditional request headers (If-None-Match, If-Modified-Since) and
/// Range headers, writing 304 or 416 responses directly to the stream when
/// appropriate.
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
    let serve_304 = cache_info.decide_serve_304(headers.if_none_match, headers.if_modified_since);

    if serve_304 {
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
            info!("Failed to write 304 response to client {client}:  {err}");
            return Err(SendfileResult::ClientError);
        }

        return Ok(ConditionalOutcome::NotModified(conn_action));
    }

    // Handle Range requests
    if let Some(range) = headers.range {
        match http_parse_range(
            range,
            headers.if_range,
            file_size,
            cache_info.last_modified_for_ims,
            cache_info.file_etag.as_deref(),
        ) {
            ParsedRange::Satisfiable(content_range, start, cl) => {
                return Ok(ConditionalOutcome::Serve(ServeParams {
                    http_status: StatusCode::PARTIAL_CONTENT,
                    content_start: start,
                    content_length: cl,
                    content_range: Some(content_range),
                    partial: true,
                }));
            }
            ParsedRange::NotSatisfiable => {
                if let Err(err) =
                    write_416_response(stream, conn_version, conn_action, file_size).await
                {
                    info!("Failed to write 416 response to client {client}:  {err}");
                    return Err(SendfileResult::ClientError);
                }

                return Ok(ConditionalOutcome::RangeNotSatisfiable(conn_action));
            }
            ParsedRange::Invalid | ParsedRange::IfRangeFailed => {}
        }
    }

    Ok(ConditionalOutcome::Serve(ServeParams {
        http_status: StatusCode::OK,
        content_start: 0,
        content_length: file_size,
        content_range: None,
        partial: false,
    }))
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
    source: (tokio::fs::File, &Path),
    conn_settings: (ConnectionVersion, ConnectionAction),
    headers: RangeRequestHeaders<'_>,
    prefetched_upstream_metadata: Option<&cache_metadata::UpstreamMetadata>,
) -> SendfileResult {
    let (file, file_path) = source;
    let (conn_version, conn_action) = conn_settings;

    let mdata = match file.metadata().await {
        Ok(m) if m.file_type().is_file() => m,
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            error!("Cache file `{}` is not a regular file", file_path.display());
            return SendfileResult::Invalid {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                msg: "Cache Access Failure",
            };
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to get metadata of cached file `{}` for client {}:  {err}",
                file_path.display(),
                conn_details.client
            );
            return SendfileResult::Invalid {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                msg: "Cache Access Failure",
            };
        }
    };

    let file_size = mdata.len();

    let cache_info = if let Some(meta) = prefetched_upstream_metadata {
        CacheInfo::with_meta(&mdata, meta)
    } else {
        let key = CacheMetadataKeyRef::new(
            &conn_details.mirror,
            &conn_details.debname,
            conn_details.layout,
        );
        CacheInfo::resolve(&file, file_path, &mdata, &key)
    };

    let ServeParams {
        http_status,
        content_start,
        content_length,
        content_range,
        partial,
    } = match evaluate_conditional_and_range(
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

    debug!(
        "Serving cached file {} from mirror {}{aliased} for client {} via sendfile...",
        conn_details.debname, conn_details.mirror, conn_details.client,
    );

    // sendfile streams the file linearly through the kernel, so help the
    // page-cache readahead window grow before the splice loop starts.
    hint_sequential_read(&file, file_path);

    // Cork the socket to coalesce headers + body into fewer TCP segments
    let _cork = CorkGuard::new_optional(stream);

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
        info!(
            "Failed to write response headers to client {}:  {err}",
            conn_details.client
        );
        return SendfileResult::ClientError;
    }

    let start = Instant::now();

    // Use sendfile(2) to transfer the file body
    metrics::REQUESTS_SENDFILE.increment();
    let transfer_result = async_sendfile(stream, &file, content_start, content_length).await;

    match transfer_result {
        Ok(()) => {
            metrics::SERVED_SENDFILE.increment();
            metrics::SERVED_TOTAL.increment();
            let elapsed = start.elapsed();
            info!(
                "Served cached file {} from mirror {}{aliased} for client {} in {} via sendfile (size={}, rate={})",
                conn_details.debname,
                conn_details.mirror,
                conn_details.client,
                HumanFmt::Time(elapsed.into()),
                HumanFmt::Size(content_length),
                HumanFmt::Rate(content_length, elapsed)
            );

            // Update database
            let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
                mirror: conn_details.mirror.clone(),
                debname: conn_details.debname.clone(),
                size: content_length,
                elapsed,
                partial,
                client_ip: conn_details.client.ip(),
            });
            send_db_command(cmd).await;

            SendfileResult::Served(conn_action)
        }
        Err(err) => {
            if is_peer_disconnect(&err) {
                metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                info!(
                    "sendfile transfer cancelled for `{}` to client {}:  {}",
                    file_path.display(),
                    conn_details.client,
                    ErrorReport(&err)
                );
            } else {
                error!(
                    "sendfile error serving `{}` to client {}:  {}",
                    file_path.display(),
                    conn_details.client,
                    ErrorReport(&err)
                );
            }
            // Response already sent, just close the connection
            SendfileResult::AfterHeaderError
        }
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
                    return Err(std::io::Error::new(ErrorKind::TimedOut, timeout_msg));
                }
            }
        }
    } else {
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
                Err(std::io::Error::new(ErrorKind::TimedOut, timeout_msg))
            }
        }
    }
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

/// Transfer up to `amount` bytes from `file` at `*file_offset` to `socket`
/// using sendfile(2), handling rate checking and writability polling.
///
/// Returns [`ChunkLoopOutcome::Complete`] when all `amount` bytes were
/// transferred.  Returns [`ChunkLoopOutcome::Eof`] if sendfile(2) reported
/// EOF (returned 0) before completion — the caller decides whether that is
/// an error.
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

async fn sendfile_chunk_loop(
    socket: &TcpStream,
    file: &tokio::fs::File,
    file_offset: &mut i64,
    amount: u64,
    rate_checker: &mut Option<RateChecker>,
) -> std::io::Result<ChunkLoopOutcome> {
    // Per-syscall cap to avoid exceeding system limits.  Always within
    // usize range since it fits in 31 bits.
    const MAX_PER_SYSCALL: usize = 0x7fff_f000;
    static_assert!(MAX_PER_SYSCALL < usize::MAX);

    let config = global_config();
    let mut remaining = amount;

    // Dup the socket and file descriptors once per chunk_loop call and
    // pass ownership through each spawn_blocking, getting them back via
    // the closure return value.  If the outer future is cancelled
    // mid-batch (client disconnect, runtime shutdown), tokio cannot
    // abort spawn_blocking — it merely detaches the JoinHandle.  The
    // detached closure still owns the OwnedFds, so the kernel
    // descriptors stay open until it returns and cannot be reassigned
    // to an unrelated FD by a parent's TcpStream/File Drop.  One dup
    // pair per transfer amortises across many EAGAIN cycles.
    let mut socket_dup = nix::unistd::dup(socket.as_fd())
        .map_err(|errno| errno_to_io_error(errno, "dup of socket fd failed"))?;
    let mut file_dup = nix::unistd::dup(file.as_fd())
        .map_err(|errno| errno_to_io_error(errno, "dup of file fd failed"))?;

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

        let s = socket_dup;
        let f = file_dup;

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

        socket_dup = s;
        file_dup = f;

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
            SendfileBatchStop::Done => return Ok(ChunkLoopOutcome::Complete),
            SendfileBatchStop::Eof => {
                warn_once_or_debug!(
                    "sendfile returned 0 at offset {file_offset} with {remaining}/{amount} bytes remaining"
                );
                return Ok(ChunkLoopOutcome::Eof {
                    transferred: amount - remaining,
                });
            }
            SendfileBatchStop::NeedsWritable => (),
            SendfileBatchStop::Error(errno) => {
                return Err(errno_to_io_error(errno, "sendfile failed"));
            }
        }
    }

    Ok(ChunkLoopOutcome::Complete)
}

/// Perform an async sendfile(2) operation, transferring `count` bytes from `file`
/// starting at `offset` to the TCP socket.
pub(crate) async fn async_sendfile(
    socket: &TcpStream,
    file: &tokio::fs::File,
    offset: u64,
    count: u64,
) -> std::io::Result<()> {
    let _counter = client_counter::ClientDownload::new();

    let Ok(mut file_offset) = i64::try_from(offset) else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "sendfile: offset exceeds i64::MAX",
        ));
    };

    let config = global_config();

    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    match sendfile_chunk_loop(socket, file, &mut file_offset, count, &mut rate_checker).await? {
        ChunkLoopOutcome::Complete => Ok(()),
        ChunkLoopOutcome::Eof { transferred } => Err(std::io::Error::new(
            ErrorKind::UnexpectedEof,
            format!(
                "sendfile: unexpected end of file (transferred {transferred}/{count} at offset {file_offset})"
            ),
        )),
    }
}

/// Like [`async_sendfile`], but for a file that is still being written to by
/// a concurrent download task.  Waits for `watch::Receiver` pings to learn
/// about new data.  The sender batches notifications (see
/// [`DownloadBarrier::ping_batched`]), so each ping indicates a meaningful
/// amount of new data on disk.
///
/// `content_start` / `content_length` may describe a sub-range (HTTP Range).
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
    status: std::sync::Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
) -> std::io::Result<()> {
    let _counter = client_counter::ClientDownload::new();

    let Ok(mut file_offset) = i64::try_from(content_start) else {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "sendfile: offset exceeds i64::MAX",
        ));
    };

    let config = global_config();

    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut remaining = content_length;
    let mut finished = false;

    while remaining > 0 {
        // Determine how many bytes the file currently has available past our offset.
        let offset_u64: u64 = file_offset
            .try_into()
            .expect("file_offset is non-negative by construction");

        let file_size = match tokio::task::block_in_place(|| nix::sys::stat::fstat(file.as_fd())) {
            Ok(stat) if stat.st_mode & nix::libc::S_IFMT == nix::libc::S_IFREG => stat
                .st_size
                .try_into()
                .expect("file size is non-negative by construction"),
            Ok(_) => {
                metrics::CACHE_NON_REGULAR.increment();
                error!("Cache file `{}` is not a regular file", file_path.display());
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Not a regular file",
                ));
            }
            Err(errno) => {
                error!(
                    "Failed to query metadata of downloading file `{}` during sendfile:  {errno}",
                    file_path.display()
                );
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
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "sendfile: file shorter than expected after download finished",
                ));
            }
            // Wait for the sender to notify us of new data on disk.
            // The sender handles timeouts, so we *should* never stall here.
            let _: Never = match receiver.changed().await {
                Ok(()) => continue,
                Err(_err @ tokio::sync::watch::error::RecvError { .. }) => {
                    // Sender dropped — download finished or aborted.
                    let st = status.read().await;
                    match *st {
                        ActiveDownloadStatus::Finished { .. } => {
                            drop(st);
                            finished = true;
                            continue;
                        }
                        ActiveDownloadStatus::Aborted(_) => {
                            drop(st);
                            return Err(std::io::Error::other(
                                "sendfile: upstream download aborted",
                            ));
                        }
                        ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download { .. } => {
                            drop(st);
                            return Err(std::io::Error::other(
                                "sendfile: unexpected download state for demoted client file-serve",
                            ));
                        }
                    }
                }
            };
        }

        // Transfer what is currently available via the shared sendfile loop.
        let outcome =
            sendfile_chunk_loop(socket, file, &mut file_offset, sendable, &mut rate_checker)
                .await?;
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
                        ActiveDownloadStatus::Finished { .. } => (true, false),
                        ActiveDownloadStatus::Aborted(_) => (false, true),
                        ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download { .. } => {
                            (false, false)
                        }
                    }
                };
                if is_aborted {
                    return Err(std::io::Error::other("sendfile: upstream download aborted"));
                }
                if is_finished {
                    finished = true;
                }
                transferred
            }
        };
        remaining = remaining
            .checked_sub(sent)
            .expect("should not have transferred more bytes than requested");
    }

    Ok(())
}

/// Serve a file that is currently being downloaded by another task, using
/// sendfile(2) for zero-copy delivery to the joining client.
async fn serve_unfinished_sendfile(
    stream: &TcpStream,
    conn_details: &ConnectionDetails,
    aliased: &str,
    dl_status: std::sync::Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    headers: RangeRequestHeaders<'_>,
) -> ZeroCopyResult {
    // Wait for the download to leave the Init state and learn the file path,
    // content length, notification receiver, and the upstream metadata
    // captured on the status (so we don't need to xattr-read the temp file
    // for ETag / Last-Modified during the conditional-request decision).
    let (file, file_path, total_size, receiver, status_meta) = {
        let mut init_waited = false;
        loop {
            let st = dl_status.read().await;
            let _: Never = match &*st {
                ActiveDownloadStatus::Init(init_rx) => {
                    let mut init_rx = init_rx.clone();
                    drop(st);
                    debug_assert!(
                        !init_waited,
                        "state should change once a ping is received or the downloading task dropped the sender"
                    );
                    if init_waited {
                        error!(
                            "download state still Init after waiting for {} from mirror {}{aliased}",
                            conn_details.debname, conn_details.mirror
                        );
                        return ZeroCopyResult::Invalid {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            msg: "Download State Corrupted",
                        };
                    }
                    if let Err(_err @ tokio::sync::watch::error::RecvError { .. }) =
                        init_rx.changed().await
                    {}
                    init_waited = true;

                    continue;
                }
                ActiveDownloadStatus::Download {
                    path,
                    content_length,
                    rx,
                    meta,
                } => {
                    let file = match tokio::fs::File::options()
                        .read(true)
                        .custom_flags(nix::libc::O_NOFOLLOW)
                        .open(path)
                        .await
                    {
                        Ok(f) => f,
                        Err(err) => {
                            metrics::CACHE_IO_FAILURE.increment();
                            error!(
                                "Failed to open downloading file `{}` for joining client {}:  {err}",
                                path.display(),
                                conn_details.client
                            );
                            return ZeroCopyResult::Invalid {
                                status: StatusCode::INTERNAL_SERVER_ERROR,
                                msg: "Cache Access Failure",
                            };
                        }
                    };
                    let r = (
                        file,
                        path.clone(),
                        *content_length,
                        rx.clone(),
                        Arc::clone(meta),
                    );
                    drop(st);
                    break r;
                }
                ActiveDownloadStatus::Finished { path, meta } => {
                    let finished_path = path.clone();
                    let prefetched = meta.clone();
                    drop(st);

                    let file = match tokio::fs::File::options()
                        .read(true)
                        .custom_flags(nix::libc::O_NOFOLLOW)
                        .open(&finished_path)
                        .await
                    {
                        Ok(f) => f,
                        Err(err) => {
                            metrics::CACHE_IO_FAILURE.increment();
                            error!(
                                "Failed to open finished file `{}` for joining client {}:  {err}",
                                finished_path.display(),
                                conn_details.client
                            );
                            return ZeroCopyResult::Invalid {
                                status: StatusCode::INTERNAL_SERVER_ERROR,
                                msg: "Cache Access Failure",
                            };
                        }
                    };

                    return serve_file_via_sendfile(
                        stream,
                        conn_details,
                        aliased,
                        (file, &finished_path),
                        (conn_version, conn_action),
                        headers,
                        prefetched.as_deref(),
                    )
                    .await
                    .into();
                }
                ActiveDownloadStatus::Aborted(_) => {
                    drop(st);
                    info!(
                        "Download of {} from mirror {}{aliased} was aborted, cannot serve joining client {}",
                        conn_details.debname, conn_details.mirror, conn_details.client
                    );
                    return ZeroCopyResult::Invalid {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        msg: "Download Aborted",
                    };
                }
            };
        }
    };

    // We need an exact content length to write a Content-Length header.
    let ContentLength::Exact(exact_size) = total_size else {
        warn_once_or_debug!(
            "Unknown content length for in-progress download of {} from mirror {}{aliased}",
            conn_details.debname,
            conn_details.mirror,
        );
        return ZeroCopyResult::NotApplicable("unknown content length for in-progress download");
    };

    let metadata = match file.metadata().await {
        Ok(m) if m.file_type().is_file() => m,
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            error!("Cache file `{}` is not a regular file", file_path.display());
            return ZeroCopyResult::Invalid {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                msg: "Cache Access Failure",
            };
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to get metadata of downloading file `{}` for joining client {}:  {err}",
                file_path.display(),
                conn_details.client
            );
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
    let ServeParams {
        http_status,
        content_start,
        content_length,
        content_range,
        partial,
    } = match evaluate_conditional_and_range(
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

    info!(
        "Serving downloading file {} from mirror {}{aliased} for joining client {} via sendfile...",
        conn_details.debname, conn_details.mirror, conn_details.client
    );

    // Joining clients also stream the partial cache file linearly via splice
    // chunks, so warm the kernel readahead window before the loop starts.
    hint_sequential_read(&file, &file_path);

    let _cork = CorkGuard::new_optional(stream);

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
        info!(
            "Failed to write response headers to joining client {}:  {err}",
            conn_details.client
        );
        return ZeroCopyResult::ClientError;
    }

    let start = Instant::now();

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

    match transfer_result {
        Ok(()) => {
            metrics::SERVED_SENDFILE.increment();
            metrics::SERVED_TOTAL.increment();
            let elapsed = start.elapsed();
            info!(
                "Served downloading file {} from mirror {}{aliased} for joining client {} in {} via sendfile (size={}, rate={})",
                conn_details.debname,
                conn_details.mirror,
                conn_details.client,
                HumanFmt::Time(elapsed.into()),
                HumanFmt::Size(content_length),
                HumanFmt::Rate(content_length, elapsed)
            );

            let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
                mirror: conn_details.mirror.clone(),
                debname: conn_details.debname.clone(),
                size: content_length,
                elapsed,
                partial,
                client_ip: conn_details.client.ip(),
            });
            send_db_command(cmd).await;

            ZeroCopyResult::Served(conn_action)
        }
        Err(err) => {
            if is_peer_disconnect(&err) {
                metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                info!(
                    "Joining client {} disconnected while serving downloading file {} from mirror {}{aliased}:  {}",
                    conn_details.client,
                    conn_details.debname,
                    conn_details.mirror,
                    ErrorReport(&err)
                );
            } else {
                warn!(
                    "Failed to sendfile downloading file {} from mirror {}{aliased} to joining client {}:  {}",
                    conn_details.debname,
                    conn_details.mirror,
                    conn_details.client,
                    ErrorReport(&err)
                );
            }
            ZeroCopyResult::AfterHeaderError
        }
    }
}

/// A stream that may have prepended data from a previous read.
/// When all prepended data is consumed, the buffer is dropped and
/// subsequent reads go straight to the inner TCP stream.
struct MaybePrependedStream {
    prepend: Option<BytesMut>,
    stream: TcpStream,
}

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
