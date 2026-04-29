use std::io::ErrorKind;
use std::num::NonZero;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::path::Path;
use std::pin::Pin;
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

use crate::database_task::{DatabaseCommand, DbCmdDelivery, DbCmdOrigin, send_db_command};
use crate::deb_mirror::{
    Mirror, Origin, ResourceFile, is_deb_package, is_unsafe_proxy_path, parse_request_path,
    valid_architecture, valid_component, valid_distribution, valid_filename, valid_mirrorname,
};
use crate::error::{ErrorReport, errno_to_io_error};
use crate::http_etag::{if_none_match, read_etag};
use crate::http_helpers::{
    ConnectionAction, ConnectionVersion, ResponseHeaders, find_header, find_header_end,
    write_304_response, write_416_response, write_invalid_response, write_response_headers,
};
use crate::http_last_modified::read_last_modified;
use crate::http_range::{
    HttpDate, ParsedRange, cache_file_http_date, compute_age, http_parse_range,
};
use crate::humanfmt::HumanFmt;
use crate::rate_checked_body::{InsufficientRate, RateCheckDirection, RateChecker};
use crate::tcp_cork_guard::CorkGuard;
use crate::{
    ActiveDownloadStatus, AppState, CachedFlavor, ClientInfo, ConnectionDetails, ContentLength,
    Never, VOLATILE_CACHE_MAX_AGE, authorize_cache_access, client_counter,
    content_type_for_cached_file, global_config, handle_hyper_connection, is_diff_request_path,
    metrics, static_assert, warn_once_or_debug, warn_once_or_info,
};

/// Maximum size for HTTP request headers buffer (matches hyper's default of 8192).
const MAX_HEADER_SIZE: usize = 8192;
/// Initial size for HTTP request headers buffer.
const INITIAL_HEADER_SIZE: usize = 2048;
/// Maximum number of HTTP headers to parse (matches hyper's default of 100).
const MAX_HEADERS: usize = 100;

/// Represents the result of a sendfile operation.
pub(crate) enum SendfileResult {
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
            Err(err) if err.kind() == ErrorKind::TimedOut => {
                info!(
                    "Timeout while reading request headers from client {client} for request {}",
                    req_num + 1
                );
                return;
            }
            Err(err) => {
                warn_once_or_info!(
                    "Failed to read request number {} from client {client}:  {}",
                    req_num + 1,
                    ErrorReport(&err),
                );
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

        if !matches!(result, SendfileResult::NotApplicable(_)) {
            metrics::REQUESTS_TOTAL.increment();
        }

        // Parse the request and try to handle it with sendfile
        #[expect(clippy::match_same_arms, reason = "keep separate for clarity")]
        let _: Never = match result {
            SendfileResult::Served(ConnectionAction::KeepAlive) => {
                // Request served via sendfile with keep-alive; continue to next request
                buf.advance(next_header_index);
                continue;
            }
            SendfileResult::Served(ConnectionAction::Close) => {
                // Request served via sendfile; close the connection as requested
                return;
            }
            SendfileResult::NotApplicable(reason) => {
                // Fall back to hyper for this and all subsequent requests
                debug!(
                    "Falling back to hyper for client {client} after {req_num} requests due to: {reason} ({} bytes buffered)",
                    buf.len()
                );

                let stream = MaybePrependedStream::new(buf, stream);

                return handle_hyper_connection(stream, client, appstate).await;
            }
            SendfileResult::Invalid { status, msg } => {
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
            SendfileResult::Rejection {
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
            SendfileResult::AfterHeaderError | SendfileResult::ClientError => {
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
    async fn inner(stream: &TcpStream, buf: &mut BytesMut) -> std::io::Result<Option<usize>> {
        // Check if we already have the complete headers from the previous read
        if let Some(next_index) = find_header_end(buf) {
            return Ok(Some(next_index));
        }

        loop {
            stream.readable().await?;

            let _: Never = match stream.try_read_buf(buf) {
                Ok(0) => return Ok(None),
                Ok(n) => {
                    // Check if we have the complete headers
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
                    continue;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(err) if err.kind() == ErrorKind::Interrupted => {
                    continue;
                }
                Err(err) => return Err(err),
            };
        }
    }

    match tokio::time::timeout(global_config().http_timeout, inner(stream, buf)).await {
        Ok(Ok(next_index)) => Ok(next_index),
        Ok(Err(err)) => Err(err),
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
            metrics::HTTP_TIMEOUT_CLIENT.increment();
            Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "reading TCP stream request headers timed out",
            ))
        }
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

/// URL-decode and validate a single field. On failure returns the
/// `SendfileResult::Invalid` the caller should propagate.
fn decode_and_validate_field<'a>(
    raw: &'a str,
    validator: fn(&str) -> bool,
    field_name: &str,
    client: &ClientInfo,
) -> Result<std::borrow::Cow<'a, str>, SendfileResult> {
    match urlencoding::decode(raw) {
        Ok(s) if validator(&s) => Ok(s),
        Ok(s) => {
            warn_once_or_info!("Unsupported {field_name} `{s}` from client {client}");
            Err(SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported request",
            })
        }
        Err(err) => {
            warn_once_or_info!(
                "Failed to decode {field_name} `{}` from client {client}:  {err}",
                raw.escape_debug()
            );
            Err(SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported URL encoding",
            })
        }
    }
}

/// URL-decode a field and validate it, returning early from the caller on failure.
///
/// Thin wrapper over [`decode_and_validate_field`] that performs the early
/// return; the underlying helper is exposed so it can be unit-tested and
/// used from contexts that cannot early-return `SendfileResult`.
macro_rules! decode_and_validate {
    ($raw:expr, $validator:expr, $field_name:expr, $client:expr) => {{
        match decode_and_validate_field($raw, $validator, $field_name, $client) {
            Ok(s) => s,
            Err(e) => return e,
        }
    }};
}

/// Try to serve a request using sendfile(2).
/// Return whether the request was handled.
async fn try_sendfile_request(
    buf: &[u8],
    stream: &TcpStream,
    client: ClientInfo,
    appstate: &AppState,
    conn_version: &mut ConnectionVersion,
) -> SendfileResult {
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
                return SendfileResult::Invalid {
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
            return SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Incomplete request header",
            };
        }
        Err(httparse::Error::Version) => {
            warn_once_or_info!("Unsupported HTTP version from client {client}");
            return SendfileResult::Invalid {
                status: StatusCode::HTTP_VERSION_NOT_SUPPORTED,
                msg: "HTTP version not supported",
            };
        }
        Err(err) => {
            warn_once_or_info!("Failed to parse HTTP request from client {client}:  {err}");
            return SendfileResult::Invalid {
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
        "CONNECT" => return SendfileResult::NotApplicable("CONNECT method not supported"),
        m => {
            warn_once_or_info!(
                "Unsupported request method from client {client}: {}",
                m.escape_debug(),
            );
            return SendfileResult::Invalid {
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
            return SendfileResult::Invalid {
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
        return SendfileResult::Invalid {
            status: StatusCode::BAD_REQUEST,
            msg: "Unsupported URI scheme",
        };
    }

    let Some(authority) = uri.authority() else {
        // RFC 7230 §5.4: A server MUST respond with a 400 status code to any
        // HTTP/1.1 request that lacks a Host header field.
        if *conn_version == ConnectionVersion::Http11 && find_header(req.headers, &HOST).is_none() {
            debug!("Missing Host header from HTTP/1.1 request from client {client}");
            return SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Missing Host header",
            };
        }
        // No authority means it's likely a direct request (web interface) - fall back
        return SendfileResult::NotApplicable("no authority");
    };

    let requested_host = match authorize_cache_access(&client, authority.host().to_string()) {
        Ok(rh) => rh,
        Err((status, msg)) => return SendfileResult::Invalid { status, msg },
    };
    let requested_port = match authority.port_u16() {
        Some(port) => {
            let Some(port) = NonZero::new(port) else {
                warn_once_or_info!("Unsupported request port 0 from client {client}");
                return SendfileResult::Invalid {
                    status: StatusCode::BAD_REQUEST,
                    msg: "Invalid port",
                };
            };
            Some(port)
        }
        None => None,
    };

    let conn_action = compute_conn_action(&req, *conn_version, &client);

    // Match all cacheable resource types for sendfile/splice serving
    let uri_path = uri.path();
    let Some(resource) = parse_request_path(uri_path) else {
        if global_config().reject_pdiff_requests && is_diff_request_path(uri_path) {
            info!("Rejecting diff request {uri_path} for client {client}");

            metrics::PDIFF_REJECTED.increment();
            return SendfileResult::Rejection {
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
            return SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported request",
            };
        }

        #[cfg(feature = "splice")]
        {
            use crate::{
                splice_conn::{SpliceProxyError, splice_simple_proxy},
                uncacheables::record_uncacheable,
            };

            record_uncacheable(&requested_host, uri_path);

            let mirror = Mirror {
                host: requested_host,
                port: requested_port,
                path: String::new(),
            };

            return match splice_simple_proxy(stream, *conn_version, conn_action, &mirror, uri_path)
                .await
            {
                Ok(()) => SendfileResult::Served(conn_action),
                Err(SpliceProxyError::UpstreamError(err)) => {
                    warn!(
                        "simple proxy: upstream error for {uri_path} from host {}:  {err}",
                        mirror.format_authority()
                    );
                    SendfileResult::Invalid {
                        status: StatusCode::BAD_GATEWAY,
                        msg: "Upstream Error",
                    }
                }
                Err(SpliceProxyError::TransferError(err)) => {
                    warn!(
                        "simple proxy: transfer error for {uri_path} from host {}:  {err}",
                        mirror.format_authority()
                    );
                    SendfileResult::Invalid {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        msg: "Transfer Error",
                    }
                }
                Err(SpliceProxyError::ClientError(err)) => {
                    debug!(
                        "simple proxy: client error for {uri_path} from host {}:  {err}",
                        mirror.format_authority()
                    );
                    SendfileResult::ClientError
                }
                Err(SpliceProxyError::AfterHeaderError(err)) => {
                    info!(
                        "simple proxy: after-header error for {uri_path} from host {}:  {err}",
                        mirror.format_authority()
                    );
                    SendfileResult::AfterHeaderError
                }
                Err(err) => {
                    warn!("simple proxy: unexpected error for {uri_path}:  {err}");
                    SendfileResult::NotApplicable("simple proxy failed")
                }
            };
        }

        #[cfg(not(feature = "splice"))]
        return SendfileResult::NotApplicable("unrecognized resource path");
    };

    // Per-resource origin fields for Packages (to record after ConnectionDetails is built)
    struct PackagesOriginFields {
        distribution: String,
        component: String,
        architecture: String,
    }

    // Decode, validate, and build per-resource debname / cached_flavor / subdir.
    let (debname, cached_flavor, subdir, mirror_path, origin_fields) = match resource {
        ResourceFile::Pool {
            mirror_path,
            filename,
        } => {
            let mirror_path =
                decode_and_validate!(mirror_path, valid_mirrorname, "mirror path", &client);
            let filename = decode_and_validate!(filename, valid_filename, "filename", &client);
            if !is_deb_package(&filename) {
                return SendfileResult::NotApplicable("non Debian binary package pool file");
            }

            (
                filename.into_owned(),
                CachedFlavor::Permanent,
                None,
                mirror_path,
                None,
            )
        }
        ResourceFile::Release {
            mirror_path,
            distribution,
            filename,
        } => {
            let mirror_path =
                decode_and_validate!(mirror_path, valid_mirrorname, "mirror path", &client);
            let distribution =
                decode_and_validate!(distribution, valid_distribution, "distribution", &client);
            let filename = decode_and_validate!(filename, valid_filename, "filename", &client);

            (
                format!("{distribution}_{filename}"),
                CachedFlavor::Volatile,
                Some(Path::new("dists")),
                mirror_path,
                None,
            )
        }
        ResourceFile::ByHash {
            mirror_path,
            filename,
        } => {
            let mirror_path =
                decode_and_validate!(mirror_path, valid_mirrorname, "mirror path", &client);
            let filename = decode_and_validate!(filename, valid_filename, "filename", &client);

            (
                filename.into_owned(),
                CachedFlavor::Permanent,
                Some(Path::new("dists/by-hash")),
                mirror_path,
                None,
            )
        }
        ResourceFile::Icon {
            mirror_path,
            distribution,
            component,
            filename,
        }
        | ResourceFile::Sources {
            mirror_path,
            distribution,
            component,
            filename,
        }
        | ResourceFile::Translation {
            mirror_path,
            distribution,
            component,
            filename,
        } => {
            let mirror_path =
                decode_and_validate!(mirror_path, valid_mirrorname, "mirror path", &client);
            let distribution =
                decode_and_validate!(distribution, valid_distribution, "distribution", &client);
            let component = decode_and_validate!(component, valid_component, "component", &client);
            let filename = decode_and_validate!(filename, valid_filename, "filename", &client);

            (
                format!("{distribution}_{component}_{filename}"),
                CachedFlavor::Volatile,
                Some(Path::new("dists")),
                mirror_path,
                None,
            )
        }
        ResourceFile::Packages {
            mirror_path,
            distribution,
            component,
            architecture,
            filename,
        } => {
            let mirror_path =
                decode_and_validate!(mirror_path, valid_mirrorname, "mirror path", &client);
            let distribution =
                decode_and_validate!(distribution, valid_distribution, "distribution", &client);
            let component = decode_and_validate!(component, valid_component, "component", &client);
            let architecture =
                decode_and_validate!(architecture, valid_architecture, "architecture", &client);
            let filename = decode_and_validate!(filename, valid_filename, "filename", &client);

            let debname = format!("{distribution}_{component}_{architecture}_{filename}");
            let origin = match architecture.as_ref() {
                "dep11" | "i18n" | "source" => None,
                _ => Some(PackagesOriginFields {
                    distribution: distribution.into_owned(),
                    component: component.into_owned(),
                    architecture: architecture.into_owned(),
                }),
            };

            (
                debname,
                CachedFlavor::Volatile,
                Some(Path::new("dists")),
                mirror_path,
                origin,
            )
        }
    };

    let aliased_host = global_config()
        .aliases
        .iter()
        .find(|alias| alias.aliases.binary_search(&requested_host).is_ok())
        .map(|alias| &alias.main);

    let aliased = match aliased_host {
        Some(alias) => format!(" aliased to host {alias}"),
        None => String::new(),
    };

    let conn_details = ConnectionDetails {
        client,
        mirror: Mirror {
            host: requested_host,
            port: requested_port,
            path: mirror_path.into_owned(),
        },
        aliased_host,
        debname,
        cached_flavor,
        subdir,
    };

    // Record origin for Packages requests (mirrors main.rs behavior)
    if let Some(fields) = origin_fields {
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
    if let Some(dl_status) = appstate
        .active_downloads
        .attach(&conn_details.mirror, &conn_details.debname)
    {
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

        // CACHE_HITS tracks permanent-file hits only and only when we have
        // actually served from cache via sendfile (NotApplicable falls back
        // to hyper); the volatile case is accounted for via VOLATILE_REFETCHED
        // by the originator.
        if !matches!(result, SendfileResult::NotApplicable(_))
            && conn_details.cached_flavor == CachedFlavor::Permanent
        {
            metrics::CACHE_HITS.increment();
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
        let file = match tokio::fs::File::open(&cache_path).await {
            Ok(f) => f,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                if conn_details.cached_flavor == CachedFlavor::Volatile {
                    cache_miss_was_volatile_notfound = true;
                }
                break 'cache_lookup None;
            }
            Err(err) => {
                error!(
                    "Failed to open cached file `{}` for client {client}:  {err}",
                    cache_path.display()
                );
                return SendfileResult::Invalid {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    msg: "Cache Access Failure",
                };
            }
        };

        // Volatile staleness: if file is older than 30s, treat as cache miss
        // so splice/hyper can fetch a fresh copy from upstream.
        if conn_details.cached_flavor == CachedFlavor::Volatile {
            match file.metadata().await {
                Ok(metadata) => {
                    let last_modified = metadata
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
                Err(err) => {
                    error!(
                        "Failed to get metadata of cached file `{}` for client {client}:  {err}",
                        cache_path.display()
                    );
                    return SendfileResult::Invalid {
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
            *conn_version,
            conn_action,
            RangeRequestHeaders::extract(req.headers),
        )
        .await;
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
            Ok(SpliceProxyOutcome::Served) => SendfileResult::Served(conn_action),
            Ok(SpliceProxyOutcome::Concurrent { status: dl_status }) => {
                // Race-loser path: another connection registered the
                // download between our earlier `attach()` (which saw
                // nothing) and `splice_proxy`'s `originate()`. The
                // existing download's status was handed back by
                // `originate()` and is held alive by the Arc, so we can
                // serve from the partial via sendfile directly — no
                // re-attach, no race-of-races fall-back.
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
                if !matches!(result, SendfileResult::NotApplicable(_))
                    && conn_details.cached_flavor == CachedFlavor::Permanent
                {
                    metrics::CACHE_HITS.increment();
                }
                result
            }
            Err(SpliceProxyError::NotApplicable(reason)) => {
                warn_once_or_debug!(
                    "splice proxy not applicable for {} from mirror {}{}: {reason}",
                    conn_details.debname,
                    conn_details.mirror,
                    aliased
                );
                SendfileResult::NotApplicable(reason)
            }
            Err(SpliceProxyError::UpstreamError(err)) => {
                warn!(
                    "splice proxy: upstream error for {} from mirror {}{}:  {err}",
                    conn_details.debname, conn_details.mirror, aliased
                );
                SendfileResult::Invalid {
                    status: StatusCode::BAD_GATEWAY,
                    msg: "Upstream Error",
                }
            }
            Err(SpliceProxyError::CacheError(err)) => {
                warn!(
                    "splice proxy: cache error for {} from mirror {}{}:  {err}",
                    conn_details.debname, conn_details.mirror, aliased
                );
                SendfileResult::Invalid {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    msg: "Cache Error",
                }
            }
            Err(SpliceProxyError::TransferError(err)) => {
                warn!(
                    "splice proxy: transfer error for {} from mirror {}{}:  {err}",
                    conn_details.debname, conn_details.mirror, aliased
                );
                SendfileResult::Invalid {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    msg: "Transfer Error",
                }
            }
            Err(SpliceProxyError::ClientError(err)) => {
                debug!(
                    "splice proxy: client error for {} from mirror {}{}:  {err}",
                    conn_details.debname, conn_details.mirror, aliased
                );
                SendfileResult::ClientError
            }
            Err(SpliceProxyError::AfterHeaderError(err)) => {
                info!(
                    "splice proxy: after-header error for {} from mirror {}{}:  {err}",
                    conn_details.debname, conn_details.mirror, aliased
                );
                SendfileResult::AfterHeaderError
            }
        }
    }

    #[cfg(not(feature = "splice"))]
    SendfileResult::NotApplicable("file not found in cache")
}

/// Pre-computed cache metadata used by [`evaluate_conditional_and_range`].
struct CacheInfo {
    file_etag: Option<String>,
    last_modified_for_ims: HttpDate,
    last_modified_str: String,
    age: u32,
}

/// Outcome of [`evaluate_conditional_and_range`].
enum ConditionalOutcome {
    /// Caller should send a 304 Not Modified (already written to the stream).
    NotModified(ConnectionAction),
    /// Caller should send a 416 Range Not Satisfiable (already written to the stream).
    RangeNotSatisfiable(ConnectionAction),
    /// Proceed with serving the file using these range parameters.
    Serve {
        http_status: StatusCode,
        content_start: u64,
        content_length: u64,
        content_range: Option<String>,
        partial: bool,
    },
}

/// Read `ETag` / Last-Modified from xattr and file metadata.
fn read_cache_info(
    file: &tokio::fs::File,
    file_path: &Path,
    metadata: &std::fs::Metadata,
) -> CacheInfo {
    let file_etag = read_etag(file, file_path);
    let cache_ts = cache_file_http_date(metadata);
    let stored_last_modified = read_last_modified(file, file_path);
    let (last_modified_for_ims, last_modified_str) = match stored_last_modified {
        Some((s, time)) => (time, s),
        None => (cache_ts, cache_ts.format()),
    };
    let age = compute_age(metadata);
    CacheInfo {
        file_etag,
        last_modified_for_ims,
        last_modified_str,
        age,
    }
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
    // Evaluate conditional request (RFC 9110 §13.1.2: If-None-Match takes precedence)
    let serve_304 = if let Some(inm) = headers.if_none_match {
        cache_info
            .file_etag
            .as_deref()
            .is_some_and(|etag| if_none_match(inm, etag))
    } else if let Some(ims) = headers.if_modified_since
        && let Some(ims_time) = HttpDate::parse(ims)
    {
        cache_info.last_modified_for_ims <= ims_time
    } else {
        false
    };

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
                return Ok(ConditionalOutcome::Serve {
                    http_status: StatusCode::PARTIAL_CONTENT,
                    content_start: start,
                    content_length: cl,
                    content_range: Some(content_range),
                    partial: true,
                });
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

    Ok(ConditionalOutcome::Serve {
        http_status: StatusCode::OK,
        content_start: 0,
        content_length: file_size,
        content_range: None,
        partial: false,
    })
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
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    headers: RangeRequestHeaders<'_>,
) -> SendfileResult {
    let (file, file_path) = source;

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(err) => {
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

    let file_size = metadata.len();

    let cache_info = read_cache_info(&file, file_path, &metadata);

    let (http_status, content_start, content_length, content_range, partial) =
        match evaluate_conditional_and_range(
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
            Ok(ConditionalOutcome::Serve {
                http_status,
                content_start,
                content_length,
                content_range,
                partial,
            }) => (
                http_status,
                content_start,
                content_length,
                content_range,
                partial,
            ),
            Err(result) => return result,
        };

    info!(
        "Serving cached file {} from mirror {}{aliased} for client {} via sendfile...",
        conn_details.debname, conn_details.mirror, conn_details.client,
    );

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
    let transfer_result = async_sendfile(stream, &file, content_start, content_length).await;

    match transfer_result {
        Ok(()) => {
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
            let is_client_disconnect = matches!(
                err.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::TimedOut
            );
            if is_client_disconnect {
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
pub(crate) fn rate_timeout_error(
    rate: &InsufficientRate,
    direction: RateCheckDirection,
) -> std::io::Error {
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

/// Wait for the socket to become readable or writable, bounded by
/// `http_timeout`.  When a `RateChecker` is supplied, polls in 1-second
/// slices so a stalled socket trips the configured rate-check window
/// (which may be much shorter than `http_timeout`).  `RateChecker::add`
/// back-fills gaps on the next sample on its own; the `rc.add(0)` calls
/// here only exist to drive `check_fail` on each tick.
async fn wait_socket_rated(
    socket: &TcpStream,
    op: SocketReadiness,
    rate_checker: &mut Option<RateChecker>,
    direction: RateCheckDirection,
    http_timeout: std::time::Duration,
) -> std::io::Result<()> {
    let timeout_msg = match (op, direction) {
        (SocketReadiness::Readable, RateCheckDirection::Client) => "client read timed out",
        (SocketReadiness::Writable, RateCheckDirection::Client) => "client write timed out",
        (SocketReadiness::Readable, RateCheckDirection::Upstream) => "upstream read timed out",
        (SocketReadiness::Writable, RateCheckDirection::Upstream) => "upstream write timed out",
    };

    let wait_once = || async move {
        match op {
            SocketReadiness::Readable => socket.readable().await,
            SocketReadiness::Writable => socket.writable().await,
        }
    };

    match tokio::time::timeout(http_timeout, async {
        if let Some(rc) = rate_checker {
            loop {
                match tokio::time::timeout(std::time::Duration::from_secs(1), wait_once()).await {
                    Ok(result) => return result,
                    Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                        rc.add(0);

                        if let Some(rate) = rc.check_fail(direction) {
                            return Err(rate_timeout_error(&rate, direction));
                        }
                    }
                }
            }
        } else {
            wait_once().await
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
            match direction {
                RateCheckDirection::Client => metrics::HTTP_TIMEOUT_CLIENT.increment(),
                RateCheckDirection::Upstream => metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment(),
            }
            Err(std::io::Error::new(ErrorKind::TimedOut, timeout_msg))
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

async fn sendfile_chunk_loop(
    socket: &TcpStream,
    file: &tokio::fs::File,
    file_offset: &mut i64,
    amount: u64,
    rate_checker: &mut Option<RateChecker>,
) -> std::io::Result<ChunkLoopOutcome> {
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

        // Limit each sendfile call to avoid exceeding system limits.
        // 0x7fff_f000 is always within usize range since it fits in 31 bits.
        static_assert!(0x7fff_f000 < usize::MAX);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "no truncation since 0x7fff_f000 < usize::MAX"
        )]
        let chunk_size = std::cmp::min(remaining, 0x7fff_f000) as usize;

        let result = {
            // Copy file descriptors
            let socket_fd = socket.as_raw_fd();
            let file_fd = file.as_raw_fd();
            let mut off = *file_offset;

            tokio::task::spawn_blocking(move || {
                // SAFETY: socket_fd and file_fd are valid for the duration of this
                // blocking task because the caller (`sendfile_chunk_loop`) holds
                // references to the TcpStream and File, and awaits this task's
                // completion before returning. BorrowedFd is used instead of OwnedFd
                // (try_clone_to_owned) to avoid a dup() syscall per sendfile iteration.
                let socket = unsafe { BorrowedFd::borrow_raw(socket_fd) };
                // SAFETY: same reasoning as above — file_fd is valid for the
                // duration of this blocking task.
                let file = unsafe { BorrowedFd::borrow_raw(file_fd) };
                sendfile(socket, file, Some(&mut off), chunk_size).map(|sent| (sent, off))
            })
            .await
            .expect("task should not panic")
        };

        // Works on Linux, might work on FreeBSD and macOS, and is probably not supported elsewhere
        let _: Never = match result {
            Ok((0, off)) => {
                debug_assert_eq!(
                    off, *file_offset,
                    "no bytes written, offset should not change"
                );
                warn_once_or_debug!(
                    "sendfile returned 0 at offset {file_offset} with {remaining}/{amount} bytes remaining"
                );
                return Ok(ChunkLoopOutcome::Eof {
                    transferred: amount - remaining,
                });
            }
            Ok((sent, new_off)) => {
                *file_offset = new_off;
                remaining = remaining
                    .checked_sub(sent as u64)
                    .expect("sendfile(2) should not transfer more bytes than requested");
                metrics::BYTES_SERVED_SENDFILE.increment_by(sent as u64);
                if let Some(rc) = rate_checker {
                    rc.add(sent);
                }
                continue;
            }
            Err(nix::errno::Errno::EAGAIN) => {
                // The socket is not ready to write, wait for it to become writable.
                // For sendfile(2) regular input files, regardless of blocking or
                // non-blocking, are always ready to read.
                continue;
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(errno) => return Err(errno_to_io_error(errno, "sendfile failed")),
        };
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
        ChunkLoopOutcome::Complete => {
            metrics::REQUESTS_SENDFILE.increment();
            Ok(())
        }
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
async fn async_sendfile_unfinished(
    socket: &TcpStream,
    file: &tokio::fs::File,
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

    metrics::REQUESTS_SENDFILE.increment();

    while remaining > 0 {
        // Determine how many bytes the file currently has available past our offset.
        let offset_u64: u64 = file_offset
            .try_into()
            .expect("file_offset is non-negative by construction");

        let file_size = match tokio::task::block_in_place(|| nix::sys::stat::fstat(file.as_fd())) {
            Ok(stat) => stat
                .st_size
                .try_into()
                .expect("file size is non-negative by construction"),
            Err(errno) => {
                error!("Failed to query metadata of downloading file during sendfile:  {errno}");
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
                        ActiveDownloadStatus::Finished(_) => {
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
                        ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download(..) => {
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
                        ActiveDownloadStatus::Finished(_) => (true, false),
                        ActiveDownloadStatus::Aborted(_) => (false, true),
                        ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download(..) => {
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
) -> SendfileResult {
    // Wait for the download to leave the Init state and learn the file path,
    // content length, and notification receiver.
    let (file, file_path, total_size, receiver) = {
        let mut init_waited = false;
        loop {
            let st = dl_status.read().await;
            let _: Never = match &*st {
                ActiveDownloadStatus::Init(init_rx) => {
                    let mut init_rx = init_rx.clone();
                    drop(st);
                    if init_waited {
                        error!(
                            "download state still Init after waiting for {} from mirror {}{aliased}",
                            conn_details.debname, conn_details.mirror
                        );
                        return SendfileResult::Invalid {
                            status: StatusCode::INTERNAL_SERVER_ERROR,
                            msg: "Download State Corrupted",
                        };
                    }
                    let _ignore = init_rx.changed().await;
                    init_waited = true;

                    continue;
                }
                ActiveDownloadStatus::Download(path, cl, rx) => {
                    let file = match tokio::fs::File::open(path).await {
                        Ok(f) => f,
                        Err(err) => {
                            error!(
                                "Failed to open downloading file `{}` for joining client {}:  {err}",
                                path.display(),
                                conn_details.client
                            );
                            return SendfileResult::Invalid {
                                status: StatusCode::INTERNAL_SERVER_ERROR,
                                msg: "Cache Access Failure",
                            };
                        }
                    };
                    let r = (file, path.clone(), *cl, rx.clone());
                    drop(st);
                    break r;
                }
                ActiveDownloadStatus::Finished(path) => {
                    let finished_path = path.clone();
                    drop(st);
                    // Download finished before we could join — serve the
                    // completed file directly via sendfile.

                    let file = match tokio::fs::File::open(&finished_path).await {
                        Ok(f) => f,
                        Err(err) => {
                            error!(
                                "Failed to open finished file `{}` for joining client {}:  {err}",
                                finished_path.display(),
                                conn_details.client
                            );
                            return SendfileResult::Invalid {
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
                        conn_version,
                        conn_action,
                        headers,
                    )
                    .await;
                }
                ActiveDownloadStatus::Aborted(_) => {
                    drop(st);
                    info!(
                        "Download of {} from mirror {}{aliased} was aborted, cannot serve joining client {}",
                        conn_details.debname, conn_details.mirror, conn_details.client
                    );
                    return SendfileResult::Invalid {
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
        return SendfileResult::NotApplicable("unknown content length for in-progress download");
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(err) => {
            error!(
                "Failed to get metadata of downloading file `{}` for joining client {}:  {err}",
                file_path.display(),
                conn_details.client
            );
            return SendfileResult::Invalid {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                msg: "Cache Access Failure",
            };
        }
    };

    let cache_info = read_cache_info(&file, &file_path, &metadata);

    // Range handling uses the total upstream size (not the current partial size on disk).
    let (http_status, content_start, content_length, content_range, partial) =
        match evaluate_conditional_and_range(
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
                return SendfileResult::Served(ca);
            }
            Ok(ConditionalOutcome::RangeNotSatisfiable(ca)) => {
                return SendfileResult::Served(ca);
            }
            Ok(ConditionalOutcome::Serve {
                http_status,
                content_start,
                content_length,
                content_range,
                partial,
            }) => (
                http_status,
                content_start,
                content_length,
                content_range,
                partial,
            ),
            Err(result) => return result,
        };

    info!(
        "Serving downloading file {} from mirror {}{aliased} for joining client {} via sendfile...",
        conn_details.debname, conn_details.mirror, conn_details.client
    );

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
        return SendfileResult::ClientError;
    }

    let start = Instant::now();

    let transfer_result = async_sendfile_unfinished(
        stream,
        &file,
        content_start,
        content_length,
        receiver,
        dl_status,
    )
    .await;

    match transfer_result {
        Ok(()) => {
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

            SendfileResult::Served(conn_action)
        }
        Err(err) => {
            let is_client_disconnect = matches!(
                err.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::BrokenPipe
                    | ErrorKind::TimedOut
            );

            if is_client_disconnect {
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
            SendfileResult::AfterHeaderError
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
