use std::fmt::Display;
use std::io::ErrorKind;
use std::num::NonZero;
use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::SystemTime;

use bytes::BytesMut;
use bytes::buf::Buf as _;
use coarsetime::{Duration, Instant};
use http::StatusCode;
use httparse::Request;
use log::{debug, error, info, trace};
use nix::sys::sendfile::sendfile;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::database_task::{DatabaseCommand, DbCmdDelivery};
use crate::deb_mirror::{Mirror, ResourceFile, parse_request_path};
use crate::deb_mirror::{valid_filename, valid_mirrorname};
use crate::http_etag::{if_none_match, read_etag};
use crate::http_range::{
    format_http_date, http_datetime_to_systemtime, http_parse_range, systemtime_to_http_datetime,
};
use crate::humanfmt::HumanFmt;
use crate::rate_checked_body::RateChecker;
use crate::{
    APP_NAME, APP_VIA, AppState, CachedFlavor, ClientInfo, ConnectionDetails, Never,
    authorize_cache_access, client_counter, global_config, handle_hyper_connection, static_assert,
    warn_once_or_info,
};

/// Maximum size for HTTP request headers buffer (matches hyper's default of 8192).
const MAX_HEADER_SIZE: usize = 8192;
/// Initial size for HTTP request headers buffer.
const INITIAL_HEADER_SIZE: usize = 2048;
/// Maximum number of HTTP headers to parse (matches hyper's default of 100).
const MAX_HEADERS: usize = 100;

/// RAII guard that sets `TCP_CORK` on creation and clears it on drop.
/// While corked, the kernel buffers small writes to coalesce them into
/// full MSS-sized TCP segments (e.g. headers + sendfile body).
pub(crate) struct CorkGuard<'a>(&'a TcpStream);

fn set_tcp_cork(stream: &TcpStream, cork: bool) -> std::io::Result<()> {
    let val: nix::libc::c_int = cork.into();
    // SAFETY: stream.as_raw_fd() is a valid socket fd; val is a stack-local c_int.
    let ret = unsafe {
        nix::libc::setsockopt(
            stream.as_raw_fd(),
            nix::libc::IPPROTO_TCP,
            nix::libc::TCP_CORK,
            std::ptr::from_ref::<nix::libc::c_int>(&val).cast(),
            #[expect(
                clippy::cast_possible_truncation,
                reason = "size_of c_int (4) always fits in socklen_t (u32)"
            )]
            {
                std::mem::size_of_val(&val) as nix::libc::socklen_t
            },
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl<'a> CorkGuard<'a> {
    pub(crate) fn new(stream: &'a TcpStream) -> std::io::Result<Self> {
        set_tcp_cork(stream, true)?;
        Ok(Self(stream))
    }
}

impl Drop for CorkGuard<'_> {
    fn drop(&mut self) {
        if let Err(err) = set_tcp_cork(self.0, false) {
            debug!("Failed to uncork TCP socket:  {err}");
        }
    }
}

#[derive(Copy, Clone)]
enum ConnectionAction {
    Close,
    KeepAlive,
}

impl Display for ConnectionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Close => "close",
            Self::KeepAlive => "keep-alive",
        })
    }
}

#[derive(Copy, Clone)]
enum ConnectionVersion {
    Http10,
    Http11,
}

impl Display for ConnectionVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Http10 => "HTTP/1.0",
            Self::Http11 => "HTTP/1.1",
        })
    }
}

enum SendfileResult {
    /// Request was served via sendfile
    Served(ConnectionAction),
    /// Request is not applicable for sendfile, fall back to hyper
    NotApplicable(&'static str),
    /// Request is invalid, reject
    Invalid {
        status: http::StatusCode,
        msg: &'static str,
    },
    /// An error occurred, close the connection; due to the error the client cannot be informed
    Error,
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
        // Try to peek and parse the next request to determine if sendfile is applicable
        let next_header_index = match read_request_headers(&stream, &mut buf).await {
            Ok(None) if req_num == 0 => {
                info!("Connection from client {client} closed before receiving request");
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
                    "Failed to read request number {} from client {client}:  {err}",
                    req_num + 1
                );
                let _ignore = write_invalid_response(
                    &stream,
                    conn_version,
                    StatusCode::BAD_REQUEST,
                    "Error reading request",
                )
                .await;
                return;
            }
        };

        // Parse the request and try to handle it with sendfile
        #[expect(clippy::match_same_arms, reason = "keep separate for clarity")]
        let _: Never = match try_sendfile_request(
            &buf,
            &stream,
            client,
            &appstate,
            &mut conn_version,
        )
        .await
        {
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

                let stream = if buf.is_empty() {
                    MaybePrependedStream::Raw(stream)
                } else {
                    MaybePrependedStream::Prepended {
                        prepend: buf,
                        stream,
                    }
                };

                return handle_hyper_connection(stream, client, appstate).await;
            }
            SendfileResult::Invalid { status, msg } => {
                if let Err(err) = write_invalid_response(&stream, conn_version, status, msg).await {
                    info!("Failed to write error response to client {client}:  {err}");
                }
                return;
            }
            SendfileResult::Error => {
                // Error occurred, should have been already logged.
                // The connection should be closed
                return;
            }
        };
    }
}

/// Compute the connection action based on the request headers.
fn compute_conn_action(
    req: &Request<'_, '_>,
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

    if let Some(hvalue) = find_header(req.headers, "connection") {
        for p in hvalue.split(',') {
            let p = p.trim();

            if p.eq_ignore_ascii_case("close") {
                return ConnectionAction::Close;
            }
            if p.eq_ignore_ascii_case("keep-alive") {
                return ConnectionAction::KeepAlive;
            }
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
        if matches!(*conn_version, ConnectionVersion::Http11)
            && find_header(req.headers, "host").is_none()
        {
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

    // Only handle permanently cached pool files (e.g., .deb files) via sendfile
    let Some(ResourceFile::Pool {
        mirror_path,
        filename,
    }) = parse_request_path(uri.path())
    else {
        return SendfileResult::NotApplicable("no pool resource");
    };

    // Validate mirror path and filename
    let mirror_path = match urlencoding::decode(mirror_path) {
        Ok(s) if valid_mirrorname(&s) => s,
        Ok(s) => {
            warn_once_or_info!("Unsupported mirror path `{s}` from client {client}");
            return SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported request",
            };
        }
        Err(err) => {
            warn_once_or_info!(
                "Failed to decode mirror path `{}` from client {client}:  {err}",
                mirror_path.escape_debug()
            );
            return SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported URL encoding",
            };
        }
    };
    let filename = match urlencoding::decode(filename) {
        Ok(s) if valid_filename(&s) => s,
        Ok(s) => {
            warn_once_or_info!("Unsupported filename `{s}` from client {client}");
            return SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported request",
            };
        }
        Err(err) => {
            warn_once_or_info!(
                "Failed to decode filename `{}` from client {client}:  {err}",
                filename.escape_debug()
            );
            return SendfileResult::Invalid {
                status: StatusCode::BAD_REQUEST,
                msg: "Unsupported URL encoding",
            };
        }
    };
    if !filename.ends_with(".deb") {
        return SendfileResult::NotApplicable("filename does not end with .deb");
    }

    let aliased_host = global_config()
        .aliases
        .iter()
        .find(|alias| alias.aliases.binary_search(&requested_host).is_ok())
        .map(|alias| &alias.main);

    let conn_details = ConnectionDetails {
        client,
        mirror: Mirror {
            host: requested_host,
            port: requested_port,
            path: mirror_path.into_owned(),
        },
        aliased_host,
        debname: filename.into_owned(),
        cached_flavor: CachedFlavor::Permanent,
        subdir: None,
    };

    let aliased = match conn_details.aliased_host {
        Some(alias) => format!(" aliased to host {alias}"),
        None => String::new(),
    };

    // Check if the file exists in cache and is not being downloaded
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

    // Check active downloads - if file is being downloaded, fall back to hyper
    if appstate
        .active_downloads
        .contains(&conn_details.mirror, &conn_details.debname)
    {
        return SendfileResult::NotApplicable("file currently in download");
    }

    // Try to open the file
    let file = match tokio::fs::File::open(&cache_path).await {
        Ok(f) => f,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            // File not in cache, fall back to hyper which will download it
            return SendfileResult::NotApplicable("file not found in cache");
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

    let metadata = match file.metadata().await {
        Ok(m) => m,
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
    };

    let file_size = metadata.len();

    let file_etag = read_etag(&file, &cache_path);

    // Cache entries are replaced on update, not overridden, so the creation time is the time the
    // file was last modified.
    let last_modified = metadata.created().unwrap_or_else(|_err| {
        metadata
            .modified()
            .expect("Platform should support modification timestamps via setup check")
    });

    let conn_action = compute_conn_action(&req, *conn_version, &client);

    // Handle If-None-Match (takes precedence over If-Modified-Since per RFC 9110 §13.1.2)
    let if_none_match_header = find_header(req.headers, "if-none-match");

    if let Some(inm) = if_none_match_header
        && let Some(ref etag) = file_etag
        && if_none_match(inm, etag)
    {
        info!(
            "Serving 304 Not Modified (If-None-Match) for cached file {} from mirror {}{} for client {client} via sendfile",
            conn_details.debname, conn_details.mirror, aliased
        );

        if let Err(err) = write_304_response(
            stream,
            *conn_version,
            conn_action,
            &last_modified,
            file_etag.as_deref(),
        )
        .await
        {
            warn_once_or_info!("Failed to write 304 response to client {client}:  {err}");
            return SendfileResult::Error;
        }

        return SendfileResult::Served(conn_action);
    }

    // Handle If-Modified-Since (only when If-None-Match is absent)
    if if_none_match_header.is_none()
        && let Some(ims) = find_header(req.headers, "if-modified-since")
        && let Some(ims_time) = http_datetime_to_systemtime(ims)
        && last_modified <= ims_time
    {
        info!(
            "Serving 304 Not Modified for cached file {} from mirror {}{} for client {client} via sendfile",
            conn_details.debname, conn_details.mirror, aliased
        );

        if let Err(err) = write_304_response(
            stream,
            *conn_version,
            conn_action,
            &last_modified,
            file_etag.as_deref(),
        )
        .await
        {
            warn_once_or_info!("Failed to write 304 response to client {client}:  {err}");
            return SendfileResult::Error;
        }

        return SendfileResult::Served(conn_action);
    }

    // Handle Range requests
    let range_header = find_header(req.headers, "range");
    let if_range_header = find_header(req.headers, "if-range");

    let (http_status, content_start, content_length, content_range, partial) = if let Some(range) =
        range_header
        && let Some((content_range, start, cl)) = http_parse_range(
            range,
            if_range_header,
            file_size,
            last_modified,
            file_etag.as_deref(),
        ) {
        (
            StatusCode::PARTIAL_CONTENT,
            start,
            cl,
            Some(content_range),
            true,
        )
    } else {
        (StatusCode::OK, 0, file_size, None, false)
    };

    info!(
        "Serving cached file {} from mirror {}{} for client {client} via sendfile...",
        conn_details.debname, conn_details.mirror, aliased
    );

    // Cork the socket to coalesce headers + body into fewer TCP segments
    let _cork = match CorkGuard::new(stream) {
        Ok(guard) => Some(guard),
        Err(err) => {
            debug!("Failed to cork TCP socket for client {client}:  {err}");
            None
        }
    };

    // Write HTTP response headers
    if let Err(err) = write_response_headers(
        stream,
        *conn_version,
        http_status,
        conn_action,
        content_length,
        &last_modified,
        content_range.as_deref(),
        file_etag.as_deref(),
    )
    .await
    {
        warn_once_or_info!("Failed to write response headers to client {client}:  {err}");
        return SendfileResult::Error;
    }

    let start = Instant::now();

    // Use sendfile(2) to transfer the file body
    match async_sendfile(stream, &file, content_start, content_length).await {
        Ok(()) => {
            let elapsed = start.elapsed();
            info!(
                "Served cached file {} from mirror {}{} for client {client} in {} via sendfile (size={}, rate={})",
                conn_details.debname,
                conn_details.mirror,
                aliased,
                HumanFmt::Time(elapsed.into()),
                HumanFmt::Size(content_length),
                HumanFmt::Rate(content_length, elapsed)
            );

            // Update database
            let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
                mirror: conn_details.mirror,
                debname: conn_details.debname,
                size: content_length,
                elapsed,
                partial,
                client_ip: client.ip(),
            });
            appstate
                .database_tx
                .send(cmd)
                .await
                .expect("database task should not die");

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
                info!(
                    "sendfile transfer cancelled for `{}` to client {client}:  {err}",
                    cache_path.display()
                );
            } else {
                error!(
                    "sendfile error serving `{}` to client {client}:  {err}",
                    cache_path.display()
                );
            }
            // Response already sent, just close the connection
            SendfileResult::Error
        }
    }
}

/// Perform an async sendfile(2) operation, transferring `count` bytes from `file`
/// starting at `offset` to the TCP socket.
async fn async_sendfile(
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

    let mut remaining = count;

    while remaining > 0 {
        if let Some(ref rate_checker) = rate_checker
            && let Some(rate) = rate_checker.check_fail()
        {
            let msg = format!(
                "Timeout occurred after a download rate of {} for the last {} seconds",
                HumanFmt::Rate(
                    rate.transferred as u64,
                    Duration::from_secs(rate.timeframe.get() as u64)
                ),
                rate.timeframe,
            );
            return Err(std::io::Error::new(ErrorKind::TimedOut, msg));
        }

        // When rate checking is enabled, periodically check for stalled writes.
        // If the client causes TCP backpressure and the socket stays unwritable,
        // we feed zero-byte samples into the rate checker so check_fail() can fire.
        // The outer http_timeout ensures a fully stalled connection is killed even if
        // rate_check_timeframe > http_timeout.
        match tokio::time::timeout(config.http_timeout, async {
            if let Some(ref mut rc) = rate_checker {
                loop {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        socket.writable(),
                    )
                    .await
                    {
                        Ok(result) => return result,
                        Err(_elapsed @ tokio::time::error::Elapsed { .. }) => {
                            rc.add(0);

                            if let Some(rate) = rc.check_fail()
                            {
                                let msg = format!(
                                    "Timeout occurred after a download rate of {} for the last {} seconds",
                                    HumanFmt::Rate(
                                        rate.transferred as u64,
                                        Duration::from_secs(rate.timeframe.get() as u64)
                                    ),
                                    rate.timeframe,
                                );
                                return Err(std::io::Error::new(ErrorKind::TimedOut, msg));
                            }
                        }
                    }
                }
            } else {
                socket.writable().await
            }
        })
        .await
        {
            Ok(result) => result?,
            Err(tokio::time::error::Elapsed { .. }) => {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "client write timed out",
                ));
            }
        }

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
            let mut off = file_offset;

            tokio::task::spawn_blocking(move || {
                // SAFETY: socket_fd and file_fd are valid for the duration of this
                // blocking task because the caller (`async_sendfile`) holds references
                // to the TcpStream and File, and awaits this task's completion before
                // returning. BorrowedFd is used instead of OwnedFd (try_clone_to_owned)
                // to avoid a dup() syscall per sendfile iteration.
                let socket = unsafe { BorrowedFd::borrow_raw(socket_fd) };
                // SAFETY: same reasoning as above — file_fd is valid for the
                // duration of this blocking task.
                let file = unsafe { BorrowedFd::borrow_raw(file_fd) };
                sendfile(socket, file, Some(&mut off), chunk_size).map(|sent| (sent, off))
            })
            .await
            .expect("spawn_blocking should not panic")
        };

        // Works on Linux, might work on FreeBSD and macOS, and is probably not supported elsewhere
        let _: Never = match result {
            Ok((0, _)) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "sendfile: unexpected end of file",
                ));
            }
            Ok((sent, new_off)) => {
                file_offset = new_off;
                remaining = remaining.saturating_sub(sent as u64);
                if let Some(ref mut rate_checker) = rate_checker {
                    rate_checker.add(sent);
                }
                continue;
            }
            Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => continue,
            Err(err) => return Err(std::io::Error::from(err)),
        };
    }

    Ok(())
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
                    continue;
                }
                Err(err) => return Err(err),
            };
        }
    }

    match tokio::time::timeout(global_config().http_timeout, inner(stream, buf)).await {
        Ok(Ok(next_index)) => Ok(next_index),
        Ok(Err(err)) => Err(err),
        Err(tokio::time::error::Elapsed { .. }) => Err(std::io::Error::new(
            ErrorKind::TimedOut,
            "timed out waiting for request headers",
        )),
    }
}

/// Check if the buffer contains the end of HTTP headers (\r\n\r\n) and return the index after the end.
#[must_use]
#[inline]
fn find_header_end(buf: &[u8]) -> Option<usize> {
    // TODO: use array_windows() once 1.94 is widely available
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Find a header value by name (case-insensitive).
#[must_use]
fn find_header<'a>(headers: &[httparse::Header<'a>], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .and_then(|h| std::str::from_utf8(h.value).ok())
}

/// Write a 304 Not Modified response to the stream.
async fn write_304_response(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    last_modified: &SystemTime,
    etag: Option<&str>,
) -> std::io::Result<()> {
    let date = format_http_date();
    let age = last_modified.elapsed().map_or(0, |dur| dur.as_secs());

    let etag_header = match etag {
        Some(etag) => format!("ETag: {etag}\r\n"),
        None => String::new(),
    };

    let last_modified_str = systemtime_to_http_datetime(*last_modified);

    let response = format!(
        "{conn_version} 304 Not Modified\r\n\
         Date: {date}\r\n\
         Via: {APP_VIA}\r\n\
         Connection: {conn_action}\r\n\
         Last-Modified: {last_modified_str}\r\n\
         {etag_header}\
         Age: {age}\r\n\
         \r\n"
    );
    trace!("Outgoing 304 response:\n{response}");
    write_all_to_stream(stream, response.as_bytes()).await
}

/// Write an error response to the stream.
async fn write_invalid_response(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    status: StatusCode,
    msg: &str,
) -> std::io::Result<()> {
    let date = format_http_date();
    let content_length = msg.len();

    let response = format!(
        "{conn_version} {status}\r\n\
         Server: {APP_NAME}\r\n\
         Date: {date}\r\n\
         Connection: close\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {content_length}\r\n\
         \r\n\
         {msg}"
    );
    trace!("Outgoing error response:\n{response}");
    write_all_to_stream(stream, response.as_bytes()).await
}

/// Write HTTP response headers for a file response.
#[expect(clippy::too_many_arguments, reason = "function has only 1 caller")]
async fn write_response_headers(
    stream: &TcpStream,
    conn_version: ConnectionVersion,
    status: StatusCode,
    conn_action: ConnectionAction,
    content_length: u64,
    last_modified: &SystemTime,
    content_range: Option<&str>,
    etag: Option<&str>,
) -> std::io::Result<()> {
    let date = format_http_date();
    let last_modified_str = systemtime_to_http_datetime(*last_modified);
    let age = last_modified.elapsed().map_or(0, |dur| dur.as_secs());

    let etag_header = match etag {
        Some(etag) => format!("ETag: {etag}\r\n"),
        None => String::new(),
    };

    let mut response = format!(
        "{conn_version} {status}\r\n\
         Date: {date}\r\n\
         Via: {APP_VIA}\r\n\
         Connection: {conn_action}\r\n\
         Content-Length: {content_length}\r\n\
         Content-Type: application/vnd.debian.binary-package\r\n\
         Last-Modified: {last_modified_str}\r\n\
         {etag_header}\
         Accept-Ranges: bytes\r\n\
         Age: {age}\r\n"
    );

    if let Some(cr) = content_range {
        response.push_str("Content-Range: ");
        response.push_str(cr);
        response.push_str("\r\n");
    }

    response.push_str("\r\n");

    trace!("Outgoing file response headers:\n{response}");
    write_all_to_stream(stream, response.as_bytes()).await
}

/// Write all bytes to the TCP stream, handling partial writes.
async fn write_all_to_stream(stream: &TcpStream, data: &[u8]) -> std::io::Result<()> {
    async fn inner(stream: &TcpStream, mut data: &[u8]) -> std::io::Result<()> {
        while !data.is_empty() {
            stream.writable().await?;

            let _: Never = match stream.try_write(data) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        ErrorKind::WriteZero,
                        "failed to write to stream",
                    ));
                }
                Ok(n) => {
                    data = &data[n..];
                    continue;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
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
            "write operation timed out",
        )),
    }
}

/// A stream that may have prepended data from a previous read.
/// When all prepended data is consumed, reads delegate to the inner TCP stream.
#[derive(Debug)]
enum MaybePrependedStream {
    Raw(TcpStream),
    Prepended {
        prepend: BytesMut,
        stream: TcpStream,
    },
}

impl AsyncRead for MaybePrependedStream {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Prepended { prepend, stream } => {
                if prepend.is_empty() {
                    Pin::new(stream).poll_read(cx, buf)
                } else {
                    let n = std::cmp::min(prepend.len(), buf.remaining());
                    buf.put_slice(&prepend[..n]);
                    prepend.advance(n);
                    Poll::Ready(Ok(()))
                }
            }
        }
    }
}

impl AsyncWrite for MaybePrependedStream {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Raw(stream) | Self::Prepended { prepend: _, stream } => {
                Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Raw(stream) | Self::Prepended { prepend: _, stream } => {
                Pin::new(stream).poll_flush(cx)
            }
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Raw(stream) | Self::Prepended { prepend: _, stream } => {
                Pin::new(stream).poll_shutdown(cx)
            }
        }
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(find_header(&headers, "host"), Some("example.com"));
        assert_eq!(find_header(&headers, "HOST"), Some("example.com"));
        assert_eq!(find_header(&headers, "range"), Some("bytes=0-100"));
        assert_eq!(find_header(&headers, "nonexistent"), None);
    }
}
