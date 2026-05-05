use std::fmt::Write as _;
use std::io::ErrorKind;
use std::num::{NonZero, Saturating};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::BytesMut;
#[cfg(feature = "ktls")]
use coarsetime::Duration;
use hashbrown::hash_map::EntryRef;
use http::{
    StatusCode,
    header::{
        CONNECTION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, LAST_MODIFIED, LOCATION,
        TRANSFER_ENCODING,
    },
};
use log::{debug, error, info, trace, warn};
use nix::fcntl::{SpliceFFlags, splice, tee};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, Interest, ReadBuf},
    net::{TcpStream, unix::pipe},
};

use crate::cache_quota::QuotaExceeded;
use crate::config::{DomainName, HttpsUpgradeMode};
use crate::database_task::{
    DatabaseCommand, DbCmdDelivery, DbCmdDownload, DbCmdOrigin, send_db_command,
};
use crate::deb_mirror::{Mirror, Origin};
use crate::error::{ErrorReport, errno_to_io_error};
use crate::guards::{DownloadBarrier, InitBarrier};
use crate::http_etag::{is_valid_etag, read_etag, write_etag};
use crate::http_helpers::{
    ConnectionAction, ConnectionVersion, find_header, write_416_response, write_all_to_stream,
    write_invalid_response,
};
use crate::http_last_modified::write_last_modified;
use crate::http_range::{
    HttpDate, ParsedRange, format_http_date, http_parse_range, parse_content_range,
};
use crate::humanfmt::HumanFmt;
#[cfg(feature = "ktls")]
use crate::ktls;
#[cfg(feature = "ktls")]
use crate::ktls_handshake::{discard_incoming, encode_tls_data, grow_incoming};
use crate::rate_checked_body::{InsufficientRate, RateCheckDirection, RateChecker};
#[cfg(feature = "ktls")]
use crate::secure_vec::SecureVec;
use crate::sendfile_conn::{
    RangeRequestHeaders, SendfileResult, async_sendfile, serve_file_via_sendfile,
    wait_readable_rated, wait_writable_rated, write_all_to_stream_rated,
};
use crate::tcp_cork_guard::CorkGuard;
use crate::utils::{self, TempPath, hint_sequential_read, tokio_tempfile, touch_volatile_mtime};
use crate::{
    APP_USER_AGENT, APP_VIA, ActiveDownloadStatus, AppState, CachedFlavor, ConnectionDetails,
    ContentLength, Never, OriginateOutcome, SCHEME_CACHE, Scheme, SchemeKey, SchemeKeyRef,
    VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER, client_counter, content_type_for_cached_file,
    global_cache_quota, global_config, is_host_allowed, metrics, static_assert, warn_once_or_debug,
    warn_once_or_info,
};
#[cfg(feature = "ktls")]
use crate::{KTLS_BLOCKED, warn_once};

// On Linux, EAGAIN and EWOULDBLOCK share the same numeric value, so matching
// one variant is equivalent to matching both. The nix crate models EWOULDBLOCK
// as a const alias of EAGAIN, which would make `EAGAIN | EWOULDBLOCK` an
// unreachable-pattern error. This assertion documents the equivalence once,
// so the individual `Err(Errno::EAGAIN)` arms throughout this module do not
// need to repeat it.
static_assert!(nix::errno::Errno::EAGAIN as i32 == nix::errno::Errno::EWOULDBLOCK as i32);

/// Conditional headers for volatile resource revalidation.
/// Sent to upstream when a cached volatile file is stale (>30s).
struct VolatileCondHeaders {
    if_modified_since: String,
    if_none_match: Option<String>,
}

/// Pre-computed byte offsets for range-filtering the splice loop output.
/// `skip` bytes are suppressed at the start, then `send` bytes are forwarded.
struct SpliceRangeFilter {
    skip: u64,
    send: u64,
}

/// Pre-computed TLS client config for use with `tls_rustls`.
/// Should only be initialized once from main.
#[cfg(feature = "tls_rustls")]
pub(crate) static TLS_CLIENT_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// Default pipe buffer size on Linux is 16 pages (64 KiB on most systems).
/// We increase it to 1 MiB to reduce the number of splice syscall pairs needed.
const PIPE_BUFFER_SIZE: i32 = 1024 * 1024;

/// How long an idle pooled connection is kept before eviction.
const POOL_IDLE_TIMEOUT: coarsetime::Duration = coarsetime::Duration::from_secs(90);

/// Maximum number of idle connections kept per host.
const POOL_MAX_IDLE_PER_HOST: usize = 4;

/// Maximum size for HTTP response headers buffer.
const MAX_RESPONSE_HEADER_SIZE: usize = 8192;

/// Maximum number of HTTP response headers to parse.
const MAX_RESPONSE_HEADERS: usize = 32;

/// Buffer size for TLS upstream reads (matches pipe buffer size).
const TLS_READ_BUF_SIZE: usize = 64 * 1024;

/// Maximum bytes to forward for volatile responses (no Content-Length / chunked non-cacheable).
const VOLATILE_BODY_MAX: usize = 1024 * 1024;

/// How long to remember kTLS setup failures before retrying.
#[cfg(feature = "ktls")]
const KTLS_BLOCK_DURATION: Duration = Duration::from_secs(600);

/// Monotonic time (coarsetime ticks) of the last opportunistic GC of `KTLS_BLOCKED`
/// from the read path. Used to rate-limit GC sweeps to at most once per
/// `KTLS_BLOCK_DURATION` on cache misses.
#[cfg(feature = "ktls")]
static KTLS_BLOCKED_LAST_GC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Returns `true` if an opportunistic GC of `KTLS_BLOCKED` should run now,
/// updating the last-GC timestamp atomically. At most one caller per
/// `KTLS_BLOCK_DURATION` wins the swap and returns `true`.
#[cfg(feature = "ktls")]
fn ktls_blocked_should_gc(now: coarsetime::Instant) -> bool {
    use std::sync::atomic::Ordering;

    let now_ticks = now.as_ticks();
    let last = KTLS_BLOCKED_LAST_GC.load(Ordering::Relaxed);
    let elapsed = coarsetime::Duration::from_ticks(now_ticks.saturating_sub(last));
    if elapsed < KTLS_BLOCK_DURATION {
        return false;
    }
    KTLS_BLOCKED_LAST_GC
        .compare_exchange(last, now_ticks, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

// ---------------------------------------------------------------------------
// UpstreamConn: TCP or TLS wrapper
// ---------------------------------------------------------------------------

#[cfg_attr(
    feature = "tls_rustls",
    expect(
        clippy::large_enum_variant,
        reason = "tokio_rustls::client::TlsStream is the biggest variant, but also the one most likely to be used"
    )
)]
#[pin_project::pin_project(project = UpstreamConnProj)]
enum UpstreamConn {
    Tcp(#[pin] TcpStream),
    #[cfg(feature = "tls_rustls")]
    Tls(#[pin] tokio_rustls::client::TlsStream<TcpStream>),
    #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
    Tls(#[pin] tokio_native_tls::TlsStream<TcpStream>),
}

impl AsyncRead for UpstreamConn {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_read(cx, buf),
            #[cfg(feature = "tls_rustls")]
            UpstreamConnProj::Tls(s) => s.poll_read(cx, buf),
            #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
            UpstreamConnProj::Tls(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for UpstreamConn {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_write(cx, buf),
            #[cfg(feature = "tls_rustls")]
            UpstreamConnProj::Tls(s) => s.poll_write(cx, buf),
            #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
            UpstreamConnProj::Tls(s) => s.poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_flush(cx),
            #[cfg(feature = "tls_rustls")]
            UpstreamConnProj::Tls(s) => s.poll_flush(cx),
            #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
            UpstreamConnProj::Tls(s) => s.poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_shutdown(cx),
            #[cfg(feature = "tls_rustls")]
            UpstreamConnProj::Tls(s) => s.poll_shutdown(cx),
            #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
            UpstreamConnProj::Tls(s) => s.poll_shutdown(cx),
        }
    }
}

impl UpstreamConn {
    #[must_use]
    const fn is_tls(&self) -> bool {
        match self {
            Self::Tcp(_) => false,
            #[cfg(feature = "tls_rustls")]
            Self::Tls(_) => true,
            #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
            Self::Tls(_) => true,
        }
    }

    /// For the TCP variant, get a reference to the inner `TcpStream`.
    /// Returns `None` for TLS connections.
    #[must_use]
    const fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Tcp(s) => Some(s),
            #[cfg(feature = "tls_rustls")]
            Self::Tls(_) => None,
            #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
            Self::Tls(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Upstream connection pool
// ---------------------------------------------------------------------------

struct PooledConn {
    conn: UpstreamConn,
    idle_since: coarsetime::Instant,
}

/// Pool key includes TLS flag so HTTP and HTTPS connections to the same
/// (host, port) — possible on mirrors reachable via both protocols on a
/// non-default port — never get mixed up.
type PoolKey = (String, u16, bool);

/// Borrowed key for allocation-free pool lookups.
#[derive(Hash)]
struct PoolKeyRef<'a>(&'a str, u16, bool);

impl hashbrown::Equivalent<PoolKey> for PoolKeyRef<'_> {
    #[inline]
    fn equivalent(&self, key: &PoolKey) -> bool {
        self.0 == key.0 && self.1 == key.1 && self.2 == key.2
    }
}

static UPSTREAM_POOL: OnceLock<parking_lot::Mutex<hashbrown::HashMap<PoolKey, Vec<PooledConn>>>> =
    OnceLock::new();

fn upstream_pool() -> &'static parking_lot::Mutex<hashbrown::HashMap<PoolKey, Vec<PooledConn>>> {
    UPSTREAM_POOL.get_or_init(|| parking_lot::Mutex::new(hashbrown::HashMap::new()))
}

/// Resolve the port for a mirror, defaulting to 80 or 443 based on TLS.
fn mirror_port(mirror: &Mirror, is_tls: bool) -> u16 {
    mirror
        .port()
        .map_or(if is_tls { 443 } else { 80 }, NonZero::get)
}

/// Try to retrieve an idle connection from the pool.
///
/// Pops from the back (most-recently-returned) and skips stale entries
/// without scanning the entire vec, keeping the lock held briefly.
fn pool_checkout(host: &str, port: u16, is_tls: bool) -> Option<UpstreamConn> {
    let mut map = upstream_pool().lock();
    let key_ref = PoolKeyRef(host, port, is_tls);
    let conns = map.get_mut(&key_ref)?;

    let now = coarsetime::Instant::now();
    let conn = loop {
        let entry = conns.pop()?;
        if now.duration_since(entry.idle_since) < POOL_IDLE_TIMEOUT {
            break entry.conn;
        }
        debug!("splice proxy: discarding stale pooled connection to {host}:{port}");
    };
    if conns.is_empty() {
        map.remove(&key_ref);
    }
    drop(map);
    debug!("splice proxy: reusing pooled connection to {host}:{port} (tls={is_tls})");
    Some(conn)
}

/// Return a connection to the pool for reuse.
fn pool_return(host: &str, port: u16, is_tls: bool, conn: UpstreamConn) {
    let mut map = upstream_pool().lock();
    let key_ref = PoolKeyRef(host, port, is_tls);
    let conns = match map.entry_ref(&key_ref) {
        EntryRef::Occupied(oentry) => oentry.into_mut(),
        EntryRef::Vacant(ventry) => ventry
            .insert_entry_with_key((key_ref.0.to_owned(), key_ref.1, key_ref.2), Vec::new())
            .into_mut(),
    };

    let now = coarsetime::Instant::now();
    conns.retain(|e| now.duration_since(e.idle_since) < POOL_IDLE_TIMEOUT);

    if conns.len() >= POOL_MAX_IDLE_PER_HOST {
        debug!("splice proxy: evicting oldest pooled connection for {host}:{port} (pool full)");
        metrics::POOL_RETURN_EVICTED.increment();
        conns.remove(0);
    }
    conns.push(PooledConn {
        conn,
        idle_since: now,
    });
    drop(map);
    debug!("splice proxy: returned connection to pool for {host}:{port} (tls={is_tls})");
}

/// Wraps an `UpstreamConn` and automatically returns it to the connection pool
/// on drop if `poolable` is true. Prevents connection leaks on early-return paths.
struct PoolGuard {
    conn: Option<UpstreamConn>,
    host: String,
    port: u16,
    is_tls: bool,
    poolable: bool,
}

impl PoolGuard {
    /// Creates a new `PoolGuard` wrapping the given `UpstreamConn`.
    fn new(conn: UpstreamConn, host: String, port: u16, poolable: bool) -> Self {
        let is_tls = conn.is_tls();
        Self {
            conn: Some(conn),
            host,
            port,
            is_tls,
            poolable,
        }
    }

    /// Marks the connection as non-poolable, preventing it from being returned to the pool on drop.
    fn unset_poolable(&mut self) {
        self.poolable = false;
    }

    /// Replace the inner connection (e.g., after a retry with a fresh connection).
    /// The old connection is dropped without being returned to the pool.
    fn replace(&mut self, conn: UpstreamConn, poolable: bool) {
        self.is_tls = conn.is_tls();
        self.conn = Some(conn);
        self.poolable = poolable;
    }
}

impl std::ops::Deref for PoolGuard {
    type Target = UpstreamConn;
    fn deref(&self) -> &UpstreamConn {
        self.conn.as_ref().expect("PoolGuard used after take")
    }
}

impl std::ops::DerefMut for PoolGuard {
    fn deref_mut(&mut self) -> &mut UpstreamConn {
        self.conn.as_mut().expect("PoolGuard used after take")
    }
}

impl Drop for PoolGuard {
    fn drop(&mut self) {
        if self.poolable
            && let Some(conn) = self.conn.take()
        {
            pool_return(&self.host, self.port, self.is_tls, conn);
        }
    }
}

impl UpstreamConn {
    /// Check if a pooled connection is still alive (not closed by the remote).
    ///
    /// For TLS connections on rustls we peek at the raw TCP socket: a closed
    /// peer (recv → 0) or error rules the connection out, while pending bytes
    /// on an idle pooled TLS connection almost certainly indicate a `close_notify`
    /// alert and are treated the same. The native-tls backend does not expose
    /// the underlying TCP fd cleanly, so we remain optimistic there.
    fn check_alive(&self) -> bool {
        fn tcp_peek_alive(fd: std::os::fd::RawFd) -> bool {
            use nix::sys::socket::{MsgFlags, recv};

            let mut buf = [0u8; 1];

            match recv(fd, &mut buf, MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT) {
                Ok(0) | Err(nix::errno::Errno::ECONNRESET) => {
                    debug!("splice proxy: pooled connection closed by peer");
                    false
                }
                Ok(pending) => {
                    warn_once_or_debug!(
                        "splice proxy: pooled connection has unexpected data ({pending} bytes pending), discarding"
                    );
                    false
                }
                // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                Err(nix::errno::Errno::EAGAIN) => true,
                Err(errno) => {
                    warn!("splice proxy: pooled connection check failed:  {errno}");
                    false
                }
            }
        }

        match self {
            Self::Tcp(tcp) => tcp_peek_alive(tcp.as_raw_fd()),
            #[cfg(feature = "tls_rustls")]
            Self::Tls(tls) => {
                let (tcp, _) = tls.get_ref();
                tcp_peek_alive(tcp.as_raw_fd())
            }
            #[cfg(not(feature = "tls_rustls"))]
            Self::Tls(_) => true,
        }
    }
}

/// Create a pipe and optionally increase its buffer size.
fn create_pipe() -> std::io::Result<(pipe::Sender, pipe::Receiver)> {
    use nix::fcntl::{FcntlArg, fcntl};

    let (sender, receiver) = pipe::pipe()?;

    // Try to increase pipe buffer size; ignore failure (non-fatal, just fewer bytes per round-trip)
    static_assert!(PIPE_BUFFER_SIZE > 0);
    if let Err(errno) = fcntl(sender.as_fd(), FcntlArg::F_SETPIPE_SZ(PIPE_BUFFER_SIZE)) {
        warn_once_or_info!("splice proxy: failed to increase pipe buffer size:  {errno}");
    }

    Ok((sender, receiver))
}

// Force-clear Tokio's cached readiness on a TCP socket or pipe end.
//
// `splice`/`tee` operate on raw fds and can return `EAGAIN` on either
// participant; Tokio doesn't see those errors so its cache stays "ready".
// We invoke `try_io` with a no-op closure that returns `WouldBlock` to
// trigger `clear_readiness` and force the next `readable()`/`writable()`
// to actually park until a fresh epoll event arrives.

fn clear_tcp_readable_cache(socket: &TcpStream) {
    let _ignore = socket.try_io(Interest::READABLE, || -> std::io::Result<()> {
        Err(std::io::ErrorKind::WouldBlock.into())
    });
}

fn clear_tcp_writable_cache(socket: &TcpStream) {
    let _ignore = socket.try_io(Interest::WRITABLE, || -> std::io::Result<()> {
        Err(std::io::ErrorKind::WouldBlock.into())
    });
}

fn clear_pipe_readable_cache(receiver: &pipe::Receiver) {
    let _ignore =
        receiver.try_io(|| -> std::io::Result<()> { Err(std::io::ErrorKind::WouldBlock.into()) });
}

fn clear_pipe_writable_cache(sender: &pipe::Sender) {
    let _ignore =
        sender.try_io(|| -> std::io::Result<()> { Err(std::io::ErrorKind::WouldBlock.into()) });
}

// ---------------------------------------------------------------------------
// Socket-to-socket splice proxy
// ---------------------------------------------------------------------------

/// Determine the scheme (HTTP or HTTPS) for a mirror based on config and scheme cache.
///
/// Returns `Some(Scheme::Http)` or `Some(Scheme::Https)` if known,
/// `None` if unknown (should try HTTPS upgrade).
fn resolve_mirror_scheme(mirror: &Mirror) -> Option<Scheme> {
    let config = global_config();

    // Check scheme cache first
    let key = SchemeKeyRef {
        host: mirror.host(),
        port: mirror.port().map(std::num::NonZero::get),
    };
    let cached = SCHEME_CACHE
        .get()
        .expect("Initialized in main()")
        .read()
        .get(&key)
        .copied();
    if let Some(cached) = cached {
        return Some(cached);
    }

    // If upgrade mode is Never, always use HTTP
    if config.https_upgrade_mode == HttpsUpgradeMode::Never {
        return Some(Scheme::Http);
    }

    // If mirror is in http_only_mirrors, use HTTP
    if config
        .http_only_mirrors
        .iter()
        .any(|m| m.permits(mirror.host()))
    {
        return Some(Scheme::Http);
    }

    // If upgrade mode is Always, use HTTPS
    if config.https_upgrade_mode == HttpsUpgradeMode::Always {
        return Some(Scheme::Https);
    }

    // Auto mode with no cached scheme: try HTTPS
    None
}

/// Connect to the upstream mirror, optionally establishing TLS.
///
/// When the scheme is known (from cache or config), connects directly.
/// In Auto mode with no cached scheme, tries HTTPS first and falls back to HTTP.
///
/// Times out after the configured HTTP timeout.
async fn connect_upstream(mirror: &Mirror) -> std::io::Result<(UpstreamConn, Scheme)> {
    let host = mirror.host().as_str();

    match resolve_mirror_scheme(mirror) {
        Some(Scheme::Http) => {
            let port = mirror.port().map_or(80, std::num::NonZero::get);
            let tcp = tcp_connect(host, port).await?;
            Ok((UpstreamConn::Tcp(tcp), Scheme::Http))
        }
        Some(Scheme::Https) => {
            let port = mirror.port().map_or(443, std::num::NonZero::get);
            let tcp = tcp_connect(host, port).await?;
            let tls = tls_connect(tcp, host).await.inspect_err(|_| {
                metrics::UPSTREAM_TLS_FAILED.increment();
            })?;
            Ok((UpstreamConn::Tls(tls), Scheme::Https))
        }
        None => {
            // Auto mode: try HTTPS first, fall back to HTTP
            // TODO: retry HTTPS after small period, fall back to HTTP
            let https_port = mirror.port().map_or(443, std::num::NonZero::get);
            match tcp_connect(host, https_port).await {
                Ok(tcp) => match tls_connect(tcp, host).await {
                    Ok(tls) => {
                        debug!(
                            "splice proxy: HTTPS upgrade succeeded for {}",
                            mirror.format_authority()
                        );
                        return Ok((UpstreamConn::Tls(tls), Scheme::Https));
                    }
                    Err(err) => {
                        metrics::UPSTREAM_TLS_FAILED.increment();
                        debug!(
                            "splice proxy: TLS handshake failed for {}, trying HTTP:  {}",
                            mirror.format_authority(),
                            ErrorReport(&err)
                        );
                    }
                },
                Err(err) => {
                    debug!(
                        "splice proxy: HTTPS connect to {} failed, trying HTTP:  {}",
                        mirror.format_authority(),
                        ErrorReport(&err)
                    );
                }
            }

            let plain_port = mirror.port().map_or(80, std::num::NonZero::get);
            let tcp = tcp_connect(host, plain_port).await?;
            Ok((UpstreamConn::Tcp(tcp), Scheme::Http))
        }
    }
}

/// Establish a TCP connection to the given host and port.
///
/// Times out after the configured HTTP timeout.
async fn tcp_connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    tokio::time::timeout(
        global_config().http_timeout,
        TcpStream::connect((host, port)),
    )
    .await
    .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| {
        metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
        std::io::Error::new(ErrorKind::TimedOut, "upstream TCP connect timed out")
    })?
    .map_err(|err| {
        metrics::UPSTREAM_CONNECT_FAILED.increment();
        std::io::Error::new(
            err.kind(),
            format!("TCP connect to upstream failed:  {err}"),
        )
    })
}

/// Perform TLS handshake over an established TCP connection.
///
/// Times out after the configured HTTP timeout.
#[cfg(feature = "tls_rustls")]
async fn tls_connect(
    tcp: TcpStream,
    host: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(
        TLS_CLIENT_CONFIG.get().expect("initialized in main()"),
    ));

    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|err| {
        std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("failed to parse server name:  {err}"),
        )
    })?;

    debug!("splice proxy: starting TLS handshake with {host}");
    let tls_stream = tokio::time::timeout(
        global_config().http_timeout,
        connector.connect(server_name, tcp),
    )
    .await
    .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| {
        metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
        std::io::Error::new(ErrorKind::TimedOut, "TLS handshake timed out")
    })?
    .map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("failed to complete TLS handshake:  {err}"),
        )
    })?;
    debug!("splice proxy: TLS handshake completed with {host}");
    Ok(tls_stream)
}

/// Perform TLS handshake over an established TCP connection with timeout.
///
/// Times out after the configured HTTP timeout.
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
async fn tls_connect(
    tcp: TcpStream,
    host: &str,
) -> std::io::Result<tokio_native_tls::TlsStream<TcpStream>> {
    let native_connector =
        tokio_native_tls::native_tls::TlsConnector::new().map_err(std::io::Error::other)?;
    let connector = tokio_native_tls::TlsConnector::from(native_connector);

    debug!("splice proxy: starting TLS handshake with {host}");
    let tls_stream =
        tokio::time::timeout(global_config().http_timeout, connector.connect(host, tcp))
            .await
            .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| {
                metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
                std::io::Error::new(ErrorKind::TimedOut, "TLS handshake timed out")
            })?
            .map_err(std::io::Error::other)?;
    debug!("splice proxy: TLS handshake completed with {host}");
    Ok(tls_stream)
}

// ---------------------------------------------------------------------------
// Unbuffered kTLS: TLS handshake + HTTP request using rustls UnbufferedClientConnection
// ---------------------------------------------------------------------------

/// Result of a successful unbuffered kTLS connection: the TCP stream is ready
/// for kTLS RX, response headers are parsed, and any extra body bytes are saved.
#[cfg(feature = "ktls")]
struct KtlsReadyState {
    response: UpstreamResponse,
    header_buf: BytesMut,
    header_end: usize,
    extra_body: Vec<u8>,
}

/// Errors from unbuffered kTLS request, distinguishing failure stages.
#[cfg(feature = "ktls")]
enum KtlsError {
    /// Failure before or during TLS handshake — connection cannot be reused
    TlsFailed(std::io::Error),
    /// TLS+HTTP succeeded, but response is not suitable for kTLS splice
    /// (non-200 status or missing/zero Content-Length). The caller reconnects
    /// via the standard path.
    ResponseNotSpliceable { response: UpstreamResponse },
    /// TLS+HTTP succeeded, but kTLS setup failed for a persistent reason
    /// (unsupported cipher, kernel lacks TLS ULP, ENOENT on setsockopt, ...).
    /// Blocks kTLS for the full `KTLS_BLOCK_DURATION`.
    KtlsSetupFailed(std::io::Error),
    /// kTLS setup failed for a plausibly transient reason (drain races,
    /// intermittent upstream stalls). Do not block further kTLS connections.
    KtlsSetupFailedTransient(std::io::Error),
}

/// Result of attempting an unbuffered kTLS connection.
#[cfg(feature = "ktls")]
enum KtlsResult {
    /// kTLS fully set up — ready for zero-copy splice
    Ready(TcpStream, KtlsReadyState),
    /// TLS+HTTP succeeded but response is not splice-eligible (non-200, no CL).
    /// Carries only the parsed response so the caller can choose to serve cached
    /// data (304) or reconnect via the standard path for a clean full fetch.
    ResponseNotSpliceable { response: UpstreamResponse },
    /// Failed — must reconnect. `tls_succeeded` indicates whether HTTPS works
    /// for this mirror, so scheme can be cached to avoid double-HTTPS in auto mode.
    Failed { tls_succeeded: bool },
}

/// Transmit any pending outgoing TLS data and mark the transmit as done.
///
/// Always calls `ttd.done()` even if the write fails, so the TLS state machine
/// advances. Returns the write result so callers can propagate or ignore errors.
///
/// Times out after the configured HTTP timeout.
#[cfg(feature = "ktls")]
async fn transmit_tls_data(
    ttd: rustls::unbuffered::TransmitTlsData<'_, rustls::client::ClientConnectionData>,
    tcp: &TcpStream,
    outgoing: &[u8],
    outgoing_used: &mut usize,
) -> std::io::Result<()> {
    let result = if *outgoing_used > 0 {
        let r = write_all_to_stream(tcp, &outgoing[..*outgoing_used]).await;
        *outgoing_used = 0;
        r
    } else {
        Ok(())
    };
    ttd.done();
    result
}

/// Drain all complete TLS records from the incoming buffer, appending decrypted
/// plaintext to `output`. Handles `EncodeTlsData` and `TransmitTlsData` states
/// as side-effects (post-handshake messages). Stops when the buffer is empty or
/// a terminal/blocked state is reached.
///
/// This is the shared drain loop used by phases 4 and 4b of the unbuffered kTLS
/// handshake, and the non-spliceable response fallback path.
///
/// Times out after the configured HTTP timeout.
#[cfg(feature = "ktls")]
async fn drain_buffered_records(
    conn: &mut rustls::client::UnbufferedClientConnection,
    incoming: &mut SecureVec,
    incoming_used: &mut usize,
    outgoing: &mut SecureVec,
    outgoing_used: &mut usize,
    tcp: &TcpStream,
    output: &mut Vec<u8>,
) -> Result<(), KtlsError> {
    use rustls::unbuffered::{AppDataRecord, ConnectionState, UnbufferedStatus};

    while *incoming_used > 0 {
        let UnbufferedStatus { discard, state } =
            conn.process_tls_records(&mut incoming[..*incoming_used]);
        let state = state.map_err(|err| {
            KtlsError::KtlsSetupFailed(std::io::Error::other(format!("TLS drain error:  {err}")))
        })?;

        match state {
            ConnectionState::ReadTraffic(mut rt) => {
                let mut total_discard = discard;
                while let Some(result) = rt.next_record() {
                    let AppDataRecord { payload, discard } = result.map_err(|err| {
                        KtlsError::KtlsSetupFailed(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("TLS record error:  {err}"),
                        ))
                    })?;
                    total_discard += discard;
                    output.extend_from_slice(payload);
                }
                discard_incoming(incoming, incoming_used, total_discard);
            }
            ConnectionState::EncodeTlsData(mut etd) => {
                // Do NOT reset `outgoing_used` here.  The rustls state
                // machine may emit several `EncodeTlsData` states in a row
                // before a single `TransmitTlsData` (e.g. a ClientHello
                // followed by an early-data finished message), and
                // `encode_tls_data` appends at `outgoing[*outgoing_used..]`.
                // Zeroing would silently drop any bytes still waiting to be
                // written.
                encode_tls_data(&mut etd, outgoing, outgoing_used);
                discard_incoming(incoming, incoming_used, discard);
            }
            ConnectionState::TransmitTlsData(ttd) => {
                transmit_tls_data(ttd, tcp, outgoing, outgoing_used)
                    .await
                    .map_err(KtlsError::KtlsSetupFailed)?;
                discard_incoming(incoming, incoming_used, discard);
            }
            ConnectionState::PeerClosed
            | ConnectionState::Closed
            | ConnectionState::ReadEarlyData(_)
            | ConnectionState::BlockedHandshake
            | ConnectionState::WriteTraffic(_) => {
                discard_incoming(incoming, incoming_used, discard);
                break;
            }
            other => {
                warn_once!("splice proxy: unexpected ConnectionState variant: {other:?}");
                discard_incoming(incoming, incoming_used, discard);
                break;
            }
        }
    }

    Ok(())
}

/// Try to establish a kTLS-ready connection using the unbuffered rustls API.
///
/// Returns a rich result indicating success, a non-spliceable response (which
/// can be forwarded directly without reconnecting), or failure with information
/// about whether TLS succeeded (to avoid redundant HTTPS attempts).
///
/// Times out after the configured HTTP timeout.
#[cfg(feature = "ktls")]
async fn try_unbuffered_ktls_connect(
    mirror: &Mirror,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> KtlsResult {
    if !ktls::is_available() {
        return KtlsResult::Failed {
            tls_succeeded: false,
        };
    }

    if resolve_mirror_scheme(mirror) == Some(Scheme::Http) {
        return KtlsResult::Failed {
            tls_succeeded: false,
        };
    }

    // Skip kTLS for mirrors where setup has recently failed (retry after KTLS_BLOCK_DURATION)
    let key = SchemeKeyRef {
        host: mirror.host().as_str(),
        port: mirror.port().map(std::num::NonZero::get),
    };
    {
        let blocked = KTLS_BLOCKED.get().expect("Initialized in main()");
        let now = coarsetime::Instant::now();
        let blocked_at = blocked.read().get(&key).copied();
        match blocked_at {
            Some(at) if now.duration_since(at) < KTLS_BLOCK_DURATION => {
                debug!(
                    "kTLS: skipping {} (setup blocked since {}s ago)",
                    mirror.host(),
                    now.duration_since(at).as_secs()
                );
                return KtlsResult::Failed {
                    tls_succeeded: false,
                };
            }
            Some(_) => {
                // Entry expired — remove it and GC other stale entries
                let mut guard = blocked.write();
                guard.retain(|_, at| now.duration_since(*at) < KTLS_BLOCK_DURATION);
            }
            None => {
                // Cache miss: opportunistically sweep stale entries once per
                // KTLS_BLOCK_DURATION. Without this, entries for hosts that are
                // never re-attempted would otherwise linger indefinitely since
                // GC only runs on the expired-hit and insert paths.
                if ktls_blocked_should_gc(now) {
                    let mut guard = blocked.write();
                    guard.retain(|_, at| now.duration_since(*at) < KTLS_BLOCK_DURATION);
                }
            }
        }
    }

    let host = mirror.host().as_str();
    let port = mirror.port().map_or(443, std::num::NonZero::get);

    let mut tcp = match tcp_connect(host, port).await {
        Ok(tcp) => tcp,
        Err(err) => {
            warn!("kTLS: TCP connect to upstream {host}:{port} failed:  {err}");
            return KtlsResult::Failed {
                tls_succeeded: false,
            };
        }
    };

    match tokio::time::timeout(
        global_config().http_timeout,
        unbuffered_ktls_request(
            &mut tcp,
            host,
            host_authority,
            upstream_path,
            resume_offset,
            resume_if_range,
            volatile_cond,
        ),
    )
    .await
    {
        Ok(Ok(state)) => KtlsResult::Ready(tcp, state),
        Ok(Err(KtlsError::TlsFailed(err))) => {
            debug!("kTLS: TLS failed:  {err}");
            KtlsResult::Failed {
                tls_succeeded: false,
            }
        }
        Ok(Err(KtlsError::ResponseNotSpliceable { response })) => {
            debug!(
                "kTLS: response not spliceable (status={})",
                response.status_code
            );
            KtlsResult::ResponseNotSpliceable { response }
        }
        Ok(Err(KtlsError::KtlsSetupFailed(err))) => {
            metrics::KTLS_FALLBACK_PERMANENT.increment();
            warn!(
                "kTLS: setup failed for {}, blocking kTLS for {}s:  {err}",
                mirror.format_authority(),
                KTLS_BLOCK_DURATION.as_secs()
            );
            let key = SchemeKey {
                host: key.host.to_owned(),
                port: key.port,
            };
            {
                let now = coarsetime::Instant::now();
                let mut blocked = KTLS_BLOCKED.get().expect("Initialized in main()").write();
                // Opportunistic GC: we already hold the write lock, so sweep out
                // any stale entries. This prevents entries for one-shot hosts
                // from accumulating indefinitely.
                blocked.retain(|_, at| now.duration_since(*at) < KTLS_BLOCK_DURATION);
                blocked.insert(key, now);
            }
            KtlsResult::Failed {
                tls_succeeded: true,
            }
        }
        Ok(Err(KtlsError::KtlsSetupFailedTransient(err))) => {
            metrics::KTLS_FALLBACK_TRANSIENT.increment();
            info!(
                "kTLS: transient setup failure for {} (no block):  {err}",
                mirror.format_authority()
            );
            // Intentionally do not insert into KTLS_BLOCKED. Transient failures
            // (drain races etc.) can plausibly succeed on the next attempt.
            KtlsResult::Failed {
                tls_succeeded: true,
            }
        }
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
            debug!("kTLS: timed out");
            KtlsResult::Failed {
                tls_succeeded: false,
            }
        }
    }
}

/// Drive an unbuffered TLS handshake, send an HTTP request, read response
/// headers, drain the buffer to record alignment, and set up kTLS RX.
#[cfg(feature = "ktls")]
async fn unbuffered_ktls_request(
    tcp: &mut TcpStream,
    host: &str,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> Result<KtlsReadyState, KtlsError> {
    use rustls::client::UnbufferedClientConnection;
    use rustls::unbuffered::{ConnectionState, EncryptError};

    // --- Build TLS config ---
    let tls_config = Arc::clone(TLS_CLIENT_CONFIG.get().expect("initialized in main()"));

    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|err| KtlsError::TlsFailed(std::io::Error::new(ErrorKind::InvalidInput, err)))?;

    let mut conn = UnbufferedClientConnection::new(tls_config, server_name).map_err(|err| {
        KtlsError::TlsFailed(std::io::Error::other(format!("unbuffered TLS new:  {err}")))
    })?;

    // --- Phase 1 of 5: TLS Handshake ---
    // Use SecureVec to zeroize TLS record buffers (containing key material and
    // partially-decrypted data) on drop.
    let mut incoming = SecureVec::new(32 * 1024);
    let mut incoming_used = 0usize;
    let mut outgoing = SecureVec::new(8 * 1024);
    let mut outgoing_used = 0usize;

    // Phase 1 errors are TLS handshake failures — map them accordingly.
    let handshake_result: std::io::Result<()> = async {
        loop {
            let status = conn.process_tls_records(&mut incoming[..incoming_used]);
            let discard = status.discard;
            let state = status
                .state
                .map_err(|err| std::io::Error::other(format!("TLS handshake error:  {err}")))?;

            match state {
                ConnectionState::EncodeTlsData(mut etd) => {
                    encode_tls_data(&mut etd, &mut outgoing, &mut outgoing_used);
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                }
                ConnectionState::TransmitTlsData(ttd) => {
                    transmit_tls_data(ttd, tcp, &outgoing, &mut outgoing_used).await?;
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                }
                ConnectionState::BlockedHandshake => {
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                    // Need more data from the server
                    grow_incoming(&mut incoming, incoming_used, "handshake")?;
                    let n = tcp.read(&mut incoming[incoming_used..]).await?;
                    if n == 0 {
                        return Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "server closed during TLS handshake",
                        ));
                    }
                    incoming_used += n;
                }
                ConnectionState::WriteTraffic(_) => {
                    // Handshake complete
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                    break;
                }
                ConnectionState::ReadTraffic(_)
                | ConnectionState::PeerClosed
                | ConnectionState::Closed
                | ConnectionState::ReadEarlyData(_)
                | _ => {
                    return Err(std::io::Error::other(
                        "unexpected state during TLS handshake",
                    ));
                }
            }
        }
        Ok(())
    }
    .await;
    handshake_result.map_err(KtlsError::TlsFailed)?;
    debug!(
        "kTLS: TLS handshake completed with {host} \
         (shared ClientSessionMemoryCache enables resumption for subsequent connections)"
    );

    // TLS handshake succeeded — all errors from here are KtlsSetupFailed
    // (except ResponseNotSpliceable for non-200/no-CL responses).

    // --- Phase 2 of 5: Send HTTP Request ---
    // Process any pending records (e.g. NewSessionTickets from TLS 1.3),
    // then encrypt and send the HTTP request.
    //
    // From here on, TLS handshake has succeeded, so errors are KtlsSetupFailed
    // (except ResponseNotSpliceable for non-200/no-CL responses).
    outgoing_used = 0;
    // Guard against a connection stuck in non-WriteTraffic states post-handshake.
    // TLS 1.3 typically sends 1-2 NewSessionTicket records; a handful of iterations
    // covers the legitimate case while still catching pathological peers quickly.
    let mut post_handshake_rounds = 0u32;

    loop {
        /// Cap on state-machine rounds between handshake-complete and
        /// first `WriteTraffic`. Bounds record-encode / record-decode iterations
        /// while rustls processes any trailing post-handshake messages
        /// (e.g. TLS 1.3 `NewSessionTicket`s).  Each legitimate ticket consumes
        /// ~2 rounds (decode → discard), so 16 accommodates up to ~8 tickets —
        /// well beyond what any real server sends.
        const MAX_POST_HANDSHAKE_ROUNDS: u32 = 16;

        post_handshake_rounds += 1;
        if post_handshake_rounds > MAX_POST_HANDSHAKE_ROUNDS {
            return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "kTLS: post-handshake state machine did not reach WriteTraffic \
                     after {MAX_POST_HANDSHAKE_ROUNDS} iterations"
                ),
            )));
        }

        let status = conn.process_tls_records(&mut incoming[..incoming_used]);
        let discard = status.discard;
        let state = status.state.map_err(|err| {
            KtlsError::KtlsSetupFailed(std::io::Error::other(format!(
                "TLS post-handshake error:  {err}"
            )))
        })?;

        match state {
            ConnectionState::EncodeTlsData(mut etd) => {
                encode_tls_data(&mut etd, &mut outgoing, &mut outgoing_used);
                discard_incoming(&mut incoming, &mut incoming_used, discard);
            }
            ConnectionState::TransmitTlsData(ttd) => {
                transmit_tls_data(ttd, tcp, &outgoing, &mut outgoing_used)
                    .await
                    .map_err(KtlsError::KtlsSetupFailed)?;
                discard_incoming(&mut incoming, &mut incoming_used, discard);
            }
            ConnectionState::WriteTraffic(mut wt) => {
                // Ready to send — encrypt and transmit the HTTP request
                let request = format_http_request(
                    upstream_path,
                    host_authority,
                    resume_offset,
                    resume_if_range,
                    volatile_cond,
                );
                let plaintext = request.as_bytes();

                let enc_len = loop {
                    match wt.encrypt(plaintext, &mut outgoing) {
                        Ok(n) => break n,
                        Err(EncryptError::InsufficientSize(isz)) => {
                            outgoing.resize(isz.required_size, 0);
                        }
                        Err(err) => {
                            return Err(KtlsError::KtlsSetupFailed(std::io::Error::other(
                                format!("TLS encrypt error:  {err}"),
                            )));
                        }
                    }
                };

                discard_incoming(&mut incoming, &mut incoming_used, discard);
                write_all_to_stream(tcp, &outgoing[..enc_len])
                    .await
                    .map_err(KtlsError::KtlsSetupFailed)?;
                break;
            }
            ConnectionState::BlockedHandshake => {
                // Post-handshake state machine needs more data (e.g., key update).
                // Read from network to avoid spinning through the iteration limit.
                discard_incoming(&mut incoming, &mut incoming_used, discard);
                grow_incoming(&mut incoming, incoming_used, "post-handshake")
                    .map_err(KtlsError::KtlsSetupFailed)?;
                let n = tcp
                    .read(&mut incoming[incoming_used..])
                    .await
                    .map_err(KtlsError::KtlsSetupFailed)?;
                if n == 0 {
                    return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "server closed during post-handshake processing",
                    )));
                }
                incoming_used += n;
            }
            ConnectionState::ReadTraffic(_)
            | ConnectionState::PeerClosed
            | ConnectionState::Closed
            | ConnectionState::ReadEarlyData(_) => {
                discard_incoming(&mut incoming, &mut incoming_used, discard);
            }
            other => {
                warn_once!("splice proxy: unexpected ConnectionState variant: {other:?}");
                discard_incoming(&mut incoming, &mut incoming_used, discard);
            }
        }
    }

    // --- Phase 3 of 5: Read Response Headers ---
    let mut header_buf = BytesMut::with_capacity(MAX_RESPONSE_HEADER_SIZE);
    let mut extra_body = Vec::new();
    let mut header_end = 0usize;
    let mut headers_complete = false;
    // Track where to start scanning for "\r\n\r\n" — avoids re-scanning
    // the entire buffer after each TLS record is appended.
    let mut header_search_offset = 0usize;

    while !headers_complete {
        // Process any TLS records already in the incoming buffer
        let need_more_data = loop {
            if incoming_used == 0 {
                break true;
            }
            let status = conn.process_tls_records(&mut incoming[..incoming_used]);
            let discard = status.discard;
            let state = status.state.map_err(|err| {
                KtlsError::KtlsSetupFailed(std::io::Error::other(format!("TLS read error:  {err}")))
            })?;

            #[expect(clippy::wildcard_enum_match_arm, reason = "clippy false-positive")]
            match state {
                ConnectionState::ReadTraffic(mut rt) => {
                    while let Some(result) = rt.next_record() {
                        let record = result.map_err(|err| {
                            KtlsError::KtlsSetupFailed(std::io::Error::other(format!(
                                "TLS record error:  {err}"
                            )))
                        })?;
                        header_buf.extend_from_slice(record.payload);
                    }
                    discard_incoming(&mut incoming, &mut incoming_used, discard);

                    // Check for complete headers (start from where we last left off)
                    if let Some(end) = header_buf[header_search_offset..]
                        .array_windows()
                        .position(|w| w == b"\r\n\r\n")
                        .map(|i| header_search_offset + i + 4)
                    {
                        header_end = end;
                        if header_buf.len() > end {
                            extra_body.extend_from_slice(&header_buf[end..]);
                            header_buf.truncate(end);
                        }
                        headers_complete = true;
                        break false;
                    }
                    // Next search can skip bytes we've already checked
                    header_search_offset = header_buf.len().saturating_sub(3);
                    if header_buf.len() > MAX_RESPONSE_HEADER_SIZE {
                        warn_once_or_info!(
                            "splice proxy: upstream response header size of {} bytes exceeds {} bytes",
                            header_buf.len(),
                            MAX_RESPONSE_HEADER_SIZE
                        );
                        return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "upstream response headers too large",
                        )));
                    }
                }
                ConnectionState::EncodeTlsData(mut etd) => {
                    // Append at `outgoing[outgoing_used..]` — see the matching
                    // note in `drain_buffered_records`.  The rustls state
                    // machine can emit several `EncodeTlsData` states before a
                    // single `TransmitTlsData`; zeroing here would drop pending
                    // bytes.
                    encode_tls_data(&mut etd, &mut outgoing, &mut outgoing_used);
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                }
                ConnectionState::TransmitTlsData(ttd) => {
                    transmit_tls_data(ttd, tcp, &outgoing, &mut outgoing_used)
                        .await
                        .map_err(KtlsError::KtlsSetupFailed)?;
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                }
                ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => {
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                    break true; // Need more data from network
                }
                state @ (ConnectionState::PeerClosed
                | ConnectionState::Closed
                | ConnectionState::ReadEarlyData(_)) => {
                    debug!("kTLS: connection in terminal state during header read: {state:?}");
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                    break true;
                }
                other => {
                    warn_once_or_debug!("kTLS: unexpected ConnectionState variant: {other:?}");
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                    break true;
                }
            }
        };

        if headers_complete {
            break;
        }
        if need_more_data {
            grow_incoming(&mut incoming, incoming_used, "header read")
                .map_err(KtlsError::KtlsSetupFailed)?;
            let n = tcp
                .read(&mut incoming[incoming_used..])
                .await
                .map_err(KtlsError::KtlsSetupFailed)?;
            if n == 0 {
                return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "server closed before sending complete response headers",
                )));
            }
            incoming_used += n;
        }
    }

    // --- Parse response to check status before setting up kTLS ---
    let response = parse_upstream_response(&header_buf, header_end).map_err(|err| {
        KtlsError::KtlsSetupFailed(std::io::Error::new(err.kind(), format!("kTLS:  {err}")))
    })?;

    if response.status_code != 200 || response.content_length.is_none_or(|ct| ct == 0) {
        // Non-spliceable response: the caller will reconnect via the standard
        // path for a complete fetch, so no need to drain the remaining TLS
        // records from this one-shot kTLS connection.
        return Err(KtlsError::ResponseNotSpliceable { response });
    }

    // --- Phase 4 of 5: Drain Remaining Buffer ---
    // Process any remaining complete TLS records in the incoming buffer.
    // Their plaintext goes into extra_body.
    drain_buffered_records(
        &mut conn,
        &mut incoming,
        &mut incoming_used,
        &mut outgoing,
        &mut outgoing_used,
        tcp,
        &mut extra_body,
    )
    .await?;

    // If there are still unprocessed bytes (partial TLS record), loop reading
    // from TCP until all records are drained or a per-read timeout fires.
    // The overall http_timeout (applied at the call site) caps total wait time.
    if incoming_used > 0 {
        let per_read_timeout = std::time::Duration::from_secs(5);

        // Log how many bytes the current partial TLS record needs.
        // TLS record header is 5 bytes: [content_type, version_hi, version_lo, length_hi, length_lo].
        // We skip the first 3 bytes and read the 2-byte big-endian length.
        if let Some(&[_, _, _, hi, lo, ..]) = incoming.get(..incoming_used) {
            let record_len = u16::from_be_bytes([hi, lo]) as usize;
            debug!(
                "kTLS drain: {incoming_used} bytes buffered, \
                 current record needs {} total",
                5 + record_len
            );
        }

        let mut drain_stop_reason = "";
        'drain: while incoming_used > 0 {
            grow_incoming(&mut incoming, incoming_used, "drain")
                .map_err(KtlsError::KtlsSetupFailed)?;

            match tokio::time::timeout(per_read_timeout, tcp.read(&mut incoming[incoming_used..]))
                .await
            {
                Ok(Ok(n @ 1..)) => {
                    incoming_used += n;
                }
                Ok(Ok(0)) => {
                    drain_stop_reason = "upstream EOF";
                    debug!("kTLS drain: {drain_stop_reason} with {incoming_used} bytes buffered");
                    break;
                }
                Ok(Err(ref err)) => {
                    drain_stop_reason = "read error";
                    debug!(
                        "kTLS drain: {drain_stop_reason} with {incoming_used} bytes buffered:  {}",
                        ErrorReport(err)
                    );
                    break;
                }
                Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                    drain_stop_reason = "per-read timeout";
                    debug!("kTLS drain: {drain_stop_reason} with {incoming_used} bytes buffered");
                    break;
                }
            }

            drain_buffered_records(
                &mut conn,
                &mut incoming,
                &mut incoming_used,
                &mut outgoing,
                &mut outgoing_used,
                tcp,
                &mut extra_body,
            )
            .await?;
            if incoming_used == 0 {
                break 'drain;
            }
        }

        if incoming_used > 0 {
            return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "kTLS: {incoming_used} bytes remain in buffer after drain \
                     ({drain_stop_reason}, partial TLS record could not be completed)"
                ),
            )));
        }
    }

    // --- Phase 5 of 5: kTLS Setup ---
    // The incoming buffer must be fully drained before extracting secrets.
    // Any unprocessed bytes would mean the RX sequence number from rustls is
    // behind the actual TLS record count on the wire, causing kTLS decryption
    // failures (wrong nonce/sequence).
    // Hard check (not debug_assert): a non-zero incoming_used would mean the rustls
    // RX sequence number is behind the actual TLS record count on the wire.
    // Proceeding would configure kTLS with a stale rx_seq, silently producing
    // garbage on decryption. Fail closed instead.
    //
    // The debug_assert catches regressions loudly in tests; the runtime branch
    // below is the real guard in release builds.
    debug_assert_eq!(
        incoming_used, 0,
        "incoming buffer must be fully drained before kTLS secret extraction"
    );
    if incoming_used != 0 {
        return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
            ErrorKind::InvalidData,
            format!(
                "kTLS: incoming buffer has {incoming_used} unprocessed bytes \
                 before secret extraction (rx_seq would be stale)"
            ),
        )));
    }

    let (version, secret_name, cipher_suite, rx_seq) = {
        let (secrets, kernel_conn) = conn.dangerous_into_kernel_connection().map_err(|err| {
            KtlsError::KtlsSetupFailed(std::io::Error::other(format!(
                "kTLS secret extraction:  {err}"
            )))
        })?;

        let version = kernel_conn.protocol_version();
        let cipher_suite = kernel_conn.negotiated_cipher_suite();

        let rustls::ExtractedSecrets { rx, tx } = secrets;
        drop(tx);
        let (rx_seq, ref rx_secrets) = rx;

        let secret_name = ktls::secret_name(rx_secrets);

        // 6b: kTLS setup order is critical: ULP must be loaded before configuring
        // crypto, and RX must be set up before draining control messages (which
        // uses recvmsg on the kTLS socket). We only configure RX: the request has
        // already been written to the wire before secret extraction, the kTLS
        // socket is not reused for another request (see the comment at the
        // KtlsResult::Ready arm), and configuring TX would add a failure surface
        // (some kernels may reject TX for ciphers they accept for RX) for no gain.
        ktls::load_ulp(&tcp).map_err(KtlsError::KtlsSetupFailed)?;
        ktls::setup_rx(&tcp, rx_seq, rx_secrets, version).map_err(KtlsError::KtlsSetupFailed)?;
        drop(rx);

        (version, secret_name, cipher_suite, rx_seq)
    };

    // drain_control_messages can fail for transient reasons (e.g. EAGAIN
    // between peek and consume). Treat those as transient so a one-off race
    // does not suppress kTLS for the full KTLS_BLOCK_DURATION. We have not
    // polled the socket here, so the "no data ready" case is the expected
    // outcome and is not an error — pass `MaybeIdle`.
    ktls::drain_control_messages(tcp.as_fd(), ktls::DrainExpect::MaybeIdle)
        .map_err(KtlsError::KtlsSetupFailedTransient)?;

    // TLS session resumption is supported via the shared ClientConfig in
    // get_tls_client_config(), which uses rustls's default ClientSessionMemoryCache
    // (256 entries). NewSessionTickets received during phases 2-4 are stored there
    // and reused on subsequent connections to the same server, enabling TLS 1.3
    // PSK resumption (1-RTT) or TLS 1.2 session ticket resumption.
    // The unbuffered API does not expose handshake_kind(), so we cannot directly
    // log whether this specific handshake was a resumption.
    debug!(
        "kTLS: RX offload configured: host={host}, version={version:?}, secret_name={secret_name}, \
        cipher={cipher_suite:?}, rx_seq={rx_seq}, extra_body={} bytes",
        extra_body.len()
    );

    metrics::KTLS_RX_ENABLED.increment();

    Ok(KtlsReadyState {
        response,
        header_buf,
        header_end,
        extra_body,
    })
}

/// Update the scheme cache for a mirror after successful connection.
fn cache_scheme(mirror: &Mirror, scheme: Scheme) {
    let key = SchemeKeyRef {
        host: mirror.host().as_str(),
        port: mirror.port().map(std::num::NonZero::get),
    };
    let scheme_cache = SCHEME_CACHE.get().expect("Initialized in main()");
    if scheme_cache.read().contains_key(&key) {
        return;
    }

    if let EntryRef::Vacant(ventry) = scheme_cache.write().entry_ref(&key) {
        ventry.insert_entry_with_key(
            SchemeKey {
                host: key.host.to_owned(),
                port: key.port,
            },
            scheme,
        );
        debug!(
            "splice proxy: cached {scheme} scheme for {}",
            mirror.format_authority()
        );
    }
}

/// Format an HTTP GET request for the upstream mirror.
fn format_http_request(
    path: &str,
    host_authority: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> String {
    let range_header = if resume_offset > 0 {
        let if_range = match resume_if_range {
            Some(ir) => format!("If-Range: {ir}\r\n"),
            None => String::new(),
        };
        format!("Range: bytes={resume_offset}-\r\n{if_range}")
    } else {
        String::new()
    };

    let volatile_headers = match volatile_cond {
        Some(vc) => {
            let mut h = format!(
                "If-Modified-Since: {}\r\nCache-Control: max-age=300\r\n",
                vc.if_modified_since
            );
            if let Some(ref inm) = vc.if_none_match {
                write!(h, "If-None-Match: {inm}\r\n").expect("string append should succeed");
            }
            h
        }
        None => String::new(),
    };

    format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host_authority}\r\n\
         User-Agent: {APP_USER_AGENT}\r\n\
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

    match tokio::time::timeout(
        global_config().http_timeout,
        write_and_flush(upstream, request.as_bytes()),
    )
    .await
    {
        Ok(result) => result,
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => Err(std::io::Error::new(
            ErrorKind::TimedOut,
            "write operation timed out",
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
    async fn inner(upstream: &mut UpstreamConn, buf: &mut BytesMut) -> std::io::Result<usize> {
        loop {
            let n = upstream.read_buf(buf).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "upstream closed before sending complete headers",
                ));
            }

            // Check if we have the complete headers
            if let Some(end) = buf
                .array_windows()
                .position(|w| w == b"\r\n\r\n")
                .map(|i| i + 4)
            {
                return Ok(end);
            }
            if buf.len() > MAX_RESPONSE_HEADER_SIZE {
                warn_once_or_info!(
                    "splice proxy: upstream response header size of {} bytes exceeds {} bytes",
                    buf.len(),
                    MAX_RESPONSE_HEADER_SIZE
                );
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "upstream response headers too large",
                ));
            }
        }
    }

    match tokio::time::timeout(global_config().http_timeout, inner(upstream, buf)).await {
        Ok(result) => result,
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
            metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
            Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "timed out reading upstream response headers",
            ))
        }
    }
}

/// Parsed upstream response header info.
struct UpstreamResponse {
    status_code: http::StatusCode,
    content_length: Option<u64>,
    content_type: Option<String>,
    last_modified: Option<String>,
    etag: Option<String>,
    content_range: Option<String>,
    location: Option<String>,
    connection_close: bool,
    is_chunked: bool,
}

/// Parse upstream HTTP response headers.
fn parse_upstream_response(buf: &[u8], header_end: usize) -> std::io::Result<UpstreamResponse> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
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
    let status_code = http::StatusCode::from_u16(raw_code).map_err(|_err| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            "invalid HTTP status code from upstream",
        )
    })?;

    metrics::record_upstream_status(status_code);

    let headers = resp.headers;

    let content_length =
        find_header(headers, &CONTENT_LENGTH).and_then(|v| v.trim().parse::<u64>().ok());

    let content_type = find_header(headers, &CONTENT_TYPE).map(String::from);

    let last_modified = find_header(headers, &LAST_MODIFIED).map(String::from);

    let etag = find_header(headers, &ETAG)
        .filter(|etag| {
            if is_valid_etag(etag) {
                true
            } else {
                warn_once_or_info!("Upstream mirror sent invalid ETag: {etag}");
                false
            }
        })
        .map(String::from);

    let content_range = find_header(headers, &CONTENT_RANGE).map(String::from);

    let location = find_header(headers, &LOCATION).map(String::from);

    let connection_close = find_header(headers, &CONNECTION)
        .is_some_and(|s| s.split(',').any(|v| v.trim().eq_ignore_ascii_case("close")));

    let is_chunked = find_header(headers, &TRANSFER_ENCODING).is_some_and(|s| {
        s.split(',')
            .any(|v| v.trim().eq_ignore_ascii_case("chunked"))
    });

    Ok(UpstreamResponse {
        status_code,
        content_length,
        content_type,
        last_modified,
        etag,
        content_range,
        location,
        connection_close,
        is_chunked,
    })
}

/// Splice data from upstream TCP socket to client socket, with zero-copy tee to a cache file.
///
/// Data flow (all in kernel space, zero userspace copies):
///   upstream → splice → `pipe_A` → tee → `pipe_B` → splice → `cache_file`
///                                  ↓
///                            splice → client
/// Return type for `splice_proxy_body` / `splice_proxy_body_tls` when a client
/// was demoted to file-serve.  The caller must `.await` the join handle
/// after the download barrier has been consumed (so the spawned task can
/// observe `ActiveDownloadStatus::Finished`).
type DemotedClientHandle = tokio::task::JoinHandle<()>;

#[expect(clippy::too_many_arguments, reason = "called from a single site")]
async fn splice_proxy_body(
    upstream: &TcpStream,
    client: &TcpStream,
    cache_file: &tokio::fs::File,
    content_length: u64,
    file_start_offset: i64,
    mut dbarrier: DownloadBarrier,
    range_filter: &SpliceRangeFilter,
    cache_path: &Path,
    total_content_length: u64,
) -> std::io::Result<(DownloadBarrier, Option<DemotedClientHandle>)> {
    let _counter = client_counter::ClientDownload::new();

    // Paired with BYTES_SERVED_SPLICE in tee_and_splice / boundary fallback.
    metrics::REQUESTS_SPLICE.increment();

    let (upstream_pipe_sender, upstream_pipe_receiver) = create_pipe()?;
    let (cache_pipe_sender, cache_pipe_receiver) = create_pipe()?;

    let config = global_config();

    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut remaining = content_length;
    let mut file_offset: i64 = file_start_offset;
    let mut client_status = ClientStatus::Active;
    let mut bytes_done: u64 = 0;
    let mut client_bytes_sent: u64 = 0;
    let mut demoted_handle: Option<DemotedClientHandle> = None;
    let client_skip = range_filter.skip;
    let client_range_end = range_filter.skip + range_filter.send;

    while remaining > 0 {
        dbarrier = dbarrier.check_upstream_rate(rate_checker.as_ref()).await?;

        static_assert!(PIPE_BUFFER_SIZE > 0 && (PIPE_BUFFER_SIZE as u64) < usize::MAX as u64);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "PIPE_BUFFER_SIZE is checked to be < usize::MAX above"
        )]
        let chunk_size = std::cmp::min(remaining, PIPE_BUFFER_SIZE as u64) as usize;

        // Step 1: splice upstream → pipe_A
        // Both fds are non-blocking; splice() never waits on I/O and reads
        // kernel buffer state directly rather than Tokio's userspace ready-flag.
        // Try the syscall optimistically and only park on EAGAIN — that way the
        // rated wait (with its rc.add(0) ticks and http_timeout budget) only
        // runs when we're actually about to park, instead of being cancelled
        // mid-flight by `select!` on every busy iteration.
        let got = loop {
            let res = splice(
                upstream,
                None,
                &upstream_pipe_sender,
                None,
                chunk_size,
                SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_MORE,
            );

            let _: Never = match res {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        format!(
                            "splice proxy: upstream closed prematurely (remaining={remaining}, chunk_size={chunk_size})"
                        ),
                    ));
                }
                Ok(n) => break n,
                Err(nix::errno::Errno::EINTR) => continue,
                // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                Err(nix::errno::Errno::EAGAIN) => {
                    // We can't tell from EAGAIN which side is the blocker, so
                    // clear both caches and wake on whichever next produces a
                    // fresh epoll event.
                    clear_tcp_readable_cache(upstream);
                    clear_pipe_writable_cache(&upstream_pipe_sender);
                    tokio::select! {
                        r = wait_readable_rated(
                            upstream,
                            &mut rate_checker,
                            RateCheckDirection::Upstream,
                            config.http_timeout,
                        ) => r?,
                        w = upstream_pipe_sender.writable() => w?,
                    }
                    continue;
                }
                Err(err) => return Err(errno_to_io_error(err, "splice failed")),
            };
        };

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(got as u64);

        // Determine how this chunk overlaps with the client range.
        let chunk_start = bytes_done;
        let chunk_end = bytes_done + got as u64;

        if !matches!(client_status, ClientStatus::Active)
            || chunk_end <= client_skip
            || chunk_start >= client_range_end
        {
            // Chunk is entirely outside client range, or client is gone/demoted — cache only
            splice_pipe_to_file(&upstream_pipe_receiver, cache_file, got, &mut file_offset).await?;
            dbarrier.ping_batched(got as u64);
        } else if chunk_start >= client_skip && chunk_end <= client_range_end {
            // Chunk is entirely inside client range — normal tee
            client_status = tee_and_splice(
                &upstream_pipe_receiver,
                &cache_pipe_receiver,
                &cache_pipe_sender,
                client,
                (cache_file, &mut file_offset),
                got,
                client_status,
                &mut dbarrier,
                &mut client_rate_checker,
                &mut client_bytes_sent,
            )
            .await?;

            if let ClientStatus::Demoted { client_bytes_sent } = client_status {
                demoted_handle = Some(spawn_file_serve_task(
                    client,
                    cache_path,
                    client_bytes_sent,
                    total_content_length,
                    &dbarrier,
                )?);
            }
        } else {
            // Boundary chunk — read into userspace, slice for client, pwrite for cache
            let mut buf = read_pipe_to_buf(&upstream_pipe_receiver, got).await?;

            debug_assert!(
                matches!(client_status, ClientStatus::Active),
                "outer condition excludes non-active"
            );
            debug_assert!(
                client_range_end > chunk_start,
                "boundary chunk must overlap client range"
            );

            // Write full chunk to cache via pwrite first, so concurrent clients
            // see progress without being gated on the first client's send speed.
            let buf_len = buf.len();
            pwrite_buf_to_file(cache_file, &mut buf, buf_len, file_offset).await?;

            #[expect(
                clippy::cast_possible_wrap,
                reason = "got is bounded by PIPE_BUFFER_SIZE which fits in i64"
            )]
            {
                file_offset += got as i64;
            }

            // Notify concurrent clients of progress
            dbarrier.ping_batched(got as u64);

            // Then send to client (may be slow)
            let client_slice = range_slice(&buf, chunk_start, range_filter.skip, range_filter.send);
            if !client_slice.is_empty() {
                match write_all_to_stream_rated(
                    client,
                    client_slice,
                    &mut client_rate_checker,
                    RateCheckDirection::Client,
                    config.http_timeout,
                )
                .await
                {
                    Ok(()) => {
                        metrics::BYTES_SERVED_SPLICE.increment_by(client_slice.len() as u64);
                    }
                    Err(err)
                        if err.kind() == ErrorKind::BrokenPipe
                            || err.kind() == ErrorKind::ConnectionReset =>
                    {
                        metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                        info!("splice proxy: client disconnected during boundary chunk");
                        client_status = ClientStatus::Disconnected;
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        bytes_done = chunk_end;

        if let Some(ref mut rate_checker) = rate_checker {
            rate_checker.add(got);
        }

        remaining = remaining
            .checked_sub(got as u64)
            .expect("splice should not return more than requested");
    }

    Ok((dbarrier, demoted_handle))
}

/// Writes the entire buffer to the cache file via pwrite at the specified offset.
async fn pwrite_buf_to_file(
    file: &tokio::fs::File,
    buf: &mut Vec<u8>,
    size: usize,
    mut offset: i64,
) -> std::io::Result<()> {
    let buf_len = buf.len();
    let mut written = 0;

    let mut temp = Vec::new();
    std::mem::swap(buf, &mut temp);

    let file_fd = file.as_raw_fd();

    while written < size {
        let (pwrite_result, temp_return) = tokio::task::spawn_blocking(move || {
            let avail = &temp[written..size];

            // SAFETY: cache_fd is valid because the caller holds a reference to the
            // tokio::fs::File, and the spawn_blocking result is awaited without cancellation
            let fd = unsafe { BorrowedFd::borrow_raw(file_fd) };
            let r = nix::sys::uio::pwrite(fd, avail, offset);
            (r, temp)
        })
        .await
        .expect("spawn_blocking should not panic");
        temp = temp_return;

        match pwrite_result {
            Ok(0) => {
                std::mem::swap(&mut temp, buf);
                assert!(temp.is_empty(), "temp buffer should be empty after re-swap");
                assert_eq!(
                    buf.len(),
                    buf_len,
                    "buffer should have the same length as before"
                );
                assert!(
                    written < size,
                    "should have written less than the requested number of bytes"
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "pwrite returned 0",
                ));
            }
            Ok(n) => {
                written += n;
                offset +=
                    i64::try_from(n).expect("pwrite(2) does not write more than i64::MAX bytes");
            }
            // EAGAIN/EWOULDBLOCK: see module-level static_assert.
            Err(nix::errno::Errno::EAGAIN) => {
                // file is not ready, wait for it to be writable
                tokio::task::yield_now().await;
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(errno) => {
                std::mem::swap(&mut temp, buf);
                assert!(temp.is_empty(), "temp buffer should be empty after re-swap");
                assert_eq!(
                    buf.len(),
                    buf_len,
                    "buffer should have the same length as before"
                );
                assert!(
                    written < size,
                    "should have written less than the requested number of bytes"
                );
                return Err(errno_to_io_error(errno, "pwrite(2) failed"));
            }
        }
    }

    std::mem::swap(&mut temp, buf);
    assert!(temp.is_empty(), "temp buffer should be empty after re-swap");
    assert_eq!(
        buf.len(),
        buf_len,
        "buffer should have the same length as before"
    );
    assert_eq!(
        written, size,
        "should have written the requested number of bytes"
    );

    Ok(())
}

/// Carries the inner read-loop result out of the async closure in
/// `splice_proxy_body_tls` so the outer scope (which holds `dbarrier`) can
/// abort with a structured `MirrorDownloadRate` when an upstream rate
/// timeout fires mid-read.
enum TlsReadOutcome {
    Io(std::io::Error),
    RateTimeout(InsufficientRate),
}

/// Transfer body from TLS upstream to client+cache via userspace read then tee+splice fan-out.
///
/// Data flow:
///   `tls_stream` →[async read]→ buffer →[write]→ `pipe_A` →[tee]→ `pipe_B` →[splice]→ `cache_file`
///                                                         ↓
///                                                   [splice]→ `client_socket`
#[expect(clippy::too_many_arguments, reason = "called from a single site")]
async fn splice_proxy_body_tls(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    cache_file: &tokio::fs::File,
    content_length: u64,
    file_start_offset: i64,
    mut dbarrier: DownloadBarrier,
    range_filter: &SpliceRangeFilter,
    cache_path: &Path,
    total_content_length: u64,
) -> std::io::Result<(DownloadBarrier, Option<DemotedClientHandle>)> {
    let _counter = client_counter::ClientDownload::new();

    // Paired with BYTES_SERVED_SPLICE in tee_and_splice / boundary fallback.
    metrics::REQUESTS_SPLICE.increment();

    let (mut upstream_pipe_sender, upstream_pipe_receiver) = create_pipe()?;
    let (cache_pipe_sender, cache_pipe_receiver) = create_pipe()?;

    let config = global_config();

    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut remaining = content_length;
    let mut file_offset: i64 = file_start_offset;
    let mut read_buf = vec![0u8; TLS_READ_BUF_SIZE]; // TODO: avoid zero initialization
    let mut client_status = ClientStatus::Active;
    let mut bytes_done: u64 = 0;
    let mut client_bytes_sent: u64 = 0;
    let mut demoted_handle: Option<DemotedClientHandle> = None;
    let client_skip = range_filter.skip;
    let client_range_end = range_filter.skip + range_filter.send;

    while remaining > 0 {
        dbarrier = dbarrier.check_upstream_rate(rate_checker.as_ref()).await?;

        // Step 1: async read from TLS stream into userspace buffer
        // The outer http_timeout ensures a fully stalled connection is killed even if
        // rate_check_timeframe > http_timeout.
        static_assert!(TLS_READ_BUF_SIZE < usize::MAX);
        debug_assert_eq!(
            read_buf.len(),
            TLS_READ_BUF_SIZE,
            "buffer size should remain constant"
        );
        #[expect(
            clippy::cast_possible_truncation,
            reason = "TLS_READ_BUF_SIZE is checked to be < usize::MAX above"
        )]
        let to_read = std::cmp::min(remaining, read_buf.len() as u64) as usize;
        let read_outcome = tokio::time::timeout(config.http_timeout, async {
            if let Some(ref mut rc) = rate_checker {
                loop {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(1),
                        upstream.read(&mut read_buf[..to_read]),
                    )
                    .await
                    {
                        Ok(Ok(n)) => return Ok(n),
                        Ok(Err(err)) => return Err(TlsReadOutcome::Io(err)),
                        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                            rc.add(0);
                            if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                                return Err(TlsReadOutcome::RateTimeout(rate));
                            }
                        }
                    }
                }
            } else {
                upstream
                    .read(&mut read_buf[..to_read])
                    .await
                    .map_err(TlsReadOutcome::Io)
            }
        })
        .await;
        let got = match read_outcome {
            Ok(Ok(n)) => n,
            Ok(Err(TlsReadOutcome::Io(err))) => return Err(err),
            Ok(Err(TlsReadOutcome::RateTimeout(rate))) => {
                return Err(dbarrier.abort_with_rate_timeout(rate).await);
            }
            Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "upstream TLS read timed out",
                ));
            }
        };
        if got == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "splice proxy: TLS upstream closed prematurely",
            ));
        }

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(got as u64);

        // Determine how this chunk overlaps with the client range.
        let chunk_start = bytes_done;
        let chunk_end = bytes_done + got as u64;

        if !matches!(client_status, ClientStatus::Active)
            || chunk_end <= client_skip
            || chunk_start >= client_range_end
        {
            // Chunk is entirely outside client range, or client is gone/demoted — cache only
            upstream_pipe_sender.write_all(&read_buf[..got]).await?;
            splice_pipe_to_file(&upstream_pipe_receiver, cache_file, got, &mut file_offset).await?;
            dbarrier.ping_batched(got as u64);
        } else if chunk_start >= client_skip && chunk_end <= client_range_end {
            // Chunk is entirely inside client range — normal tee+splice path
            upstream_pipe_sender.write_all(&read_buf[..got]).await?;
            client_status = tee_and_splice(
                &upstream_pipe_receiver,
                &cache_pipe_receiver,
                &cache_pipe_sender,
                client,
                (cache_file, &mut file_offset),
                got,
                client_status,
                &mut dbarrier,
                &mut client_rate_checker,
                &mut client_bytes_sent,
            )
            .await?;

            if let ClientStatus::Demoted { client_bytes_sent } = client_status {
                demoted_handle = Some(spawn_file_serve_task(
                    client,
                    cache_path,
                    client_bytes_sent,
                    total_content_length,
                    &dbarrier,
                )?);
            }
        } else {
            // Boundary chunk — data is already in read_buf, handle in userspace.
            // Write cache first, then send to client.
            debug_assert!(
                matches!(client_status, ClientStatus::Active),
                "outer condition excludes non-active"
            );
            debug_assert!(
                client_range_end > chunk_start,
                "boundary chunk must overlap client range"
            );

            // Write full chunk to cache via pwrite first, so concurrent clients
            // see progress without being gated on the first client's send speed.
            pwrite_buf_to_file(cache_file, &mut read_buf, got, file_offset).await?;

            #[expect(
                clippy::cast_possible_wrap,
                reason = "got is bounded by TLS_READ_BUF_SIZE which fits in i64"
            )]
            {
                file_offset += got as i64;
            }

            // Notify concurrent clients of progress
            dbarrier.ping_batched(got as u64);

            // Then send to client (may be slow)
            let client_slice = range_slice(
                &read_buf[..got],
                chunk_start,
                range_filter.skip,
                range_filter.send,
            );
            if matches!(client_status, ClientStatus::Active) && !client_slice.is_empty() {
                match write_all_to_stream_rated(
                    client,
                    client_slice,
                    &mut client_rate_checker,
                    RateCheckDirection::Client,
                    config.http_timeout,
                )
                .await
                {
                    Ok(()) => {
                        metrics::BYTES_SERVED_SPLICE.increment_by(client_slice.len() as u64);
                    }
                    Err(err)
                        if err.kind() == ErrorKind::BrokenPipe
                            || err.kind() == ErrorKind::ConnectionReset =>
                    {
                        metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                        info!("splice proxy: client disconnected during TLS boundary chunk");
                        client_status = ClientStatus::Disconnected;
                    }
                    Err(err) => return Err(err),
                }
            }
        }

        bytes_done = chunk_end;

        if let Some(ref mut rate_checker) = rate_checker {
            rate_checker.add(got);
        }

        remaining = remaining
            .checked_sub(got as u64)
            .expect("read(2) should not return more than requested");
    }

    Ok((dbarrier, demoted_handle))
}

/// Duplicate the client socket fd and spawn a task that serves remaining bytes
/// from the cache file.  Returns the `JoinHandle` so the caller can await it
/// after the download barrier has been consumed.
fn spawn_file_serve_task(
    client: &TcpStream,
    cache_path: &Path,
    client_bytes_sent: u64,
    total_content_length: u64,
    dbarrier: &DownloadBarrier,
) -> std::io::Result<DemotedClientHandle> {
    // Duplicate the client socket so the spawned task owns its own fd.
    // The original fd stays open in the connection handler but won't be
    // written to after demotion.
    let client_fd =
        nix::unistd::dup(client).map_err(|errno| errno_to_io_error(errno, "dup(2) failed"))?;
    let std_stream = std::net::TcpStream::from(client_fd);
    std_stream.set_nonblocking(true)?;
    let client_stream = TcpStream::from_std(std_stream)?;

    let receiver = dbarrier.subscribe();
    let status = Arc::clone(dbarrier.status());
    let cache_path = cache_path.to_path_buf();

    warn_once_or_info!(
        "splice proxy: demoting slow client to file-serve at offset {}",
        client_bytes_sent
    );

    Ok(tokio::task::spawn(serve_remaining_from_file(
        client_stream,
        cache_path,
        client_bytes_sent,
        total_content_length,
        receiver,
        status,
    )))
}

/// Serve remaining bytes of a download from the cache file to a demoted client.
///
/// This follows the same pattern as `serve_unfinished_file()` in `main.rs`:
/// read from the cache file, wait for `dbarrier` notifications when at EOF,
/// and stop when the download finishes or aborts.
async fn serve_remaining_from_file(
    client: TcpStream,
    cache_path: PathBuf,
    offset: u64,
    content_length: u64,
    mut receiver: tokio::sync::watch::Receiver<()>,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
) {
    use tokio::io::AsyncSeekExt as _;

    let config = global_config();

    let mut file = match tokio::fs::File::open(&cache_path).await {
        Ok(f) => f,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to open cache file `{}` for demoted client:  {err}",
                cache_path.display()
            );
            return;
        }
    };

    if let Err(err) = file.seek(std::io::SeekFrom::Start(offset)).await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to seek cache file `{}`:  {err}",
            cache_path.display()
        );
        return;
    }

    // Demoted clients keep reading the partial cache file linearly through a
    // BufReader, so warm the kernel readahead window before the loop starts.
    hint_sequential_read(&file, &cache_path);

    let _counter = client_counter::ClientDownload::new();
    // The request was already counted as REQUESTS_SPLICE at proxy entry;
    // only the bytes split to BYTES_SERVED_COPY here.
    metrics::CLIENTS_DEMOTED.increment();

    let mut bytes_sent = offset;
    let mut finished = false;
    let buf_size = config.buffer_size;
    let mut reader = tokio::io::BufReader::with_capacity(buf_size, &mut file);
    let mut read_buf = BytesMut::with_capacity(buf_size);
    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    // TODO: use sendfile?

    loop {
        // Read all currently available data from cache file
        loop {
            read_buf.clear();
            match reader.read_buf(&mut read_buf).await {
                Ok(0) => break, // EOF — may need to wait for more data
                Ok(n) => {
                    bytes_sent += n as u64;
                    if let Err(err) = write_all_to_stream_rated(
                        &client,
                        &read_buf[..n],
                        &mut client_rate_checker,
                        RateCheckDirection::Client,
                        config.http_timeout,
                    )
                    .await
                    {
                        if err.kind() == ErrorKind::BrokenPipe
                            || err.kind() == ErrorKind::ConnectionReset
                        {
                            metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                            debug!(
                                "splice proxy: demoted client disconnected at offset {bytes_sent}"
                            );
                        } else {
                            info!(
                                "splice proxy: demoted client write error at offset {bytes_sent}:  {err}"
                            );
                        }
                        return;
                    }
                    metrics::BYTES_SERVED_COPY.increment_by(n as u64);
                }
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "splice proxy: failed to read cache file `{}`:  {}",
                        cache_path.display(),
                        ErrorReport(&err)
                    );
                    return;
                }
            }
        }

        if finished || bytes_sent >= content_length {
            break;
        }

        // Wait for notification that more data has been written to cache
        if let Err(tokio::sync::watch::error::RecvError { .. }) = receiver.changed().await {
            // Sender dropped — download finished or aborted
            let st = status.read().await;
            let _: Never = match *st {
                ActiveDownloadStatus::Finished(_) => {
                    drop(st);
                    finished = true;
                    continue; // Read remaining data
                }
                ActiveDownloadStatus::Aborted(_) => {
                    drop(st);
                    debug!("splice proxy: download aborted, stopping demoted client file-serve");
                    return;
                }
                ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download(..) => {
                    drop(st);
                    error!(
                        "splice proxy: unexpected download state for demoted client file-serve of `{}`",
                        cache_path.display()
                    );
                    return;
                }
            };
        }
    }

    debug!("splice proxy: demoted client file-serve complete, sent {bytes_sent} bytes");
}

/// Status of the first (splice) client after a tee+splice iteration.
enum ClientStatus {
    /// Client is still connected and receiving data at acceptable speed.
    Active,
    /// Client disconnected mid-transfer.
    Disconnected,
    /// Client send rate dropped below the minimum threshold.
    /// The caller should spawn a file-serve task to continue serving
    /// the client from the cache file at the given byte offset.
    Demoted { client_bytes_sent: u64 },
}

/// Shared tee+splice fan-out: consume `got` bytes from `pipe_A`, duplicate to `pipe_B`,
/// splice `pipe_A→client` and `pipe_B→cache`.
///
/// If the client disconnects mid-transfer, the function continues to drain `pipe_A` and
/// write to the cache file so concurrent hyper clients can still complete.
///
/// If the client send rate drops below the configured minimum, remaining bytes are
/// drained and `ClientStatus::Demoted` is returned so the caller can transition the
/// client to file-serve.
#[expect(clippy::too_many_arguments, reason = "function has only 2 callers")]
async fn tee_and_splice(
    upstream_pipe_rx: &pipe::Receiver,
    cache_pipe_rx: &pipe::Receiver,
    cache_pipe_tx: &pipe::Sender,
    client: &TcpStream,
    target: (&tokio::fs::File, &mut i64),
    got: usize,
    client_status: ClientStatus,
    dbarrier: &mut DownloadBarrier,
    client_rate_checker: &mut Option<RateChecker>,
    client_bytes_sent: &mut u64,
) -> std::io::Result<ClientStatus> {
    let (cache_file, file_offset) = target;
    let mut status = client_status;
    let mut remaining = got;

    while remaining > 0 {
        if matches!(status, ClientStatus::Active) {
            // Tee pipe_A → pipe_B, then splice pipe_B → cache, then splice pipe_A → client.
            // Cache is written first so concurrent clients see progress immediately
            // without being gated on a potentially slow first client.

            // Step 2: tee pipe_A → pipe_B (duplicates without consuming from pipe_A)
            // Same optimistic-then-park pattern as Step 1: try tee first and
            // only `select!`-park on EAGAIN, after clearing both caches.
            let teed: usize = loop {
                let res = tee(
                    upstream_pipe_rx,
                    cache_pipe_tx,
                    remaining,
                    SpliceFFlags::empty(),
                );

                let _: Never = match res {
                    Ok(0) => {
                        return Err(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "splice proxy: tee returned 0",
                        ));
                    }
                    Ok(n) => break n,
                    Err(nix::errno::Errno::EINTR) => continue,
                    // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                    Err(nix::errno::Errno::EAGAIN) => {
                        clear_pipe_readable_cache(upstream_pipe_rx);
                        clear_pipe_writable_cache(cache_pipe_tx);
                        tokio::select! {
                            r = upstream_pipe_rx.readable() => r?,
                            w = cache_pipe_tx.writable() => w?,
                        }
                        continue;
                    }
                    Err(err) => return Err(errno_to_io_error(err, "tee failed")),
                };
            };

            // Step 3: splice pipe_B → cache file first (fast, local disk I/O)
            splice_pipe_to_file(cache_pipe_rx, cache_file, teed, file_offset).await?;

            // Notify concurrent clients that new data is on disk
            dbarrier.ping_batched(teed as u64);

            // Step 4: splice pipe_A → client (may be slow, but no longer blocks cache)
            // pipe_A always has data on entry (just filled by tee), so try the
            // splice optimistically and only park on EAGAIN. This keeps
            // `wait_writable_rated`'s rc.add(0) ticks and http_timeout intact
            // — they only run when the client is actually back-pressuring,
            // not on every busy iteration where pipe-readable would otherwise
            // win the `select!` race and cancel them mid-flight.
            let mut client_remaining = teed;
            while client_remaining > 0 {
                let result = splice(
                    upstream_pipe_rx,
                    None,
                    client,
                    None,
                    client_remaining,
                    SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_MORE,
                );

                let _: Never = match result {
                    Ok(0) | Err(nix::errno::Errno::EPIPE | nix::errno::Errno::ECONNRESET) => {
                        // Client disconnected — drain the remaining teed bytes from pipe_A
                        // by splicing them to /dev/null (discard)
                        info!("splice proxy: client disconnected, continuing cache-only");
                        status = ClientStatus::Disconnected;
                        drain_pipe(upstream_pipe_rx, client_remaining).await?;
                        break;
                    }
                    Ok(n) => {
                        client_remaining -= n;
                        *client_bytes_sent += n as u64;
                        metrics::BYTES_SERVED_SPLICE.increment_by(n as u64);
                        if let Some(rc) = client_rate_checker {
                            rc.add(n);
                            if rc.check_fail(RateCheckDirection::Client).is_some() {
                                // Client is too slow — drain remaining teed bytes
                                // (cache already has them) and signal demotion
                                info!(
                                    "splice proxy: client send rate too low, demoting to file-serve"
                                );
                                // `client_remaining` has already been decremented by `n` (the bytes
                                // just sent to the client), so it is exactly the count of teed
                                // bytes still sitting in pipe_A that need to be drained before
                                // we can stop servicing the client.
                                drain_pipe(upstream_pipe_rx, client_remaining).await?;

                                status = ClientStatus::Demoted {
                                    client_bytes_sent: *client_bytes_sent,
                                };
                                break;
                            }
                        }

                        continue;
                    }
                    Err(nix::errno::Errno::EINTR) => continue,
                    // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                    Err(nix::errno::Errno::EAGAIN) => {
                        clear_pipe_readable_cache(upstream_pipe_rx);
                        clear_tcp_writable_cache(client);
                        tokio::select! {
                            w = wait_writable_rated(
                                client,
                                client_rate_checker,
                                RateCheckDirection::Client,
                                global_config().http_timeout,
                            ) => w?,
                            r = upstream_pipe_rx.readable() => r?,
                        }
                        continue;
                    }
                    Err(err) => return Err(errno_to_io_error(err, "splice failed")),
                };
            }

            remaining = remaining
                .checked_sub(teed)
                .expect("splice should not return more than requested");
        } else {
            // Client is gone or demoted — splice pipe_A directly to cache (no tee needed)
            splice_pipe_to_file(upstream_pipe_rx, cache_file, remaining, file_offset).await?;
            dbarrier.ping_batched(remaining as u64);
            remaining = 0;
        }
    }

    Ok(status)
}

/// Read exactly `count` bytes from a pipe into a Vec (for boundary chunks
/// that straddle a client range boundary and need userspace slicing).
async fn read_pipe_to_buf(rx: &pipe::Receiver, count: usize) -> std::io::Result<Vec<u8>> {
    let mut read_buf = vec![0u8; count]; // TODO: avoid zero initialization
    let mut read_bytes = 0;

    while read_bytes < count {
        rx.readable().await?;

        let buf = &mut read_buf[read_bytes..];

        match rx.try_read(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "read_pipe_to_buf: pipe closed with bytes remaining",
                ));
            }
            Ok(n) => read_bytes += n,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }

    debug_assert_eq!(
        read_bytes, count,
        "should have read the requested amount of bytes"
    );
    debug_assert_eq!(
        read_buf.len(),
        count,
        "the result buffer should have the requested length"
    );

    Ok(read_buf)
}

/// Return the sub-slice of `buf` (which represents file bytes at
/// `[buf_file_start, buf_file_start + buf.len())`) that overlaps the client
/// range `[range_start, range_start + range_len)`.
#[must_use]
fn range_slice(buf: &[u8], buf_file_start: u64, range_start: u64, range_len: u64) -> &[u8] {
    let buf_end = buf_file_start + buf.len() as u64;
    let range_end = range_start + range_len;
    let overlap_start = buf_file_start.max(range_start);
    let overlap_end = buf_end.min(range_end);
    if overlap_start >= overlap_end {
        return &[];
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "overlap offsets are bounded by buf.len() which fits in usize"
    )]
    let local_start = (overlap_start - buf_file_start) as usize;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "overlap offsets are bounded by buf.len() which fits in usize"
    )]
    let local_end = (overlap_end - buf_file_start) as usize;
    &buf[local_start..local_end]
}

/// Drain `count` bytes from a pipe by reading and discarding them.
async fn drain_pipe(rx: &pipe::Receiver, count: usize) -> std::io::Result<()> {
    let read_buf_size = std::cmp::min(count, 8 * 1024);
    let mut read_buf = vec![0u8; read_buf_size]; // TODO: avoid zero initialization
    let mut remaining = count;
    while remaining > 0 {
        rx.readable().await?;

        let to_read = std::cmp::min(remaining, read_buf_size);
        let buf = &mut read_buf[..to_read];

        // TODO: splice(2) to /dev/null ?
        match rx.try_read(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "drain_pipe: pipe closed with bytes remaining",
                ));
            }
            Ok(n) => {
                remaining = remaining
                    .checked_sub(n)
                    .expect("read should not return more than requested");
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

/// Splice `count` bytes from a pipe into a file at the given offset.
async fn splice_pipe_to_file(
    rx: &pipe::Receiver,
    file: &tokio::fs::File,
    count: usize,
    file_offset: &mut i64,
) -> std::io::Result<()> {
    /// Maximum consecutive `EAGAIN` (yield + retry) cycles before giving up.
    /// Local disk I/O should never stall indefinitely; hitting this cap means
    /// the underlying filesystem is deadlocked or returning spurious EAGAIN,
    /// and we prefer to fail the request over spinning forever.
    const MAX_EAGAIN_RETRIES: u32 = 1000;
    let mut eagain_retries: u32 = 0;

    let mut remaining = count;
    while remaining > 0 {
        rx.readable().await?;

        let pipe_r_fd = rx.as_raw_fd();
        let file_fd = file.as_raw_fd();

        let offset = *file_offset;

        let result = tokio::task::spawn_blocking(move || {
            let mut off = offset;

            // SAFETY: pipe_r_fd is valid because the caller holds the OwnedFd,
            // and the spawn_blocking result is awaited without cancellation
            let src = unsafe { BorrowedFd::borrow_raw(pipe_r_fd) };
            // SAFETY: file_fd is valid because the caller holds a reference to the File,
            // and the spawn_blocking result is awaited without cancellation
            let dst = unsafe { BorrowedFd::borrow_raw(file_fd) };
            splice(
                src,
                None,
                dst,
                Some(&mut off),
                remaining,
                SpliceFFlags::SPLICE_F_MOVE,
            )
            .map(|n| (n, off))
        })
        .await
        .expect("spawn_blocking should not panic");

        let _: Never = match result {
            Ok((0, _)) => {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "splice proxy: failed to write to cache file",
                ));
            }
            Ok((n, new_off)) => {
                *file_offset = new_off;
                remaining = remaining
                    .checked_sub(n)
                    .expect("splice should not return more than requested");
                eagain_retries = 0;
                continue;
            }
            Err(nix::errno::Errno::EINTR) => {
                continue;
            }
            // EAGAIN/EWOULDBLOCK: see module-level static_assert.
            Err(nix::errno::Errno::EAGAIN) => {
                eagain_retries += 1;
                if eagain_retries > MAX_EAGAIN_RETRIES {
                    return Err(std::io::Error::new(
                        ErrorKind::WouldBlock,
                        format!(
                            "splice to cache file stalled: {MAX_EAGAIN_RETRIES} \
                             consecutive EAGAIN retries"
                        ),
                    ));
                }
                // probably file is not writable, yield to avoid busy loop
                tokio::task::yield_now().await;
                continue;
            }
            Err(err) => return Err(errno_to_io_error(err, "splice failed")),
        };
    }

    Ok(())
}

/// Send request and read+parse response headers on an existing connection.
///
/// Times out after the configured HTTP timeout.
async fn send_and_read_headers(
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

    let mut hdr_buf = BytesMut::with_capacity(MAX_RESPONSE_HEADER_SIZE);
    let hdr_end = read_upstream_response_headers(up, &mut hdr_buf).await?;
    let resp = parse_upstream_response(&hdr_buf, hdr_end)?;
    Ok((resp, hdr_buf, hdr_end))
}

/// Standard (non-kTLS) upstream connect→request→read-headers→parse pipeline.
/// Tries a pooled connection first; falls back to a fresh connection on failure.
///
/// Times out after the configured HTTP timeout.
async fn standard_upstream_connect(
    mirror: &Mirror,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> Result<
    (
        UpstreamConn,
        UpstreamResponse,
        BytesMut,
        usize,
        &'static str,
        bool, // poolable
    ),
    SpliceProxyError,
> {
    // Try a pooled connection first.
    // Resolve scheme to determine the port for pool lookup.
    if let Some(scheme) = resolve_mirror_scheme(mirror) {
        let is_tls = matches!(scheme, Scheme::Https);
        let port = mirror_port(mirror, is_tls);
        if let Some(mut pooled) = pool_checkout(mirror.host(), port, is_tls) {
            if pooled.check_alive() {
                match send_and_read_headers(
                    &mut pooled,
                    host_authority,
                    upstream_path,
                    resume_offset,
                    resume_if_range,
                    volatile_cond,
                )
                .await
                {
                    Ok((resp, hdr_buf, hdr_end)) => {
                        let label = if is_tls {
                            " (TLS, reused)"
                        } else {
                            " (reused)"
                        };
                        let poolable = !resp.connection_close;
                        metrics::POOL_REUSED.increment();
                        return Ok((pooled, resp, hdr_buf, hdr_end, label, poolable));
                    }
                    Err(err) => {
                        metrics::POOL_MISS_FAILED.increment();
                        debug!(
                            "splice proxy: pooled connection to {host_authority} failed, \
                             opening fresh:  {}",
                            ErrorReport(&err)
                        );
                    }
                }
            } else {
                metrics::POOL_MISS_DEAD.increment();
                debug!("splice proxy: pooled connection to {host_authority} is dead, discarding");
            }
        } else {
            metrics::POOL_MISS_EMPTY.increment();
        }
    }

    debug!("splice proxy: no pooled connection to {host_authority}, opening fresh...");

    metrics::POOL_NEW.increment();

    let (mut up, scheme) = connect_upstream(mirror).await.map_err(|err| {
        warn!("splice proxy: failed to connect to upstream {host_authority}:  {err}");
        SpliceProxyError::UpstreamError(err)
    })?;
    cache_scheme(mirror, scheme);

    let is_tls = up.is_tls();

    let (resp, hdr_buf, hdr_end) = send_and_read_headers(
        &mut up,
        host_authority,
        upstream_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
    )
    .await
    .map_err(|err| {
        warn!("splice proxy: failed upstream request to {host_authority}:  {err}");
        SpliceProxyError::UpstreamError(err)
    })?;

    let label = if is_tls { " (TLS)" } else { "" };
    let poolable = !resp.connection_close;
    Ok((up, resp, hdr_buf, hdr_end, label, poolable))
}

/// Follow a 301 redirect if the Location target is valid and allowed.
///
/// On success, replaces the upstream connection, response, header buffer, and TLS label
/// with those from the redirected request, and returns `Some(redirected_path)`.
/// If the redirect is not followable (invalid URI, disallowed host), logs and returns `None`
/// so the caller falls through to the non-200 forwarding path.
///
/// Times out after the configured HTTP timeout.
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors splice_proxy's mutable state"
)]
async fn follow_redirect(
    upstream_resp: &mut UpstreamResponse,
    upstream: &mut PoolGuard,
    header_buf: &mut BytesMut,
    header_end: &mut usize,
    tls_label: &mut &'static str,
    conn_details: &ConnectionDetails,
    original_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> Result<Option<String>, SpliceProxyError> {
    let Some(location) = upstream_resp.location.as_deref() else {
        return Ok(None);
    };
    let Ok(moved_uri) = location.parse::<http::Uri>() else {
        debug!("splice proxy: 301 with unparsable Location `{location}`, not following");
        return Ok(None);
    };
    if !moved_uri
        .scheme()
        .is_some_and(|s| *s == http::uri::Scheme::HTTP || *s == http::uri::Scheme::HTTPS)
    {
        debug!("splice proxy: 301 redirect to non-HTTP scheme `{moved_uri}`, not following");
        return Ok(None);
    }
    let Some(moved_host) = moved_uri.host() else {
        return Ok(None);
    };
    if !is_host_allowed(moved_host) {
        debug!(
            "splice proxy: 301 redirect host `{moved_host}` not in allowed_mirrors, not following"
        );
        return Ok(None);
    }
    let Ok(moved_domain) = DomainName::new(moved_host.to_owned()) else {
        warn!(
            "splice proxy: 301 redirect host `{moved_host}` is not a valid domain, not following"
        );
        return Ok(None);
    };

    // Reject self-redirects: if the target (host, port, path) matches the request
    // we just made, following it would just repeat the same request and create
    // unnecessary load (and potentially loop on a misconfigured mirror).
    let moved_path = moved_uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let moved_port_effective = moved_uri.port_u16().unwrap_or_else(|| {
        if moved_uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
            443
        } else {
            80
        }
    });
    let original_port_effective = mirror_port(&conn_details.mirror, upstream.is_tls());
    if moved_host == conn_details.mirror.host()
        && moved_port_effective == original_port_effective
        && moved_path == original_path
    {
        debug!(
            "splice proxy: 301 redirect target `{moved_uri}` matches original request, not following"
        );
        return Ok(None);
    }

    debug!(
        "splice proxy: following 301 redirect from {} to {moved_uri}",
        conn_details.mirror
    );

    // Mark as non-poolable so the old connection is discarded (not returned to
    // pool) when we reassign *upstream below.
    upstream.unset_poolable();

    let moved_port = moved_uri.port_u16().and_then(NonZero::new);
    let redirect_mirror = Mirror::new(moved_domain, moved_port, String::new());
    let redirect_authority = redirect_mirror.format_authority();
    let redirect_path = moved_path;

    let (up, resp, hdr_buf, hdr_end_new, label, poolable) = standard_upstream_connect(
        &redirect_mirror,
        &redirect_authority,
        redirect_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
    )
    .await?;
    let port = mirror_port(&redirect_mirror, up.is_tls());
    *upstream = PoolGuard::new(up, moved_host.to_owned(), port, poolable);
    *upstream_resp = resp;
    *header_buf = hdr_buf;
    *header_end = hdr_end_new;
    *tls_label = label;

    Ok(Some(redirect_path.to_owned()))
}

/// Forward remaining body bytes from upstream to client (no caching).
/// Used for non-200 responses where we just want to relay the body.
async fn forward_upstream_body(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    count: u64,
) -> std::io::Result<()> {
    let config = global_config();
    let mut buf = vec![0u8; TLS_READ_BUF_SIZE]; // TODO: avoid zero initialization
    let mut remaining = count;
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    while remaining > 0 {
        static_assert!(TLS_READ_BUF_SIZE < usize::MAX);
        debug_assert_eq!(
            buf.len(),
            TLS_READ_BUF_SIZE,
            "buffer size should remain constant"
        );
        #[expect(
            clippy::cast_possible_truncation,
            reason = "TLS_READ_BUF_SIZE is checked to be < usize::MAX above"
        )]
        let to_read = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = match tokio::time::timeout(config.http_timeout, upstream.read(&mut buf[..to_read]))
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
                    "upstream read timed out during body forward",
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
            &buf[..n],
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

    Ok(())
}

/// Forward body bytes from upstream to client until EOF, with a size cap.
/// Used for non-200 responses that lack a Content-Length header.
async fn forward_upstream_body_until_eof(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    max_bytes: usize,
) -> std::io::Result<()> {
    let config = global_config();
    let mut buf = BytesMut::with_capacity(TLS_READ_BUF_SIZE);
    let mut total = 0;
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

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
                    "upstream read timed out during body forward",
                ));
            }
        };

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);

        total += n as u64;
        if total > max_bytes as u64 {
            warn_once_or_info!(
                "splice proxy: upstream error response body exceeded {} byte cap, truncating",
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

    Ok(())
}

/// State for the chunked transfer-encoding decoder.
///
/// Tracks position within the chunked framing so we can detect the terminating
/// `0\r\n\r\n` while forwarding all raw bytes transparently to the client.
enum ChunkedState {
    /// Accumulating the hex chunk-size line (up to `\r\n`).
    ReadingSize,
    /// Forwarding chunk data bytes; `remaining` counts undecoded payload bytes.
    ReadingData { remaining: usize },
    /// Expecting the `\r\n` trailer after chunk data.
    ReadingTrailer { seen_cr: bool },
    /// The final `0\r\n` chunk has been received; still expecting the
    /// closing `\r\n` that terminates the (empty) trailer section.
    /// `remaining` is the count of still-unseen bytes of that final CRLF
    /// (starts at 2, decrements to 0 when fully consumed).
    Done { remaining: u8 },
}

/// Forward a chunked transfer-encoded body from upstream to client.
///
/// All raw bytes (chunk-size lines, data, CRLFs) are forwarded unchanged.
/// The state machine only tracks framing to detect the terminating zero-length
/// chunk, so the connection can be reused afterwards.
async fn forward_upstream_chunked_body(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    body_prefix: &[u8],
    max_bytes: usize,
) -> std::io::Result<()> {
    let config = global_config();
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut state = ChunkedState::ReadingSize;
    let mut size_buf = Vec::<u8>::with_capacity(32);
    let mut total = Saturating(0);

    // Process a slice of bytes through the state machine, forwarding them to the
    // client.  Returns `true` when the terminal chunk has been fully consumed.
    //
    // We define this as a macro instead of a closure/function because it needs
    // mutable access to several locals (`state`, `size_buf`, `total`) while also
    // performing async writes.
    macro_rules! process_buf {
        ($data:expr) => {{
            let data: &[u8] = $data;
            // Validate framing before forwarding, so we never send bytes past a
            // detected framing error. On invalid framing the client connection
            // is closed by the error-return path in the caller; without this
            // pre-check the client would first receive the corrupt bytes and
            // only then see the connection drop.
            let mut i = 0usize;
            let mut done = false;
            while i < data.len() && !done {
                match state {
                    ChunkedState::ReadingSize => {
                        while i < data.len() {
                            let b = data[i];
                            i += 1;
                            size_buf.push(b);
                            if b == b'\n' && size_buf.len() >= 2 && size_buf[size_buf.len() - 2] == b'\r' {
                                // Parse hex chunk size (ignore optional chunk extensions after ';')
                                let line = &size_buf[..size_buf.len() - 2]; // strip \r\n
                                let hex_end = line.iter().position(|&c| c == b';').unwrap_or(line.len());
                                let hex_str = std::str::from_utf8(&line[..hex_end]).map_err(|_| {
                                    std::io::Error::new(
                                        ErrorKind::InvalidData,
                                        "chunked encoding: invalid chunk-size line",
                                    )
                                })?;
                                let chunk_size = usize::from_str_radix(hex_str.trim(), 16).map_err(|_| {
                                    std::io::Error::new(
                                        ErrorKind::InvalidData,
                                        "chunked encoding: invalid chunk-size hex",
                                    )
                                })?;
                                size_buf.clear();
                                if chunk_size == 0 {
                                    // Terminal chunk — still need to consume
                                    // the closing \r\n (empty trailer section).
                                    state = ChunkedState::Done { remaining: 2 };
                                } else {
                                    total += chunk_size;
                                    if total > Saturating(max_bytes) {
                                        warn_once_or_info!(
                                            "splice proxy: chunked response body exceeded {} byte cap",
                                            max_bytes
                                        );
                                        return Err(std::io::Error::other(
                                            "chunked response body exceeded size cap",
                                        ));
                                    }
                                    state = ChunkedState::ReadingData { remaining: chunk_size };
                                }
                                break;
                            }
                            // Guard against absurdly long size lines
                            if size_buf.len() > 64 {
                                return Err(std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    "chunked encoding: chunk-size line too long",
                                ));
                            }
                        }
                    }
                    ChunkedState::ReadingData { ref mut remaining } => {
                        let avail = data.len() - i;
                        let consume = std::cmp::min(*remaining, avail);
                        *remaining -= consume;
                        i += consume;
                        if *remaining == 0 {
                            state = ChunkedState::ReadingTrailer { seen_cr: false };
                        }
                    }
                    ChunkedState::ReadingTrailer { ref mut seen_cr } => {
                        while i < data.len() {
                            let b = data[i];
                            i += 1;
                            if !*seen_cr {
                                if b == b'\r' {
                                    *seen_cr = true;
                                } else {
                                    return Err(std::io::Error::new(
                                        ErrorKind::InvalidData,
                                        "chunked encoding: expected \\r after chunk data",
                                    ));
                                }
                            } else {
                                if b == b'\n' {
                                    state = ChunkedState::ReadingSize;
                                } else {
                                    return Err(std::io::Error::new(
                                        ErrorKind::InvalidData,
                                        "chunked encoding: expected \\n after chunk data \\r",
                                    ));
                                }
                                break;
                            }
                        }
                    }
                    ChunkedState::Done { ref mut remaining } => {
                        // Validate the closing \r\n after the 0-length chunk.
                        // Trailer sections (header fields between `0\r\n` and
                        // the final `\r\n`) are not forwarded by this proxy;
                        // we reject them as a framing sanity check to catch
                        // truncation / smuggling rather than silently skipping.
                        while i < data.len() && *remaining > 0 {
                            let b = data[i];
                            i += 1;
                            let expected = if *remaining == 2 { b'\r' } else { b'\n' };
                            if b != expected {
                                return Err(std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    "chunked encoding: expected \\r\\n after 0-length chunk \
                                     (trailer sections are not supported)",
                                ));
                            }
                            *remaining -= 1;
                        }
                        if *remaining == 0 {
                            done = true;
                        }
                    }
                }
            }
            // Framing validated — forward the raw bytes to the client unchanged.
            if !data.is_empty() {
                write_all_to_stream_rated(
                    client,
                    data,
                    &mut client_rate_checker,
                    RateCheckDirection::Client,
                    config.http_timeout,
                )
                .await
                .map_err(|e| {
                    std::io::Error::new(e.kind(), format!("chunked forward: client write:  {e}"))
                })?;
                metrics::BYTES_SERVED_PASSTHROUGH.increment_by(data.len() as u64);
            }
            done
        }};
    }

    // Bootstrap: process bytes that arrived with the response headers.
    if process_buf!(body_prefix) {
        return Ok(());
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
                    "upstream read timed out during chunked body forward",
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

        if process_buf!(&buf[..n]) {
            return Ok(());
        }
    }
}

/// Discard a stale partial download file and retry the upstream request from scratch.
///
/// Shared by the 416 and invalid-Content-Range recovery paths.
#[expect(
    clippy::too_many_arguments,
    reason = "called from exactly 2 sites in splice_proxy"
)]
async fn discard_partial_and_retry(
    partial: &mut utils::PartialDownload,
    mirror: &Mirror,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: &mut u64,
    upstream: &mut PoolGuard,
    upstream_resp: &mut UpstreamResponse,
    header_buf: &mut BytesMut,
    header_end: &mut usize,
) -> Result<(), SpliceProxyError> {
    partial.discard_resume().await;
    *resume_offset = 0;
    upstream.unset_poolable();
    let (up, resp, hdr_buf, hdr_end, _label, pool) =
        standard_upstream_connect(mirror, host_authority, upstream_path, 0, None, None).await?;
    upstream.replace(up, pool);
    *upstream_resp = resp;
    *header_buf = hdr_buf;
    *header_end = hdr_end;
    Ok(())
}

/// Splice-based proxy: connects to upstream (HTTP or HTTPS), transfers the response body
/// to the client socket via tee+splice fan-out while caching to disk.
///
/// For plain TCP upstreams, the entire path is zero-copy (splice from socket).
/// For TLS upstreams, the upstream read goes through userspace (decryption), but the
/// fan-out to client + cache still benefits from tee+splice.
pub(crate) async fn splice_proxy(
    client_stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    conn_details: &ConnectionDetails,
    upstream_path: &str,
    appstate: &AppState,
    client_range: RangeRequestHeaders<'_>,
) -> Result<SpliceProxyOutcome, SpliceProxyError> {
    // Register with active downloads to coordinate with concurrent clients.
    // A `Concurrent` outcome means another download for this key won the race
    // between sendfile's earlier `attach()` and our `originate()` here. It is
    // an alternate success — the caller retries as a sendfile late joiner
    // instead of falling all the way back to hyper. No late-joiner double
    // count, since `attach()` and `insert()` are mutually exclusive paths.
    let (init_tx, status) = match appstate
        .active_downloads
        .originate(&conn_details.mirror, &conn_details.debname)
    {
        OriginateOutcome::Originator { init_tx, status } => (init_tx, status),
        OriginateOutcome::Concurrent { status } => {
            return Ok(SpliceProxyOutcome::Concurrent { status });
        }
    };

    // TODO: use become: https://github.com/rust-lang/rust/issues/112788
    splice_proxy_drive(
        client_stream,
        conn_version,
        conn_action,
        conn_details,
        upstream_path,
        appstate,
        client_range,
        init_tx,
        status,
    )
    .await
    .map(|()| SpliceProxyOutcome::Served)
}

/// Body of [`splice_proxy`] after the originate check has succeeded. Kept as
/// a separate fn returning `Result<(), SpliceProxyError>` so the many
/// `Ok(())` early-returns scattered through the body do not need to be
/// rewritten just because the outer success type changed.
#[expect(
    clippy::too_many_arguments,
    reason = "function has only 1 caller and is a tail call"
)]
async fn splice_proxy_drive(
    client_stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    conn_details: &ConnectionDetails,
    upstream_path: &str,
    appstate: &AppState,
    client_range: RangeRequestHeaders<'_>,
    init_tx: tokio::sync::watch::Sender<()>,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
) -> Result<(), SpliceProxyError> {
    let ibarrier = InitBarrier::new(
        init_tx,
        &status,
        &appstate.active_downloads,
        &conn_details.mirror,
        &conn_details.debname,
    );

    let mirror = &conn_details.mirror;
    let host_authority = mirror.format_authority();

    // Check for a partial download file to resume (permanent files only).
    // Opens the file upfront (if it exists and is non-empty) to get size + mtime
    // from the same file descriptor, avoiding TOCTOU races between metadata() and open().
    // The guard uses keep_on_drop: true so the partial file survives on fallback
    // (e.g., concurrent download → hyper path picks it up for resume).
    // Explicit guard.remove() is used only when a stale partial must be discarded.
    let mut resume_offset: u64 = 0;
    let mut resume_if_range: Option<String> = None;
    let mut partial = if conn_details.cached_flavor == CachedFlavor::Permanent {
        match utils::open_partial_file(&ibarrier).await {
            Ok((file, size, mtime, guard)) if size > 0 => {
                resume_offset = size;
                resume_if_range = read_etag(&file, &guard).or_else(|| Some(mtime.format()));
                info!(
                    "splice proxy: found partial download ({} bytes) for {} from mirror {}, will attempt resume",
                    resume_offset, conn_details.debname, conn_details.mirror
                );
                utils::PartialDownload::Resumable { file, guard }
            }
            Ok((_file, _size, _mtime, guard)) => {
                // Zero-byte partial — treat as no partial
                utils::PartialDownload::Fresh(guard)
            }
            Err((err, guard)) => {
                if err.kind() != std::io::ErrorKind::NotFound {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "splice proxy: failed to open partial file for {} from mirror {}:  {err}",
                        conn_details.debname, conn_details.mirror
                    );
                    drop(guard);
                    return Err(SpliceProxyError::CacheError);
                }
                // File doesn't exist — proceed without resume
                utils::PartialDownload::Fresh(guard)
            }
        }
    } else {
        utils::PartialDownload::Volatile
    };

    // --- Volatile revalidation: read cached file metadata for conditional headers ---
    // When a stale volatile file exists in cache, prepare If-Modified-Since / If-None-Match
    // headers so the upstream can respond with 304 Not Modified if the content hasn't changed.
    let mut volatile_cond: Option<VolatileCondHeaders> = None;
    let mut volatile_cache_path: Option<PathBuf> = None;
    if conn_details.cached_flavor == CachedFlavor::Volatile {
        let cache_path = conn_details
            .cache_dir_path()
            .join(Path::new(&conn_details.debname));
        if let Ok(file) = tokio::fs::File::open(&cache_path).await
            && let Ok(metadata) = file.metadata().await
        {
            // Use mtime (last revalidated time), matching the hyper backend.
            // Mtime is repurposed as "last revalidated" by touch_volatile_mtime(),
            // so it correctly tells upstream "has this changed since I last checked?".
            let mtime = metadata
                .modified()
                .expect("Platform should support modification timestamps via setup check");
            let if_modified_since = HttpDate::from(mtime).format();
            let if_none_match = read_etag(&file, &cache_path);
            volatile_cond = Some(VolatileCondHeaders {
                if_modified_since,
                if_none_match,
            });
            volatile_cache_path = Some(cache_path);
        }
    }

    // --- Prepare upstream connection ---
    // Try unbuffered kTLS first (handles connect + handshake + request + response
    // headers in one shot with guaranteed record alignment). Falls back to the
    // standard buffered path on any failure.
    #[cfg(feature = "ktls")]
    let unbuffered_result = try_unbuffered_ktls_connect(
        mirror,
        &host_authority,
        upstream_path,
        resume_offset,
        resume_if_range.as_deref(),
        volatile_cond.as_ref(),
    )
    .await;

    // Handle kTLS ResponseNotSpliceable early for cases we can fully resolve
    // from the already-buffered data (304 → serve cache, 200-without-CL non-volatile
    // → 502). Everything else falls through to the standard path, which reconnects
    // to deliver a complete response rather than forwarding a potentially truncated
    // body from the one-shot kTLS attempt.
    #[cfg(feature = "ktls")]
    if let KtlsResult::ResponseNotSpliceable { ref response, .. } = unbuffered_result {
        cache_scheme(mirror, Scheme::Https);
        if response.status_code == 200 {
            if conn_details.cached_flavor == CachedFlavor::Volatile {
                // Volatile files without Content-Length: fall through to standard
                // path for buffered download (same as 206/416 fall-through below).
                debug!(
                    "splice proxy: volatile file without Content-Length (from kTLS attempt), \
                     falling back to standard path for buffered download"
                );
            } else {
                debug!("splice proxy: no usable Content-Length (from kTLS attempt), returning 502");
                write_invalid_response(
                    client_stream,
                    conn_version,
                    conn_action,
                    StatusCode::BAD_GATEWAY,
                    "no Content-Length",
                )
                .await
                .map_err(SpliceProxyError::ClientError)?;
                return Ok(());
            }
        }
        // During resume, 206 and 416 need the standard buffered path
        if resume_offset > 0 && (response.status_code == 206 || response.status_code == 416) {
            debug!(
                "splice proxy: kTLS got {} during resume, falling back to standard path",
                response.status_code
            );
            // Fall through to standard_upstream_connect via Failed branch below
        } else if response.status_code == 304
            && let Some(cache_path) = volatile_cache_path
        {
            // 304 from kTLS for volatile resource — serve cached file via sendfile.
            // The standard 304 handler below (after upstream connect) handles this
            // for the non-kTLS path; here we handle it for kTLS before falling through.
            // Fall through to the standard path which will re-connect and get the same 304.
            // Actually, we already have the 304 — no need to reconnect. Handle it directly.

            debug!(
                "splice proxy: kTLS upstream returned 304 for {} from mirror {}, serving cached file",
                conn_details.debname, conn_details.mirror
            );

            metrics::VOLATILE_REFETCHED_UPTODATE.increment();

            let file = match tokio::fs::File::open(&cache_path).await {
                Ok(f) => f,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "splice proxy: failed to open cached file `{}` after 304:  {err}",
                        cache_path.display()
                    );
                    return Err(SpliceProxyError::CacheError);
                }
            };
            let file = touch_volatile_mtime(file, &cache_path).await;
            ibarrier.finished(cache_path.clone()).await;

            return match serve_file_via_sendfile(
                client_stream,
                conn_details,
                "",
                (file, &cache_path),
                conn_version,
                conn_action,
                client_range,
            )
            .await
            {
                SendfileResult::Served(_)
                | SendfileResult::ClientError
                | SendfileResult::AfterHeaderError => Ok(()),
                SendfileResult::Invalid { status, msg }
                | SendfileResult::Rejection { status, msg, .. } => {
                    write_invalid_response(client_stream, conn_version, conn_action, status, msg)
                        .await
                        .map_err(SpliceProxyError::ClientError)?;
                    Ok(())
                }
                SendfileResult::NotApplicable(reason) => {
                    Err(SpliceProxyError::NotApplicable(reason))
                }
            };
        } else {
            // Non-200 / no-Content-Length response from the kTLS attempt.
            // We cannot safely forward just the buffered bytes: the body may be
            // longer than what rustls already decrypted, and the kTLS connection
            // has been consumed for a single request — there is no userspace read
            // loop to pull the remainder. Falling through to the standard path
            // reconnects and re-fetches, which delivers a complete response to
            // the client. One extra request is cheaper than a truncated reply.
            debug!(
                "splice proxy: upstream returned {} (from kTLS attempt), reconnecting via standard path",
                response.status_code
            );
            // Fall through to the `ResponseNotSpliceable { .. }` match arm below,
            // which calls standard_upstream_connect().
        }
    }

    let pool_host = mirror.host().to_string();

    #[cfg(feature = "ktls")]
    let (
        mut upstream,
        mut upstream_resp,
        mut header_buf,
        mut header_end,
        ktls_extra_body,
        mut tls_label,
    ) = match unbuffered_result {
        KtlsResult::Ready(tcp, state) => {
            cache_scheme(mirror, Scheme::Https);
            // kTLS connections must NOT be pooled: the socket has kernel TLS
            // TX+RX configured for this specific session's keys and sequence
            // numbers. Reusing it for a new request would layer a new TLS
            // handshake on top of the kTLS socket, corrupting the stream.
            // Future optimization: kTLS sockets could be pooled as a separate
            // "kTLS-ready" type that writes plaintext (kernel encrypts via TX)
            // and splices responses (kernel decrypts via RX), skipping the TLS
            // handshake entirely. This requires a distinct pool entry type,
            // control-message draining between requests, and key-update handling.
            let poolable = false;
            let splice_extra = state.extra_body;
            let port = mirror_port(mirror, true);
            (
                PoolGuard::new(UpstreamConn::Tcp(tcp), pool_host, port, poolable),
                state.response,
                state.header_buf,
                state.header_end,
                splice_extra,
                " (kTLS)",
            )
        }
        KtlsResult::ResponseNotSpliceable { .. } => {
            // Normally handled above, but during resume 206/416 fall through here
            // to use the standard buffered path for proper resume handling.
            let (up, resp, hdr_buf, hdr_end, label, poolable) = standard_upstream_connect(
                mirror,
                &host_authority,
                upstream_path,
                resume_offset,
                resume_if_range.as_deref(),
                volatile_cond.as_ref(),
            )
            .await?;
            let port = mirror_port(mirror, up.is_tls());
            (
                PoolGuard::new(up, pool_host, port, poolable),
                resp,
                hdr_buf,
                hdr_end,
                Vec::new(),
                label,
            )
        }
        KtlsResult::Failed { tls_succeeded } => {
            // Cache HTTPS scheme if TLS handshake succeeded, avoiding double-HTTPS
            // in auto mode
            if tls_succeeded {
                cache_scheme(mirror, Scheme::Https);
            }
            let (up, resp, hdr_buf, hdr_end, label, poolable) = standard_upstream_connect(
                mirror,
                &host_authority,
                upstream_path,
                resume_offset,
                resume_if_range.as_deref(),
                volatile_cond.as_ref(),
            )
            .await?;
            let port = mirror_port(mirror, up.is_tls());
            (
                PoolGuard::new(up, pool_host, port, poolable),
                resp,
                hdr_buf,
                hdr_end,
                Vec::new(),
                label,
            )
        }
    };

    #[cfg(not(feature = "ktls"))]
    let (mut upstream, mut upstream_resp, mut header_buf, mut header_end, mut tls_label) = {
        let (up, resp, hdr_buf, hdr_end, label, poolable) = standard_upstream_connect(
            mirror,
            &host_authority,
            upstream_path,
            resume_offset,
            resume_if_range.as_deref(),
            volatile_cond.as_ref(),
        )
        .await?;
        let port = mirror_port(mirror, up.is_tls());
        (
            PoolGuard::new(up, pool_host, port, poolable),
            resp,
            hdr_buf,
            hdr_end,
            label,
        )
    };

    // Handle resume: if we sent Range and got 200 (server ignores Range), discard partial
    if resume_offset > 0 && upstream_resp.status_code == 200 {
        info!(
            "splice proxy: server returned 200 instead of 206 for resume of {} from mirror {}, starting fresh",
            conn_details.debname, conn_details.mirror
        );
        partial.discard_resume().await;
        resume_offset = 0;
    }

    // Handle resume: if we got 416 (stale partial), discard and retry without Range
    if resume_offset > 0 && upstream_resp.status_code == 416 {
        warn!(
            "splice proxy: 416 for resume of {} from mirror {}, discarding stale partial and retrying",
            conn_details.debname, conn_details.mirror
        );
        discard_partial_and_retry(
            &mut partial,
            mirror,
            &host_authority,
            upstream_path,
            &mut resume_offset,
            &mut upstream,
            &mut upstream_resp,
            &mut header_buf,
            &mut header_end,
        )
        .await?;
    }

    // Handle 304 Not Modified for volatile resources: upstream confirms the cached copy
    // is still current. Update the file's mtime to reset the freshness window, then
    // serve the cached file via sendfile.
    if upstream_resp.status_code == 304
        && let Some(cache_path) = volatile_cache_path
    {
        debug!(
            "splice proxy: upstream returned 304 for {} from mirror {}, serving cached file",
            conn_details.debname, conn_details.mirror
        );

        metrics::VOLATILE_REFETCHED_UPTODATE.increment();

        // Pool the upstream connection back (304 has no body).
        if upstream_resp.connection_close {
            upstream.unset_poolable();
        }
        drop(upstream);

        let file = match tokio::fs::File::open(&cache_path).await {
            Ok(f) => f,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "splice proxy: failed to open cached file `{}` after 304:  {err}",
                    cache_path.display()
                );
                return Err(SpliceProxyError::CacheError);
            }
        };
        let file = touch_volatile_mtime(file, &cache_path).await;
        ibarrier.finished(cache_path.clone()).await;

        match serve_file_via_sendfile(
            client_stream,
            conn_details,
            "",
            (file, &cache_path),
            conn_version,
            conn_action,
            client_range,
        )
        .await
        {
            SendfileResult::Served(_)
            | SendfileResult::ClientError
            | SendfileResult::AfterHeaderError => return Ok(()),
            SendfileResult::Invalid { status, msg }
            | SendfileResult::Rejection { status, msg, .. } => {
                write_invalid_response(client_stream, conn_version, conn_action, status, msg)
                    .await
                    .map_err(SpliceProxyError::ClientError)?;
                return Ok(());
            }
            SendfileResult::NotApplicable(reason) => {
                return Err(SpliceProxyError::NotApplicable(reason));
            }
        }
    }

    // Handle 301 Moved Permanently: follow the redirect if the target host is allowed.
    // Only follows one redirect (no loops), matching hyper behavior.
    let redirected_path_owned = if upstream_resp.status_code == 301 {
        follow_redirect(
            &mut upstream_resp,
            &mut upstream,
            &mut header_buf,
            &mut header_end,
            &mut tls_label,
            conn_details,
            upstream_path,
            resume_offset,
            resume_if_range.as_deref(),
            volatile_cond.as_ref(),
        )
        .await?
    } else {
        None
    };
    let upstream_path = redirected_path_owned.as_deref().unwrap_or(upstream_path);

    // Forward non-200/non-206 responses directly to the client instead of falling back
    // to hyper (which would open a redundant second connection).
    if upstream_resp.status_code != 200 && upstream_resp.status_code != 206 {
        debug!(
            "splice proxy: upstream returned {}, forwarding directly",
            upstream_resp.status_code
        );

        metrics::record_client_status(upstream_resp.status_code);

        // Forward raw response headers to client
        write_all_to_stream(client_stream, &header_buf[..header_end])
            .await
            .map_err(SpliceProxyError::ClientError)?;

        // Forward any body data that arrived with the headers
        let body_prefix = &header_buf[header_end..];

        let config = global_config();
        let mut prefix_client_rate_checker = config
            .min_download_rate
            .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

        // Forward the remaining body data
        if let Some(cl) = upstream_resp.content_length {
            if !body_prefix.is_empty() {
                write_all_to_stream_rated(
                    client_stream,
                    body_prefix,
                    &mut prefix_client_rate_checker,
                    RateCheckDirection::Client,
                    config.http_timeout,
                )
                .await
                .map_err(|err| {
                    info!(
                        "splice proxy: failed to send body prefix to client {}:  {err}",
                        conn_details.client
                    );
                    SpliceProxyError::AfterHeaderError
                })?;
                metrics::BYTES_SERVED_PASSTHROUGH.increment_by(body_prefix.len() as u64);
            }
            let already_sent = body_prefix.len() as u64;
            let remaining = cl.saturating_sub(already_sent);
            if remaining > 0 {
                forward_upstream_body(&mut upstream, client_stream, remaining)
                    .await
                    .map_err(|err| {
                        info!(
                            "splice proxy: failed to send remaining body to client {}:  {err}",
                            conn_details.client
                        );
                        SpliceProxyError::AfterHeaderError
                    })?;
            }
        } else if upstream_resp.is_chunked {
            // Chunked encoding: forward raw framing, detect termination
            forward_upstream_chunked_body(
                &mut upstream,
                client_stream,
                body_prefix,
                VOLATILE_BODY_MAX,
            )
            .await
            .map_err(|err| {
                info!(
                    "splice proxy: failed to send body prefix to client {}:  {err}",
                    conn_details.client
                );
                SpliceProxyError::AfterHeaderError
            })?;
        } else {
            // No Content-Length and not chunked: read until EOF
            if !body_prefix.is_empty() {
                write_all_to_stream_rated(
                    client_stream,
                    body_prefix,
                    &mut prefix_client_rate_checker,
                    RateCheckDirection::Client,
                    config.http_timeout,
                )
                .await
                .map_err(|err| {
                    info!(
                        "splice proxy: failed to send body prefix to client {}:  {err}",
                        conn_details.client
                    );
                    SpliceProxyError::AfterHeaderError
                })?;
                metrics::BYTES_SERVED_PASSTHROUGH.increment_by(body_prefix.len() as u64);
            }
            upstream.unset_poolable();
            forward_upstream_body_until_eof(&mut upstream, client_stream, VOLATILE_BODY_MAX)
                .await
                .map_err(|err| {
                    info!(
                        "splice proxy: failed to forward body to client {}:  {err}",
                        conn_details.client
                    );
                    SpliceProxyError::AfterHeaderError
                })?;
        }

        // InitBarrier fires on return, which is correct: nothing was cached
        // PoolGuard::drop handles returning the connection to pool if poolable
        return Ok(());
    }

    // Volatile stale-but-present revalidation that returned a fresh body
    // (200 or 206) — counterpart to the 304 / UPTODATE case above. The
    // volatile-not-found path leaves `volatile_cache_path` as None and is
    // intentionally not split into UPTODATE/OUTOFDATE.
    if volatile_cache_path.is_some() {
        metrics::VOLATILE_REFETCHED_OUTOFDATE.increment();
    }

    // Handle resume: if we got 206 but Content-Range is invalid/mismatched,
    // discard partial and retry fresh — same pattern as 416 handling above.
    if resume_offset > 0 && upstream_resp.status_code == 206 {
        let content_range_valid = upstream_resp
            .content_range
            .as_deref()
            .and_then(parse_content_range)
            .is_some_and(|(start, _, _)| start == resume_offset);

        if !content_range_valid {
            warn!(
                "splice proxy: invalid Content-Range for 206 response of {} from mirror {}, discarding partial and retrying fresh",
                conn_details.debname, conn_details.mirror
            );
            discard_partial_and_retry(
                &mut partial,
                mirror,
                &host_authority,
                upstream_path,
                &mut resume_offset,
                &mut upstream,
                &mut upstream_resp,
                &mut header_buf,
                &mut header_end,
            )
            .await?;
        }
    }

    // Determine total file size and body size for resume vs fresh downloads
    let (total_file_size, body_content_length) = if resume_offset > 0
        && upstream_resp.status_code == 206
    {
        let content_range = upstream_resp
            .content_range
            .as_deref()
            .and_then(parse_content_range);

        match content_range {
            Some((start, _end, total)) if start == resume_offset => {
                let Some(remaining) = total.checked_sub(resume_offset) else {
                    warn_once_or_info!(
                        "splice proxy: inconsistent Content-Range for 206 response of {} from mirror {}: \
                         total {total} < resume_offset {resume_offset}",
                        conn_details.debname,
                        conn_details.mirror
                    );
                    write_invalid_response(
                        client_stream,
                        conn_version,
                        conn_action,
                        StatusCode::BAD_GATEWAY,
                        "upstream Content-Range total < resume offset",
                    )
                    .await
                    .map_err(SpliceProxyError::ClientError)?;
                    return Ok(());
                };
                #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
                let remaining_percent = remaining as f32 / total as f32 * 100.0;
                info!(
                    "splice proxy: resuming download of {} from mirror {} at byte {} ({} ({:.1}%) remaining of {} total)",
                    conn_details.debname,
                    conn_details.mirror,
                    resume_offset,
                    remaining,
                    remaining_percent,
                    total
                );
                (total, remaining)
            }
            _ => {
                // Should not happen: invalid Content-Range was already handled above
                // with a fresh retry. If we still get here, the retried response is
                // also broken — return error to client.
                warn!(
                    "splice proxy: unexpected Content-Range state for 206 response of {} from mirror {}: {:?}",
                    conn_details.debname, conn_details.mirror, upstream_resp.content_range
                );
                write_invalid_response(
                    client_stream,
                    conn_version,
                    conn_action,
                    StatusCode::BAD_GATEWAY,
                    "unexpected Content-Range",
                )
                .await
                .map_err(SpliceProxyError::ClientError)?;
                return Ok(());
            }
        }
    } else {
        // Fresh download
        resume_offset = 0;
        let Some(cl) = upstream_resp.content_length else {
            if conn_details.cached_flavor == CachedFlavor::Volatile {
                return handle_volatile_buffered_download(
                    &mut upstream,
                    client_stream,
                    conn_version,
                    conn_action,
                    conn_details,
                    upstream_path,
                    &upstream_resp,
                    &header_buf,
                    header_end,
                    ibarrier,
                    client_range,
                    tls_label,
                )
                .await;
            }
            debug!(
                "splice proxy: no Content-Length for file {} from mirror {}",
                conn_details.debname, conn_details.mirror
            );
            // Body framing unknown — any bytes in header_buf tail or on the
            // socket cannot be safely skipped, so don't return the connection
            // to the pool.
            upstream.unset_poolable();
            write_invalid_response(
                client_stream,
                conn_version,
                conn_action,
                StatusCode::BAD_GATEWAY,
                "no Content-Length",
            )
            .await
            .map_err(SpliceProxyError::ClientError)?;
            return Ok(());
        };
        (cl, cl)
    };
    let resume_offset = resume_offset; // mark immutable

    let Some(total_content_length) = NonZero::new(total_file_size) else {
        debug!(
            "splice proxy: zero total file size for file {} from mirror {}",
            conn_details.debname, conn_details.mirror
        );
        // Protocol-violating response — don't trust the connection's framing.
        upstream.unset_poolable();
        write_invalid_response(
            client_stream,
            conn_version,
            conn_action,
            StatusCode::BAD_GATEWAY,
            "zero total file size",
        )
        .await
        .map_err(SpliceProxyError::ClientError)?;
        return Ok(());
    };
    let Some(body_content_length) = NonZero::new(body_content_length) else {
        debug!(
            "splice proxy: zero body content length for file {} from mirror {}",
            conn_details.debname, conn_details.mirror
        );
        upstream.unset_poolable();
        write_invalid_response(
            client_stream,
            conn_version,
            conn_action,
            StatusCode::BAD_GATEWAY,
            "zero body Content-Length",
        )
        .await
        .map_err(SpliceProxyError::ClientError)?;
        return Ok(());
    };

    // Parse client Range request now that we know the total file size.
    let client_range_result = client_range.range.map(|range| {
        let cache_time = upstream_resp
            .last_modified
            .as_deref()
            .and_then(HttpDate::parse)
            .unwrap_or(HttpDate::UNIX_EPOCH);
        http_parse_range(
            range,
            client_range.if_range,
            total_content_length.get(),
            cache_time,
            upstream_resp.etag.as_deref(),
        )
    });
    // Range is not satisfiable — return 416.
    if matches!(client_range_result, Some(ParsedRange::NotSatisfiable)) {
        write_416_response(
            client_stream,
            conn_version,
            conn_action,
            total_content_length.get(),
        )
        .await
        .map_err(SpliceProxyError::ClientError)?;
        return Ok(());
    }
    let (content_range_hdr, client_range_start, client_range_len, is_partial) =
        match client_range_result {
            Some(ParsedRange::Satisfiable(cr, start, len)) => (Some(cr), start, len, true),
            _ => (None, 0, total_content_length.get(), false),
        };

    // Create cache directory and temp file
    let dest_dir = conn_details.cache_dir_path();
    if let Err(err) = tokio::fs::create_dir_all(&dest_dir).await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to create cache directory `{}`:  {err}",
            dest_dir.display()
        );
        return Err(SpliceProxyError::CacheError);
    }

    let filename = Path::new(&conn_details.debname);
    assert!(
        filename.is_relative(),
        "path construction must not contain absolute components"
    );

    let prev_file_size = match conn_details.cached_flavor {
        CachedFlavor::Volatile => {
            let prev_path = dest_dir.join(filename);
            match tokio::fs::metadata(&prev_path).await {
                Ok(m) => m.len(),
                Err(err) if err.kind() == ErrorKind::NotFound => 0,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "splice proxy: failed to stat existing volatile file `{}`:  {err}",
                        prev_path.display()
                    );
                    return Err(SpliceProxyError::CacheError);
                }
            }
        }
        CachedFlavor::Permanent => {
            // permanent files are never overridden
            0
        }
    };

    let reservation = match global_cache_quota().try_acquire(
        ContentLength::Exact(total_content_length),
        prev_file_size,
        &conn_details.debname,
    ) {
        Ok(r) => Some(r),
        Err(_err @ QuotaExceeded) => {
            write_invalid_response(
                client_stream,
                conn_version,
                conn_action,
                StatusCode::SERVICE_UNAVAILABLE,
                "Disk quota reached",
            )
            .await
            .map_err(SpliceProxyError::ClientError)?;
            return Ok(());
        }
    };

    // Create/open the output file: partial path for permanent files, random temp for volatile.
    // Defuse the guard once we take ownership of the partial path — from here on, the
    // download's own TempPath (keep_on_drop: true) manages the file lifetime.
    let (mut tempfile, temppath) = match partial {
        utils::PartialDownload::Resumable { mut file, guard } => {
            // Resume: use the file already opened during the partial-file check.
            // The file handle has been held open since the check, so no TOCTOU race.
            // Verify the file size matches expectations (should always hold since
            // we've held the fd open, but check as defense-in-depth).
            use tokio::io::AsyncSeekExt as _;
            let current_size = file.seek(std::io::SeekFrom::End(0)).await.unwrap_or(0);
            if current_size != resume_offset {
                error!(
                    "splice proxy: partial file size {current_size} != expected {resume_offset} despite held fd"
                );
                write_invalid_response(
                    client_stream,
                    conn_version,
                    conn_action,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Cache Access Failure",
                )
                .await
                .map_err(SpliceProxyError::ClientError)?;
                return Ok(());
            }
            (file, guard)
        }
        utils::PartialDownload::Fresh(guard) => utils::create_partial_file(guard, 0o640)
            .await
            .map_err(|(err, path)| {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "splice proxy: failed to create partial file `{}`:  {err}",
                    path.display()
                );
                SpliceProxyError::CacheError
            })?,
        utils::PartialDownload::Volatile => {
            let tmppath: PathBuf = [&global_config().cache_directory, Path::new("tmp"), filename]
                .iter()
                .collect();
            tokio_tempfile(&tmppath, 0o640).await.map_err(|err| {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "splice proxy: failed to create temp file `{}`:  {err}",
                    tmppath.display()
                );
                SpliceProxyError::CacheError
            })?
        }
    };

    // Write ETag xattr early so it survives partial downloads for resume
    if let Some(ref etag) = upstream_resp.etag {
        write_etag(&tempfile, &temppath, etag);
    }
    // Persist upstream Last-Modified to xattr (RFC 9110 §10.2.2: forward origin's value)
    if let Some(ref lm) = upstream_resp.last_modified {
        write_last_modified(&tempfile, &temppath, lm);
    }

    let mut dbarrier = ibarrier
        .download(
            temppath.to_path_buf(),
            ContentLength::Exact(total_content_length),
            reservation,
        )
        .await;

    let body_prefix = &header_buf[header_end..];

    #[cfg_attr(
        not(feature = "ktls"),
        expect(unused_mut, reason = "kTLS needs to adjust for extra body")
    )]
    let Some(mut splice_count) = body_content_length
        .get()
        .checked_sub(body_prefix.len() as u64)
    else {
        error!(
            "splice proxy: body prefix ({} bytes) exceeds body content length ({} bytes) \
             for {} from mirror {}",
            body_prefix.len(),
            body_content_length,
            conn_details.debname,
            conn_details.mirror
        );
        upstream.unset_poolable();
        write_invalid_response(
            client_stream,
            conn_version,
            conn_action,
            StatusCode::BAD_GATEWAY,
            "body Content-Length mismatch",
        )
        .await
        .map_err(SpliceProxyError::ClientError)?;
        return Ok(());
    };

    #[cfg(feature = "ktls")]
    {
        let extra_len = ktls_extra_body.len() as u64;

        splice_count = if let Some(sc) = splice_count.checked_sub(extra_len) {
            sc
        } else {
            error!(
                "splice proxy: kTLS extra body ({extra_len} bytes) exceeds remaining \
                 body content length ({splice_count} bytes) for {} from mirror {}",
                conn_details.debname, conn_details.mirror
            );
            upstream.unset_poolable();
            write_invalid_response(
                client_stream,
                conn_version,
                conn_action,
                StatusCode::BAD_GATEWAY,
                "body Content-Length mismatch",
            )
            .await
            .map_err(SpliceProxyError::ClientError)?;
            return Ok(());
        };
    }

    let start = coarsetime::Instant::now();

    if resume_offset > 0 {
        #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
        let resume_percent = resume_offset as f32 / total_content_length.get() as f32 * 100.0;

        info!(
            "Splice proxy{tls_label}: resuming and serving {} from mirror {} for client {} at byte {} ({}%)...",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client,
            resume_offset,
            resume_percent
        );
    } else {
        info!(
            "Splice proxy{tls_label}: downloading and serving {} from mirror {} for client {}...",
            conn_details.debname, conn_details.mirror, conn_details.client
        );
    }

    // Write response headers to client
    let last_modified_str = upstream_resp.last_modified.as_deref();
    let content_type = content_type_for_cached_file(&conn_details.debname);
    if let Some(upstream_ct) = upstream_resp.content_type.as_deref()
        && !upstream_ct.eq_ignore_ascii_case(content_type)
    {
        warn!(
            "splice proxy: upstream Content-Type `{upstream_ct}` differs from expected `{content_type}` for {}",
            conn_details.debname
        );
    }
    let date = format_http_date();
    // Fresh response streamed straight from origin → Age is 0 per RFC 9111 §4.2.3.
    let age: u32 = 0;
    let (status_line, response_content_length) = if is_partial {
        ("206 Partial Content", client_range_len)
    } else {
        ("200 OK", total_content_length.get())
    };
    let response_headers = format!(
        "{conn_version} {status_line}\r\n\
         Date: {date}\r\n\
         Via: {APP_VIA}\r\n\
         Connection: {conn_action}\r\n\
         Content-Length: {response_content_length}\r\n\
         Content-Type: {content_type}\r\n\
         {last_modified_header}\
         {etag_header}\
         Accept-Ranges: bytes\r\n\
         Age: {age}\r\n\
         {content_range_header}\
         \r\n",
        last_modified_header = if let Some(lm) = last_modified_str {
            format!("Last-Modified: {lm}\r\n")
        } else {
            String::new()
        },
        etag_header = match upstream_resp.etag.as_deref() {
            Some(etag) => format!("ETag: {etag}\r\n"),
            None => String::new(),
        },
        content_range_header = if let Some(ref cr) = content_range_hdr {
            format!("Content-Range: {cr}\r\n")
        } else {
            String::new()
        },
    );

    // Cork the socket to coalesce headers + body prefix into fewer TCP segments
    let cork = CorkGuard::new_optional(client_stream);

    trace!("Outgoing {status_line} response:\n{response_headers}");

    metrics::record_client_status(if is_partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    });
    write_all_to_stream(client_stream, response_headers.as_bytes())
        .await
        .map_err(|err| {
            let level = if err.kind() == std::io::ErrorKind::BrokenPipe {
                log::Level::Info
            } else {
                log::Level::Warn
            };
            log::log!(
                level,
                "splice proxy: failed to write response headers to client:  {err}"
            );

            SpliceProxyError::ClientError(err)
        })?;

    // For resumed downloads, send the existing partial file content to the client first
    // using sendfile(2) for zero-copy transfer from the cache file to the client socket.
    // With a client Range, only send the overlap of [0, resume_offset) with the range.
    if resume_offset > 0 {
        let client_range_end = client_range_start + client_range_len;
        let send_start = client_range_start.min(resume_offset);
        let send_end = client_range_end.min(resume_offset);
        if send_end > send_start {
            let partial_reader = tokio::fs::File::open(temppath.as_ref())
                .await
                .map_err(|err| {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!("splice proxy: failed to open partial file for reading:  {err}");
                    SpliceProxyError::AfterHeaderError
                })?;

            async_sendfile(
                client_stream,
                &partial_reader,
                send_start,
                send_end - send_start,
            )
            .await
            .map_err(|err| {
                info!("splice proxy: failed to sendfile partial data to client:  {err}");
                SpliceProxyError::AfterHeaderError
            })?;
        }
    }

    // Track file cursor for range-filtering pre-loop buffers.
    #[cfg_attr(
        not(feature = "ktls"),
        expect(unused_mut, reason = "kTLS needs to adjust for included body")
    )]
    let mut pre_loop_file_pos: u64 = resume_offset;

    // If upstream sent body data in the same read as headers, write it directly.
    if !body_prefix.is_empty() {
        let client_slice = range_slice(
            body_prefix,
            pre_loop_file_pos,
            client_range_start,
            client_range_len,
        );
        if !client_slice.is_empty() {
            let config = global_config();
            let mut prefix_rc = config
                .min_download_rate
                .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
            write_all_to_stream_rated(
                client_stream,
                client_slice,
                &mut prefix_rc,
                RateCheckDirection::Client,
                config.http_timeout,
            )
            .await
            .map_err(|err| {
                info!("splice proxy: failed to write body prefix to client:  {err}");

                SpliceProxyError::AfterHeaderError
            })?;
        }

        tempfile.write_all(body_prefix).await.map_err(|err| {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to write body prefix to cache file `{}`:  {err}",
                temppath.display()
            );
            SpliceProxyError::AfterHeaderError
        })?;

        #[cfg(feature = "ktls")]
        {
            pre_loop_file_pos += body_prefix.len() as u64;
        }

        // Notify concurrent clients of progress
        dbarrier.ping();
    }

    // Write any kTLS-drained buffered plaintext to client + cache
    #[cfg(feature = "ktls")]
    if !ktls_extra_body.is_empty() {
        let client_slice = range_slice(
            &ktls_extra_body,
            pre_loop_file_pos,
            client_range_start,
            client_range_len,
        );
        if !client_slice.is_empty() {
            let config = global_config();
            let mut prefix_rc = config
                .min_download_rate
                .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
            write_all_to_stream_rated(
                client_stream,
                client_slice,
                &mut prefix_rc,
                RateCheckDirection::Client,
                config.http_timeout,
            )
            .await
            .map_err(|err| {
                info!("splice proxy: failed to write kTLS extra body to client:  {err}");

                SpliceProxyError::AfterHeaderError
            })?;
        }

        tempfile.write_all(&ktls_extra_body).await.map_err(|err| {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to write kTLS extra body to cache file `{}`:  {err}",
                temppath.display()
            );
            SpliceProxyError::AfterHeaderError
        })?;

        #[expect(
            unused_assignments,
            reason = "tracks file position for range filtering; last assignment before splice loop"
        )]
        {
            pre_loop_file_pos += ktls_extra_body.len() as u64;
        }

        // Notify concurrent clients of progress
        dbarrier.ping();
    }

    // Uncork before entering the splice loop, which uses SPLICE_F_MORE for coalescing
    drop(cork);

    // Transfer the remaining body
    let demoted_handle = if splice_count > 0 {
        let body_offset: i64 = (resume_offset + body_content_length.get() - splice_count)
            .try_into()
            .expect("the body prefix + extra body is limited in size");

        // Compute client range relative to splice region for the body transfer.
        // splice_file_start is the file offset where the splice region begins.
        let splice_file_start = resume_offset + body_content_length.get() - splice_count;
        let client_range_end = client_range_start + client_range_len;
        let splice_file_end = splice_file_start + splice_count;
        // How many bytes to skip at the start of the splice region before sending to client.
        // Worked example: total file = 1000, resume_offset = 0, splice_file_start = 0,
        // splice_file_end = 1000, client Range: bytes=200-499 → client_range_start = 200,
        // client_range_len = 300, client_range_end = 500.
        //   client_skip = 200 - 0 = 200 (drop leading bytes before the range)
        //   client_send = min(500, 1000) - (0 + 200) = 300 (send exactly the range)
        // If the range ends past the splice region (e.g. due to a body prefix already
        // consumed), the min() clamps to splice_file_end and saturating_sub clamps at 0.
        let client_skip = client_range_start.saturating_sub(splice_file_start);
        // How many bytes to send to client from within the splice region.
        let client_send = client_range_end
            .min(splice_file_end)
            .saturating_sub(splice_file_start + client_skip);
        let range_filter = SpliceRangeFilter {
            skip: client_skip,
            send: client_send,
        };

        // `dbarrier` is moved in by value: on success it's returned for the
        // rename step; on a structured rate-timeout it's already consumed into
        // `Aborted(MirrorDownloadRate)`; on any other io::Error it's dropped
        // inside the callee and the Drop impl records `AlreadyLoggedJustFail`.
        let (returned_dbarrier, demoted_handle) = if let Some(tcp_upstream) = upstream.as_tcp() {
            // Zero-copy path for TCP (plain or kTLS)
            splice_proxy_body(
                tcp_upstream,
                client_stream,
                &tempfile,
                splice_count,
                body_offset,
                dbarrier,
                &range_filter,
                &temppath,
                total_content_length.get(),
            )
            .await
        } else {
            // TLS: userspace read, then tee+splice fan-out
            splice_proxy_body_tls(
                &mut upstream,
                client_stream,
                &tempfile,
                splice_count,
                body_offset,
                dbarrier,
                &range_filter,
                &temppath,
                total_content_length.get(),
            )
            .await
        }
        .map_err(|err| {
            info!(
                "splice proxy: body transfer failed for {} from mirror {}:  {err}",
                conn_details.debname, conn_details.mirror
            );
            SpliceProxyError::AfterHeaderError
        })?;
        dbarrier = returned_dbarrier;
        demoted_handle
    } else {
        None
    };

    // PoolGuard::drop returns the connection to pool if still poolable.
    // Drop it now before the sync+rename to free the upstream socket promptly.
    drop(upstream);

    // Sync cache file to ensure durability
    if let Err(err) = tempfile.sync_all().await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to sync cache file `{}`:  {err}",
            temppath.display()
        );
    }
    drop(tempfile);

    // Move temp file to final cache path
    let dest_file_path = dest_dir.join(filename);

    // Lock to block all downloading tasks, since the file from the
    // path of the downloading state is going to be moved.
    let rbarrier = dbarrier.begin_rename().await;

    match tokio::fs::rename(&temppath, &dest_file_path).await {
        Ok(()) => {
            TempPath::defuse(temppath);

            rbarrier.release(dest_file_path, total_content_length.get());
        }
        Err(err) => {
            drop(rbarrier);
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to rename temp file `{}` to `{}`:  {err}",
                temppath.display(),
                dest_file_path.display()
            );
            return Err(SpliceProxyError::AfterHeaderError);
        }
    }

    let elapsed = start.elapsed();

    info!(
        "Splice proxy{tls_label}: served and cached {} from mirror {} for client {} in {} (size={}, rate={}{})",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client,
        HumanFmt::Time(elapsed.into()),
        HumanFmt::Size(total_content_length.get()),
        HumanFmt::Rate(body_content_length.get(), elapsed),
        if resume_offset > 0 {
            format!(", resumed from {}", HumanFmt::Size(resume_offset))
        } else {
            String::new()
        }
    );

    // Record download in database (mirrors download_file() in main.rs).
    let cmd = DatabaseCommand::Download(DbCmdDownload {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: total_content_length.get(),
        elapsed,
        client_ip: conn_details.client.ip(),
    });
    send_db_command(cmd).await;

    // Record delivery in database
    let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: total_content_length.get(),
        elapsed,
        partial: is_partial,
        client_ip: conn_details.client.ip(),
    });
    send_db_command(cmd).await;

    // Record origin in database (mirrors the hyper path in main.rs).
    if let Some(origin) = Origin::from_path(
        upstream_path,
        conn_details.mirror.host().clone(),
        conn_details.mirror.port(),
    ) {
        match origin.architecture.as_str() {
            "dep11" | "i18n" | "source" => (),
            _ => {
                let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
                send_db_command(cmd).await;
            }
        }
    }

    // If the first client was demoted to file-serve, wait for the
    // background task to finish sending before returning control to the
    // connection handler (which may reuse the socket for keep-alive).
    if let Some(handle) = demoted_handle
        && let Err(err) = handle.await
    {
        error!(
            "splice proxy: demoted client file-serve task panicked:  {}",
            ErrorReport(&err)
        );
    }

    Ok(())
}

/// Read upstream body into a `Vec<u8>` until EOF, up to `max_bytes`.
/// Returns the buffered body. Connection is not poolable after this.
async fn read_body_to_vec_until_eof(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let config = global_config();
    let size = (prefix.len() + 4096).min(max_bytes);
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(prefix);
    let mut buf = BytesMut::with_capacity(TLS_READ_BUF_SIZE); // TODO: replace body Vec?
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

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
                    "upstream read timed out during volatile body buffering",
                ));
            }
        };

        if body.len().checked_add(n).is_none_or(|sum| sum > max_bytes) {
            warn_once_or_info!(
                "splice proxy: volatile response body exceeded {max_bytes} byte cap"
            );
            return Err(std::io::Error::other(
                "volatile response body exceeded size cap",
            ));
        }

        body.extend_from_slice(&buf[..n]);

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
async fn read_dechunk_body_to_vec(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    // State machine for chunked decoding.
    enum State {
        /// Accumulating the hex chunk-size line (up to `\r\n`).
        ReadingSize,
        /// Reading chunk data bytes; `remaining` counts undecoded payload bytes.
        ReadingData { remaining: usize },
        /// Expecting the `\r\n` trailer after chunk data.
        ReadingTrailer { seen_cr: bool },
        /// The final `0\r\n` chunk has been received; done.
        Done,
    }

    let config = global_config();
    let mut body = Vec::with_capacity(4096);
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
    let mut state = State::ReadingSize;
    let mut size_buf = Vec::with_capacity(32);
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
                            "upstream read timed out during chunked body buffering",
                        ));
                    }
                };
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

        let mut i = 0;
        while i < data.len() {
            match state {
                State::ReadingSize => {
                    let b = data[i];
                    i += 1;
                    size_buf.push(b);
                    if b == b'\n' && size_buf.len() >= 2 && size_buf[size_buf.len() - 2] == b'\r' {
                        let line = &size_buf[..size_buf.len() - 2];
                        let hex_end = line.iter().position(|&c| c == b';').unwrap_or(line.len());
                        let hex_str = std::str::from_utf8(&line[..hex_end]).map_err(|_err| {
                            std::io::Error::new(
                                ErrorKind::InvalidData,
                                "chunked encoding: invalid chunk-size line",
                            )
                        })?;
                        let chunk_size =
                            usize::from_str_radix(hex_str.trim(), 16).map_err(|_err| {
                                std::io::Error::new(
                                    ErrorKind::InvalidData,
                                    "chunked encoding: invalid chunk-size hex",
                                )
                            })?;
                        size_buf.clear();
                        if chunk_size == 0 {
                            state = State::Done;
                        } else {
                            if body
                                .len()
                                .checked_add(chunk_size as usize)
                                .is_none_or(|sum| sum > max_bytes)
                            {
                                warn_once_or_info!(
                                    "splice proxy: chunked volatile body exceeded {max_bytes} byte cap"
                                );
                                return Err(std::io::Error::other(
                                    "chunked volatile body exceeded size cap",
                                ));
                            }
                            state = State::ReadingData {
                                remaining: chunk_size,
                            };
                        }
                    }
                }
                State::ReadingData { ref mut remaining } => {
                    let avail = data.len() - i;
                    let taken = avail.min(*remaining);
                    body.extend_from_slice(&data[i..i + taken]);
                    *remaining -= taken;
                    i += taken;
                    if *remaining == 0 {
                        state = State::ReadingTrailer { seen_cr: false };
                    }
                }
                State::ReadingTrailer { ref mut seen_cr } => {
                    let b = data[i];
                    i += 1;
                    if !*seen_cr && b == b'\r' {
                        *seen_cr = true;
                    } else if *seen_cr && b == b'\n' {
                        state = State::ReadingSize;
                    } else {
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "chunked encoding: expected CRLF after chunk data",
                        ));
                    }
                }
                State::Done => break,
            }
        }

        if matches!(state, State::Done) {
            break;
        }
    }

    Ok(body)
}

/// Handle the full lifecycle for volatile files whose upstream response has no
/// Content-Length.  The entire body is buffered into memory (up to 1 MiB),
/// then served to the client and cached, bypassing splice(2).
#[expect(
    clippy::too_many_arguments,
    reason = "lifecycle function threading full context"
)]
async fn handle_volatile_buffered_download(
    upstream: &mut PoolGuard,
    client_stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    conn_details: &ConnectionDetails,
    upstream_path: &str,
    upstream_resp: &UpstreamResponse,
    header_buf: &[u8],
    header_end: usize,
    ibarrier: InitBarrier<'_>,
    client_range: RangeRequestHeaders<'_>,
    tls_label: &str,
) -> Result<(), SpliceProxyError> {
    let max_bytes: usize = VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER
        .get()
        .try_into()
        .expect("constant fits"); // TODO: const conversion once stable
    let body_prefix = &header_buf[header_end..];

    // Buffer the entire body into memory.
    let body = if upstream_resp.is_chunked {
        read_dechunk_body_to_vec(upstream, body_prefix, max_bytes).await
    } else {
        // Close-delimited: read until EOF.
        upstream.unset_poolable();
        read_body_to_vec_until_eof(upstream, body_prefix, max_bytes).await
    }
    .map_err(|err| {
        warn_once_or_info!(
            "splice proxy: volatile buffered download failed for {}:  {err}",
            conn_details.debname
        );
        SpliceProxyError::TransferError
    })?;

    // Drop upstream early to free the socket.
    // (PoolGuard::drop returns the connection to pool if still poolable.)

    let Some(total_content_length) = NonZero::new(body.len() as u64) else {
        debug!(
            "splice proxy: zero-length volatile body for {} from mirror {}",
            conn_details.debname, conn_details.mirror
        );
        write_invalid_response(
            client_stream,
            conn_version,
            conn_action,
            StatusCode::BAD_GATEWAY,
            "zero-length body",
        )
        .await
        .map_err(SpliceProxyError::ClientError)?;
        return Ok(());
    };

    info!(
        "Splice proxy{tls_label}: buffered volatile download of {} from mirror {} for client {} ({} bytes)...",
        conn_details.debname, conn_details.mirror, conn_details.client, total_content_length
    );

    let prev_file_size = {
        let prev_path = conn_details
            .cache_dir_path()
            .join(Path::new(&conn_details.debname));

        match tokio::fs::metadata(&prev_path).await {
            Ok(m) => m.len(),
            Err(err) if err.kind() == ErrorKind::NotFound => 0,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "splice proxy: failed to stat existing volatile file `{}`:  {err}",
                    prev_path.display()
                );
                return Err(SpliceProxyError::CacheError);
            }
        }
    };

    // Acquire cache quota with exact known size.
    let reservation = match global_cache_quota().try_acquire(
        ContentLength::Exact(total_content_length),
        prev_file_size,
        &conn_details.debname,
    ) {
        Ok(r) => Some(r),
        Err(_err @ QuotaExceeded) => {
            write_invalid_response(
                client_stream,
                conn_version,
                conn_action,
                StatusCode::SERVICE_UNAVAILABLE,
                "Disk quota reached",
            )
            .await
            .map_err(SpliceProxyError::ClientError)?;
            return Ok(());
        }
    };

    // Parse client Range against the now-known total size.
    let cache_time = HttpDate::now();
    let client_range_result = client_range.range.map(|range| {
        http_parse_range(
            range,
            client_range.if_range,
            total_content_length.get(),
            cache_time,
            upstream_resp.etag.as_deref(),
        )
    });

    // Range is not satisfiable — return 416.
    if matches!(client_range_result, Some(ParsedRange::NotSatisfiable)) {
        write_416_response(
            client_stream,
            conn_version,
            conn_action,
            total_content_length.get(),
        )
        .await
        .map_err(SpliceProxyError::ClientError)?;
        return Ok(());
    }

    #[expect(clippy::cast_possible_truncation, reason = "body capped at 1 MiB")]
    let (content_range_hdr, client_range_start, client_range_len, is_partial) =
        match client_range_result {
            Some(ParsedRange::Satisfiable(cr, start, len)) => {
                (Some(cr), start as usize, len as usize, true)
            }
            _ => (None, 0, body.len(), false),
        };

    // Create cache directory and temp file.
    let dest_dir = conn_details.cache_dir_path();
    if let Err(err) = tokio::fs::create_dir_all(&dest_dir).await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to create cache directory `{}`:  {err}",
            dest_dir.display()
        );
        return Err(SpliceProxyError::CacheError);
    }

    let filename = Path::new(&conn_details.debname);
    assert!(
        filename.is_relative(),
        "path construction must not contain absolute components"
    );

    let tmppath: PathBuf = [&global_config().cache_directory, Path::new("tmp"), filename]
        .iter()
        .collect();
    let (mut tempfile, temppath) = tokio_tempfile(&tmppath, 0o640).await.map_err(|err| {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to create temp file `{}`:  {err}",
            tmppath.display()
        );
        SpliceProxyError::CacheError
    })?;

    // Write ETag xattr if present.
    if let Some(ref etag) = upstream_resp.etag {
        write_etag(&tempfile, &temppath, etag);
    }
    // Persist upstream Last-Modified to xattr (RFC 9110 §10.2.2: forward origin's value)
    if let Some(ref lm) = upstream_resp.last_modified {
        write_last_modified(&tempfile, &temppath, lm);
    }

    // Transition barrier: InitBarrier → DownloadBarrier.
    let mut dbarrier: DownloadBarrier = ibarrier
        .download(
            temppath.to_path_buf(),
            ContentLength::Exact(total_content_length),
            reservation,
        )
        .await;

    let start = coarsetime::Instant::now();

    // Send response headers to client.
    let last_modified_str = upstream_resp.last_modified.as_deref().unwrap_or("");
    let content_type = content_type_for_cached_file(&conn_details.debname);
    if let Some(upstream_ct) = upstream_resp.content_type.as_deref()
        && !upstream_ct.eq_ignore_ascii_case(content_type)
    {
        warn!(
            "splice proxy: upstream Content-Type `{upstream_ct}` differs from expected `{content_type}` for {}",
            conn_details.debname
        );
    }
    let date = format_http_date();
    // Fresh response streamed straight from origin → Age is 0 per RFC 9111 §4.2.3.
    let age: u32 = 0;
    let (status_line, response_content_length) = if is_partial {
        ("206 Partial Content", client_range_len)
    } else {
        ("200 OK", body.len())
    };
    let response_headers = format!(
        "{conn_version} {status_line}\r\n\
         Date: {date}\r\n\
         Via: {APP_VIA}\r\n\
         Connection: {conn_action}\r\n\
         Content-Length: {response_content_length}\r\n\
         Content-Type: {content_type}\r\n\
         {last_modified_header}\
         {etag_header}\
         Accept-Ranges: bytes\r\n\
         Age: {age}\r\n\
         {content_range_header}\
         \r\n",
        last_modified_header = if last_modified_str.is_empty() {
            String::new()
        } else {
            format!("Last-Modified: {last_modified_str}\r\n")
        },
        etag_header = match upstream_resp.etag.as_deref() {
            Some(etag) => format!("ETag: {etag}\r\n"),
            None => String::new(),
        },
        content_range_header = if let Some(ref cr) = content_range_hdr {
            format!("Content-Range: {cr}\r\n")
        } else {
            String::new()
        },
    );

    // Cork to coalesce headers + body into fewer TCP segments.
    let cork = CorkGuard::new_optional(client_stream);

    trace!("Outgoing {status_line} response:\n{response_headers}");

    metrics::record_client_status(if is_partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    });
    write_all_to_stream(client_stream, response_headers.as_bytes())
        .await
        .map_err(|err| {
            let level = if err.kind() == std::io::ErrorKind::BrokenPipe {
                log::Level::Info
            } else {
                log::Level::Warn
            };
            log::log!(
                level,
                "splice proxy: failed to write response headers to client:  {err}"
            );
            SpliceProxyError::ClientError(err)
        })?;

    // Send body (range-filtered if needed) to client.
    let body_slice = &body[client_range_start..client_range_start + client_range_len];
    {
        let config = global_config();
        let mut volatile_rc = config
            .min_download_rate
            .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
        write_all_to_stream_rated(
            client_stream,
            body_slice,
            &mut volatile_rc,
            RateCheckDirection::Client,
            config.http_timeout,
        )
        .await
        .map_err(|err| {
            info!(
                "splice proxy: failed to write response body to client {}:  {err}",
                conn_details.client
            );
            SpliceProxyError::AfterHeaderError
        })?;
    }

    drop(cork);

    // Write full body to cache file.
    tempfile.write_all(&body).await.map_err(|err| {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to write volatile body to cache file `{}`:  {err}",
            temppath.display()
        );
        SpliceProxyError::AfterHeaderError
    })?;

    dbarrier.ping();

    // Sync cache file.
    if let Err(err) = tempfile.sync_all().await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to sync cache file `{}`:  {err}",
            temppath.display()
        );
    }
    drop(tempfile);

    // Move temp file to final cache path.
    let dest_file_path = dest_dir.join(filename);
    let rbarrier = dbarrier.begin_rename().await;

    match tokio::fs::rename(&temppath, &dest_file_path).await {
        Ok(()) => {
            TempPath::defuse(temppath);
            rbarrier.release(dest_file_path, total_content_length.get());
        }
        Err(err) => {
            drop(rbarrier);
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to rename temp file `{}` to `{}`:  {err}",
                temppath.display(),
                dest_file_path.display()
            );
            return Err(SpliceProxyError::AfterHeaderError);
        }
    }

    let elapsed = start.elapsed();

    info!(
        "Splice proxy{tls_label}: served and cached {} from mirror {} for client {} in {} (size={}, buffered volatile)",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client,
        HumanFmt::Time(elapsed.into()),
        HumanFmt::Size(total_content_length.get()),
    );

    // Record download in database (mirrors download_file() in main.rs).
    let cmd = DatabaseCommand::Download(DbCmdDownload {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: total_content_length.get(),
        elapsed,
        client_ip: conn_details.client.ip(),
    });
    send_db_command(cmd).await;

    // Record delivery in database.
    let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: total_content_length.get(),
        elapsed,
        partial: is_partial,
        client_ip: conn_details.client.ip(),
    });
    send_db_command(cmd).await;

    // Record origin in database (mirrors the hyper path in main.rs).
    if let Some(origin) = Origin::from_path(
        upstream_path,
        conn_details.mirror.host().clone(),
        conn_details.mirror.port(),
    ) {
        match origin.architecture.as_str() {
            "dep11" | "i18n" | "source" => (),
            _ => {
                let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
                send_db_command(cmd).await;
            }
        }
    }

    Ok(())
}

/// Simple (uncached) splice proxy for unrecognized resource paths.
///
/// Hop-by-hop headers per RFC 9110 §7.6.1 — must not be forwarded to the client.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Rewrite upstream response headers for the simple-proxy pass-through.
///
/// Strips hop-by-hop headers, drops `Content-Length` if `Transfer-Encoding:
/// chunked` is also present (RFC 9112 §6.1 defense against smuggling), and
/// emits exactly one `Connection:` header matching the client's keep-alive
/// decision regardless of how many `Connection:` headers the upstream sent
/// (they're hop-by-hop and therefore all dropped during the filter pass).
///
/// Extracted from `splice_simple_proxy` so the filtering invariants can be
/// unit-tested without requiring a live upstream socket.
fn rewrite_simple_proxy_headers(
    raw_headers: &[u8],
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    status_code: http::StatusCode,
) -> std::io::Result<String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
    let mut parsed = httparse::Response::new(&mut headers);
    if parsed.parse(raw_headers).is_err() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "failed to re-parse upstream headers for rewrite",
        ));
    }
    let has_chunked_te = parsed.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value).is_ok_and(|v| {
                v.split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("chunked"))
            })
    });

    let mut buf = format!("{conn_version} {status_code}\r\nConnection: {conn_action}\r\n");
    for h in parsed.headers.iter() {
        if HOP_BY_HOP.iter().any(|n| h.name.eq_ignore_ascii_case(n)) {
            continue;
        }
        if has_chunked_te && h.name.eq_ignore_ascii_case("content-length") {
            // RFC 9112 §6.1: drop Content-Length when Transfer-Encoding:
            // chunked is also present (defense against smuggling).
            continue;
        }
        // Reject non-ASCII header values: HTTP headers are ASCII per RFC
        // 9110 §5.5, and non-ASCII bytes smuggled via `from_utf8_lossy`
        // would silently introduce U+FFFD replacement chars into the
        // rewritten headers.
        let Ok(value) = std::str::from_utf8(h.value) else {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("non-UTF8 value for header `{}`", h.name),
            ));
        };
        if value
            .bytes()
            .any(|b| !b.is_ascii() || b == b'\r' || b == b'\n')
        {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("invalid bytes in header `{}` value", h.name),
            ));
        }
        buf.push_str(h.name);
        buf.push_str(": ");
        buf.push_str(value);
        buf.push_str("\r\n");
    }
    buf.push_str("Via: ");
    buf.push_str(APP_VIA);
    buf.push_str("\r\n");
    buf.push_str("\r\n");
    Ok(buf)
}

/// Connects to upstream, sends a GET request, and forwards the complete response
/// (headers + body) to the client.  No caching, no active-download tracking,
/// no resume handling — just a transparent relay.
pub(crate) async fn splice_simple_proxy(
    client_stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    mirror: &Mirror,
    upstream_path: &str,
) -> Result<(), SpliceProxyError> {
    let host_authority = mirror.format_authority();

    let (up, resp, hdr_buf, hdr_end, _label, poolable) =
        standard_upstream_connect(mirror, &host_authority, upstream_path, 0, None, None).await?;

    let port = mirror_port(mirror, up.is_tls());

    debug!(
        "simple proxy: upstream returned {} for {upstream_path} from {host_authority}",
        resp.status_code
    );

    let mut upstream = PoolGuard::new(up, mirror.host().to_string(), port, poolable);

    // Rewrite response headers: adjust HTTP version and Connection header
    // to match the client's protocol version and keep-alive strategy.
    let rewritten_headers = match rewrite_simple_proxy_headers(
        &hdr_buf[..hdr_end],
        conn_version,
        conn_action,
        resp.status_code,
    ) {
        Ok(s) => s,
        Err(err) => {
            upstream.unset_poolable();
            return Err(SpliceProxyError::UpstreamError(err));
        }
    };

    trace!("Outgoing rewritten headers:\n{rewritten_headers}");

    metrics::record_client_status(resp.status_code);
    metrics::REQUESTS_PASSTHROUGH.increment();
    write_all_to_stream(client_stream, rewritten_headers.as_bytes())
        .await
        .map_err(SpliceProxyError::ClientError)?;

    // Forward any body data that arrived with the headers
    let body_prefix = &hdr_buf[hdr_end..];

    let config = global_config();
    let mut prefix_client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    // Forward the remaining body.
    //
    // Framing priority: chunked takes precedence over Content-Length when
    // both are present.  RFC 9112 §6.1 requires that Content-Length be
    // ignored when Transfer-Encoding: chunked is also set (defense against
    // request/response smuggling), and the header rewrite above already
    // strips Content-Length in that case — so we must frame the body the
    // same way the client will be reading it.
    if resp.is_chunked {
        // Chunked encoding: forward raw framing, detect termination
        forward_upstream_chunked_body(&mut upstream, client_stream, body_prefix, VOLATILE_BODY_MAX)
            .await
            .map_err(|err| {
                info!("splice proxy: failed to forward chunked body to client:  {err}");
                SpliceProxyError::AfterHeaderError
            })?;
    } else if let Some(cl) = resp.content_length {
        if !body_prefix.is_empty() {
            write_all_to_stream_rated(
                client_stream,
                body_prefix,
                &mut prefix_client_rate_checker,
                RateCheckDirection::Client,
                config.http_timeout,
            )
            .await
            .map_err(|err| {
                info!("splice proxy: failed to write body prefix to client:  {err}");
                SpliceProxyError::AfterHeaderError
            })?;
            metrics::BYTES_SERVED_PASSTHROUGH.increment_by(body_prefix.len() as u64);
        }
        let already_sent = body_prefix.len() as u64;
        let remaining = cl.saturating_sub(already_sent);
        if remaining > 0 {
            forward_upstream_body(&mut upstream, client_stream, remaining)
                .await
                .map_err(|err| {
                    info!("splice proxy: failed to forward body to client:  {err}");
                    SpliceProxyError::AfterHeaderError
                })?;
        }
    } else {
        // No Content-Length and not chunked: read until EOF
        if !body_prefix.is_empty() {
            write_all_to_stream_rated(
                client_stream,
                body_prefix,
                &mut prefix_client_rate_checker,
                RateCheckDirection::Client,
                config.http_timeout,
            )
            .await
            .map_err(|err| {
                info!("splice proxy: failed to write body prefix to client:  {err}");
                SpliceProxyError::AfterHeaderError
            })?;
            metrics::BYTES_SERVED_PASSTHROUGH.increment_by(body_prefix.len() as u64);
        }
        upstream.unset_poolable();
        forward_upstream_body_until_eof(&mut upstream, client_stream, VOLATILE_BODY_MAX)
            .await
            .map_err(|err| {
                info!("splice proxy: failed to forward body to client:  {err}");
                SpliceProxyError::AfterHeaderError
            })?;
    }

    // PoolGuard::drop handles returning the connection to pool if poolable
    Ok(())
}

/// Successful outcomes of [`splice_proxy`]. `Concurrent` is an alternate
/// success path, not an error: another download for the same key won the
/// originate race, and the carried `status` lets the caller serve the client
/// from the in-flight partial via the sendfile backend without falling back
/// to hyper. Late-joiner accounting was already performed inside
/// [`crate::ActiveDownloads::originate`].
pub(crate) enum SpliceProxyOutcome {
    Served,
    Concurrent {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
}

/// Errors that can occur during splice proxy.
pub(crate) enum SpliceProxyError {
    /// Not applicable for splice proxy; fall back to hyper
    NotApplicable(&'static str),
    /// Error communicating with upstream
    UpstreamError(std::io::Error),
    /// Error writing to client
    ClientError(std::io::Error),
    /// Error with cache file operations
    CacheError,
    /// Error during body transfer
    TransferError,
    /// Error occurring after response headers were already written to the client.
    /// The caller must close the connection without emitting a new HTTP status.
    AfterHeaderError,
}

#[cfg(test)]
mod tests {
    use nix::fcntl::{FcntlArg, fcntl};

    use super::*;

    #[test]
    fn test_rewrite_simple_proxy_headers_single_connection() {
        // Upstream sends two Connection headers; the rewrite must emit
        // exactly one (ours), regardless of how many the upstream sent.
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Connection: keep-alive\r\n\
                    Connection: close\r\n\
                    Content-Type: text/plain\r\n\
                    Content-Length: 5\r\n\
                    \r\n";
        let out = rewrite_simple_proxy_headers(
            raw,
            ConnectionVersion::Http11,
            ConnectionAction::KeepAlive,
            http::StatusCode::OK,
        )
        .expect("rewrite should succeed");

        let connection_lines = out
            .split("\r\n")
            .filter(|line| line.to_ascii_lowercase().starts_with("connection:"))
            .count();
        assert_eq!(
            connection_lines, 1,
            "expected exactly one Connection header in rewritten output, got:\n{out}"
        );
        assert!(out.contains("Connection: keep-alive\r\n"));
        // Upstream's Connection values must not be forwarded.
        assert!(!out.contains("Connection: close"));
        // Content-Length passes through when no chunked TE is present.
        assert!(out.contains("Content-Length: 5\r\n"));
        assert!(out.contains("Via: "));
    }

    #[test]
    fn test_rewrite_simple_proxy_headers_drops_cl_with_chunked() {
        // RFC 9112 §6.1: Content-Length must be dropped when Transfer-Encoding:
        // chunked is also present (smuggling defense).
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Content-Length: 12345\r\n\
                    \r\n";
        let out = rewrite_simple_proxy_headers(
            raw,
            ConnectionVersion::Http11,
            ConnectionAction::Close,
            http::StatusCode::OK,
        )
        .expect("rewrite should succeed");
        assert!(!out.to_ascii_lowercase().contains("content-length:"));
        assert!(out.contains("Transfer-Encoding: chunked\r\n"));
    }

    #[tokio::test]
    async fn test_create_pipe() {
        let (tx, rx) = create_pipe().expect("pipe creation should succeed");
        // Verify the fds are valid (non-negative)
        assert!(rx.as_raw_fd() >= 0);
        assert!(tx.as_raw_fd() >= 0);
        assert_ne!(rx.as_raw_fd(), tx.as_raw_fd());
        // `create_pipe()` treats pipe resizing as best-effort, so do not
        // require the kernel to honor `PIPE_BUFFER_SIZE` exactly here.
        let size = fcntl(rx.as_fd(), FcntlArg::F_GETPIPE_SZ).unwrap();
        assert!(
            size >= 64 * 1024,
            "pipe size shouldn't be too small, got {size}"
        );
    }

    #[test]
    fn test_parse_upstream_response() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 12345\r\n\
                        Content-Type: application/vnd.debian.binary-package\r\n\
                        Last-Modified: Thu, 01 Jan 2025 00:00:00 GMT\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length, Some(12345));
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
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length, None);
        assert!(resp.is_chunked);
    }

    #[test]
    fn test_parse_upstream_response_not_chunked() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert!(!resp.is_chunked);
        assert_eq!(resp.content_length, Some(42));
    }

    #[test]
    fn test_parse_upstream_response_404() {
        let headers = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.status_code, 404);
    }

    #[test]
    fn test_range_slice_no_overlap_before() {
        let buf = &[10, 20, 30, 40, 50];
        // buf covers file bytes [100, 105), range is [0, 50) — no overlap
        assert_eq!(range_slice(buf, 100, 0, 50), &[] as &[u8]);
    }

    #[test]
    fn test_range_slice_no_overlap_after() {
        let buf = &[10, 20, 30, 40, 50];
        // buf covers [100, 105), range is [200, 50) — no overlap
        assert_eq!(range_slice(buf, 100, 200, 50), &[] as &[u8]);
    }

    #[test]
    fn test_range_slice_full_overlap() {
        let buf = &[10, 20, 30, 40, 50];
        // buf covers [100, 105), range is [0, 200) — buf entirely inside range
        assert_eq!(range_slice(buf, 100, 0, 200), buf);
    }

    #[test]
    fn test_range_slice_exact_match() {
        let buf = &[10, 20, 30, 40, 50];
        // buf covers [100, 105), range is [100, 5) — exact match
        assert_eq!(range_slice(buf, 100, 100, 5), buf);
    }

    #[test]
    fn test_range_slice_partial_start() {
        let buf = &[10, 20, 30, 40, 50];
        // buf covers [100, 105), range starts at 102 — skip first 2 bytes
        assert_eq!(range_slice(buf, 100, 102, 100), &[30, 40, 50]);
    }

    #[test]
    fn test_range_slice_partial_end() {
        let buf = &[10, 20, 30, 40, 50];
        // buf covers [100, 105), range is [0, 103) — only first 3 bytes overlap
        assert_eq!(range_slice(buf, 100, 0, 103), &[10, 20, 30]);
    }

    #[test]
    fn test_range_slice_partial_both_ends() {
        let buf = &[10, 20, 30, 40, 50];
        // buf covers [100, 105), range is [101, 3) = [101, 104) — middle 3 bytes
        assert_eq!(range_slice(buf, 100, 101, 3), &[20, 30, 40]);
    }

    #[test]
    fn test_range_slice_single_byte() {
        let buf = &[10, 20, 30, 40, 50];
        // range is [102, 1) = [102, 103) — single byte at offset 2
        assert_eq!(range_slice(buf, 100, 102, 1), &[30]);
    }

    #[test]
    fn test_range_slice_zero_length_range() {
        let buf = &[10, 20, 30, 40, 50];
        // zero-length range
        assert_eq!(range_slice(buf, 100, 102, 0), &[] as &[u8]);
    }

    #[test]
    fn test_range_slice_empty_buf() {
        let buf: &[u8] = &[];
        assert_eq!(range_slice(buf, 100, 100, 50), &[] as &[u8]);
    }

    #[test]
    fn test_range_slice_adjacent_no_overlap() {
        let buf = &[10, 20, 30];
        // buf covers [100, 103), range is [103, 5) — adjacent, no overlap
        assert_eq!(range_slice(buf, 100, 103, 5), &[] as &[u8]);
        // range is [97, 3) = [97, 100) — adjacent before, no overlap
        assert_eq!(range_slice(buf, 100, 97, 3), &[] as &[u8]);
    }

    #[test]
    fn test_range_slice_one_byte_overlap_at_boundary() {
        let buf = &[10, 20, 30];
        // buf covers [100, 103), range is [102, 5) = [102, 107) — 1 byte overlap at end
        assert_eq!(range_slice(buf, 100, 102, 5), &[30]);
        // range is [99, 2) = [99, 101) — 1 byte overlap at start
        assert_eq!(range_slice(buf, 100, 99, 2), &[10]);
    }

    #[test]
    fn test_mirror_port_defaults() {
        let mirror = Mirror::new(
            DomainName::new("example.com".into()).unwrap(),
            None,
            String::new(),
        );
        assert_eq!(mirror_port(&mirror, false), 80);
        assert_eq!(mirror_port(&mirror, true), 443);
    }

    #[test]
    fn test_mirror_port_explicit() {
        let mirror = Mirror::new(
            DomainName::new("example.com".into()).unwrap(),
            Some(NonZero::new(8080).unwrap()),
            String::new(),
        );
        assert_eq!(mirror_port(&mirror, false), 8080);
        assert_eq!(mirror_port(&mirror, true), 8080);
    }

    #[test]
    fn test_parse_upstream_response_etag() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        ETag: \"abc123\"\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.etag.as_deref(), Some("\"abc123\""));
    }

    #[test]
    fn test_parse_upstream_response_invalid_etag_ignored() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        ETag: not-a-valid-etag\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.etag, None);
    }

    #[test]
    fn test_parse_upstream_response_content_range() {
        let headers = b"HTTP/1.1 206 Partial Content\r\n\
                        Content-Length: 500\r\n\
                        Content-Range: bytes 100-599/1000\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.status_code, 206);
        assert_eq!(resp.content_range.as_deref(), Some("bytes 100-599/1000"));
    }

    #[test]
    fn test_parse_upstream_response_connection_close() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        Connection: close\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert!(resp.connection_close);
    }

    #[test]
    fn test_parse_upstream_response_connection_keep_alive() {
        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 100\r\n\
                        Connection: keep-alive\r\n\
                        \r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert!(!resp.connection_close);
    }

    #[test]
    fn test_parse_upstream_response_no_connection_header() {
        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
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
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.content_length, Some(42));
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
        assert!(parse_upstream_response(garbage, garbage.len()).is_err());
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
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length, Some(999));
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
        let resp = parse_upstream_response(headers, headers.len()).expect("should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length, None);
        assert_eq!(resp.content_type, None);
        assert_eq!(resp.last_modified, None);
        assert_eq!(resp.etag, None);
        assert_eq!(resp.content_range, None);
        assert!(!resp.connection_close);
    }

    #[cfg(feature = "ktls")]
    #[test]
    fn test_discard_incoming() {
        let mut buf = [0u8; 16];
        buf[..6].copy_from_slice(b"abcdef");
        let mut used = 6;

        // Discard first 3 bytes: "def" remains
        discard_incoming(&mut buf, &mut used, 3);
        assert_eq!(used, 3);
        assert_eq!(&buf[..used], b"def");

        // Discard 0 bytes: no change
        discard_incoming(&mut buf, &mut used, 0);
        assert_eq!(used, 3);
        assert_eq!(&buf[..used], b"def");

        // Discard all remaining
        discard_incoming(&mut buf, &mut used, 3);
        assert_eq!(used, 0);
    }
}
