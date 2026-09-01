use std::{
    io::ErrorKind,
    num::{NonZero, Saturating},
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};

use bytes::BytesMut;
use hashbrown::hash_map::EntryRef;
use http::{
    StatusCode,
    header::{
        CONNECTION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, LAST_MODIFIED, LOCATION,
        TRANSFER_ENCODING,
    },
};
use nix::fcntl::{SpliceFFlags, splice, tee};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf},
    net::{TcpStream, unix::pipe},
};
use tracing::{debug, error, info, trace, warn};

use crate::cache_conditional::RangeRequestHeaders;
use crate::cache_layout;
use crate::cache_layout::{CachedFlavor, ConnectionDetails, SUBDIR_TMP};
use crate::cache_quota::QuotaExceeded;
use crate::config::ClientHost;
use crate::database_task::{
    DatabaseCommand, DbCmdOrigin, DbCmdTransfer, TransferKind, send_db_command,
};
use crate::deb_mirror::{Mirror, MirrorKind, Origin};
use crate::error::{ErrorReport, errno_to_io_error};
use crate::guards::{DownloadBarrier, InitBarrier};
use crate::http_etag::write_etag;
use crate::http_helpers::{
    ConnectionAction, ConnectionVersion, OptHeader, WritePhase, find_header, write_416_response,
    write_all_to_stream, write_invalid_response,
};
use crate::http_last_modified::write_last_modified;
use crate::http_range::{
    HttpDate, ParsedRange, format_http_date, http_parse_range, parse_content_range,
};
use crate::humanfmt::HumanFmt;
#[cfg(feature = "ktls")]
use crate::ktls;
#[cfg(feature = "ktls")]
use crate::ktls::UlpAttachError;
#[cfg(feature = "ktls")]
use crate::ktls_handshake::{discard_incoming, encode_tls_data, grow_incoming};
#[cfg(not(feature = "hyper"))]
use crate::limits;
use crate::limits::{MAX_UPSTREAM_HEADER_SIZE, MAX_UPSTREAM_HEADERS};
use crate::precise_instant::PreciseInstant;
use crate::rate_checker::{RateCheckDirection, RateChecker};
use crate::rate_log;
use crate::scheme_cache::SchemeDecision;
#[cfg(feature = "ktls")]
use crate::secure_vec::SecureVec;
use crate::sendfile_conn::{
    SendfileResult, async_sendfile, async_sendfile_unfinished, clear_tcp_readable_cache,
    clear_tcp_writable_cache, serve_file_via_sendfile, wait_readable_rated, wait_writable_rated,
    write_all_to_stream_rated,
};
use crate::tcp_cork_guard::CorkGuard;
use crate::upstream_head::{
    DownloadPlan, RejectReason, ResumeAnomaly, ResumeState, UpstreamHead, plan_download,
    plan_fresh_download,
};
use crate::utils::{
    self, CacheAccessFailure, hint_sequential_read, is_peer_disconnect, regular_file_metadata,
    tokio_nofollow_options, tokio_tempfile, touch_volatile_mtime,
};
use crate::xattr_helpers;
use crate::{
    APP_USER_AGENT, APP_VIA, AppState, ClientInfo, ContentLength, Never, Scheme,
    VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER,
    active_downloads::{ActiveDownloadStatus, OriginateOutcome},
    cache_metadata::{self, InvalidValidator},
    client_counter, content_type_for_cached_file, global_cache_quota, global_config,
    global_verify_throttle, metrics,
    permitted_host_cache::is_host_allowed_cached,
    scheme_cache, static_assert, upstream_retry, warn_on_content_type_mismatch, warn_once,
    warn_once_or_debug, warn_once_or_info,
};
#[cfg(feature = "ktls")]
use crate::{KTLS_BLOCKED, SchemeKey, SchemeKeyRef};
#[cfg(not(feature = "hyper"))]
use crate::{ProxyCacheBody, VOLATILE_CACHE_MAX_AGE, error::UpstreamFetchError, full_body};

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
    if_none_match: Option<Arc<str>>,
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

/// Dedicated TLS client config for the kTLS handshake path, cloned from
/// `TLS_CLIENT_CONFIG` with `enable_secret_extraction` set. Secret extraction
/// hands raw traffic secrets to the kernel and is confined to this config —
/// the plain userspace-TLS fallback (`tls_connect`, via `TLS_CLIENT_CONFIG`)
/// never needs extractable secrets. Cloning shares the `resumption` session
/// store (an `Arc<ClientSessionMemoryCache>` internally) with
/// `TLS_CLIENT_CONFIG`, so session tickets learned on one path still benefit
/// the other.
/// Should only be initialized once from main.
#[cfg(feature = "ktls")]
pub(crate) static KTLS_CLIENT_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// Default pipe buffer size on Linux is 16 pages (64 KiB on most systems).
/// We increase it to 1 MiB to reduce the number of splice syscall pairs needed.
const PIPE_BUFFER_SIZE: i32 = 1024 * 1024;

/// How long an idle pooled connection is kept before eviction.
const POOL_IDLE_TIMEOUT: coarsetime::Duration = coarsetime::Duration::from_secs(90);

/// Maximum number of idle connections kept per host.
const POOL_MAX_IDLE_PER_HOST: usize = 4;

/// Buffer size for TLS upstream reads.  TLS records are at most 16 KiB, so
/// a larger buffer amortizes the per-chunk pwrite+write pair — 256 KiB
/// costs one allocation per concurrent userspace-TLS download (not per
/// connection) and quarters the loop iterations per MiB.
const TLS_READ_BUF_SIZE: usize = 256 * 1024;

/// Cadence of the upstream rate-check tick in `splice_proxy_body_tls`'s
/// read loop.
const RATE_TICK_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

/// Maximum bytes to forward for volatile responses (no Content-Length / chunked non-cacheable).
const VOLATILE_BODY_MAX: usize = 1024 * 1024;

/// How long to remember kTLS setup failures before retrying.
#[cfg(feature = "ktls")]
const KTLS_BLOCK_DURATION: coarsetime::Duration = coarsetime::Duration::from_secs(600);

/// `tls_label` value for a kTLS-offloaded upstream connection. Doubles as the
/// kTLS marker at body-transfer time: every reconnect helper updates
/// `tls_label`, so it always describes the *current* upstream connection.
#[cfg(feature = "ktls")]
const KTLS_TLS_LABEL: &str = " (kTLS)";

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

/// Block kTLS for `key` for `KTLS_BLOCK_DURATION`, sweeping stale entries
/// while the write lock is held.
#[cfg(feature = "ktls")]
fn block_ktls_host(key: &SchemeKeyRef<'_>) {
    let key = SchemeKey {
        host: key.host.to_owned(),
        port: key.port,
    };
    let now = coarsetime::Instant::now();
    let mut blocked = KTLS_BLOCKED.get().expect("Initialized in main()").write();
    // Opportunistic GC: we already hold the write lock, so sweep out any
    // stale entries. This prevents entries for one-shot hosts from
    // accumulating indefinitely.
    blocked.retain(|_, at| now.duration_since(*at) < KTLS_BLOCK_DURATION);
    blocked.insert(key, now);
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
    Tls(#[pin] TlsStream),
}

/// Userspace-TLS upstream stream of the selected TLS backend. The one `cfg`
/// pair here keeps every `UpstreamConn::Tls` match arm backend-agnostic.
#[cfg(feature = "tls_rustls")]
type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
type TlsStream = tokio_native_tls::TlsStream<TcpStream>;

impl AsyncRead for UpstreamConn {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_read(cx, buf),
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
            UpstreamConnProj::Tls(s) => s.poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_flush(cx),
            UpstreamConnProj::Tls(s) => s.poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_shutdown(cx),
            UpstreamConnProj::Tls(s) => s.poll_shutdown(cx),
        }
    }
}

impl UpstreamConn {
    #[must_use]
    const fn is_tls(&self) -> bool {
        match self {
            Self::Tcp(_) => false,
            Self::Tls(_) => true,
        }
    }

    /// For the TCP variant, get a reference to the inner `TcpStream`.
    /// Returns `None` for TLS connections.
    #[must_use]
    const fn as_tcp(&self) -> Option<&TcpStream> {
        match self {
            Self::Tcp(s) => Some(s),
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
        let Self {
            0: host,
            1: port,
            2: is_tls,
        } = self;
        let (khost, kport, kis_tls) = key;
        host == khost && port == kport && is_tls == kis_tls
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
        match conns.pop() {
            Some(entry) if now.duration_since(entry.idle_since) < POOL_IDLE_TIMEOUT => {
                break Some(entry.conn);
            }
            Some(_) => {
                debug!("splice proxy: discarding stale pooled connection to {host}:{port}");
            }
            None => break None,
        }
    };
    if conns.is_empty() {
        map.remove(&key_ref);
    }
    drop(map);
    let conn = conn?;
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
    poolable: bool,
}

impl PoolGuard {
    /// Creates a new `PoolGuard` wrapping the given `UpstreamConn`.
    fn new(conn: UpstreamConn, host: String, port: u16, poolable: bool) -> Self {
        Self {
            conn: Some(conn),
            host,
            port,
            poolable,
        }
    }

    /// Marks the connection as non-poolable, preventing it from being returned to the pool on drop.
    fn unset_poolable(&mut self) {
        self.poolable = false;
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
            // Derive from the connection itself rather than caching it in a
            // field that could drift from `conn`'s actual scheme.
            pool_return(&self.host, self.port, conn.is_tls(), conn);
        }
    }
}

/// RAII poison for a pooled upstream connection whose response body has not
/// yet been fully drained from the socket. While this guard is alive, any
/// drop (i.e. any early return in the download body) marks the wrapped
/// `PoolGuard` non-poolable, so a half-read connection can never re-enter the
/// pool. Call [`UnconsumedBodyGuard::consumed`] once the body has been fully
/// read to defuse it.
struct UnconsumedBodyGuard<'g> {
    upstream: &'g mut PoolGuard,
    consumed: bool,
}

impl<'g> UnconsumedBodyGuard<'g> {
    fn new(upstream: &'g mut PoolGuard) -> Self {
        Self {
            upstream,
            consumed: false,
        }
    }

    /// Defuse: the response body has been fully drained, so the connection's
    /// existing `poolable` decision (from `Connection:` keep-alive) stands.
    fn consumed(&mut self) {
        self.consumed = true;
    }
}

impl Drop for UnconsumedBodyGuard<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            self.upstream.unset_poolable();
        }
    }
}

impl std::ops::Deref for UnconsumedBodyGuard<'_> {
    type Target = PoolGuard;
    fn deref(&self) -> &PoolGuard {
        self.upstream
    }
}

impl std::ops::DerefMut for UnconsumedBodyGuard<'_> {
    fn deref_mut(&mut self) -> &mut PoolGuard {
        self.upstream
    }
}

/// One upstream request/response in flight: the pool-guarded connection the
/// response arrived on, its parsed head, and the bytes read alongside it
/// (`header_buf[header_end..]` is the body prefix). Built only by
/// [`standard_upstream_connect`] and the kTLS `Ready` arm of
/// [`acquire_upstream`], and replaced wholesale by the reconnect helpers
/// ([`follow_redirect`], [`discard_partial_and_retry`]), so every field always
/// describes the same connection.
struct UpstreamExchange {
    conn: PoolGuard,
    response: UpstreamResponse,
    header_buf: BytesMut,
    header_end: usize,
    /// Log suffix naming the connection flavour (TLS-ness, pool reuse).
    tls_label: &'static str,
}

/// Outcome of [`acquire_upstream`].
#[cfg_attr(
    feature = "ktls",
    expect(
        clippy::large_enum_variant,
        reason = "Exchange is the overwhelmingly common variant; boxing it would cost an allocation per download"
    )
)]
enum UpstreamAcquire {
    /// Response head in hand on a live connection.
    Exchange(UpstreamExchange),
    /// The kTLS attempt's 200 has no usable Content-Length and the planner
    /// refused it (already logged and counted, upstream status recorded). No
    /// connection is left: the caller answers 502 with `reason.body()`.
    #[cfg(feature = "ktls")]
    KtlsReject(RejectReason),
    /// The kTLS attempt got a 304 for a volatile file whose cached copy lives
    /// at this path (upstream status recorded). No connection is left: the
    /// caller serves the cached file.
    #[cfg(feature = "ktls")]
    KtlsNotModified(PathBuf),
}

impl UpstreamConn {
    /// Check if a pooled connection is still alive (not closed by the remote).
    ///
    /// For TLS connections on rustls we peek at the raw TCP socket: a closed
    /// peer (recv → 0) or error rules the connection out, while pending bytes
    /// on an idle pooled TLS connection almost certainly indicate a `close_notify`
    /// alert and are treated the same. The native-tls backend does not expose
    /// the underlying TCP fd cleanly, so we remain optimistic there.
    fn check_alive(&self, host: &str, port: u16) -> bool {
        fn tcp_peek_alive(fd: std::os::fd::RawFd, host: &str, port: u16) -> bool {
            use nix::sys::socket::{MsgFlags, recv};

            let mut buf = [0u8; 1];

            match recv(fd, &mut buf, MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT) {
                Ok(0) | Err(nix::errno::Errno::ECONNRESET) => {
                    debug!("splice proxy: pooled connection to {host}:{port} closed by peer");
                    false
                }
                Ok(pending) => {
                    debug_assert_eq!(pending, 1, "buffer has size of 1");
                    warn_once_or_debug!(
                        "splice proxy: pooled connection to {host}:{port} has unexpected data; discarding it and connecting fresh"
                    );
                    false
                }
                // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                Err(nix::errno::Errno::EAGAIN) => true,
                Err(errno) => {
                    warn_once_or_info!(
                        "splice proxy: failed to check the pooled connection to {host}:{port}; discarding it and connecting fresh:  {}",
                        ErrorReport(&errno)
                    );
                    false
                }
            }
        }

        /// rustls exposes the underlying TCP socket, so peek at it.
        #[cfg(feature = "tls_rustls")]
        fn tls_peek_alive(tls: &TlsStream, host: &str, port: u16) -> bool {
            let (tcp, _) = tls.get_ref();
            tcp_peek_alive(tcp.as_raw_fd(), host, port)
        }

        /// native-tls hides the socket: stay optimistic.
        #[cfg(not(feature = "tls_rustls"))]
        fn tls_peek_alive(_tls: &TlsStream, _host: &str, _port: u16) -> bool {
            true
        }

        match self {
            Self::Tcp(tcp) => tcp_peek_alive(tcp.as_raw_fd(), host, port),
            Self::Tls(tls) => tls_peek_alive(tls, host, port),
        }
    }
}

/// Process-wide write-only handle to `/dev/null` used by [`drain_pipe`] as the
/// destination of `splice(2)` calls that discard pipe contents.
///
/// Opened lazily on first use; held for the lifetime of the process. The fd is
/// `O_NONBLOCK` so `splice(2)` never parks a Tokio runtime thread when the pipe
/// has data ready — `/dev/null` accepts any amount instantly, so the syscall
/// either returns the bytes-moved count or `EAGAIN` (only the pipe side can
/// stall).
static DEV_NULL: OnceLock<std::fs::File> = OnceLock::new();

/// Return a shared, lazily-opened handle to `/dev/null`. The first call opens
/// the file; subsequent calls return the cached handle.
fn dev_null() -> std::io::Result<&'static std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(f) = DEV_NULL.get() {
        return Ok(f);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "/dev/null sink, not a cache path; needs its own custom_flags which would overwrite the helper's O_NOFOLLOW"
    )]
    let f = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open("/dev/null")?;
    Ok(DEV_NULL.get_or_init(|| f))
}

/// Create a pipe and optionally increase its buffer size.
fn create_pipe() -> std::io::Result<(pipe::Sender, pipe::Receiver)> {
    use nix::fcntl::{FcntlArg, fcntl};

    let (sender, receiver) = pipe::pipe()?;

    // Try to increase pipe buffer size; ignore failure (non-fatal, just fewer bytes per round-trip)
    static_assert!(PIPE_BUFFER_SIZE > 0);
    if let Err(errno) = fcntl(sender.as_fd(), FcntlArg::F_SETPIPE_SZ(PIPE_BUFFER_SIZE)) {
        warn_once_or_info!(
            "splice proxy: failed to increase the pipe buffer size; continuing with the default size:  {}",
            ErrorReport(&errno)
        );
    }

    Ok((sender, receiver))
}

// Force-clear Tokio's cached readiness on a pipe end. See
// `sendfile_conn::clear_tcp_writable_cache` for the rationale (the TCP
// variants live there so the sendfile path can share them).

fn clear_pipe_readable_cache(receiver: &pipe::Receiver) {
    let _ignore = receiver.try_io(|| -> std::io::Result<()> { Err(ErrorKind::WouldBlock.into()) });
}

fn clear_pipe_writable_cache(sender: &pipe::Sender) {
    let _ignore = sender.try_io(|| -> std::io::Result<()> { Err(ErrorKind::WouldBlock.into()) });
}

// ---------------------------------------------------------------------------
// Socket-to-socket splice proxy
// ---------------------------------------------------------------------------

/// An upstream connect failure, tagged with whether retrying it can plausibly
/// succeed. Retrying a deterministic failure costs a full TCP connect plus a
/// full TLS handshake per attempt and buys nothing.
enum ConnectError {
    /// DNS/TCP failure, timeout, or a network error mid-handshake -- retry may help.
    Transient(std::io::Error),
    /// Deterministic for this (host, scheme): unparsable server name, certificate
    /// rejection. Retrying re-runs the same handshake and fails identically.
    Permanent(std::io::Error),
}

impl ConnectError {
    /// The wrapped error, for `ErrorReport` logging.
    fn io_err(&self) -> &std::io::Error {
        match self {
            Self::Transient(err) | Self::Permanent(err) => err,
        }
    }
}

/// The retry disposition of a connect failure -- the pure half of
/// [`ConnectError`], split out so [`classify_tls_error`] stays unit-testable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectRetry {
    Transient,
    Permanent,
}

impl ConnectRetry {
    /// Pair the disposition with the error it was derived from.
    fn attach(self, err: std::io::Error) -> ConnectError {
        match self {
            Self::Transient => ConnectError::Transient(err),
            Self::Permanent => ConnectError::Permanent(err),
        }
    }
}

/// Decide whether a failed TLS handshake is worth retrying.
///
/// `InvalidData` (rustls rejecting the peer certificate or its TLS records) and
/// `InvalidInput` (an unparsable server name) are a pure function of the host
/// string and the peer's certificate chain: a retry re-runs the identical
/// handshake and fails identically. Everything else -- including `TimedOut` --
/// may be a transport hiccup.
///
/// Pass the kind of the *original* error, before it is wrapped: a wrapper
/// reports its own kind and keeps the cause behind `source()`.
const fn classify_tls_error(kind: ErrorKind) -> ConnectRetry {
    if matches!(kind, ErrorKind::InvalidData | ErrorKind::InvalidInput) {
        ConnectRetry::Permanent
    } else {
        ConnectRetry::Transient
    }
}

/// Connect to the upstream mirror, optionally establishing TLS.
///
/// `scheme` is resolved by the caller: `Some(_)` connects with that scheme
/// directly, `None` is the Auto-upgrade case -- try HTTPS first, fall back to HTTP.
/// Only the error that escapes here is classified for the caller's retry loop;
/// a permanent TLS failure inside the Auto branch still falls back to HTTP.
///
/// Times out after the configured HTTP timeout.
async fn connect_upstream(
    mirror: &Mirror,
    scheme: Option<Scheme>,
) -> Result<(UpstreamConn, Scheme), ConnectError> {
    let host = mirror.host().as_str();

    match scheme {
        Some(Scheme::Http) => {
            let tcp = tcp_connect(host, mirror_port(mirror, false))
                .await
                .map_err(ConnectError::Transient)?;
            Ok((UpstreamConn::Tcp(tcp), Scheme::Http))
        }
        Some(Scheme::Https) => {
            let tcp = tcp_connect(host, mirror_port(mirror, true))
                .await
                .map_err(ConnectError::Transient)?;
            let tls = tls_connect(tcp, host).await.inspect_err(|_| {
                metrics::UPSTREAM_TLS_FAILED.increment();
            })?;
            Ok((UpstreamConn::Tls(tls), Scheme::Https))
        }
        None => {
            // Auto mode: try HTTPS first, fall back to HTTP
            // TODO: retry HTTPS after small period, fall back to HTTP
            match tcp_connect(host, mirror_port(mirror, true)).await {
                Ok(tcp) => match tls_connect(tcp, host).await {
                    Ok(tls) => {
                        debug!(
                            "splice proxy: HTTPS upgrade succeeded for {}",
                            mirror.format_authority()
                        );
                        return Ok((UpstreamConn::Tls(tls), Scheme::Https));
                    }
                    Err(err) => {
                        // Deliberately not propagated: the HTTP fallback below is
                        // the point of Auto mode, so even a permanent TLS failure
                        // must not abort it.
                        metrics::UPSTREAM_TLS_FAILED.increment();
                        debug!(
                            "splice proxy: TLS handshake failed for {}, trying HTTP:  {}",
                            mirror.format_authority(),
                            ErrorReport(err.io_err())
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

            let tcp = tcp_connect(host, mirror_port(mirror, false))
                .await
                .map_err(ConnectError::Transient)?;
            Ok((UpstreamConn::Tcp(tcp), Scheme::Http))
        }
    }
}

/// Establish a TCP connection to the given host and port.
///
/// Times out after the configured HTTP timeout.
async fn tcp_connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
    let http_timeout = global_config().http_timeout;
    tokio::time::timeout(http_timeout, TcpStream::connect((host, port)))
        .await
        .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| {
            // A connect timeout is a TCP setup failure too: classify it under
            // both the timeout-specific counter and the broad connect-failed
            // counter so dashboards summing UPSTREAM_CONNECT_FAILED see all
            // TCP setup losses, not just non-timeout errors.
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
            metrics::UPSTREAM_CONNECT_FAILED.increment();
            std::io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "upstream TCP connect timed out after {}",
                    HumanFmt::Time(http_timeout)
                ),
            )
        })?
        .map_err(|err| {
            metrics::UPSTREAM_CONNECT_FAILED.increment();
            std::io::Error::new(
                err.kind(),
                format!("TCP connect to upstream failed:  {err}"),
            )
        })
        .inspect(|tcp| {
            // Disable Nagle on upstream connections.  Mirror requests are mostly
            // small headers followed by a long body, so up to a 40 ms ACK delay
            // between segments is dead time we can avoid.
            if global_config().upstream_tcp_nodelay
                && let Err(err) = tcp.set_nodelay(true)
            {
                warn_once_or_debug!(
                    "Failed to set TCP_NODELAY on the upstream connection to {host}:{port}; continuing with Nagle enabled:  {}",
                    ErrorReport(&err)
                );
            }
        })
}

/// Perform TLS handshake over an established TCP connection.
///
/// Times out after the configured HTTP timeout.
#[cfg(feature = "tls_rustls")]
async fn tls_connect(tcp: TcpStream, host: &str) -> Result<TlsStream, ConnectError> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(
        TLS_CLIENT_CONFIG.get().expect("initialized in main()"),
    ));

    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|err| {
        // Pure function of the host string: never retryable.
        ConnectError::Permanent(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("failed to parse server name:  {err}"),
        ))
    })?;

    debug!("splice proxy: starting TLS handshake with {host}");
    let http_timeout = global_config().http_timeout;
    let tls_stream = tokio::time::timeout(http_timeout, connector.connect(server_name, tcp))
        .await
        .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| {
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
            ConnectError::Transient(std::io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "TLS handshake timed out after {}",
                    HumanFmt::Time(http_timeout)
                ),
            ))
        })?
        .map_err(|err| {
            // Classify before wrapping: the wrapper keeps the cause on
            // `source()`, and only the original kind tells a certificate
            // rejection (`InvalidData`) from a transport error.
            classify_tls_error(err.kind()).attach(std::io::Error::new(
                err.kind(),
                format!("failed to complete TLS handshake:  {err}"),
            ))
        })?;
    debug!("splice proxy: TLS handshake completed with {host}");
    Ok(tls_stream)
}

/// Perform TLS handshake over an established TCP connection with timeout.
///
/// Times out after the configured HTTP timeout.
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
async fn tls_connect(tcp: TcpStream, host: &str) -> Result<TlsStream, ConnectError> {
    let native_connector = tokio_native_tls::native_tls::TlsConnector::new().map_err(|err| {
        // Building the connector touches no network: a failure here is the
        // local TLS stack refusing to initialise and repeats identically.
        ConnectError::Permanent(std::io::Error::other(err))
    })?;
    let connector = tokio_native_tls::TlsConnector::from(native_connector);

    debug!("splice proxy: starting TLS handshake with {host}");
    let http_timeout = global_config().http_timeout;
    let tls_stream = tokio::time::timeout(http_timeout, connector.connect(host, tcp))
        .await
        .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| {
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
            ConnectError::Transient(std::io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "TLS handshake timed out after {}",
                    HumanFmt::Time(http_timeout)
                ),
            ))
        })?
        .map_err(|err| {
            // `native_tls::Error` is opaque: it carries no `io::ErrorKind`, so a
            // certificate rejection is indistinguishable from a transport error
            // and lands on `ErrorKind::Other`. Classify conservatively (i.e.
            // transient, keep retrying) rather than guess from the message.
            let err = std::io::Error::other(err);
            classify_tls_error(err.kind()).attach(err)
        })?;
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
    /// Response head plus every body byte already decrypted in userspace
    /// (bytes past the header terminator and the plaintext drained from
    /// buffered TLS records before RX offload took over). `header_buf[header_end..]`
    /// is therefore the body prefix, exactly as on the standard path.
    header_buf: BytesMut,
    header_end: usize,
}

/// Errors from unbuffered kTLS request, distinguishing failure stages.
#[cfg(feature = "ktls")]
enum KtlsError {
    /// Failure before or during TLS handshake — connection cannot be reused
    TlsFailed(std::io::Error),
    /// TLS+HTTP succeeded, but response is not suitable for kTLS splice
    /// (non-200 status or missing/zero Content-Length). The caller serves
    /// cached data (volatile 304) or reconnects via the standard path.
    ResponseNotSpliceable { response: Box<UpstreamResponse> },
    /// TLS handshake succeeded but the upstream emitted malformed HTTP — the
    /// failure has nothing to do with kTLS. The caller falls back to the
    /// standard path without blocking kTLS for this host.
    UpstreamProtocolError(std::io::Error),
    /// kTLS setup failed for a reason that would repeat deterministically on
    /// a retry (unsupported cipher or TLS version, `TLS_RX` setsockopt
    /// failure, pathological peer state machines, internal invariant
    /// violations). ULP attach failures are handled earlier, at the
    /// attach-after-connect site in `try_unbuffered_ktls_connect`, and never
    /// reach this variant. Blocks kTLS for the full `KTLS_BLOCK_DURATION`.
    KtlsSetupFailed(std::io::Error),
    /// kTLS setup failed for a plausibly transient reason: network-flavored
    /// errors (read/write failures, EOF, truncation), errors triggered by
    /// peer-supplied TLS data, drain races. Upstream flakiness says nothing
    /// about kTLS capability — do not block further kTLS connections.
    KtlsSetupFailedTransient(std::io::Error),
}

/// Result of attempting an unbuffered kTLS connection.
///
/// Socket contract: only `Ready` carries a live socket, and it is a *fresh*
/// TCP connection kept out of the pool. `try_unbuffered_ktls_connect` connects
/// its own socket, attaches the TLS ULP irrevocably, and — because the
/// unbuffered path fuses handshake + request-send + response-read into one shot
/// (the request is on the wire before `setup_rx`, see `unbuffered_ktls_request`)
/// — no non-`Ready` outcome leaves a reusable socket: every failure path has
/// already dropped it. So a caller must **reconnect from scratch** on
/// `ResponseNotSpliceable`/`Failed`; it must never try to salvage the kTLS
/// socket into a userspace-TLS handshake (that would layer TLS over an
/// in-flight session and corrupt the stream). This is why the fall-through
/// arms below re-enter `standard_upstream_connect` rather than reusing.
#[cfg(feature = "ktls")]
enum KtlsResult {
    /// kTLS fully set up — ready for zero-copy splice. Carries a fresh,
    /// non-poolable socket (see the socket contract above).
    Ready(TcpStream, KtlsReadyState),
    /// TLS+HTTP succeeded but response is not splice-eligible (non-200, no CL).
    /// Carries only the parsed response so the caller can choose to serve cached
    /// data (304) or reconnect via the standard path for a clean full fetch.
    /// The kTLS socket is already dropped (socket contract above).
    ResponseNotSpliceable { response: UpstreamResponse },
    /// Failed — must reconnect from scratch (socket contract above); the kTLS
    /// socket is gone. `tls_succeeded` indicates whether HTTPS works for this
    /// mirror, so scheme can be cached to avoid double-HTTPS in auto mode.
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
        let r = write_all_to_stream(tcp, &outgoing[..*outgoing_used], WritePhase::Header).await;
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
/// Shared drain loop used by Phase 4 of the unbuffered kTLS handshake,
/// called once after the initial response is parsed and again per iteration
/// of the post-response read loop until the incoming buffer is empty.
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
        // Triggered by peer-supplied TLS data — transient, no host block.
        let state = state.map_err(|err| {
            KtlsError::KtlsSetupFailedTransient(std::io::Error::other(format!(
                "TLS drain error:  {err}"
            )))
        })?;

        match state {
            ConnectionState::ReadTraffic(mut rt) => {
                let mut total_discard = discard;
                while let Some(result) = rt.next_record() {
                    let AppDataRecord { payload, discard } = result.map_err(|err| {
                        KtlsError::KtlsSetupFailedTransient(std::io::Error::new(
                            ErrorKind::InvalidData,
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
                    .map_err(KtlsError::KtlsSetupFailedTransient)?;
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
                warn_once!(
                    "splice proxy: unexpected ConnectionState variant while draining buffered records: {other:?}; stopping the drain"
                );
                discard_incoming(incoming, incoming_used, discard);
                break;
            }
        }
    }

    Ok(())
}

/// Additional bytes the next drain read should request so it stops exactly at
/// the end of the TLS record currently at the front of `incoming` — never
/// pulling bytes of the *following* record into the buffer.
///
/// Reading past a record boundary is what lets a fast upstream keep the buffer
/// perpetually mid-record: every greedy read appends a fresh partial record, so
/// `process_tls_records` never drains to `incoming_used == 0` and the kTLS
/// hand-off (which needs record alignment) fails after buffering megabytes.
/// Bounding each read to the current record means that once it completes, the
/// buffer holds only whole records and drains empty — alignment after one
/// record instead of never.
///
/// The record length is header bytes 3..5 (big-endian), matched from the
/// buffered prefix `incoming[..incoming_used]`. Until the whole 5-byte header is
/// buffered the pattern fails to match, and we ask only for the missing header
/// bytes — never indexing past what is actually buffered.
#[cfg(feature = "ktls")]
fn record_framed_read_len(incoming: &[u8], incoming_used: usize) -> usize {
    /// TLS record header: content type (1) + legacy version (2) + length (2).
    const TLS_RECORD_HEADER_LEN: usize = 5;

    if let Some(&[_, _, _, hi, lo, ..]) = incoming.get(..incoming_used) {
        let record_len = u16::from_be_bytes([hi, lo]) as usize;
        (TLS_RECORD_HEADER_LEN + record_len).saturating_sub(incoming_used)
    } else {
        TLS_RECORD_HEADER_LEN - incoming_used.min(TLS_RECORD_HEADER_LEN)
    }
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

    // kTLS is HTTPS-only: skip mirrors resolved to plain HTTP.
    if scheme_cache::resolve(mirror.into(), global_config()) == SchemeDecision::Http {
        return KtlsResult::Failed {
            tls_succeeded: false,
        };
    }

    // Skip kTLS for mirrors where setup has recently failed (retry after KTLS_BLOCK_DURATION)
    let key = SchemeKeyRef::from(mirror);
    {
        let blocked = KTLS_BLOCKED.get().expect("Initialized in main()");
        let now = coarsetime::Instant::now();
        let blocked_at = blocked.read().get(&key).copied();
        match blocked_at {
            Some(at) if now.duration_since(at) < KTLS_BLOCK_DURATION => {
                debug!(
                    "kTLS: skipping {} (setup blocked {} ago)",
                    mirror.host(),
                    HumanFmt::Time(now.duration_since(at).into())
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
    let port = mirror_port(mirror, true);

    let mut tcp = match tcp_connect(host, port).await {
        Ok(tcp) => tcp,
        Err(err) => {
            // Fall through to the standard path: its retry loop re-attempts with
            // backoff and owns the terminal WARN + scheme eviction, and Auto mode
            // regains its HTTPS->HTTP port fallback there.
            debug!(
                "kTLS: TCP connect to upstream {host}:{port} failed, retrying via standard path:  {}",
                ErrorReport(&err)
            );
            return KtlsResult::Failed {
                tls_succeeded: false,
            };
        }
    };

    // Attach the TLS ULP now, before any bytes are exchanged (the
    // kernel-canonical order): TCP_ULP requires TCP_ESTABLISHED, and by the
    // time the response headers have been read a Connection-close upstream
    // may already have FIN'd the socket into CLOSE_WAIT. Until setup_rx the
    // kernel context is TLS_BASE passthrough, so the rustls handshake below
    // is unaffected. The attach is irrevocable: this socket must never reach
    // the connection pool (every failure path drops it; Ready sockets are
    // marked non-poolable). Synchronous setsockopt — needs no timeout cover.
    if let Err(attach_err) = ktls::attach_ulp(&tcp) {
        return match attach_err {
            UlpAttachError::Unavailable(err) => {
                metrics::KTLS_FALLBACK_PERMANENT.increment();
                // Fires at most once: attach_ulp latched the availability
                // gate, so is_available() short-circuits later requests.
                warn!(
                    "kTLS: TLS ULP no longer available; disabling kTLS for this run:  {}",
                    ErrorReport(&err)
                );
                KtlsResult::Failed {
                    tls_succeeded: false,
                }
            }
            UlpAttachError::Transient(err) => {
                metrics::KTLS_FALLBACK_TRANSIENT.increment();
                info!(
                    "kTLS: ULP attach for {} raced connection close (no block):  {}",
                    mirror.format_authority(),
                    ErrorReport(&err)
                );
                KtlsResult::Failed {
                    tls_succeeded: false,
                }
            }
            UlpAttachError::Persistent(err) => {
                metrics::KTLS_FALLBACK_PERMANENT.increment();
                warn!(
                    "kTLS: failed to attach the TLS ULP for {}; blocking kTLS for this host for {}:  {}",
                    mirror.format_authority(),
                    HumanFmt::Time(KTLS_BLOCK_DURATION.into()),
                    ErrorReport(&err)
                );
                block_ktls_host(&key);
                KtlsResult::Failed {
                    tls_succeeded: false,
                }
            }
        };
    }

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
            debug!(
                "kTLS: TLS handshake with {host_authority} failed:  {}",
                ErrorReport(&err)
            );
            KtlsResult::Failed {
                tls_succeeded: false,
            }
        }
        Ok(Err(KtlsError::ResponseNotSpliceable { response })) => {
            // Expected routing outcomes, not degradations discovered here: 304
            // resolves from the buffered response with no second fetch, and
            // 206/416 answer a Range this very request chose to send -- the
            // caller's resume branch owns that fallback log.
            if response.status_code == 304
                || (resume_offset > 0
                    && (response.status_code == 206 || response.status_code == 416))
            {
                debug!(
                    "kTLS: response not spliceable (status={})",
                    response.status_code
                );
            } else {
                // The kTLS socket is one-shot, so anything not resolvable
                // from the buffered response costs a reconnect and a second
                // full fetch of the same object -- permanently doubling
                // upstream traffic for a mirror that always answers this way.
                warn_once_or_info!(
                    "kTLS: upstream {} response not spliceable (status {}); refetching over a fresh connection",
                    mirror.format_authority(),
                    response.status_code
                );
            }
            KtlsResult::ResponseNotSpliceable {
                response: *response,
            }
        }
        Ok(Err(KtlsError::UpstreamProtocolError(err))) => {
            metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
            warn_once_or_info!(
                "kTLS: upstream {} sent malformed HTTP; refetching over the standard path without blocking kTLS for this host:  {}",
                mirror.format_authority(),
                ErrorReport(&err)
            );
            // Do not insert into KTLS_BLOCKED. The TLS layer worked; the upstream's
            // HTTP framing is at fault, and that condition is independent of the
            // kernel-TLS offload. Userspace fallback will hit the same problem.
            KtlsResult::Failed {
                tls_succeeded: true,
            }
        }
        Ok(Err(KtlsError::KtlsSetupFailed(err))) => {
            metrics::KTLS_FALLBACK_PERMANENT.increment();
            warn!(
                "kTLS: failed to set up kernel TLS for {}; blocking kTLS for this host for {}:  {}",
                mirror.format_authority(),
                HumanFmt::Time(KTLS_BLOCK_DURATION.into()),
                ErrorReport(&err)
            );
            block_ktls_host(&key);
            KtlsResult::Failed {
                tls_succeeded: true,
            }
        }
        Ok(Err(KtlsError::KtlsSetupFailedTransient(err))) => {
            metrics::KTLS_FALLBACK_TRANSIENT.increment();
            info!(
                "kTLS: failed to set up kernel TLS for {} (transient, not blocking kTLS for this host):  {}",
                mirror.format_authority(),
                ErrorReport(&err)
            );
            // Intentionally do not insert into KTLS_BLOCKED. Transient failures
            // (drain races etc.) can plausibly succeed on the next attempt.
            KtlsResult::Failed {
                tls_succeeded: true,
            }
        }
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
            debug!("kTLS: handshake with {host_authority} timed out");
            KtlsResult::Failed {
                tls_succeeded: false,
            }
        }
    }
}

/// Drive an unbuffered TLS handshake, send an HTTP request, read response
/// headers, drain the buffer to record alignment, and set up kTLS RX.
///
/// Precondition: `tcp` already has the TLS ULP attached
/// (`ktls::attach_ulp`). The kernel context is in `TLS_BASE` passthrough
/// mode until `setup_rx`, so all handshake I/O below behaves as plain TCP.
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
    use rustls::unbuffered::{AppDataRecord, ConnectionState, EncryptError};

    // --- Build TLS config ---
    let tls_config = Arc::clone(KTLS_CLIENT_CONFIG.get().expect("initialized in main()"));

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

            #[expect(
                clippy::wildcard_enum_match_arm,
                reason = "all known variants are matched; the @-binding on the terminal arm hides them from the lint"
            )]
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
                unexpected_state @ (ConnectionState::ReadTraffic(_)
                | ConnectionState::PeerClosed
                | ConnectionState::Closed
                | ConnectionState::ReadEarlyData(_)) => {
                    warn_once!(
                        "splice proxy: unexpected terminal ConnectionState during TLS handshake with upstream {host_authority}: {unexpected_state:?}; aborting the kTLS handshake"
                    );
                    return Err(std::io::Error::other(
                        "unexpected state during TLS handshake",
                    ));
                }
                other => {
                    warn_once!(
                        "splice proxy: unexpected ConnectionState variant during TLS handshake with upstream {host_authority}: {other:?}; aborting the kTLS handshake"
                    );
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

    // TLS handshake succeeded. From here on, classification follows one
    // principle: KtlsSetupFailed (600s host block) is reserved for failures
    // that would repeat deterministically on a retry — pathological peer
    // state machines (round caps), oversized headers/buffers, internal
    // invariant violations, and kernel setup_rx rejection. Network-flavored
    // failures (read/write errors, EOF, truncation) and errors triggered by
    // peer-supplied TLS data map to KtlsSetupFailedTransient: upstream
    // flakiness says nothing about this host's kTLS capability and must not
    // disable kTLS for 600s. Routing outcomes keep their own variants:
    // ResponseNotSpliceable (non-200/no-CL), UpstreamProtocolError
    // (malformed HTTP, no block).

    // --- Phase 2 of 5: Send HTTP Request ---
    // Process any pending records (e.g. NewSessionTickets from TLS 1.3),
    // then encrypt and send the HTTP request.
    // Do NOT reset `outgoing_used` here. Any bytes still pending from Phase 1
    // are correctly transmitted by the next `TransmitTlsData` arm below
    // (`encode_tls_data` appends at `outgoing[outgoing_used..]`); the
    // `WriteTraffic` arm further down fail-closes if bytes are still pending
    // by the time it runs.
    // Guard against a connection stuck in non-WriteTraffic states post-handshake.
    // TLS 1.3 typically sends 1-2 NewSessionTicket records; a handful of iterations
    // covers the legitimate case while still catching pathological peers quickly.
    let mut post_handshake_rounds = 0u32;
    // Instant the encrypted HTTP request was transmitted - start of the
    // upstream-rate window. Set in the `WriteTraffic` arm below; every other
    // arm of the request-send loop continues or returns, so the compiler can
    // prove definite initialisation by the time the post-loop read occurs.
    let req_sent: Option<PreciseInstant>;

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
        // Triggered by peer-supplied TLS data — transient, no host block.
        let state = status.state.map_err(|err| {
            KtlsError::KtlsSetupFailedTransient(std::io::Error::other(format!(
                "TLS post-handshake error:  {err}"
            )))
        })?;

        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "all known variants are matched; the @-binding on the terminal arm hides them from the lint"
        )]
        match state {
            ConnectionState::EncodeTlsData(mut etd) => {
                encode_tls_data(&mut etd, &mut outgoing, &mut outgoing_used);
                discard_incoming(&mut incoming, &mut incoming_used, discard);
            }
            ConnectionState::TransmitTlsData(ttd) => {
                transmit_tls_data(ttd, tcp, &outgoing, &mut outgoing_used)
                    .await
                    .map_err(KtlsError::KtlsSetupFailedTransient)?;
                discard_incoming(&mut incoming, &mut incoming_used, discard);
            }
            ConnectionState::WriteTraffic(mut wt) => {
                // Ready to send — encrypt and transmit the HTTP request.
                // The kTLS socket is one-shot (never pooled), so advertise
                // Connection: close and let the upstream release the
                // connection promptly instead of holding it idle.
                //
                // The rustls state machine pairs every EncodeTlsData with a
                // TransmitTlsData before yielding WriteTraffic, so no encoded
                // bytes should be pending here. wt.encrypt() below writes at
                // outgoing[0..] and only outgoing[..enc_len] is transmitted,
                // so pending bytes would be silently clobbered. Fail closed
                // rather than corrupt the stream if that pairing ever breaks.
                debug_assert_eq!(
                    outgoing_used, 0,
                    "un-transmitted TLS bytes pending at WriteTraffic"
                );
                if outgoing_used != 0 {
                    return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "kTLS: {outgoing_used} un-transmitted TLS bytes pending at \
                             WriteTraffic; request encryption would clobber them"
                        ),
                    )));
                }
                let request = format_http_request(
                    upstream_path,
                    host_authority,
                    resume_offset,
                    resume_if_range,
                    volatile_cond,
                    ConnectionAction::Close,
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
                write_all_to_stream(tcp, &outgoing[..enc_len], WritePhase::Header)
                    .await
                    .map_err(KtlsError::KtlsSetupFailedTransient)?;
                req_sent = Some(PreciseInstant::now());
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
                    .map_err(KtlsError::KtlsSetupFailedTransient)?;
                if n == 0 {
                    return Err(KtlsError::KtlsSetupFailedTransient(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "server closed during post-handshake processing",
                    )));
                }
                incoming_used += n;
            }
            unexpected_state @ (ConnectionState::ReadTraffic(_)
            | ConnectionState::PeerClosed
            | ConnectionState::Closed
            | ConnectionState::ReadEarlyData(_)) => {
                warn_once!(
                    "splice proxy: unexpected ConnectionState during post-handshake request send to upstream {host_authority} (peer closed or sent data before request?): {unexpected_state:?}; discarding the buffered TLS records and retrying the send"
                );
                discard_incoming(&mut incoming, &mut incoming_used, discard);
            }
            other => {
                warn_once!(
                    "splice proxy: unexpected ConnectionState variant during post-handshake request to upstream {host_authority}: {other:?}; discarding the buffered TLS records and retrying the send"
                );
                discard_incoming(&mut incoming, &mut incoming_used, discard);
            }
        }
    }

    // --- Phase 3 of 5: Read Response Headers ---
    let mut header_buf = BytesMut::with_capacity(MAX_UPSTREAM_HEADER_SIZE);
    let mut extra_body = Vec::new();
    let mut header_end = 0usize;
    let mut headers_complete = false;
    // Track where to start scanning for "\r\n\r\n" — avoids re-scanning
    // the entire buffer after each TLS record is appended.
    let mut header_search_offset = 0usize;

    let mut header_read_rounds = 0u32;

    while !headers_complete {
        /// Cap on outer header-read iterations. Each iteration corresponds to
        /// one network read (or one record-processing pass that asks for more
        /// data). A healthy small-header response completes in 1-2 iterations;
        /// even a large-header response over 1-KiB packets sits well below
        /// 256. Hitting the cap means the rustls state machine is stuck (e.g.
        /// peer keeps sending records that never advance to `ReadTraffic`) —
        /// fail fast and attribute the failure rather than waiting for
        /// `http_timeout`.
        const MAX_PHASE3_ROUNDS: u32 = 256;

        header_read_rounds = header_read_rounds.saturating_add(1);
        if header_read_rounds > MAX_PHASE3_ROUNDS {
            return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
                ErrorKind::TimedOut,
                format!(
                    "Phase 3 header-read loop exceeded {MAX_PHASE3_ROUNDS} iterations without completion"
                ),
            )));
        }

        // Process any TLS records already in the incoming buffer
        let need_more_data = loop {
            if incoming_used == 0 {
                break true;
            }
            let status = conn.process_tls_records(&mut incoming[..incoming_used]);
            let discard = status.discard;
            // Triggered by peer-supplied TLS data — transient, no host block.
            let state = status.state.map_err(|err| {
                KtlsError::KtlsSetupFailedTransient(std::io::Error::other(format!(
                    "TLS read error:  {err}"
                )))
            })?;

            #[expect(clippy::wildcard_enum_match_arm, reason = "clippy false-positive")]
            match state {
                ConnectionState::ReadTraffic(mut rt) => {
                    let mut total_discard = discard;
                    while let Some(result) = rt.next_record() {
                        let AppDataRecord { payload, discard } = result.map_err(|err| {
                            KtlsError::KtlsSetupFailedTransient(std::io::Error::other(format!(
                                "TLS record error:  {err}"
                            )))
                        })?;
                        header_buf.extend_from_slice(payload);
                        total_discard += discard;
                    }
                    discard_incoming(&mut incoming, &mut incoming_used, total_discard);

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
                    if header_buf.len() > MAX_UPSTREAM_HEADER_SIZE {
                        warn_once_or_info!(
                            "splice proxy: upstream {host_authority} response header size of {} bytes exceeds {} bytes; abandoning the kTLS attempt",
                            header_buf.len(),
                            MAX_UPSTREAM_HEADER_SIZE
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
                        .map_err(KtlsError::KtlsSetupFailedTransient)?;
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                }
                ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => {
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                    break true; // Need more data from network
                }
                state @ (ConnectionState::PeerClosed
                | ConnectionState::Closed
                | ConnectionState::ReadEarlyData(_)) => {
                    warn_once_or_debug!(
                        "kTLS: connection to upstream {host_authority} in terminal state during header read (upstream closed before headers complete?): {state:?}; retrying the upstream read"
                    );
                    discard_incoming(&mut incoming, &mut incoming_used, discard);
                    break true;
                }
                other => {
                    warn_once_or_debug!(
                        "kTLS: unexpected ConnectionState variant during header read from upstream {host_authority}: {other:?}; retrying the upstream read"
                    );
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
                .map_err(KtlsError::KtlsSetupFailedTransient)?;
            if n == 0 {
                return Err(KtlsError::KtlsSetupFailedTransient(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "server closed before sending complete response headers",
                )));
            }
            incoming_used += n;
        }
    }

    // --- Parse response to check status before setting up kTLS ---
    // Malformed HTTP from the upstream is not a kTLS issue — surface it as
    // UpstreamProtocolError so the host stays eligible for kTLS retries.
    let mut response =
        parse_upstream_response(&header_buf, header_end, host_authority).map_err(|err| {
            KtlsError::UpstreamProtocolError(std::io::Error::new(
                err.kind(),
                format!("kTLS upstream protocol error:  {err}"),
            ))
        })?;
    response.request_sent_at = req_sent;

    if response.status_code != 200 || response.content_length().is_none_or(|ct| ct == 0) {
        // Non-spliceable response: the caller will reconnect via the standard
        // path for a complete fetch, so no need to drain the remaining TLS
        // records from this one-shot kTLS connection.
        return Err(KtlsError::ResponseNotSpliceable {
            response: Box::new(response),
        });
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
        /// Defensive backstop on decrypted body bytes buffered while waiting to
        /// reach a TLS record boundary. The loop reads record-framed (see
        /// `record_framed_read_len`), so it now adds at most one record to
        /// `extra_body` before reaching alignment — this cap can no longer be
        /// the routine outcome it once was. It still bounds the bytes drained
        /// *before* the loop (Phase 3/4), which are read greedily and are
        /// limited only by the 2 MiB incoming-buffer cap (`grow_incoming`); keep
        /// it comfortably above that so a large legitimate first burst never
        /// trips it. On a trip: give up on kTLS for this connection (transient —
        /// no host block) and let the standard streaming path handle the fetch.
        const MAX_KTLS_EXTRA_BODY: usize = 2 * 1024 * 1024 + 256 * 1024;

        let per_read_timeout = std::time::Duration::from_secs(5);

        // Log how many bytes the current partial TLS record needs.
        // TLS record header is 5 bytes: [content_type, version_hi, version_lo, length_hi, length_lo].
        // We skip the first 3 bytes and read the 2-byte big-endian length.
        if let Some(&[_, _, _, hi, lo, ..]) = incoming.get(..incoming_used) {
            let record_len = u16::from_be_bytes([hi, lo]) as usize;
            debug!(
                "kTLS: draining with {incoming_used} bytes buffered, \
                 current record needs {} bytes total",
                5 + record_len
            );
        }

        let mut drain_stop_reason = "";
        'drain: while incoming_used > 0 {
            grow_incoming(&mut incoming, incoming_used, "drain")
                .map_err(KtlsError::KtlsSetupFailed)?;

            // Bound this read to the end of the current record so it never pulls
            // the following partial record in — that is what would keep us
            // perpetually mid-record against a fast upstream. `.max(1)` guards
            // the abnormal case where a whole record is already buffered but
            // undrained: a zero-length read slice would misread as EOF.
            let want = record_framed_read_len(&incoming, incoming_used).max(1);
            let read_end = (incoming_used + want).min(incoming.len());

            match tokio::time::timeout(
                per_read_timeout,
                tcp.read(&mut incoming[incoming_used..read_end]),
            )
            .await
            {
                Ok(Ok(n @ 1..)) => {
                    incoming_used += n;
                }
                Ok(Ok(0)) => {
                    drain_stop_reason = "upstream EOF";
                    debug!(
                        "kTLS: drain stopped ({drain_stop_reason}) with {incoming_used} bytes buffered"
                    );
                    break;
                }
                Ok(Err(ref err)) => {
                    drain_stop_reason = "read error";
                    debug!(
                        "kTLS: drain stopped ({drain_stop_reason}) with {incoming_used} bytes buffered:  {}",
                        ErrorReport(err)
                    );
                    break;
                }
                Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                    drain_stop_reason = "per-read timeout";
                    debug!(
                        "kTLS: drain stopped ({drain_stop_reason}) with {incoming_used} bytes buffered"
                    );
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
            if extra_body.len() > MAX_KTLS_EXTRA_BODY {
                return Err(KtlsError::KtlsSetupFailedTransient(std::io::Error::other(
                    format!(
                        "kTLS: buffered {} bytes of decrypted body without reaching \
                         TLS record alignment; falling back to the streaming path",
                        extra_body.len()
                    ),
                )));
            }
            if incoming_used == 0 {
                break 'drain;
            }
        }

        if incoming_used > 0 {
            // Upstream truncation (EOF/reset/stall mid-record) — transient,
            // no host block.
            return Err(KtlsError::KtlsSetupFailedTransient(std::io::Error::new(
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

        // Gate on the kernel's probed TLS_RX support matrix before touching the
        // socket: an unsupported cipher/version would fail the setup_rx
        // setsockopt deterministically, so reject up front as KtlsSetupFailed
        // (the caller's 600s host block is correct for a deterministic failure)
        // rather than discover it after a full upstream request per host.
        if !ktls::rx_supported(version, rx_secrets) {
            return Err(KtlsError::KtlsSetupFailed(std::io::Error::new(
                ErrorKind::Unsupported,
                format!(
                    "kTLS: {secret_name} with {version:?} not supported by this kernel's TLS_RX"
                ),
            )));
        }

        // The TLS ULP was attached right after connect() in
        // try_unbuffered_ktls_connect: TCP_ULP demands an ESTABLISHED socket,
        // and by now a Connection-close upstream may already have FIN'd the
        // socket into CLOSE_WAIT. setup_rx has no such state check — queued
        // ciphertext stays decryptable after the FIN. RX must be configured
        // before draining control messages (which uses recvmsg on the kTLS
        // socket). We only configure RX: the request has already been written
        // to the wire before secret extraction, the kTLS socket is not reused
        // for another request (see the comment at the KtlsResult::Ready arm),
        // and configuring TX would add a failure surface (some kernels may
        // reject TX for ciphers they accept for RX) for no gain.
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

    // TLS session resumption is supported via the resumption store shared
    // between TLS_CLIENT_CONFIG and KTLS_CLIENT_CONFIG (init_splice_tls_client_config
    // clones one from the other), which uses rustls's default
    // ClientSessionMemoryCache (256 entries). NewSessionTickets received during
    // phases 2-4 are stored there and reused on subsequent connections to the
    // same server via either config, enabling TLS 1.3 PSK resumption (1-RTT)
    // or TLS 1.2 session ticket resumption.
    // The unbuffered API does not expose handshake_kind(), so we cannot directly
    // log whether this specific handshake was a resumption.
    debug!(
        "kTLS: RX offload configured: host={host}, version={version:?}, secret_name={secret_name}, \
        cipher={cipher_suite:?}, rx_seq={rx_seq}, extra_body={} bytes",
        extra_body.len()
    );

    metrics::KTLS_RX_ENABLED.increment();

    // Credit body bytes that arrived through the kTLS handshake: the
    // extra_body drained from already-buffered TLS records after the
    // headers. (Phase 3 folds any bytes past the header terminator into
    // `extra_body` and truncates `header_buf` to `header_end`, so the
    // first term is 0 today; kept for robustness against reordering.)
    // These are upstream payload that downstream consumers will write to
    // the cache/client without a separate read syscall, so credit them here.
    let downloaded_body = (header_buf.len() - header_end) + extra_body.len();
    if downloaded_body > 0 {
        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(downloaded_body as u64);
    }

    // Hand the drained plaintext to the drive as part of the body prefix so
    // the kTLS and standard paths share one pre-loop write.
    header_buf.extend_from_slice(&extra_body);

    Ok(KtlsReadyState {
        response,
        header_buf,
        header_end,
    })
}

/// Update the scheme cache for a mirror after successful connection.
fn cache_scheme(mirror: &Mirror, scheme: Scheme) {
    if scheme_cache::record_success(mirror.into(), scheme) {
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
        // a \r\n\r\n that straddles the previous read boundary).
        let scan_from = search_offset.saturating_sub(3);
        if let Some(rel) = buf[scan_from..]
            .array_windows()
            .position(|w| w == b"\r\n\r\n")
        {
            return Ok(scan_from + rel + 4);
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
enum BodyFraming {
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
    async fn relay_to_client(
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
            let mut rate_checker = config
                .min_download_rate
                .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
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
    async fn read_to_vec(
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
struct UpstreamResponse {
    status_code: StatusCode,
    framing: BodyFraming,
    content_type: Option<String>,
    last_modified: Option<String>,
    etag: Option<String>,
    content_range: Option<String>,
    location: Option<String>,
    connection_close: bool,
    /// Instant the upstream request was sent - start of the upstream-rate
    /// window. `None` only on responses built by the bare parser in tests.
    request_sent_at: Option<PreciseInstant>,
}

impl UpstreamResponse {
    /// The body's fixed length, only when the response is length-delimited
    /// (`Content-Length`). `None` for chunked or close-delimited framing.
    fn content_length(&self) -> Option<u64> {
        match self.framing {
            BodyFraming::ContentLength(n) => Some(n),
            BodyFraming::Chunked | BodyFraming::CloseDelimited => None,
        }
    }

    /// The backend-neutral projection consumed by
    /// `upstream_head::plan_download`.
    fn head(&self) -> UpstreamHead {
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
    /// prefix (`docs/logging.md`, cross-backend parity).
    fn discard_invalid_validators(&mut self, conn_details: &ConnectionDetails) {
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
fn parse_upstream_response(
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

enum DeliveryResult {
    Success(u64),
    Failure(u64),
}

/// Which of the three independent I/O parties a body-transfer failure came
/// from.
///
/// `splice_proxy_body{,_tls}` drive an upstream socket, a client socket and a
/// cache file (plus the internal splice pipes) in one loop.  They used to
/// collapse every failure into a bare `io::Error`, which the caller then
/// labelled `AfterHeaderClient` wholesale -- so an upstream stall was logged
/// as "client response delivery failed ... upstream read timed out".  Every
/// throw site now names its side so the outer arm can attribute it correctly.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum BodyFailureSide {
    /// Reading from (or rate-checking) the upstream connection.
    Upstream,
    /// Writing to the client socket.
    Client,
    /// A cached-file syscall (`pwrite`, or the `splice` into the cache fd).
    /// Kept distinct from `Proxy` so only genuine cached-file failures bump
    /// `CACHE_IO_FAILURE`, whose documented scope is cached-file syscalls.
    Cache,
    /// Another proxy-side resource: the internal splice pipes, or the fd
    /// duplication behind the demoted file-serve task.
    Proxy,
}

/// An `io::Error` out of `splice_proxy_body{,_tls}` tagged with the side of
/// the proxy that produced it.  Construct via [`BodyTransferError::upstream`]
/// / [`BodyTransferError::client`] / [`BodyTransferError::proxy`] so the
/// tagging stays greppable at every throw site.
pub(crate) struct BodyTransferError {
    side: BodyFailureSide,
    err: std::io::Error,
}

impl BodyTransferError {
    fn upstream(err: std::io::Error) -> Self {
        Self {
            side: BodyFailureSide::Upstream,
            err,
        }
    }

    fn client(err: std::io::Error) -> Self {
        Self {
            side: BodyFailureSide::Client,
            err,
        }
    }

    fn cache(err: std::io::Error) -> Self {
        Self {
            side: BodyFailureSide::Cache,
            err,
        }
    }

    fn proxy(err: std::io::Error) -> Self {
        Self {
            side: BodyFailureSide::Proxy,
            err,
        }
    }
}

/// The caller must `.await` the join handle after the download barrier has
/// been consumed (so the spawned task can observe a terminal
/// `ActiveDownloadStatus` -- `Verifying` while integrity hashing is in
/// flight, then `Finished` once `RenameBarrier::commit` flips the variant).
type DemotedClientHandle = tokio::task::JoinHandle<DeliveryResult>;

/// Splice data from upstream TCP socket to client socket, with zero-copy tee to a cache file.
///
/// Data flow (all in kernel space, zero userspace copies):
///
/// ```text
///   upstream -> splice -> pipe_A --tee--> pipe_B -> splice -> cache_file
///                                  |
///                                  `--> splice -> client
/// ```
///
/// On error the upstream is left mid-message (fewer than `content_length`
/// bytes consumed), so its socket still holds undelivered bytes -- the caller
/// must mark the upstream non-poolable to keep the poisoned connection out of
/// the pool.
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
    #[cfg(feature = "ktls")] upstream_is_ktls: bool,
) -> Result<(DownloadBarrier, Option<DemotedClientHandle>, bool, u64), BodyTransferError> {
    // Dropped at the demotion transition so the spawned `serve_remaining_from_file`
    // task's own `ClientDownload` (in `async_sendfile_unfinished`) takes over the
    // accounting cleanly — see the `ClientStatus::Demoted` branch below.
    // `Option` is required because the borrow checker can't prove the demotion
    // branch fires at most once per call when it's nested in the loop below.
    let mut counter = Some(client_counter::ClientDownload::new());

    // `REQUESTS_SPLICE` is bumped by `splice_proxy_drive` alongside the
    // response-headers emission (next to `record_client_status`), since
    // this body fn is skipped when the entire response fits in the
    // body_prefix / kTLS extra-body and we still need to count it.

    let (upstream_pipe_sender, mut upstream_pipe_receiver) =
        create_pipe().map_err(BodyTransferError::proxy)?;
    let (cache_pipe_sender, cache_pipe_receiver) =
        create_pipe().map_err(BodyTransferError::proxy)?;

    let config = global_config();

    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    // Budget for draining kTLS control records that arrive mid-stream (e.g. a
    // late NewSessionTicket) — see the drain-retry arm in the splice loop.
    // Multiple bursts over a long download are plausible; each drain consumes
    // a whole burst.
    #[cfg(feature = "ktls")]
    let mut ktls_drain_retries: u32 = 8;

    let mut remaining = content_length;
    let mut file_offset: i64 = file_start_offset;
    let mut client_status = ClientStatus::Active;
    let mut bytes_done: u64 = 0;
    // Absolute cache-file offset of the next byte the client expects, and the
    // count of bytes still owed to it. Maintained across both the
    // `tee_and_splice` and boundary-chunk paths so that on demotion we can
    // hand sendfile the exact resume point and length regardless of resume
    // offset, body-prefix advance, or 206 range filtering.
    let mut client_file_pos: u64 = u64::try_from(file_start_offset)
        .expect("file_start_offset is non-negative by construction")
        + range_filter.skip;
    let mut client_remaining: u64 = range_filter.send;
    let mut demoted_handle: Option<DemotedClientHandle> = None;
    let client_skip = range_filter.skip;
    let client_range_end = range_filter.skip + range_filter.send;

    while remaining > 0 {
        dbarrier = dbarrier
            .check_upstream_rate(rate_checker.as_ref())
            .await
            .map_err(BodyTransferError::upstream)?;

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
                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                    return Err(BodyTransferError::upstream(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        format!(
                            "splice proxy: upstream closed prematurely (remaining={remaining}, chunk_size={chunk_size})"
                        ),
                    )));
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
                        ) => r.map_err(BodyTransferError::upstream)?,
                        w = upstream_pipe_sender.writable() => w.map_err(BodyTransferError::proxy)?,
                    }
                    continue;
                }
                // A kTLS control record (e.g. a late NewSessionTicket) at the
                // head of the receive queue fails splice(2) instead of
                // delivering bytes; the errno varies by kernel version
                // (EINVAL/EIO/EBADMSG). Drain the record(s) and retry. The
                // budget keeps this bounded: drain_control_messages detects
                // a KeyUpdate itself and aborts immediately (it cannot be
                // rekeyed), so the budget only bounds genuine bursts of
                // NewSessionTickets, not a stuck KeyUpdate loop.
                #[cfg(feature = "ktls")]
                Err(
                    err @ (nix::errno::Errno::EINVAL
                    | nix::errno::Errno::EIO
                    | nix::errno::Errno::EBADMSG),
                ) if upstream_is_ktls && ktls_drain_retries > 0 => {
                    ktls_drain_retries -= 1;
                    if let Err(drain_err) =
                        ktls::drain_control_messages(upstream.as_fd(), ktls::DrainExpect::DataReady)
                    {
                        warn_once!(
                            "splice proxy (kTLS): failed to drain mid-stream control records for `{}`; aborting the transfer:  {}",
                            cache_path.display(),
                            ErrorReport(&drain_err)
                        );
                        return Err(BodyTransferError::upstream(errno_to_io_error(
                            err,
                            "splice failed on kTLS record",
                        )));
                    }
                    debug!("splice proxy: drained mid-stream kTLS control record(s), retrying");
                    continue;
                }
                // Kernels >= 6.14 pause RX after delivering a KeyUpdate
                // control record and fail subsequent reads with EKEYEXPIRED
                // until a new key is installed. Rekey is impossible in this
                // design (rustls has been consumed; the traffic secret
                // needed to derive the next key was handed to the kernel),
                // so there is nothing a drain-and-retry could fix -- abort
                // immediately instead of burning the drain budget.
                #[cfg(feature = "ktls")]
                Err(err @ nix::errno::Errno::EKEYEXPIRED) if upstream_is_ktls => {
                    return Err(BodyTransferError::upstream(errno_to_io_error(
                        err,
                        "upstream sent TLS KeyUpdate (kernel paused RX awaiting rekey); \
                         kernel TLS cannot rekey",
                    )));
                }
                // Budget spent: the same errno now falls through to the
                // generic arm, which surfaces as a plain "splice failed:
                // Invalid argument". Say that the kTLS drain budget is what
                // ran out.
                #[cfg(feature = "ktls")]
                Err(
                    err @ (nix::errno::Errno::EINVAL
                    | nix::errno::Errno::EIO
                    | nix::errno::Errno::EBADMSG),
                ) if upstream_is_ktls => {
                    warn_once!(
                        "splice proxy (kTLS): mid-stream control-record drain budget exhausted for `{}`; aborting the transfer:  {}",
                        cache_path.display(),
                        ErrorReport(&err)
                    );
                    return Err(BodyTransferError::upstream(errno_to_io_error(
                        err,
                        "splice failed after kTLS drains",
                    )));
                }
                Err(err) => {
                    return Err(BodyTransferError::upstream(errno_to_io_error(
                        err,
                        "splice failed",
                    )));
                }
            };
        };

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(got as u64);

        // Feed the upstream RC up-front (the bytes have already arrived) so
        // any subsequent `check_fail` in this iteration — in particular the
        // `DemoteRequested → check_upstream_rate` adjudication below — sees
        // the freshest window. Without this the upstream RC would still be
        // one chunk behind the client RC at the moment a slow upstream
        // causes the client check inside `tee_and_splice` to trip.
        if let Some(ref mut rate_checker) = rate_checker {
            rate_checker.add(got);
        }

        // Determine how this chunk overlaps with the client range.
        let chunk_start = bytes_done;
        let chunk_end = bytes_done + got as u64;

        if !matches!(client_status, ClientStatus::Active)
            || chunk_end <= client_skip
            || chunk_start >= client_range_end
        {
            // Chunk is entirely outside client range, or client is gone/demoted — cache only
            splice_pipe_to_file(&upstream_pipe_receiver, cache_file, got, &mut file_offset)
                .await
                .map_err(BodyTransferError::cache)?;
            dbarrier.ping_batched(got as u64);
        } else if chunk_start >= client_skip && chunk_end <= client_range_end {
            // Chunk is entirely inside client range — normal tee
            client_status = tee_and_splice(
                &upstream_pipe_receiver,
                &cache_pipe_receiver,
                &cache_pipe_sender,
                client,
                (cache_file, &mut file_offset),
                range_filter.send,
                got,
                client_status,
                &mut dbarrier,
                &mut client_rate_checker,
                &mut client_file_pos,
                &mut client_remaining,
            )
            .await?;

            if let ClientStatus::DemoteRequested {
                client_file_pos: demote_pos,
                client_remaining: demote_remaining,
            } = client_status
            {
                // Slow upstream is the most common reason the client RC trips;
                // surface that root cause via the existing MirrorDownloadRate
                // abort before spinning up a doomed demoted file-serve task.
                dbarrier = dbarrier
                    .check_upstream_rate(rate_checker.as_ref())
                    .await
                    .map_err(BodyTransferError::upstream)?;

                // Upstream is healthy — client really is the bottleneck.
                #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
                let demote_remaining_percent =
                    100.0 * demote_remaining as f32 / range_filter.send as f32;
                info!(
                    "splice proxy: demoting slow client to file-serve of `{}` at cache offset {} with {} remaining out of {} ({:.1}%)",
                    cache_path.display(),
                    HumanFmt::Size(demote_pos),
                    HumanFmt::Size(demote_remaining),
                    HumanFmt::Size(range_filter.send),
                    demote_remaining_percent,
                );
                // Hand accounting off to the spawned demoted-serve task — its
                // `async_sendfile_unfinished` creates its own `ClientDownload`
                // so net `ACTIVE_CLIENT_DOWNLOADS` stays at 1 across the transition.
                drop(counter.take());
                demoted_handle = Some(
                    spawn_file_serve_task(
                        client,
                        cache_path,
                        demote_pos,
                        demote_remaining,
                        &dbarrier,
                    )
                    .map_err(BodyTransferError::proxy)?,
                );
                client_status = ClientStatus::Demoted;
            }
        } else {
            // Boundary chunk — read into userspace, slice for client, pwrite for cache
            let mut buf = read_pipe_to_buf(&mut upstream_pipe_receiver, got)
                .await
                .map_err(BodyTransferError::proxy)?;

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
            pwrite_buf_to_file(cache_file, &mut buf, buf_len, file_offset)
                .await
                .map_err(BodyTransferError::cache)?;

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
                        let sent = client_slice.len() as u64;
                        metrics::BYTES_SERVED_SPLICE.increment_by(sent);
                        client_file_pos += sent;
                        client_remaining = client_remaining
                            .checked_sub(sent)
                            .expect("client_remaining tracks bytes still owed to the client");
                    }
                    // Rate-stall / HTTP per-op timeout on the client write:
                    // the proxy gave up on this client but the upstream
                    // download must continue so the cache is populated for
                    // the late-joiner.  `HTTP_TIMEOUT_CLIENT_BODY` is already
                    // bumped at the `write_all_to_stream_rated` throw site;
                    // don't also bump `CLIENT_DISCONNECTED_MID_BODY`.
                    Err(err) if err.kind() == ErrorKind::TimedOut => {
                        info!(
                            "splice proxy: client {} timed out during boundary chunk; abandoning the client:  {}",
                            client
                                .peer_addr()
                                .map_or_else(|_| String::from("<unknown>"), |a| a.to_string()),
                            ErrorReport(&err)
                        );
                        client_status = ClientStatus::Disconnected;
                    }
                    Err(err) if is_peer_disconnect(&err) => {
                        metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                        info!(
                            "splice proxy: client {} disconnected during boundary chunk",
                            client
                                .peer_addr()
                                .map_or_else(|_| String::from("<unknown>"), |a| a.to_string())
                        );
                        client_status = ClientStatus::Disconnected;
                    }
                    Err(err) => return Err(BodyTransferError::client(err)),
                }
            }
        }

        bytes_done = chunk_end;

        remaining = remaining
            .checked_sub(got as u64)
            .expect("splice should not return more than requested");
    }

    let client_disconnected = matches!(client_status, ClientStatus::Disconnected);
    let client_bytes_written = range_filter.send - client_remaining;
    Ok((
        dbarrier,
        demoted_handle,
        client_disconnected,
        client_bytes_written,
    ))
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

            // SAFETY: file_fd is valid because the caller holds a reference to the
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
                debug_assert!(temp.is_empty(), "temp buffer should be empty after re-swap");
                debug_assert_eq!(
                    buf.len(),
                    buf_len,
                    "buffer should have the same length as before"
                );
                debug_assert!(
                    written < size,
                    "should have written less than the requested number of bytes"
                );
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
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
                // yield to avoid busy loop
                tokio::task::yield_now().await;
            }
            Err(nix::errno::Errno::EINTR) => {}
            Err(errno) => {
                std::mem::swap(&mut temp, buf);
                debug_assert!(temp.is_empty(), "temp buffer should be empty after re-swap");
                debug_assert_eq!(
                    buf.len(),
                    buf_len,
                    "buffer should have the same length as before"
                );
                debug_assert!(
                    written < size,
                    "should have written less than the requested number of bytes"
                );
                return Err(errno_to_io_error(errno, "pwrite(2) failed"));
            }
        }
    }

    std::mem::swap(&mut temp, buf);
    debug_assert!(temp.is_empty(), "temp buffer should be empty after re-swap");
    debug_assert_eq!(
        buf.len(),
        buf_len,
        "buffer should have the same length as before"
    );
    debug_assert_eq!(
        written, size,
        "should have written the requested number of bytes"
    );

    Ok(())
}

/// Transfer body from TLS upstream to client+cache in userspace.
///
/// Data flow:
///   `tls_stream` →[async read]→ buffer →\[pwrite\]→ `cache_file`
///                                       →[write]→ `client_socket`
///
/// Once the bytes have been decrypted into userspace a pipe+tee fan-out
/// adds no zero-copy benefit -- `write` into a pipe copies user→kernel
/// exactly like a direct socket `write`, and `splice` pipe→file copies
/// into the page cache exactly like `pwrite` -- so the direct form saves
/// three syscalls per chunk. The cache is always written first so
/// concurrent clients see progress without being gated on this client's
/// send speed.
///
/// On error the upstream is left mid-message (fewer than `content_length`
/// bytes consumed), so its socket still holds undelivered bytes -- the caller
/// must mark the upstream non-poolable to keep the poisoned connection out of
/// the pool.
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
) -> Result<(DownloadBarrier, Option<DemotedClientHandle>, bool, u64), BodyTransferError> {
    // Dropped at the demotion transition so the spawned `serve_remaining_from_file`
    // task's own `ClientDownload` (in `async_sendfile_unfinished`) takes over the
    // accounting cleanly — see the `ClientStatus::Demoted` branch below.
    // `Option` is required because the borrow checker can't prove the demotion
    // branch fires at most once per call when it's nested in the loop below.
    let mut counter = Some(client_counter::ClientDownload::new());

    // `REQUESTS_SPLICE` is bumped by `splice_proxy_drive` alongside the
    // response-headers emission (next to `record_client_status`), since
    // this body fn is skipped when the entire response fits in the
    // body_prefix / kTLS extra-body and we still need to count it.

    let config = global_config();

    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

    let mut remaining = content_length;
    let mut file_offset: i64 = file_start_offset;
    // `Vec::with_capacity` reserves uninitialized backing storage; `read_buf`
    // writes into the spare capacity via `BufMut` so the buffer never has
    // to be zero-initialized before being overwritten by upstream data.
    let mut read_buf: Vec<u8> = Vec::with_capacity(TLS_READ_BUF_SIZE);
    let mut client_status = ClientStatus::Active;
    let mut bytes_done: u64 = 0;
    // See `splice_proxy_body` for the rationale on tracking absolute client
    // position and remaining bytes here.
    let mut client_file_pos: u64 = u64::try_from(file_start_offset)
        .expect("file_start_offset is non-negative by construction")
        + range_filter.skip;
    let mut client_remaining: u64 = range_filter.send;
    let mut demoted_handle: Option<DemotedClientHandle> = None;

    // One pinned re-armable sleep per body for the http_timeout deadline
    // and one for the 1 s rate-check tick — the previous version built two
    // fresh `Timeout` futures per chunk (see `wait_socket_rated` for the
    // same pattern and rationale).
    let outer = tokio::time::sleep(config.http_timeout);
    tokio::pin!(outer);
    let tick = tokio::time::sleep(RATE_TICK_PERIOD);
    tokio::pin!(tick);

    while remaining > 0 {
        dbarrier = dbarrier
            .check_upstream_rate(rate_checker.as_ref())
            .await
            .map_err(BodyTransferError::upstream)?;

        // Step 1: async read from TLS stream into userspace buffer
        // The outer http_timeout ensures a fully stalled connection is killed even if
        // rate_check_timeframe > http_timeout.
        debug_assert_eq!(
            read_buf.capacity(),
            TLS_READ_BUF_SIZE,
            "buffer capacity should remain constant"
        );
        read_buf.clear();
        let to_read = std::cmp::min(remaining, TLS_READ_BUF_SIZE as u64);
        outer
            .as_mut()
            .reset(tokio::time::Instant::now() + config.http_timeout);
        let got = {
            let mut taken = (&mut *upstream).take(to_read);
            let read_fut = taken.read_buf(&mut read_buf);
            tokio::pin!(read_fut);
            loop {
                tokio::select! {
                    biased;
                    // The pinned future is re-polled (not re-created) after a
                    // tick fires, so no read progress is ever cancelled.
                    result = &mut read_fut => match result {
                        Ok(n) => break n,
                        Err(err) => return Err(BodyTransferError::upstream(err)),
                    },
                    () = &mut tick, if rate_checker.is_some() => {
                        let rc = rate_checker
                            .as_mut()
                            .expect("guarded by rate_checker.is_some()");
                        rc.add(0);
                        if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                            return Err(BodyTransferError::upstream(
                                dbarrier.abort_with_rate_timeout(rate).await,
                            ));
                        }
                        tick.as_mut()
                            .reset(tokio::time::Instant::now() + RATE_TICK_PERIOD);
                    }
                    () = &mut outer => {
                        metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                        return Err(BodyTransferError::upstream(std::io::Error::new(
                            ErrorKind::TimedOut,
                            format!(
                                "upstream TLS read timed out after {}",
                                HumanFmt::Time(config.http_timeout)
                            ),
                        )));
                    }
                }
            }
        };
        if got == 0 {
            metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
            return Err(BodyTransferError::upstream(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "splice proxy: TLS upstream closed prematurely",
            )));
        }

        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(got as u64);

        // See `splice_proxy_body` for the rationale on feeding the upstream
        // RC up-front rather than at the end of the iteration.
        if let Some(ref mut rate_checker) = rate_checker {
            rate_checker.add(got);
        }

        // Determine how this chunk overlaps with the client range.
        let chunk_start = bytes_done;
        let chunk_end = bytes_done + got as u64;

        // Write the full chunk to cache via pwrite first, so concurrent
        // clients see progress without being gated on this client's send
        // speed.
        pwrite_buf_to_file(cache_file, &mut read_buf, got, file_offset)
            .await
            .map_err(BodyTransferError::cache)?;

        #[expect(
            clippy::cast_possible_wrap,
            reason = "got is bounded by TLS_READ_BUF_SIZE which fits in i64"
        )]
        {
            file_offset += got as i64;
        }

        // Notify concurrent clients of progress
        dbarrier.ping_batched(got as u64);

        // Then send the overlap with the client range (may be slow)
        let client_slice = range_slice(
            &read_buf[..got],
            chunk_start,
            range_filter.skip,
            range_filter.send,
        );
        if matches!(client_status, ClientStatus::Active) && !client_slice.is_empty() {
            client_status = write_client_or_demote(
                client,
                client_slice,
                &mut client_rate_checker,
                &mut client_file_pos,
                &mut client_remaining,
                range_filter.send,
            )
            .await
            .map_err(BodyTransferError::client)?;

            if let ClientStatus::DemoteRequested {
                client_file_pos: demote_pos,
                client_remaining: demote_remaining,
            } = client_status
            {
                // Slow upstream is the most common reason the client RC trips;
                // surface that root cause via the existing MirrorDownloadRate
                // abort before spinning up a doomed demoted file-serve task.
                dbarrier = dbarrier
                    .check_upstream_rate(rate_checker.as_ref())
                    .await
                    .map_err(BodyTransferError::upstream)?;

                // Upstream is healthy — client really is the bottleneck.
                #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
                let demote_remaining_percent =
                    100.0 * demote_remaining as f32 / range_filter.send as f32;
                info!(
                    "splice proxy: demoting slow client to file-serve of `{}` at cache offset {} with {} remaining out of {} ({:.1}%)",
                    cache_path.display(),
                    HumanFmt::Size(demote_pos),
                    HumanFmt::Size(demote_remaining),
                    HumanFmt::Size(range_filter.send),
                    demote_remaining_percent,
                );
                // Hand accounting off to the spawned demoted-serve task — its
                // `async_sendfile_unfinished` creates its own `ClientDownload`
                // so net `ACTIVE_CLIENT_DOWNLOADS` stays at 1 across the transition.
                drop(counter.take());
                demoted_handle = Some(
                    spawn_file_serve_task(
                        client,
                        cache_path,
                        demote_pos,
                        demote_remaining,
                        &dbarrier,
                    )
                    .map_err(BodyTransferError::proxy)?,
                );
                client_status = ClientStatus::Demoted;
            }
        }

        bytes_done = chunk_end;

        remaining = remaining
            .checked_sub(got as u64)
            .expect("read(2) should not return more than requested");
    }

    let client_disconnected = matches!(client_status, ClientStatus::Disconnected);
    let client_bytes_written = range_filter.send - client_remaining;
    Ok((
        dbarrier,
        demoted_handle,
        client_disconnected,
        client_bytes_written,
    ))
}

/// Write `slice` to the client with rate checking, translating client
/// failures into [`ClientStatus`] transitions instead of hard errors:
/// the cache already holds these bytes, so a slow or gone client must
/// not abort the download (late joiners depend on it).
///
/// Mirrors the `tee_and_splice` client-splice semantics: a client
/// rate-check trip after progress returns `DemoteRequested` (the caller
/// adjudicates the actual demote), a peer disconnect returns
/// `Disconnected` (bumping `CLIENT_DISCONNECTED_MID_BODY`), and a rated
/// wait timeout abandons the client (`Disconnected`, no metric — the
/// timeout counters were already bumped at rejection) so the download
/// continues cache-only. Only unexpected I/O errors are returned as
/// `Err`.
async fn write_client_or_demote(
    client: &TcpStream,
    slice: &[u8],
    client_rate_checker: &mut Option<RateChecker>,
    client_file_pos: &mut u64,
    client_remaining: &mut u64,
    client_total: u64,
) -> std::io::Result<ClientStatus> {
    let disconnected = |client_remaining: u64| {
        metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
        let client_sent = client_total - client_remaining;
        #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
        let client_sent_percent = 100.0 * client_sent as f32 / client_total as f32;
        info!(
            "splice proxy: client disconnected after {} out of {} ({:.1}%), continuing cache-only",
            HumanFmt::Size(client_sent),
            HumanFmt::Size(client_total),
            client_sent_percent,
        );
        ClientStatus::Disconnected
    };

    let mut written = 0;
    while written < slice.len() {
        // `try_write` clears tokio's cached writability itself on
        // `WouldBlock`, so the rated wait below parks properly.
        match client.try_write(&slice[written..]) {
            Ok(n) => {
                written += n;
                *client_file_pos += n as u64;
                *client_remaining = client_remaining
                    .checked_sub(n as u64)
                    .expect("client_remaining tracks bytes still owed to the client");
                metrics::BYTES_SERVED_SPLICE.increment_by(n as u64);
                if let Some(rc) = client_rate_checker {
                    rc.add(n);
                    if rc.check_fail(RateCheckDirection::Client).is_some() {
                        // Client RC tripped — the cache already has the
                        // bytes, hand off to the caller for demote
                        // adjudication.
                        return Ok(ClientStatus::DemoteRequested {
                            client_file_pos: *client_file_pos,
                            client_remaining: *client_remaining,
                        });
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                match wait_writable_rated(
                    client,
                    client_rate_checker,
                    RateCheckDirection::Client,
                    global_config().http_timeout,
                )
                .await
                {
                    Ok(()) => {}
                    // Rate-stall / HTTP per-op timeout on the client write:
                    // abandon the client but keep downloading for late
                    // joiners; no CLIENT_DISCONNECTED_MID_BODY bump (the
                    // timeout metrics were bumped at error construction).
                    Err(err) if err.kind() == ErrorKind::TimedOut => {
                        info!(
                            "splice proxy: client {} timed out during TLS body; abandoning the client:  {}",
                            client
                                .peer_addr()
                                .map_or_else(|_| String::from("<unknown>"), |a| a.to_string()),
                            ErrorReport(&err)
                        );
                        return Ok(ClientStatus::Disconnected);
                    }
                    Err(err) if is_peer_disconnect(&err) => {
                        return Ok(disconnected(*client_remaining));
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(err) if is_peer_disconnect(&err) => {
                return Ok(disconnected(*client_remaining));
            }
            Err(err) => return Err(err),
        }
    }

    Ok(ClientStatus::Active)
}

/// Duplicate the client socket fd and spawn a task that serves remaining bytes
/// from the cache file.  Returns the `JoinHandle` so the caller can await it
/// after the download barrier has been consumed.
fn spawn_file_serve_task(
    client: &TcpStream,
    cache_path: &Path,
    content_start: u64,
    content_length: u64,
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

    // Open the cache file synchronously here, before the caller's splice loop
    // continues, so the fd is captured pre-rename: the download is still
    // mid-body (the file provably exists), and this fixes a race where the
    // download could finish and `RenamePlan::commit` rename the temp file away
    // before a spawned task's open ran (NotFound, truncating this client). This
    // is a short local-file open syscall on the async worker, consistent with
    // the synchronous `dup(2)` above.
    let std_file = match utils::nofollow_options().read(true).open(&cache_path) {
        Ok(f) => f,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to open cache file `{}` for the demoted client; the demoted client gets no further bytes:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            return Ok(tokio::task::spawn(async { DeliveryResult::Failure(0) }));
        }
    };
    let file = tokio::fs::File::from_std(std_file);

    Ok(tokio::task::spawn(serve_remaining_from_file(
        client_stream,
        file,
        cache_path,
        content_start,
        content_length,
        receiver,
        status,
    )))
}

/// Serve remaining bytes of a download from the cache file to a demoted client
/// via Linux `sendfile(2)`.
///
/// Delegates to [`async_sendfile_unfinished`], which handles the same
/// growing-file / `watch::Receiver` / `ActiveDownloadStatus` interplay used by
/// the sendfile late-joiner path.  The request was already counted as
/// `REQUESTS_SPLICE` when its response headers were emitted; only the bytes
/// flow through `BYTES_SERVED_SENDFILE` (incremented inside
/// `sendfile_chunk_loop`).
async fn serve_remaining_from_file(
    client: TcpStream,
    file: tokio::fs::File,
    cache_path: PathBuf,
    content_start: u64,
    content_length: u64,
    receiver: tokio::sync::watch::Receiver<()>,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
) -> DeliveryResult {
    debug!(
        "splice proxy: starting to serve remaining bytes of `{}` from the cache file for the demoted client at offset {content_start} ({content_length} bytes remaining)",
        cache_path.display()
    );

    // Demoted clients keep reading the partial cache file linearly via
    // sendfile chunks, so warm the kernel readahead window before the loop
    // starts.  The final size is unknown (file still growing), so always
    // hint.
    hint_sequential_read(&file, u64::MAX, &cache_path);

    metrics::CLIENTS_DEMOTED.increment();

    match async_sendfile_unfinished(
        &client,
        &file,
        &cache_path,
        content_start,
        content_length,
        receiver,
        status,
    )
    .await
    {
        Ok(bytes) => {
            debug!(
                "splice proxy: demoted client file-serve complete, sent {bytes} bytes from cache offset {content_start}"
            );
            DeliveryResult::Success(bytes)
        }
        Err((bytes, err)) => {
            if is_peer_disconnect(&err) {
                metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                debug!(
                    "splice proxy: demoted client disconnected during file-serve of `{}` from cache offset {content_start}:  {}",
                    cache_path.display(),
                    ErrorReport(&err)
                );
            } else {
                info!(
                    "splice proxy: demoted client file-serve of `{}` failed at cache offset {content_start}; the client did not get the full body:  {}",
                    cache_path.display(),
                    ErrorReport(&err)
                );
            }

            DeliveryResult::Failure(bytes)
        }
    }
}

/// Status of the first (splice) client after a tee+splice iteration.
enum ClientStatus {
    /// Client is still connected and receiving data at acceptable speed.
    Active,
    /// Client disconnected mid-transfer.
    Disconnected,
    /// Client send rate dropped below the minimum threshold during the
    /// inner tee+splice loop and the teed bytes still in `pipe_A` have
    /// been drained. The caller adjudicates whether to actually demote
    /// (transitioning to [`ClientStatus::Demoted`]) or to abort the
    /// whole splice with an upstream-rate timeout: when the upstream
    /// rate has also fallen below threshold the client RC is observing
    /// the upstream bottleneck, so the caller surfaces the upstream
    /// failure instead of spawning a doomed file-serve task.
    DemoteRequested {
        /// Absolute cache file offset of the next byte the client expects.
        client_file_pos: u64,
        /// Bytes still owed to the client (matches the response Content-Length
        /// minus what was already written before/during the splice loop).
        client_remaining: u64,
    },
    /// Caller has accepted the demote: a file-serve task has been spawned
    /// and is now responsible for the client. Subsequent iterations of the
    /// splice loop treat this identically to `Disconnected` (cache-only
    /// path), and the byte counts the spawned task needs were already
    /// passed in via the preceding `DemoteRequested`.
    Demoted,
}

/// Shared tee+splice fan-out: consume `got` bytes from `pipe_A`, duplicate to `pipe_B`,
/// splice `pipe_A→client` and `pipe_B→cache`.
///
/// If the client disconnects mid-transfer, the function continues to drain `pipe_A` and
/// write to the cache file so concurrent hyper clients can still complete.
///
/// If the client send rate drops below the configured minimum, remaining bytes are
/// drained and `ClientStatus::DemoteRequested` is returned so the caller can
/// either promote it to `ClientStatus::Demoted` (spawn a file-serve task) or
/// abort the splice with an upstream-rate timeout when the upstream is the
/// actual bottleneck.
#[expect(clippy::too_many_arguments, reason = "function has only 2 callers")]
async fn tee_and_splice(
    upstream_pipe_rx: &pipe::Receiver,
    cache_pipe_rx: &pipe::Receiver,
    cache_pipe_tx: &pipe::Sender,
    client: &TcpStream,
    target: (&tokio::fs::File, &mut i64),
    client_total: u64,
    got: usize,
    client_status: ClientStatus,
    dbarrier: &mut DownloadBarrier,
    client_rate_checker: &mut Option<RateChecker>,
    client_file_pos: &mut u64,
    client_remaining: &mut u64,
) -> Result<ClientStatus, BodyTransferError> {
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
                        return Err(BodyTransferError::proxy(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "splice proxy: tee returned 0",
                        )));
                    }
                    Ok(n) => break n,
                    Err(nix::errno::Errno::EINTR) => continue,
                    // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                    Err(nix::errno::Errno::EAGAIN) => {
                        clear_pipe_readable_cache(upstream_pipe_rx);
                        clear_pipe_writable_cache(cache_pipe_tx);
                        tokio::select! {
                            r = upstream_pipe_rx.readable() => r.map_err(BodyTransferError::proxy)?,
                            w = cache_pipe_tx.writable() => w.map_err(BodyTransferError::proxy)?,
                        }
                        continue;
                    }
                    Err(err) => {
                        return Err(BodyTransferError::proxy(errno_to_io_error(
                            err,
                            "tee failed",
                        )));
                    }
                };
            };

            // Step 3: splice pipe_B → cache file first (fast, local disk I/O)
            splice_pipe_to_file(cache_pipe_rx, cache_file, teed, file_offset)
                .await
                .map_err(BodyTransferError::cache)?;

            // Notify concurrent clients that new data is on disk
            dbarrier.ping_batched(teed as u64);

            // Step 4: splice pipe_A → client (may be slow, but no longer blocks cache)
            // pipe_A always has data on entry (just filled by tee), so try the
            // splice optimistically and only park on EAGAIN. This keeps
            // `wait_writable_rated`'s rc.add(0) ticks and http_timeout intact
            // — they only run when the client is actually back-pressuring,
            // not on every busy iteration where pipe-readable would otherwise
            // win the `select!` race and cancel them mid-flight.
            // Tracks how many of the just-teed bytes are still sitting in
            // `pipe_A` waiting to be spliced to the client. Distinct from the
            // outer `client_remaining` parameter (response-level total).
            let mut teed_remaining = teed;
            while teed_remaining > 0 {
                let result = splice(
                    upstream_pipe_rx,
                    None,
                    client,
                    None,
                    teed_remaining,
                    SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_MORE,
                );

                let _: Never = match result {
                    Ok(0)
                    | Err(
                        nix::errno::Errno::EPIPE
                        | nix::errno::Errno::ECONNRESET
                        | nix::errno::Errno::ECONNABORTED
                        | nix::errno::Errno::ENOTCONN,
                    ) => {
                        // Client disconnected — drain the remaining teed bytes from pipe_A
                        // by splicing them to /dev/null (discard)
                        metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                        let client_sent = client_total - *client_remaining;
                        #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
                        let client_sent_percent = 100.0 * client_sent as f32 / client_total as f32;
                        info!(
                            "splice proxy: client disconnected after {} out of {} ({:.1}%), continuing cache-only",
                            HumanFmt::Size(client_sent),
                            HumanFmt::Size(client_total),
                            client_sent_percent,
                        );
                        status = ClientStatus::Disconnected;
                        drain_pipe(upstream_pipe_rx, teed_remaining)
                            .await
                            .map_err(BodyTransferError::proxy)?;
                        break;
                    }
                    Ok(n) => {
                        teed_remaining -= n;
                        *client_file_pos += n as u64;
                        *client_remaining = client_remaining
                            .checked_sub(n as u64)
                            .expect("client_remaining tracks bytes still owed to the client");
                        metrics::BYTES_SERVED_SPLICE.increment_by(n as u64);
                        if let Some(rc) = client_rate_checker {
                            rc.add(n);
                            if rc.check_fail(RateCheckDirection::Client).is_some() {
                                // Client RC tripped — drain remaining teed bytes
                                // (cache already has them) and hand off to the
                                // caller. The outer loop decides whether to
                                // actually demote or to abort the splice on
                                // upstream-rate failure (slow upstream is the
                                // most common reason the client RC also trips).
                                // `teed_remaining` has already been decremented by `n` (the bytes
                                // just sent to the client), so it is exactly the count of teed
                                // bytes still sitting in pipe_A that need to be drained before
                                // we can stop servicing the client.
                                drain_pipe(upstream_pipe_rx, teed_remaining)
                                    .await
                                    .map_err(BodyTransferError::proxy)?;

                                status = ClientStatus::DemoteRequested {
                                    client_file_pos: *client_file_pos,
                                    client_remaining: *client_remaining,
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
                            ) => w.map_err(BodyTransferError::client)?,
                            r = upstream_pipe_rx.readable() => r.map_err(BodyTransferError::proxy)?,
                        }
                        continue;
                    }
                    Err(err) => {
                        return Err(BodyTransferError::client(errno_to_io_error(
                            err,
                            "splice failed",
                        )));
                    }
                };
            }

            remaining = remaining
                .checked_sub(teed)
                .expect("splice should not return more than requested");
        } else {
            // Client is gone or demoted — splice pipe_A directly to cache (no tee needed)
            splice_pipe_to_file(upstream_pipe_rx, cache_file, remaining, file_offset)
                .await
                .map_err(BodyTransferError::cache)?;
            dbarrier.ping_batched(remaining as u64);
            remaining = 0;
        }
    }

    Ok(status)
}

/// Read exactly `count` bytes from a pipe into a Vec (for boundary chunks
/// that straddle a client range boundary and need userspace slicing).
async fn read_pipe_to_buf(rx: &mut pipe::Receiver, count: usize) -> std::io::Result<Vec<u8>> {
    // Reserve uninitialized capacity; `read_buf` fills bytes via `BufMut`
    // so no zero-init pass is performed before the data is overwritten.
    let mut read_buf: Vec<u8> = Vec::with_capacity(count);

    while read_buf.len() < count {
        let want = (count - read_buf.len()) as u64;
        let n = (&mut *rx).take(want).read_buf(&mut read_buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "read_pipe_to_buf: pipe closed with bytes remaining",
            ));
        }
    }

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

/// Drain `count` bytes from a pipe by `splice(2)`ing them into `/dev/null`.
///
/// Zero-copy — no userspace buffer is allocated and the bytes never cross
/// the kernel/userspace boundary. The destination fd is shared process-wide
/// via [`dev_null`]; the receiver is the caller-owned pipe end.
///
/// Returns `UnexpectedEof` if the pipe's write end closes before `count` bytes
/// have been moved.
async fn drain_pipe(rx: &pipe::Receiver, count: usize) -> std::io::Result<()> {
    if count == 0 {
        return Ok(());
    }
    let devnull = dev_null()?;
    let mut remaining = count;
    while remaining > 0 {
        rx.readable().await?;

        let result = splice(
            rx,
            None,
            devnull,
            None,
            remaining,
            SpliceFFlags::SPLICE_F_MOVE,
        );

        let _: Never = match result {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "drain_pipe: pipe closed with bytes remaining",
                ));
            }
            Ok(n) => {
                remaining = remaining
                    .checked_sub(n)
                    .expect("splice should not return more than requested");
                continue;
            }
            Err(nix::errno::Errno::EINTR) => continue,
            // EAGAIN/EWOULDBLOCK: see module-level static_assert. Force Tokio
            // to re-arm readiness so the next `readable().await` actually
            // parks on a fresh epoll event instead of spinning on the cached
            // ready bit.
            Err(nix::errno::Errno::EAGAIN) => {
                clear_pipe_readable_cache(rx);
                continue;
            }
            Err(err) => {
                return Err(errno_to_io_error(
                    err,
                    "drain_pipe: splice to /dev/null failed",
                ));
            }
        };
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
    scheme_override: Option<Scheme>,
) -> Result<UpstreamExchange, SpliceProxyError> {
    // Resolve the scheme decision ONCE per connect: it drives the pool-lookup
    // key, the HTTPS-upgrade accounting, and the connect itself. A per-request
    // redirect forcing the scheme carries no decision, and so does none of the
    // scheme-cache / upgrade-metric bookkeeping below.
    let (resolved_scheme, decision) = if let Some(scheme) = scheme_override {
        (Some(scheme), None)
    } else {
        let decision = scheme_cache::resolve(mirror.into(), global_config());
        // `None` = Auto upgrade, i.e. try HTTPS then fall back to HTTP.
        (decision.fixed_scheme(), Some(decision))
    };

    // Try a pooled connection first. In Auto mode without a cached scheme there
    // is no key to look up by, so account for it as `POOL_MISS_NO_SCHEME` and
    // fall through to the fresh-connect path — the invariant
    // `POOL_NEW ≈ sum(POOL_MISS_*)` then holds for first connections too.
    if let Some(scheme) = resolved_scheme {
        let is_tls = matches!(scheme, Scheme::Https);
        let port = mirror_port(mirror, is_tls);
        if let Some(mut pooled) = pool_checkout(mirror.host(), port, is_tls) {
            if pooled.check_alive(mirror.host(), port) {
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
                        return Ok(UpstreamExchange {
                            conn: PoolGuard::new(pooled, mirror.host().to_string(), port, poolable),
                            response: resp,
                            header_buf: hdr_buf,
                            header_end: hdr_end,
                            tls_label: label,
                        });
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
    } else {
        metrics::POOL_MISS_NO_SCHEME.increment();
    }

    debug!("splice proxy: no pooled connection to {host_authority}, opening fresh...");

    metrics::POOL_NEW.increment();

    // HTTPS-upgrade accounting, read off the decision resolved above. The timing
    // and the deliberate divergences from hyper are documented on the counters in
    // metrics.rs.
    if decision.is_some_and(SchemeDecision::is_upgrade_attempt) {
        metrics::HTTPS_UPGRADE_ATTEMPTED.increment();
    }

    let mut backoff = upstream_retry::Backoff::new(
        global_config().upstream_retry_budget,
        coarsetime::Instant::now(),
    );
    let (mut up, scheme) = loop {
        let err = match connect_upstream(mirror, resolved_scheme).await {
            Ok(conn) => break conn,
            Err(err) => err,
        };
        let attempt = backoff.attempt();
        // A permanent failure repeats identically on every retry, so it skips
        // the budget and drops straight into the terminal branch below --
        // sparing 10 pointless TCP connects and TLS handshakes.
        let permanent = matches!(err, ConnectError::Permanent(_));
        let next = if permanent {
            None
        } else {
            backoff.next_retry(coarsetime::Instant::now())
        };
        let Some(delay) = next else {
            if permanent {
                warn_once_or_info!(
                    "splice proxy: not retrying permanent connect failure to upstream {host_authority} for {upstream_path}; returning 502:  {}",
                    ErrorReport(err.io_err())
                );
            } else {
                // The limit names which budget stopped the retries -- attempt
                // cap or `upstream_retry_budget`.
                warn_once_or_info!(
                    "splice proxy: failed to connect to upstream {host_authority} for {upstream_path} after {attempt} connection attempts ({}); returning 502:  {}",
                    backoff.limit(),
                    ErrorReport(err.io_err())
                );
            }
            if let Some(decision) = decision {
                // Evict a stale cached scheme so the next request re-resolves,
                // mirroring the hyper backend.
                if let Some(scheme) = scheme_cache::record_failure(mirror.into()) {
                    // A learned scheme is sticky, so losing it silently changes
                    // how every later request to this host is dialled (an
                    // evicted https entry can hand the host back to plain http
                    // under Auto mode).
                    warn_once_or_info!(
                        "splice proxy: evicted cached {scheme} scheme for host {} after connect failure; the next request re-decides the scheme",
                        mirror.format_authority()
                    );
                }
                if decision.is_upgrade_attempt() {
                    metrics::HTTPS_UPGRADE_FAILED.increment();
                }
            }
            return Err(SpliceProxyError::Upstream);
        };
        debug!(
            "splice proxy: failed to connect to {host_authority} after {attempt} connection attempts, will retry in {} ms:  {}",
            delay.as_millis(),
            ErrorReport(err.io_err())
        );
        tokio::time::sleep(delay).await;
    };
    if let Some(decision) = decision {
        cache_scheme(mirror, scheme);
        // Loop-exit upgrade outcome: HTTPS connected → SUCCEEDED; fell back to
        // HTTP → REVERTED.
        if decision.is_upgrade_attempt() {
            match scheme {
                Scheme::Https => metrics::HTTPS_UPGRADE_SUCCEEDED.increment(),
                Scheme::Http => metrics::HTTPS_UPGRADE_REVERTED.increment(),
            }
        }
    }

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
        warn_once_or_info!(
            "splice proxy: failed upstream request to {host_authority} for {upstream_path}; returning 502:  {}",
            ErrorReport(&err)
        );
        SpliceProxyError::Upstream
    })?;

    let label = if is_tls { " (TLS)" } else { "" };
    let poolable = !resp.connection_close;
    let port = mirror_port(mirror, is_tls);
    Ok(UpstreamExchange {
        conn: PoolGuard::new(up, mirror.host().to_string(), port, poolable),
        response: resp,
        header_buf: hdr_buf,
        header_end: hdr_end,
        tls_label: label,
    })
}

/// Follow a 3xx redirect if the Location target is valid and allowed.
///
/// On success, replaces `exchange` (connection, response, header buffer and
/// TLS label) with the redirected request's exchange, and returns
/// `Some(redirected_path)`. If the redirect is not followable (invalid URI,
/// disallowed host), logs and returns `None` so the caller falls through to the
/// non-200 forwarding path.
///
/// Times out after the configured HTTP timeout.
async fn follow_redirect(
    exchange: &mut UpstreamExchange,
    conn_details: &ConnectionDetails,
    original_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> Result<Option<String>, SpliceProxyError> {
    let status = exchange.response.status_code;
    let Some(location) = exchange.response.location.as_deref() else {
        // Every other reject branch below logs; without this one a broken
        // upstream's 3xx is forwarded to the client with nothing cached and
        // no explanation anywhere.
        warn_once_or_info!(
            "splice proxy: upstream {} answered {status} for {} without a Location header; forwarding the redirect to the client uncached",
            conn_details.mirror,
            conn_details.debname
        );
        return Ok(None);
    };
    let Ok(moved_uri) = location.parse::<http::Uri>() else {
        debug!(
            "splice proxy: {status} with unparsable Location `{}`, not following",
            location.escape_debug()
        );
        return Ok(None);
    };
    if moved_uri.scheme().is_none() {
        // A relative Location (`/pool/...`) is legal per RFC 9110 and common
        // on redirectors, but this backend only follows absolute targets, so
        // the resource is forwarded uncached on every request. Checked before
        // the scheme branch below, which would otherwise report a relative
        // target as a non-HTTP scheme.
        warn_once_or_info!(
            "splice proxy: upstream {} sent {status} for {} with relative Location `{}`; not following the redirect and not caching the response",
            conn_details.mirror,
            conn_details.debname,
            location.escape_debug()
        );
        return Ok(None);
    }
    let Some(redirect_scheme) = moved_uri.scheme().and_then(Scheme::from_uri_scheme) else {
        debug!("splice proxy: {status} redirect to non-HTTP scheme `{moved_uri}`, not following");
        return Ok(None);
    };
    let Some(moved_host) = moved_uri.host() else {
        debug!("splice proxy: {status} redirect target `{moved_uri}` has no host, not following");
        return Ok(None);
    };
    if !is_host_allowed_cached(moved_host) {
        debug!(
            "splice proxy: {status} redirect host `{moved_host}` not in allowed_mirrors, not following"
        );
        return Ok(None);
    }
    let Ok(moved_domain) = ClientHost::new(moved_host.to_owned()) else {
        // Upstream-controlled and per request, like its sibling branches.
        warn_once_or_info!(
            "splice proxy: upstream {} sent {status} for {} with an invalid redirect host `{}`; not following the redirect and not caching the response",
            conn_details.mirror,
            conn_details.debname,
            moved_host.escape_debug()
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
    let original_port_effective = mirror_port(&conn_details.mirror, exchange.conn.is_tls());
    if moved_host == conn_details.mirror.host()
        && moved_port_effective == original_port_effective
        && moved_path == original_path
    {
        debug!(
            "splice proxy: {status} redirect target `{moved_uri}` matches original request, not following"
        );
        return Ok(None);
    }

    debug!(
        "splice proxy: following {status} redirect from {} to {moved_uri}",
        conn_details.mirror
    );

    // Mark as non-poolable so the old connection is discarded (not returned to
    // pool) when we reassign `*exchange` below.
    exchange.conn.unset_poolable();

    let moved_port = moved_uri.port_u16().and_then(NonZero::new);
    // Redirect Mirror: used only for upstream dispatch/formatting; never persisted.
    let redirect_mirror = Mirror::new(
        moved_domain,
        moved_port,
        String::new(),
        MirrorKind::Structured,
    );
    let redirect_authority = redirect_mirror.format_authority();
    let redirect_path = moved_path;

    *exchange = standard_upstream_connect(
        &redirect_mirror,
        &redirect_authority,
        redirect_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
        Some(redirect_scheme),
    )
    .await
    .inspect_err(|_| {
        // The throw site inside `standard_upstream_connect` already WARNs
        // with the underlying error detail (per `SpliceProxyError::Upstream`
        // log convention); this line adds the redirect breadcrumb so an
        // operator can correlate the connect failure with the redirect that
        // pointed at the now-failing target.
        warn_once_or_info!(
            "splice proxy: failed to connect to the upstream after a {status} redirect from {} to `{moved_uri}`; returning 502",
            conn_details.mirror
        );
    })?;

    Ok(Some(redirect_path.to_owned()))
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
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
    let mut client_rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

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
///
/// On success the closing `\r\n` after the `0\r\n` terminator has been fully
/// consumed from the upstream socket buffer, so the connection can be safely
/// returned to the pool (mirrors the buffered variant
/// [`read_dechunk_body_to_vec`]). On error the connection state is
/// indeterminate -- callers must mark the upstream non-poolable.
async fn forward_upstream_chunked_body(
    upstream: &mut UpstreamConn,
    client: &TcpStream,
    body_prefix: &[u8],
    max_bytes: usize,
) -> std::io::Result<u64> {
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
    // Tracks raw bytes (framing + data) written to the client.
    let mut client_total: u64 = 0;

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
                                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                                    std::io::Error::new(
                                        ErrorKind::InvalidData,
                                        "chunked encoding: invalid chunk-size line",
                                    )
                                })?;
                                let chunk_size = usize::from_str_radix(hex_str.trim(), 16).map_err(|_| {
                                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
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
                                            "splice proxy: chunked response body exceeded {} byte cap; truncating the relayed body",
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
                                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
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
                                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                                    return Err(std::io::Error::new(
                                        ErrorKind::InvalidData,
                                        "chunked encoding: expected CR after chunk data",
                                    ));
                                }
                            } else {
                                if b == b'\n' {
                                    state = ChunkedState::ReadingSize;
                                } else {
                                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                                    return Err(std::io::Error::new(
                                        ErrorKind::InvalidData,
                                        "chunked encoding: expected LF after chunk data CR",
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
                                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
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
            // Framing validated -- forward the raw bytes to the client unchanged.
            // When the terminal chunk has been consumed we forward only the
            // validated prefix `&data[..i]`; any bytes past the closing \r\n
            // are a framing violation (smuggling attempt, buggy upstream) and
            // must NOT be relayed to the client. Mirrors the buffered variant
            // `read_dechunk_body_to_vec`, which treats trailing-after-Done as
            // a poison-connection error.
            let forward_slice: &[u8] = if done { &data[..i] } else { data };
            if !forward_slice.is_empty() {
                write_all_to_stream_rated(
                    client,
                    forward_slice,
                    &mut client_rate_checker,
                    RateCheckDirection::Client,
                    config.http_timeout,
                )
                .await
                .map_err(|e| {
                    std::io::Error::new(e.kind(), format!("chunked forward: client write:  {e}"))
                })?;
                metrics::BYTES_SERVED_PASSTHROUGH.increment_by(forward_slice.len() as u64);
                client_total += forward_slice.len() as u64;
            }
            if done && i < data.len() {
                // Defence in depth: well-behaved upstreams send no bytes past
                // the closing `\r\n`. Surface this as a framing violation and
                // drop the client connection. Callers must mark the upstream
                // non-poolable on any error returned from this function
                // (stray bytes in the kernel socket buffer would poison the
                // next checkout) -- matches the buffered counterpart
                // `read_dechunk_body_to_vec`.
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "chunked encoding: trailing bytes after 0-length chunk",
                ));
            }
            done
        }};
    }

    // Bootstrap: process bytes that arrived with the response headers.
    if process_buf!(body_prefix) {
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

        if process_buf!(&buf[..n]) {
            return Ok(client_total);
        }
    }
}

/// Log an upstream response the planner rejected (`DownloadPlan::Reject`).
///
/// `origin` tags the kTLS one-shot attempt (`" (from kTLS attempt)"`) or is
/// empty.  Wording mirrors `hyper_conn.rs::serve_new_file` modulo the
/// subsystem prefix (`docs/logging.md`, cross-backend parity).
fn warn_upstream_reject(reason: RejectReason, conn_details: &ConnectionDetails, origin: &str) {
    match reason {
        RejectReason::Unsolicited206 => warn_once_or_info!(
            "splice proxy: upstream returned 206 Partial Content without a Range request for {} from mirror {}{origin}; returning 502",
            conn_details.debname,
            conn_details.mirror
        ),
        RejectReason::InconsistentContentRange {
            content_length,
            span,
        } => warn_once_or_info!(
            "splice proxy: Content-Length {content_length} disagrees with Content-Range span {span} for {} from mirror {}{origin}; returning 502",
            conn_details.debname,
            conn_details.mirror
        ),
        RejectReason::Oversize { total } => warn_once_or_info!(
            "splice proxy: upstream declared total size {} for file {} from mirror {}{origin}, exceeding `max_object_size`; returning 502",
            HumanFmt::Size(total),
            conn_details.debname,
            conn_details.mirror
        ),
        RejectReason::NoContentLength => warn_once_or_info!(
            "splice proxy: upstream sent no usable Content-Length for file {} from mirror {}{origin}; returning 502",
            conn_details.debname,
            conn_details.mirror
        ),
        RejectReason::ZeroContentLength => warn_once_or_info!(
            "splice proxy: upstream declared Content-Length 0 for file {} from mirror {}{origin}; returning 502",
            conn_details.debname,
            conn_details.mirror
        ),
    }
}

/// Discard a stale partial download file and retry the upstream request from scratch.
///
/// Shared by the 416 and invalid-Content-Range recovery paths
/// (`ResumeAnomaly::needs_refetch`).
async fn discard_partial_and_retry(
    partial: &mut utils::PartialDownload,
    mirror: &Mirror,
    host_authority: &str,
    upstream_path: &str,
    exchange: &mut UpstreamExchange,
    conn_details: &ConnectionDetails,
) -> Result<(), SpliceProxyError> {
    partial.discard_resume().await;
    exchange.conn.unset_poolable();
    *exchange =
        standard_upstream_connect(mirror, host_authority, upstream_path, 0, None, None, None)
            .await?;
    // The fresh connect above does not follow redirects; the caller's top-level
    // redirect handling already ran on the original (now-discarded) response, so
    // follow one redirect here if the retry also lands on a 3xx (the retry is
    // always a fresh full request: resume_offset=0, no If-Range/volatile cond).
    if matches!(
        exchange.response.status_code,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    ) {
        follow_redirect(exchange, conn_details, upstream_path, 0, None, None).await?;
    }
    Ok(())
}

/// Acquire the upstream exchange for a cache-miss download.
///
/// Under `ktls` the unbuffered kTLS attempt runs first (connect + handshake +
/// request + response headers in one shot with guaranteed record alignment)
/// and falls back to [`standard_upstream_connect`] on any failure or on a
/// response it cannot splice -- except for the two responses resolvable from
/// the already-buffered head alone (a planner-rejected 200, a 304 with a
/// cached copy), which come back as their own [`UpstreamAcquire`] variants so
/// no reconnect is spent on them. Without `ktls` this is
/// `standard_upstream_connect`.
///
/// Times out after the configured HTTP timeout.
async fn acquire_upstream(
    conn_details: &ConnectionDetails,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
    #[cfg(feature = "ktls")] volatile_cache_path: &mut Option<PathBuf>,
) -> Result<UpstreamAcquire, SpliceProxyError> {
    let mirror = &conn_details.mirror;

    #[cfg(feature = "ktls")]
    {
        let unbuffered_result = try_unbuffered_ktls_connect(
            mirror,
            host_authority,
            upstream_path,
            resume_offset,
            resume_if_range,
            volatile_cond,
        )
        .await;

        // Handle kTLS ResponseNotSpliceable early for cases we can fully resolve
        // from the already-buffered data (304 -> serve cache, 200-without-CL non-volatile
        // -> 502). Everything else falls through to the standard path, which reconnects
        // to deliver a complete response rather than forwarding a potentially truncated
        // body from the one-shot kTLS attempt.
        if let KtlsResult::ResponseNotSpliceable { ref response, .. } = unbuffered_result {
            cache_scheme(mirror, Scheme::Https);
            if response.status_code == 200 {
                // A 200 the kTLS path could not splice has no usable
                // Content-Length (absent, chunked or zero).  The planner refuses
                // what it would refuse on the standard path too (permanent files,
                // `Content-Length: 0`) without a reconnect; a volatile file falls
                // through to the standard path for a buffered download, whose
                // reconnect bumps `record_upstream_status` itself.
                match plan_fresh_download::<PathBuf>(
                    &response.head(),
                    conn_details.cached_flavor,
                    None,
                    global_config().max_object_size,
                ) {
                    DownloadPlan::Reject(reason) => {
                        reason.record_metrics();
                        warn_upstream_reject(reason, conn_details, " (from kTLS attempt)");
                        // Honoring the kTLS-parsed response: record its status before
                        // the caller emits our own 502 to the client. (The standard
                        // path is not reconnected for, so no other site will record
                        // this 200.)
                        metrics::record_upstream_status(response.status_code);
                        return Ok(UpstreamAcquire::KtlsReject(reason));
                    }
                    DownloadPlan::NotModified(_)
                    | DownloadPlan::Passthrough
                    | DownloadPlan::Download { .. } => {
                        debug!(
                            "splice proxy: volatile file without Content-Length (from kTLS attempt), \
                             falling back to standard path for buffered download"
                        );
                    }
                }
            }
            // During resume, 206 and 416 need the standard buffered path
            if resume_offset > 0 && (response.status_code == 206 || response.status_code == 416) {
                debug!(
                    "splice proxy: kTLS got {} during resume, falling back to standard path",
                    response.status_code
                );
                // Fall through to standard_upstream_connect via the ResponseNotSpliceable arm below
            } else if response.status_code == 304
                && let Some(cache_path) = volatile_cache_path.take()
            {
                // 304 from kTLS for volatile resource -- the caller serves the cached
                // file directly rather than reconnecting on the standard path just to
                // get the same 304.
                debug!(
                    "splice proxy: kTLS upstream returned 304 for {} from mirror {}, serving cached file",
                    conn_details.debname, conn_details.mirror
                );

                // Honoring the kTLS-parsed 304: record its upstream status here
                // since no standard-path reconnect will run for this response.
                metrics::record_upstream_status(response.status_code);

                return Ok(UpstreamAcquire::KtlsNotModified(cache_path));
            } else {
                // Non-200 / no-Content-Length response from the kTLS attempt.
                // We cannot safely forward just the buffered bytes: the body may be
                // longer than what rustls already decrypted, and the kTLS connection
                // has been consumed for a single request -- there is no userspace read
                // loop to pull the remainder. Falling through to the standard path
                // reconnects and re-fetches, which delivers a complete response to
                // the client. One extra request is cheaper than a truncated reply.
                debug!(
                    "splice proxy: upstream returned {} (from kTLS attempt), reconnecting via standard path",
                    response.status_code
                );
                // Fall through to the `ResponseNotSpliceable { .. }` match arm below,
                // which leads to standard_upstream_connect().
            }
        }

        match unbuffered_result {
            KtlsResult::Ready(tcp, state) => {
                // The kTLS fast path is outside HTTPS_UPGRADE_* accounting (see
                // metrics.rs); both sides of the identity are skipped together.
                cache_scheme(mirror, Scheme::Https);
                // kTLS connections must NOT be pooled: the socket has kernel TLS
                // RX configured for this specific session's keys and sequence
                // numbers. Reusing it for a new request would layer a new TLS
                // handshake on top of the kTLS socket, corrupting the stream.
                // Future optimization: kTLS sockets could be pooled as a separate
                // "kTLS-ready" type that writes plaintext (kernel encrypts via TX)
                // and splices responses (kernel decrypts via RX), skipping the TLS
                // handshake entirely. This requires a distinct pool entry type,
                // control-message draining between requests, and key-update handling.
                let poolable = false;
                let port = mirror_port(mirror, true);
                // Honoring the kTLS-parsed response: record its upstream status
                // here since no standard-path reconnect will run for this flow.
                metrics::record_upstream_status(state.response.status_code);
                let KtlsReadyState {
                    response,
                    header_buf,
                    header_end,
                } = state;
                return Ok(UpstreamAcquire::Exchange(UpstreamExchange {
                    conn: PoolGuard::new(
                        UpstreamConn::Tcp(tcp),
                        mirror.host().to_string(),
                        port,
                        poolable,
                    ),
                    response,
                    header_buf,
                    header_end,
                    tls_label: KTLS_TLS_LABEL,
                }));
            }
            KtlsResult::ResponseNotSpliceable { response: _ } => {
                // Normally handled above, but during resume 206/416 fall through here
                // to use the standard buffered path for proper resume handling.
                // A full reconnect, not a reuse of the kTLS socket: that socket is
                // already dropped and would be unsound to reuse (KtlsResult contract).
            }
            KtlsResult::Failed { tls_succeeded } => {
                // Cache HTTPS scheme if TLS handshake succeeded, avoiding double-HTTPS
                // in auto mode
                if tls_succeeded {
                    cache_scheme(mirror, Scheme::Https);
                }
            }
        }
    }

    standard_upstream_connect(
        mirror,
        host_authority,
        upstream_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
        None,
    )
    .await
    .map(UpstreamAcquire::Exchange)
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
    let (init_tx, status) = match appstate.active_downloads.originate(conn_details.key()) {
        OriginateOutcome::Originator { init_tx, status } => (init_tx, status),
        OriginateOutcome::Concurrent { status } => {
            return Ok(SpliceProxyOutcome::Concurrent { status });
        }
        OriginateOutcome::AtCapacity { max } => {
            return Ok(SpliceProxyOutcome::AtCapacity { max });
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

/// Serve a cached volatile file after an upstream `304 Not Modified`: refresh
/// the freshness window via `touch_volatile_mtime`, release the init barrier,
/// then deliver the file with `sendfile(2)`. Shared by the kTLS fast path and
/// the standard upstream path in [`splice_proxy_drive`]; the per-path bits
/// (status recording, upstream-connection pooling, `debug!` wording) stay at
/// the call site, and `invalid_tag` carries the call-site location tag for
/// `SpliceProxyError::Client`.
#[expect(
    clippy::too_many_arguments,
    reason = "shared 304 tail path; splitting the args would not aid clarity"
)]
async fn serve_volatile_304_via_sendfile(
    client_stream: &TcpStream,
    conn_details: &ConnectionDetails,
    cache_path: &Path,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    client_range: RangeRequestHeaders<'_>,
    ibarrier: InitBarrier<'_>,
    invalid_tag: &'static str,
) -> Result<(), SpliceProxyError> {
    if !conn_details.client.is_cleanup_synthetic() {
        metrics::VOLATILE_REFETCHED_UPTODATE.increment();
    }

    let file = match tokio_nofollow_options().read(true).open(cache_path).await {
        Ok(f) => f,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to open cached file `{}` after 304; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            return Err(SpliceProxyError::Cache);
        }
    };
    let file = touch_volatile_mtime(file, cache_path).await;
    ibarrier.finished(cache_path.to_path_buf()).await;

    match serve_file_via_sendfile(
        client_stream,
        conn_details,
        "",
        (file, None, cache_path),
        (conn_version, conn_action),
        client_range,
        None,
    )
    .await
    {
        SendfileResult::Served(_)
        | SendfileResult::ClientError
        | SendfileResult::AfterHeaderError => Ok(()),
        SendfileResult::Invalid { status, msg } => {
            write_invalid_response(client_stream, conn_version, conn_action, status, msg, None)
                .await
                .map_err(|err| SpliceProxyError::Client(err, invalid_tag))?;
            Ok(())
        }
    }
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
    let mirror = &conn_details.mirror;
    let host_authority = mirror.format_authority();
    // Capture the original (pre-redirect) client request path. A 301 redirect
    // below shadows `upstream_path` to the redirected URL; the Origin row and
    // `handle_volatile_buffered_download` must carry the original path so
    // registry keys match across all backends (the hyper backend in
    // hyper_conn.rs always uses the client-request URI).
    // Strip the query so cache identity (registry keys, Origin rows) stays
    // path-only; the query still rides on the upstream GET line via
    // `upstream_path`. Matches the hyper backend.
    let original_uri_path = upstream_path
        .split_once('?')
        .map_or(upstream_path, |(path, _)| path);

    let ibarrier = InitBarrier::new(
        init_tx,
        &status,
        &appstate.active_downloads,
        conn_details,
        original_uri_path,
    );

    // Cleanup probes bypass the throttle: they run once per 24h cycle and a
    // 503 would hard-fail the index-fetch cascade; their commit outcome
    // still records/clears throttle state. (Only the hyper gate is reachable
    // by cleanup today; kept here for parallel-path symmetry.)
    if !conn_details.client.is_cleanup_synthetic()
        && let Some(throttled) = global_verify_throttle().check(conn_details.key())
    {
        warn_once_or_info!(
            "splice proxy: rejecting request for {} from client {}: recently failed checksum verification ({} consecutive failures), retry in {}",
            conn_details.debname,
            conn_details.client,
            throttled.failures,
            HumanFmt::Time(throttled.remaining)
        );
        metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.increment();
        write_invalid_response(
            client_stream,
            conn_version,
            conn_action,
            StatusCode::SERVICE_UNAVAILABLE,
            "Recently failed checksum verification",
            Some(throttled.remaining),
        )
        .await
        .map_err(|err| SpliceProxyError::Client(err, "verify-throttle 503"))?;
        return Ok(());
    }

    // Check for a partial download file to resume (permanent files only).
    // Opens the file upfront (if it exists and is non-empty) to get size + mtime
    // from the same file descriptor, avoiding TOCTOU races between metadata() and open().
    // The guard uses keep_on_drop: true so the partial file survives on fallback
    // (e.g., concurrent download → hyper path picks it up for resume).
    // Explicit guard.remove() is used only when a stale partial must be discarded.
    let (resume_offset, resume_expected_total, resume_if_range, mut partial) =
        if conn_details.cached_flavor == CachedFlavor::Permanent {
            match utils::prepare_partial_resume(
                &ibarrier,
                &conn_details.debname,
                &conn_details.mirror,
                "splice proxy: ",
            )
            .await
            {
                Ok(r) => (r.offset, r.expected_total, r.if_range, r.partial),
                Err((err, guard)) if err.kind() == ErrorKind::NotFound => {
                    (0, None, None, utils::PartialDownload::Fresh(guard))
                }
                Err((_err, guard)) => {
                    // Error already logged in `open_partial_file()`.
                    drop(guard);
                    return Err(SpliceProxyError::Cache);
                }
            }
        } else {
            (0, None, None, utils::PartialDownload::Volatile)
        };

    // --- Volatile revalidation: read cached file metadata for conditional headers ---
    // When a stale volatile file exists in cache, prepare If-Modified-Since / If-None-Match
    // headers so the upstream can respond with 304 Not Modified if the content hasn't changed.
    let mut volatile_cond: Option<VolatileCondHeaders> = None;
    let mut volatile_cache_path: Option<PathBuf> = None;
    if conn_details.cached_flavor == CachedFlavor::Volatile {
        let cache_path = conn_details.cache_file_path();

        let file = match tokio_nofollow_options().read(true).open(&cache_path).await {
            Ok(f) => Some(f),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to open volatile cached file `{}`; returning 500:  {}",
                    cache_path.display(),
                    ErrorReport(&err)
                );
                return Err(SpliceProxyError::Cache);
            }
        };
        if let Some(file) = file {
            let mdata = match regular_file_metadata(&file, &cache_path).await {
                Ok(m) => m,
                Err(CacheAccessFailure) => {
                    return Err(SpliceProxyError::Cache);
                }
            };

            // Use mtime (last revalidated time), matching the hyper backend.
            // Mtime is repurposed as "last revalidated" by touch_volatile_mtime(),
            // so it correctly tells upstream "has this changed since I last checked?".
            let mtime = mdata
                .modified()
                .expect("Platform should support modification timestamps via setup check");
            let if_modified_since = HttpDate::from(mtime).format();
            let key = conn_details.key();
            let if_none_match = cache_metadata::store()
                .resolve(&key, &file, &cache_path)
                .etag
                .clone();
            volatile_cond = Some(VolatileCondHeaders {
                if_modified_since,
                if_none_match,
            });
            volatile_cache_path = Some(cache_path);
        }
    }

    // --- Prepare upstream connection ---
    #[cfg_attr(
        not(feature = "ktls"),
        expect(
            clippy::infallible_destructuring_match,
            reason = "the kTLS-only variants make the match refutable in ktls builds"
        )
    )]
    let mut exchange = match acquire_upstream(
        conn_details,
        &host_authority,
        upstream_path,
        resume_offset,
        resume_if_range.as_deref(),
        volatile_cond.as_ref(),
        #[cfg(feature = "ktls")]
        &mut volatile_cache_path,
    )
    .await?
    {
        UpstreamAcquire::Exchange(exchange) => exchange,
        #[cfg(feature = "ktls")]
        UpstreamAcquire::KtlsReject(reason) => {
            write_invalid_response(
                client_stream,
                conn_version,
                conn_action,
                StatusCode::BAD_GATEWAY,
                reason.body(),
                None,
            )
            .await
            .map_err(|err| SpliceProxyError::Client(err, "kTLS upstream reject 502"))?;
            return Ok(());
        }
        #[cfg(feature = "ktls")]
        UpstreamAcquire::KtlsNotModified(cache_path) => {
            return serve_volatile_304_via_sendfile(
                client_stream,
                conn_details,
                &cache_path,
                conn_version,
                conn_action,
                client_range,
                ibarrier,
                "kTLS post-304 invalid response",
            )
            .await;
        }
    };

    // Handle 3xx redirects (301/302/307/308): follow if the target host is allowed.
    // Only follows one redirect (no loops), matching hyper behavior. Runs first —
    // before the resume/304/passthrough handlers — so those all operate on the
    // (possibly redirected) response, mirroring hyper_conn.rs which follows the
    // redirect before its NOT_MODIFIED check.
    let redirected_path_owned = if matches!(
        exchange.response.status_code,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    ) {
        follow_redirect(
            &mut exchange,
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

    exchange.response.discard_invalid_validators(conn_details);

    // Volatile stale-but-present revalidation that returned a fresh body
    // (200 or 206): counterpart to the 304 / UPTODATE case in
    // `serve_volatile_304_via_sendfile`. The volatile-not-found path leaves
    // `volatile_cache_path` as None and is intentionally not split into
    // UPTODATE/OUTOFDATE.
    if volatile_cache_path.is_some()
        && (exchange.response.status_code == 200 || exchange.response.status_code == 206)
        && !conn_details.client.is_cleanup_synthetic()
    {
        metrics::VOLATILE_REFETCHED_OUTOFDATE.increment();
    }

    let plan = match plan_download(
        &exchange.response.head(),
        ResumeState::new(resume_offset, resume_expected_total),
        conn_details.cached_flavor,
        volatile_cache_path,
        global_config().max_object_size,
    ) {
        Ok(plan) => plan,
        Err(anomaly) => {
            match anomaly {
                ResumeAnomaly::RangeIgnored => info!(
                    "splice proxy: server returned 200 instead of 206 for resume of {} from mirror {}, starting fresh",
                    conn_details.debname, conn_details.mirror
                ),
                ResumeAnomaly::RangeNotSatisfiable => warn_once_or_info!(
                    "splice proxy: server returned 416 for resume of {} from mirror {} (partial {}); discarding the stale partial and retrying fresh",
                    conn_details.debname,
                    conn_details.mirror,
                    HumanFmt::Size(resume_offset)
                ),
                ResumeAnomaly::ContentRangeMismatch => warn_once_or_info!(
                    "splice proxy: invalid or mismatched Content-Range in 206 for {} from mirror {}; discarding the partial and retrying fresh",
                    conn_details.debname,
                    conn_details.mirror
                ),
            }
            if anomaly.needs_refetch() {
                discard_partial_and_retry(
                    &mut partial,
                    mirror,
                    &host_authority,
                    upstream_path,
                    &mut exchange,
                    conn_details,
                )
                .await?;
            } else {
                partial.discard_resume().await;
            }
            // A resume never revalidates: there is no cached copy to serve.
            plan_fresh_download(
                &exchange.response.head(),
                conn_details.cached_flavor,
                None,
                global_config().max_object_size,
            )
        }
    };

    // No reconnect helper runs past this point, so the exchange is final:
    // split it into the locals the rest of the download uses.
    let UpstreamExchange {
        conn: mut upstream,
        response: upstream_resp,
        header_buf,
        header_end,
        tls_label,
    } = exchange;

    let (total_content_length, body_content_length, resume_offset) = match plan {
        DownloadPlan::NotModified(cache_path) => {
            // Upstream confirms the cached copy is still current: refresh the
            // freshness window and serve the cached file via sendfile.
            debug!(
                "splice proxy: upstream returned 304 for {} from mirror {}, serving cached file",
                conn_details.debname, conn_details.mirror
            );

            // Pool the upstream connection back (304 has no body).
            if upstream_resp.connection_close {
                upstream.unset_poolable();
            }
            drop(upstream);

            return serve_volatile_304_via_sendfile(
                client_stream,
                conn_details,
                &cache_path,
                conn_version,
                conn_action,
                client_range,
                ibarrier,
                "post-304 invalid response",
            )
            .await;
        }
        DownloadPlan::Passthrough => {
            // Forward non-200/non-206 responses directly to the client instead
            // of falling back to hyper (which would open a redundant second
            // connection).
            debug!(
                "splice proxy: upstream returned {}, forwarding directly",
                upstream_resp.status_code
            );

            metrics::REQUESTS_PASSTHROUGH.increment();
            metrics::record_client_status(upstream_resp.status_code);

            // Rewrite the response headers before forwarding: strip hop-by-hop
            // headers, emit a single `Connection:` matching our keep-alive
            // decision, drop `Content-Length` when chunked, and append `Via:`.
            // Nothing has been written to the client yet, so a malformed-header
            // error can safely bail to a 502 via the outer arm.
            let passthrough_headers = match rewrite_simple_proxy_headers(
                &header_buf[..header_end],
                conn_version,
                conn_action,
                upstream_resp.status_code,
            ) {
                Ok(s) => s,
                Err(err) => {
                    warn_once_or_info!(
                        "splice proxy: failed to rewrite passthrough headers for {} from mirror {}; returning 502:  {}",
                        conn_details.debname,
                        conn_details.mirror,
                        ErrorReport(&err)
                    );
                    upstream.unset_poolable();
                    return Err(SpliceProxyError::Upstream);
                }
            };
            write_all_to_stream(
                client_stream,
                passthrough_headers.as_bytes(),
                WritePhase::Header,
            )
            .await
            .map_err(|err| SpliceProxyError::Client(err, "passthrough headers"))?;

            // Forward the body that arrived with the headers plus the rest,
            // framed per the upstream's (precedence-resolved) framing.
            let body_prefix = &header_buf[header_end..];
            upstream_resp
                .framing
                .relay_to_client(&mut upstream, client_stream, body_prefix, VOLATILE_BODY_MAX)
                .await
                .map_err(|err| SpliceProxyError::AfterHeaderClient(err, "passthrough body"))?;

            // InitBarrier fires on return, which is correct: nothing was cached
            // PoolGuard::drop handles returning the connection to pool if poolable
            metrics::SERVED_PASSTHROUGH.increment();
            metrics::SERVED_TOTAL.increment();
            return Ok(());
        }
        DownloadPlan::Reject(reason) => {
            reason.record_metrics();
            warn_upstream_reject(reason, conn_details, "");
            // Protocol-violating or unusable response: body bytes in the
            // header_buf tail or on the socket cannot be safely skipped, so
            // don't return the connection to the pool.
            upstream.unset_poolable();
            write_invalid_response(
                client_stream,
                conn_version,
                conn_action,
                StatusCode::BAD_GATEWAY,
                reason.body(),
                None,
            )
            .await
            .map_err(|err| SpliceProxyError::Client(err, "upstream reject 502"))?;
            return Ok(());
        }
        DownloadPlan::Download {
            total: ContentLength::Exact(total),
            body: ContentLength::Exact(body),
            resume_offset,
        } => {
            if resume_offset > 0 {
                #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
                let remaining_percent = body.get() as f32 / total.get() as f32 * 100.0;
                info!(
                    "splice proxy: resuming download of {} from mirror {} at {} ({} ({:.1}%) remaining of {} total)",
                    conn_details.debname,
                    conn_details.mirror,
                    HumanFmt::Size(resume_offset),
                    HumanFmt::Size(body.get()),
                    remaining_percent,
                    HumanFmt::Size(total.get())
                );
            }
            (total, body, resume_offset)
        }
        // A volatile file without a usable Content-Length (chunked or
        // close-delimited): length-delimited bodies are spliced, anything
        // else is buffered.
        DownloadPlan::Download { .. } => {
            return handle_volatile_buffered_download(
                &mut upstream,
                client_stream,
                conn_version,
                conn_action,
                conn_details,
                original_uri_path,
                &upstream_resp,
                &header_buf,
                header_end,
                ibarrier,
                client_range,
                tls_label,
            )
            .await;
        }
    };

    // Committed to splicing a length-delimited body: keep the upstream out of
    // the pool for the whole "body not yet drained" window, so no early return
    // below can leave a half-read connection re-poolable. Defused via
    // `consumed()` once the body is fully read.
    let mut upstream_guard = UnconsumedBodyGuard::new(&mut upstream);

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
        .map_err(|err| SpliceProxyError::Client(err, "416 response"))?;
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
            "splice proxy: failed to create cache directory `{}`; aborting the download:  {}",
            dest_dir.display(),
            ErrorReport(&err)
        );
        return Err(SpliceProxyError::Cache);
    }

    let filename = Path::new(&conn_details.debname);
    assert!(
        filename.is_relative(),
        "path construction must not contain absolute components"
    );

    let prev_file_size = match conn_details.cached_flavor {
        CachedFlavor::Volatile => {
            let prev_path = dest_dir.join(filename);
            match tokio::fs::symlink_metadata(&prev_path).await {
                Ok(m) if m.file_type().is_file() => m.len(),
                Ok(_) => {
                    metrics::CACHE_NON_REGULAR.increment();
                    error!(
                        "splice proxy: previous cache file `{}` is not a regular file; counting it as 0 bytes for the quota and overwriting it",
                        prev_path.display()
                    );
                    // `task_cache_scan` skips non-regular entries entirely
                    // (symlinks/FIFOs/sockets/dirs are not tallied into the
                    // tracked cache size), so the quota never accounted for
                    // them — there's nothing to "free" on overwrite.  0 is
                    // correct here and does not produce a reconciliation
                    // discrepancy.
                    0
                }
                Err(err) if err.kind() == ErrorKind::NotFound => 0,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "splice proxy: failed to stat existing volatile file `{}`; returning 500:  {}",
                        prev_path.display(),
                        ErrorReport(&err)
                    );
                    return Err(SpliceProxyError::Cache);
                }
            }
        }
        CachedFlavor::Permanent => {
            // permanent files are never overwritten
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
                None,
            )
            .await
            .map_err(|err| SpliceProxyError::Client(err, "quota 503"))?;
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
            let current_size = match file.seek(std::io::SeekFrom::End(0)).await {
                Ok(size) => size,
                Err(err) => {
                    // Substituting 0 makes the mismatch branch below report an
                    // empty partial file, which is not what happened -- the
                    // discarded errno is the whole diagnosis.
                    error!(
                        "splice proxy: failed to determine partial file size for {} from mirror {}; treating the partial as empty and returning 500:  {}",
                        conn_details.debname,
                        conn_details.mirror,
                        ErrorReport(&err)
                    );
                    0
                }
            };
            if current_size != resume_offset {
                error!(
                    "splice proxy: partial file size {current_size} != expected {resume_offset} for {} from mirror {} despite held fd; aborting the resume and returning 500",
                    conn_details.debname, conn_details.mirror
                );
                write_invalid_response(
                    client_stream,
                    conn_version,
                    conn_action,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Cache Access Failure",
                    None,
                )
                .await
                .map_err(|err| SpliceProxyError::Client(err, "partial-size mismatch 500"))?;
                return Ok(());
            }
            (file, guard)
        }
        utils::PartialDownload::Fresh(guard) => utils::create_partial_file(guard, 0o640)
            .await
            .map_err(|(err, path)| {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "splice proxy: failed to create partial file `{}`; aborting the download:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
                SpliceProxyError::Cache
            })?,
        utils::PartialDownload::Volatile => {
            let tmppath: PathBuf = [
                &global_config().cache_directory,
                Path::new(SUBDIR_TMP),
                filename,
            ]
            .iter()
            .collect();
            tokio_tempfile(&tmppath, 0o640).await.map_err(|err| {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "splice proxy: failed to create temp file `{}`; aborting the download:  {}",
                    tmppath.display(),
                    ErrorReport(&err)
                );
                SpliceProxyError::Cache
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
    // Persist expected total size so a future resume can detect upstream file changes.
    xattr_helpers::write_expected_size(&tempfile, &temppath, total_content_length.get());

    let download_meta = cache_metadata::UpstreamMetadata::from_upstream(
        upstream_resp.etag.clone(),
        upstream_resp.last_modified.clone(),
    );
    let mut dbarrier = ibarrier
        .download(
            temppath.to_path_buf(),
            ContentLength::Exact(total_content_length),
            reservation,
            Arc::new(download_meta),
        )
        .await;

    let body_prefix = &header_buf[header_end..];

    let Some(splice_count) = body_content_length
        .get()
        .checked_sub(body_prefix.len() as u64)
    else {
        metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
        error!(
            "splice proxy: body prefix ({} bytes) exceeds body content length ({} bytes) \
             for {} from mirror {}; returning 502",
            body_prefix.len(),
            body_content_length,
            conn_details.debname,
            conn_details.mirror
        );
        // `upstream_guard` poisons the connection on drop.
        write_invalid_response(
            client_stream,
            conn_version,
            conn_action,
            StatusCode::BAD_GATEWAY,
            "body Content-Length mismatch",
            None,
        )
        .await
        .map_err(|err| SpliceProxyError::Client(err, "body-CL mismatch 502"))?;
        return Ok(());
    };

    let start = PreciseInstant::now();

    // Per-request rate-logging timestamps.
    //   - `t_req_sent`: start of the upstream-rate window (instant the upstream
    //     request was sent; falls back to `start` only for bare-parser
    //     responses, i.e. tests).
    //   - `t_upstream_done`: end of the upstream-rate window. Initialised here
    //     so the case where the splice loop never runs (whole body arrived with
    //     the headers) still has a sane figure; reassigned right after the
    //     splice body block when it does run.
    //   - `t_client_first`: start of the client-rate window (just before the
    //     response-header write below).
    //   - `t_client_done`: end of the client-rate window; first set after the
    //     prefix writes, then reassigned after the splice body block and after
    //     the demoted file-serve task completes.
    //   - `client_bytes_sent`: best-effort count of body bytes written toward
    //     the client, for the disconnect segment.
    let t_req_sent = upstream_resp.request_sent_at.unwrap_or(start);
    let mut t_upstream_done = PreciseInstant::now();
    let mut client_bytes_sent: u64 = 0;

    if resume_offset > 0 {
        #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
        let resume_percent = resume_offset as f32 / total_content_length.get() as f32 * 100.0;

        debug!(
            "splice proxy{tls_label}: resuming and serving {} from mirror {} for client {} at byte {} ({:.1}%)...",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client,
            resume_offset,
            resume_percent
        );
    } else {
        debug!(
            "splice proxy{tls_label}: downloading and serving {} from mirror {} for client {}...",
            conn_details.debname, conn_details.mirror, conn_details.client
        );
    }

    // Write response headers to client
    let last_modified_str = upstream_resp.last_modified.as_deref();
    let content_type = content_type_for_cached_file(&conn_details.debname);
    warn_on_content_type_mismatch(
        upstream_resp.content_type.as_deref(),
        &conn_details.mirror,
        &conn_details.debname,
    );
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
        last_modified_header = OptHeader("Last-Modified", last_modified_str),
        etag_header = OptHeader("ETag", upstream_resp.etag.as_deref()),
        content_range_header = OptHeader("Content-Range", content_range_hdr.as_ref()),
    );

    // Cork the socket to coalesce headers + body prefix into fewer TCP segments
    let cork = CorkGuard::new_optional(client_stream);

    trace!("Outgoing {status_line} response:\n{response_headers}");

    metrics::record_client_status(if is_partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    });
    // Bump once per splice-served response, regardless of whether the body
    // ends up flowing through `splice_proxy_body{,_tls}`, the body-prefix
    // direct write, or the kTLS-extra-body direct write.
    metrics::REQUESTS_SPLICE.increment();
    // Start of the client-rate window: the first byte heading to the client.
    let t_client_first = PreciseInstant::now();
    write_all_to_stream(
        client_stream,
        response_headers.as_bytes(),
        WritePhase::Header,
    )
    .await
    .map_err(|err| SpliceProxyError::Client(err, "response headers"))?;

    // For resumed downloads, send the existing partial file content to the client first
    // using sendfile(2) for zero-copy transfer from the cache file to the client socket.
    // With a client Range, only send the overlap of [0, resume_offset) with the range.
    if resume_offset > 0 {
        let client_range_end = client_range_start + client_range_len;
        let send_start = client_range_start.min(resume_offset);
        let send_end = client_range_end.min(resume_offset);
        if send_end > send_start {
            let partial_reader = tokio_nofollow_options()
                .read(true)
                .open(temppath.as_ref())
                .await
                .map_err(|err| {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "splice proxy: failed to reopen partial file `{}` for resume; aborting the transfer and closing the connection:  {}",
                        temppath.display(),
                        ErrorReport(&err)
                    );
                    SpliceProxyError::AfterHeaderIo
                })?;

            match async_sendfile(
                client_stream,
                &partial_reader,
                send_start,
                send_end - send_start,
            )
            .await
            {
                Ok(sent) => client_bytes_sent += sent,
                Err((_sent, err)) => {
                    return Err(SpliceProxyError::AfterHeaderClient(
                        err,
                        "resume sendfile to client",
                    ));
                }
            }
        }
    }

    // File cursor for range-filtering the pre-loop buffer.
    let pre_loop_file_pos: u64 = resume_offset;

    // Latches if a pre-loop client write fails.  We swallow the error to
    // keep caching the buffered prefix, but if the splice loop
    // never runs (entire body is in the prefix; `splice_count == 0`) we
    // need to close the connection at the end so the handler does not
    // keep-alive a socket whose write side just broke and so we do not
    // claim success after sending fewer bytes than `Content-Length`.
    let mut prefix_client_failed = false;

    // If upstream sent body data in the same read as headers (or, on the kTLS
    // path, decrypted it in userspace before RX offload), write it directly.
    // When the upstream is fast enough that the entire body lands inside the
    // kTLS handshake drain, the prefix holds the full file.
    if !body_prefix.is_empty() {
        // Cache write first: the bytes are already in our hands, so the cache
        // file is the source of truth that other clients read from.  Only
        // after that do we attempt the client write — if the client has
        // disconnected, we log and keep filling the cache; if the splice loop
        // later observes the broken client connection, it will continue via
        // its disconnect/cache-only handling instead of dropping these prefix
        // bytes from the cache entirely.
        // `tokio::fs::File::write_all` only queues the write on the blocking
        // pool; the follow-up `flush` waits for it, so a failure (e.g. disk
        // full) surfaces HERE at the classified site. Without it the error
        // stays parked in the file handle -- `sync_all` below never reports a
        // deferred write error -- and a truncated file would be renamed in as
        // a success. Flushing before the splice loop also keeps the queued
        // write from racing the loop's raw `splice(2)` appends to the same fd.
        let write_res = match tempfile.write_all(body_prefix).await {
            Ok(()) => tempfile.flush().await,
            Err(err) => Err(err),
        };
        write_res.map_err(|err| {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to write body prefix to cache file `{}`; aborting the download and closing the connection:  {}",
                temppath.display(),
                ErrorReport(&err)
            );
            SpliceProxyError::AfterHeaderIo
        })?;

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
            if let Err(err) = write_all_to_stream_rated(
                client_stream,
                client_slice,
                &mut prefix_rc,
                RateCheckDirection::Client,
                config.http_timeout,
            )
            .await
            {
                // Both of this writer's stall paths surface as `TimedOut`,
                // which `is_peer_disconnect` deliberately excludes: the
                // rate-check failure and the `http_timeout` write stall (which
                // bumps `HTTP_TIMEOUT_CLIENT_BODY`). Pre-branch it so a slow or
                // stalled client stays `info` like hyper's rate-timeout sibling.
                if err.kind() == ErrorKind::TimedOut || is_peer_disconnect(&err) {
                    info!(
                        "splice proxy: failed to write body prefix to client {} for {} from mirror {}; continuing cache-only:  {}",
                        conn_details.client,
                        conn_details.debname,
                        conn_details.mirror,
                        ErrorReport(&err)
                    );
                } else {
                    warn!(
                        "splice proxy: failed to write body prefix to client {} for {} from mirror {}; continuing cache-only:  {}",
                        conn_details.client,
                        conn_details.debname,
                        conn_details.mirror,
                        ErrorReport(&err)
                    );
                }
                prefix_client_failed = true;
            } else {
                metrics::BYTES_SERVED_SPLICE.increment_by(client_slice.len() as u64);
                client_bytes_sent += client_slice.len() as u64;
            }
        }

        // Notify concurrent clients of progress
        dbarrier.ping();
    }

    // Uncork before entering the splice loop, which uses SPLICE_F_MORE for coalescing
    drop(cork);

    // Client-rate-window end after the prefix write; covers
    // the case where the splice loop never runs (whole body in the prefix).
    // Reassigned after the splice body block and the demoted file-serve task.
    let mut t_client_done = PreciseInstant::now();

    // Transfer the remaining body
    let (demoted_handle, body_client_disconnected) = if splice_count > 0 {
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
        // Whether the upstream socket has kTLS RX configured: tls_label is
        // maintained by every reconnect helper, so it describes the current
        // connection (and a kTLS attempt only yields Ready for 200 responses,
        // so no reconnect path fires after it).
        #[cfg(feature = "ktls")]
        let upstream_is_ktls = tls_label == KTLS_TLS_LABEL;

        let (returned_dbarrier, demoted_handle, body_client_disconnected, body_client_bytes) =
            if let Some(tcp_upstream) = upstream_guard.as_tcp() {
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
                    #[cfg(feature = "ktls")]
                    upstream_is_ktls,
                )
                .await
            } else {
                // TLS: userspace read, then tee+splice fan-out
                splice_proxy_body_tls(
                    &mut upstream_guard,
                    client_stream,
                    &tempfile,
                    splice_count,
                    body_offset,
                    dbarrier,
                    &range_filter,
                    &temppath,
                )
                .await
            }
            // Any body-transfer error leaves the upstream mid-message (fewer
            // than content_length bytes consumed), so the socket still holds
            // undelivered bytes. `upstream_guard` (still armed here) poisons
            // the connection on the early return so PoolGuard::drop discards it
            // rather than re-pooling it -- the next checkout would otherwise log
            // "pooled connection to ... has unexpected data; connecting fresh".
            //
            // The body helpers tag which party broke, so the outer arm can
            // attribute the failure instead of blaming the client for an
            // upstream stall. Cache- and proxy-side failures are logged here
            // (the on-disk path is in scope) and reported as `AfterHeaderIo`,
            // whose contract is exactly "inner site logs, outer arm silent".
            .map_err(|BodyTransferError { side, err }| match side {
                BodyFailureSide::Upstream => {
                    SpliceProxyError::AfterHeaderUpstream(err, "splice body transfer")
                }
                BodyFailureSide::Client => {
                    SpliceProxyError::AfterHeaderClient(err, "splice body transfer")
                }
                BodyFailureSide::Cache => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "splice proxy: failed to write the cache file `{}` in splice body transfer; aborting the transfer and closing the connection:  {}",
                        temppath.display(),
                        ErrorReport(&err)
                    );
                    SpliceProxyError::AfterHeaderIo
                }
                BodyFailureSide::Proxy => {
                    // Splice pipes / fd duplication -- not a cached-file
                    // syscall, so `CACHE_IO_FAILURE` stays out of it.
                    error!(
                        "splice proxy: proxy-side I/O failure in splice body transfer for `{}`; aborting the transfer and closing the connection:  {}",
                        temppath.display(),
                        ErrorReport(&err)
                    );
                    SpliceProxyError::AfterHeaderIo
                }
            })?;
        dbarrier = returned_dbarrier;
        // The splice body block ran: the upstream-rate and client-rate windows
        // both end here. The demoted-client case reassigns `t_client_done`
        // again after the file-serve task completes.
        t_upstream_done = PreciseInstant::now();
        t_client_done = t_upstream_done;
        client_bytes_sent += body_client_bytes;
        (demoted_handle, body_client_disconnected)
    } else {
        (None, false)
    };

    // The full upstream body is now drained: either the splice loop consumed
    // exactly `splice_count` bytes, or `splice_count` was 0 because the whole
    // body arrived in the prefix / kTLS-extra-body. The client-write outcome is
    // irrelevant to poolability — the download always drains upstream fully.
    // Defuse the poison guard and release its borrow before dropping upstream.
    upstream_guard.consumed();
    drop(upstream_guard);

    // PoolGuard::drop returns the connection to pool if still poolable.
    // Drop it now before the sync+rename to free the upstream socket promptly.
    drop(upstream);

    // Sync cache file to ensure durability
    if let Err(err) = tempfile.sync_all().await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to sync cache file `{}`; committing it to the cache anyway:  {}",
            temppath.display(),
            ErrorReport(&err)
        );
    }
    drop(tempfile);

    // Move temp file to final cache path
    let dest_file_path = dest_dir.join(filename);

    // Lock to block all downloading tasks, since the file from the
    // path of the downloading state is going to be moved.
    let rbarrier = dbarrier.begin_rename().await;

    let cache_committed = rbarrier
        .commit(temppath, dest_file_path, total_content_length.get())
        .await
        .is_ok();
    // On failure commit() logged the cause and dropped the barrier; the
    // temp-file guard removed the partial. The body was already fully
    // delivered to the client; this only leaves the cache without the file
    // (future requests re-download). The DB records below are skipped
    // because nothing was cached, but we still finish the client-facing
    // bookkeeping (await the demoted task, count the delivery) before
    // returning.

    let elapsed = start.elapsed();

    if cache_committed {
        // Record download in database (mirrors download_file() in hyper_conn.rs).
        let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
            mirror: conn_details.mirror.clone(),
            debname: conn_details.debname.clone(),
            size: total_content_length.get(),
            elapsed,
            client_ip: conn_details.client.ip(),
            kind: TransferKind::Download,
        });
        send_db_command(cmd).await;

        // Record origin in database for this cached download.  This is an
        // intentional asymmetry with the hyper backend: `Origin::from_path` is
        // only called from the hyper simple-proxy passthrough in
        // `hyper_conn.rs`; the hyper cache-download paths in
        // `download_file`/`serve_new_file` never record an Origin row.  The
        // splice path records Origins for cached downloads too, so it is doing
        // strictly more origin-recording work than hyper.  Treat the splice
        // origin write as the source of truth for cached-download origins for
        // now.  Use the original (pre-redirect) client request path so the
        // recorded origin layout is stable across upstream redirects (the
        // redirected `upstream_path` would otherwise poison the DB with a
        // different origin row for the same logical download).
        if let Some(origin) = Origin::from_path(
            original_uri_path,
            conn_details.mirror.host().clone(),
            conn_details.mirror.port(),
        ) && !cache_layout::is_pseudo_arch(&origin.architecture)
        {
            let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
            send_db_command(cmd).await;
        }
    }

    // If the first client was demoted to file-serve, wait for the
    // background task to finish sending before returning control to the
    // connection handler (which may reuse the socket for keep-alive).
    // No demotion means the splice loop served the client itself (or there
    // was no body to splice) — that's a success, not a failure.
    let demoted_client_succeeded = if let Some(handle) = demoted_handle {
        let succeeded = match handle.await {
            Ok(DeliveryResult::Success(bytes)) => {
                client_bytes_sent += bytes;
                true
            }
            Ok(DeliveryResult::Failure(bytes)) => {
                client_bytes_sent += bytes;
                false
            }
            Err(err) => {
                error!(
                    "splice proxy: demoted client file-serve task panicked; treating the delivery as failed and closing the connection:  {}",
                    ErrorReport(&err)
                );
                false
            }
        };
        // The demoted file-serve task is the last thing to write to the
        // client, so the client-rate window ends here.
        t_client_done = PreciseInstant::now();
        succeeded
    } else {
        true
    };

    let client_succeeded =
        !prefix_client_failed && !body_client_disconnected && demoted_client_succeeded;

    // Only log a completion "…cached…" line when the file actually landed in
    // the cache; the commit-failure path already logged an ERROR (rename) or
    // commit() logged the mismatch/verify failure internally.
    if cache_committed {
        let in_time = conn_details.request_received_at.elapsed();
        let volatile = if conn_details.cached_flavor == CachedFlavor::Volatile {
            "volatile "
        } else {
            ""
        };
        let upstream = rate_log::upstream_segment(
            body_content_length.get(),
            t_upstream_done.duration_since(t_req_sent),
        );
        let client = if client_succeeded {
            rate_log::client_segment(
                response_content_length,
                t_client_done.duration_since(t_client_first),
            )
        } else {
            rate_log::client_disconnect_segment(
                client_bytes_sent,
                t_client_done.duration_since(t_client_first),
            )
        };
        info!(
            "{} {volatile}file {} from mirror {} for client {} in {} via splice{tls_label} ({upstream}, {client}){}",
            if client_succeeded {
                "Served and cached"
            } else {
                "Cached"
            },
            conn_details.debname,
            conn_details.mirror,
            conn_details.client,
            HumanFmt::Time(in_time),
            if resume_offset > 0 {
                format!(", resumed from {}", HumanFmt::Size(resume_offset))
            } else {
                String::new()
            },
        );
    }

    if !client_succeeded {
        // The actual failure (prefix-write, body splice, or demoted task)
        // was already logged at its source.  Route through `AfterHeaderIo`
        // so the outer arm silently closes the connection rather than
        // emitting a duplicate client-error log line.
        return Err(SpliceProxyError::AfterHeaderIo);
    }

    metrics::SERVED_SPLICE.increment();
    metrics::SERVED_TOTAL.increment();

    if cache_committed {
        let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
            mirror: conn_details.mirror.clone(),
            debname: conn_details.debname.clone(),
            size: total_content_length.get(),
            elapsed,
            kind: TransferKind::Delivery {
                partial: is_partial,
            },
            client_ip: conn_details.client.ip(),
        });
        send_db_command(cmd).await;
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
    let size = (prefix.len() + 4096).min(max_bytes.saturating_add(1));
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(prefix);
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

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
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));

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

/// Empty-bodied response for the cleanup bridge (`packages.rs` only reads the
/// status on non-200s).
#[cfg(not(feature = "hyper"))]
fn cleanup_response(status: StatusCode) -> http::Response<ProxyCacheBody> {
    http::Response::builder()
        .status(status)
        .body(full_body(bytes::Bytes::new()))
        .expect("static response is valid")
}

/// Parse the `max-age` directive from a request's `Cache-Control` header.
#[cfg(not(feature = "hyper"))]
fn cache_control_max_age(
    req: &http::Request<http_body_util::Empty<()>>,
) -> Option<std::time::Duration> {
    let value = req
        .headers()
        .get(http::header::CACHE_CONTROL)?
        .to_str()
        .ok()?;
    value
        .split(',')
        .find_map(|directive| directive.trim().strip_prefix("max-age="))
        .and_then(|secs| secs.parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
}

/// Serve a cleanup index request from the already-open cache file, if fresh.
///
/// Returns `None` when the cached copy is stale (or has a future mtime) and
/// the caller should fetch upstream; `Some` carries either the cached bytes
/// or a 500 on cache anomalies (mirroring the hyper backend's
/// `serve_volatile_file` error handling).
#[cfg(not(feature = "hyper"))]
async fn serve_cached_cleanup_file(
    mut file: tokio::fs::File,
    cache_path: &Path,
    req: &http::Request<http_body_util::Empty<()>>,
) -> Option<http::Response<ProxyCacheBody>> {
    let mdata = match regular_file_metadata(&file, cache_path).await {
        Ok(data) => data,
        Err(CacheAccessFailure) => {
            return Some(cleanup_response(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    let modified = mdata
        .modified()
        .expect("Platform should support modification timestamps via setup check");
    let Ok(elapsed) = modified.elapsed() else {
        warn_once_or_info!(
            "Volatile file `{}` was modified in the future; treating it as stale and refetching from upstream",
            cache_path.display()
        );
        return None;
    };
    let max_age = cache_control_max_age(req).unwrap_or(VOLATILE_CACHE_MAX_AGE);
    if elapsed >= max_age {
        return None;
    }

    let max_bytes = limits::MAX_DECOMPRESSED_PACKAGES_SIZE.get();
    if mdata.len() > max_bytes {
        warn_once_or_info!(
            "splice cleanup: cached file `{}` exceeds the {max_bytes} byte buffering cap; refetching from upstream",
            cache_path.display()
        );
        return None;
    }
    let size = usize::try_from(mdata.len()).expect("size below buffering cap fits usize");

    hint_sequential_read(&file, mdata.len(), cache_path);
    let mut body = Vec::with_capacity(size);
    match file.read_to_end(&mut body).await {
        Ok(_bytes) => {
            debug!(
                "splice cleanup: serving `{}` from cache (age {} within {})",
                cache_path.display(),
                HumanFmt::Time(elapsed),
                HumanFmt::Time(max_age)
            );
            Some(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(full_body(body))
                    .expect("cached response is valid"),
            )
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice cleanup: failed to read cached file `{}`; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            Some(cleanup_response(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// Cleanup index fetch for hyper-less builds: the `process_cache_request`
/// bridge in `main.rs` lands here.
///
/// A cached copy younger than the request's `Cache-Control: max-age`
/// (cleanup sends 1 week) is served without touching upstream. This
/// deliberately diverges from the hyper backend, which revalidates
/// conditionally past `VOLATILE_CACHE_MAX_AGE` (30s): without conditional
/// refetch machinery here yet, honoring the caller-declared max-age avoids a
/// full re-download of every index each cleanup cycle, and a stale index errs
/// toward *keeping* cached debs — the conservative direction for cleanup.
#[cfg(not(feature = "hyper"))]
#[must_use]
pub(crate) async fn splice_cleanup_request(
    conn_details: &ConnectionDetails,
    req: &http::Request<http_body_util::Empty<()>>,
) -> http::Response<ProxyCacheBody> {
    let cache_path = conn_details.cache_file_path();
    match tokio_nofollow_options().read(true).open(&cache_path).await {
        Ok(file) => {
            if let Some(resp) = serve_cached_cleanup_file(file, &cache_path, req).await {
                return resp;
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice cleanup: failed to open cached file `{}`; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            return cleanup_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    cleanup_upstream_fetch(&conn_details.mirror, &req.uri().to_string()).await
}

#[cfg(not(feature = "hyper"))]
#[must_use]
async fn cleanup_upstream_fetch(
    mirror: &Mirror,
    upstream_uri: &str,
) -> http::Response<ProxyCacheBody> {
    let upstream_path_buf = upstream_uri
        .parse::<http::Uri>()
        .ok()
        .and_then(|uri| uri.path_and_query().map(|pq| pq.as_str().to_owned()));
    let upstream_path = upstream_path_buf.as_deref().unwrap_or(upstream_uri);
    let host_authority = mirror.format_authority();
    let UpstreamExchange {
        conn: mut upstream,
        response: resp,
        header_buf: hdr_buf,
        header_end: hdr_end,
        tls_label: _,
    } = match standard_upstream_connect(mirror, &host_authority, upstream_path, 0, None, None, None)
        .await
    {
        Ok(v) => v,
        Err(_err) => {
            debug!("splice cleanup request to {upstream_path} failed to connect/read headers");
            let mut resp = cleanup_response(StatusCode::BAD_GATEWAY);
            // `SpliceProxyError::Upstream` carries no payload (details were
            // logged at the throw site); give cleanup's decision log a
            // generic transport reason instead of a bare 502.
            resp.extensions_mut().insert(UpstreamFetchError {
                reason: "upstream connect or response-header read failed".to_owned(),
            });
            return resp;
        }
    };

    let status = resp.status_code;
    let body_prefix = &hdr_buf[hdr_end..];

    if status != StatusCode::OK {
        // Drain the (small) error body so the connection returns to the pool;
        // the `.xz` -> `.gz` -> raw probe cascade reuses it for the next format.
        // Oversized or unreadable error bodies mark the connection non-poolable
        // instead (via the cap error or `inspect_err`).
        const MAX_ERROR_BODY_DRAIN: usize = 64 * 1024;
        if let Err(err) = resp
            .framing
            .read_to_vec(&mut upstream, body_prefix, MAX_ERROR_BODY_DRAIN)
            .await
        {
            debug!(
                "splice cleanup request to {host_authority}{upstream_path} failed to drain the error body:  {}",
                ErrorReport(&err)
            );
        }
        return cleanup_response(status);
    }

    let max_bytes: usize = limits::MAX_DECOMPRESSED_PACKAGES_SIZE
        .get()
        .try_into()
        .expect("constant fits into usize");
    let body = resp
        .framing
        .read_to_vec(&mut upstream, body_prefix, max_bytes)
        .await;

    match body {
        Ok(body) => http::Response::builder()
            .status(StatusCode::OK)
            .body(full_body(body))
            .expect("upstream response is valid"),
        Err(err) => {
            debug!(
                "splice cleanup request to {host_authority}{upstream_path} failed to read the body:  {}",
                ErrorReport(&err)
            );
            let mut resp = cleanup_response(StatusCode::BAD_GATEWAY);
            resp.extensions_mut().insert(UpstreamFetchError {
                reason: ErrorReport(&err).to_string(),
            });
            resp
        }
    }
}

/// State machine for the buffered chunked-body decoder.
///
/// Mirrors [`ChunkedState`] used by the streaming variant
/// [`forward_upstream_chunked_body`]; the `Done { remaining }` variant counts
/// the still-unseen bytes of the closing `\r\n` after the `0\r\n` terminator,
/// so the upstream socket buffer is left empty and the connection can be
/// safely returned to the pool. Trailer header fields between `0\r\n` and the
/// final `\r\n` are rejected (same policy as the streaming variant).
enum BufferedDechunkState {
    /// Accumulating the hex chunk-size line (up to `\r\n`).
    ReadingSize,
    /// Reading chunk data bytes; `remaining` counts undecoded payload bytes.
    ReadingData { remaining: usize },
    /// Expecting the `\r\n` trailer after chunk data.
    ReadingTrailer { seen_cr: bool },
    /// The final `0\r\n` chunk has been received; still expecting the
    /// closing `\r\n` that terminates the (empty) trailer section.
    /// `remaining` is the count of still-unseen bytes of that final CRLF
    /// (starts at 2, decrements to 0 when fully consumed).
    Done { remaining: u8 },
}

/// Pure step of [`read_dechunk_body_to_vec`]: process one buffer of upstream
/// bytes through the state machine, appending decoded payload to `body`.
///
/// Returns the number of bytes consumed from `data`. When the terminal chunk
/// and its closing CRLF have been fully consumed, `state` transitions to
/// `Done { remaining: 0 }` and the function stops processing further bytes
/// (so callers can detect trailing/leftover bytes if needed).
///
/// Factored out so the framing logic is unit-testable without setting up
/// `RUNTIMEDETAILS` (the I/O wrapper depends on `global_config()`).
fn buffered_dechunk_step(
    state: &mut BufferedDechunkState,
    size_buf: &mut Vec<u8>,
    body: &mut Vec<u8>,
    data: &[u8],
    max_bytes: usize,
) -> std::io::Result<usize> {
    let mut i = 0usize;
    while i < data.len() {
        match state {
            BufferedDechunkState::ReadingSize => {
                let b = data[i];
                i += 1;
                size_buf.push(b);
                if b == b'\n' && size_buf.len() >= 2 && size_buf[size_buf.len() - 2] == b'\r' {
                    let line = &size_buf[..size_buf.len() - 2];
                    let hex_end = line.iter().position(|&c| c == b';').unwrap_or(line.len());
                    let hex_str = std::str::from_utf8(&line[..hex_end]).map_err(|_err| {
                        metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "chunked encoding: invalid chunk-size line",
                        )
                    })?;
                    let chunk_size = usize::from_str_radix(hex_str.trim(), 16).map_err(|_err| {
                        metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                        std::io::Error::new(
                            ErrorKind::InvalidData,
                            "chunked encoding: invalid chunk-size hex",
                        )
                    })?;
                    size_buf.clear();
                    if chunk_size == 0 {
                        // Terminal chunk -- still need to consume the closing
                        // \r\n that ends the (empty) trailer section.
                        *state = BufferedDechunkState::Done { remaining: 2 };
                    } else {
                        if body
                            .len()
                            .checked_add(chunk_size)
                            .is_none_or(|sum| sum > max_bytes)
                        {
                            warn_once_or_info!(
                                "splice proxy: chunked volatile body exceeded {max_bytes} byte cap; aborting the download"
                            );
                            return Err(std::io::Error::other(
                                "chunked volatile body exceeded size cap",
                            ));
                        }
                        *state = BufferedDechunkState::ReadingData {
                            remaining: chunk_size,
                        };
                    }
                } else if size_buf.len() > 64 {
                    // Guard against absurdly long size lines (matches the
                    // streaming variant's 64-byte cap).
                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "chunked encoding: chunk-size line too long",
                    ));
                }
            }
            BufferedDechunkState::ReadingData { remaining } => {
                let avail = data.len() - i;
                let taken = avail.min(*remaining);
                body.extend_from_slice(&data[i..i + taken]);
                *remaining -= taken;
                i += taken;
                if *remaining == 0 {
                    *state = BufferedDechunkState::ReadingTrailer { seen_cr: false };
                }
            }
            BufferedDechunkState::ReadingTrailer { seen_cr } => {
                let b = data[i];
                i += 1;
                if !*seen_cr && b == b'\r' {
                    *seen_cr = true;
                } else if *seen_cr && b == b'\n' {
                    *state = BufferedDechunkState::ReadingSize;
                } else {
                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                    return Err(std::io::Error::new(
                        ErrorKind::InvalidData,
                        "chunked encoding: expected CRLF after chunk data",
                    ));
                }
            }
            BufferedDechunkState::Done { remaining } => {
                // Validate the closing \r\n after the 0-length chunk. Trailer
                // header fields between `0\r\n` and the final `\r\n` are not
                // supported (matches the streaming variant) -- reject as a
                // framing sanity check rather than silently skipping.
                while i < data.len() && *remaining > 0 {
                    let b = data[i];
                    i += 1;
                    let expected = if *remaining == 2 { b'\r' } else { b'\n' };
                    if b != expected {
                        metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                        return Err(std::io::Error::new(
                            ErrorKind::InvalidData,
                            "chunked encoding: expected \\r\\n after 0-length chunk \
                             (trailer sections are not supported)",
                        ));
                    }
                    *remaining -= 1;
                }
                if *remaining == 0 {
                    // Stop processing -- leave any trailing bytes in `data`
                    // unconsumed so the caller can detect framing surprises.
                    return Ok(i);
                }
            }
        }
    }
    Ok(i)
}

/// Dechunk a chunked-encoded body from upstream into a `Vec<u8>`, up to `max_bytes`
/// of decoded payload.
///
/// On success the closing `\r\n` after the `0\r\n` terminator has been fully
/// consumed from the upstream socket buffer, so the connection can be safely
/// returned to the pool (mirrors the streaming variant
/// [`forward_upstream_chunked_body`]). On error the connection state is
/// indeterminate -- callers must mark the upstream non-poolable.
async fn read_dechunk_body_to_vec(
    upstream: &mut UpstreamConn,
    prefix: &[u8],
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let config = global_config();
    let mut body = Vec::with_capacity(4096);
    let mut rate_checker = config
        .min_download_rate
        .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
    let mut state = BufferedDechunkState::ReadingSize;
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

        let consumed =
            buffered_dechunk_step(&mut state, &mut size_buf, &mut body, data, max_bytes)?;

        if matches!(state, BufferedDechunkState::Done { remaining: 0 }) {
            if consumed < data.len() {
                // Defence in depth: well-behaved upstreams send no bytes
                // past the closing `\r\n`. If trailing bytes are present
                // we treat the connection as poisoned and bail. Callers
                // must mark the upstream non-poolable on any error
                // returned from this function (stray bytes in the kernel
                // socket buffer would poison the next checkout).
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "chunked encoding: trailing bytes after 0-length chunk",
                ));
            }
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
    // The original (pre-redirect) client request URI path. Used for
    // `RenamePlan.raw_uri_path` and the recorded `Origin` so registry keys
    // and DB origin rows match the hyper backend.
    original_uri_path: &str,
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

    // Capture t_req_sent before buffering so the upstream-rate window is never
    // inverted. The fallback is a pre-read now() so t_req_sent <= t_upstream_done.
    let t_req_sent = upstream_resp
        .request_sent_at
        .unwrap_or_else(PreciseInstant::now);

    // Account this buffered serve under `ACTIVE_CLIENT_DOWNLOADS` for the
    // duration of the function (RAII drop on every return path).  Mirrors
    // the canonical `splice_proxy_body{,_tls}` holders; the buffered path
    // bypasses those and would otherwise undercount.
    let _client_count = client_counter::ClientDownload::new();

    // Buffer the entire body into memory. This path is only reached without a
    // usable Content-Length (the length-delimited case is spliced), so framing
    // is chunked or close-delimited; a `ContentLength` body is still read
    // correctly (to its declared length) but flags the routing slip.
    if let BodyFraming::ContentLength(len) = upstream_resp.framing {
        warn_once!(
            "splice proxy: volatile buffered download of {} reached with a Content-Length body ({len} bytes)",
            conn_details.debname
        );
    }
    let body = upstream_resp
        .framing
        .read_to_vec(upstream, body_prefix, max_bytes)
        .await
        .map_err(|err| {
            warn_once_or_info!(
                "splice proxy: volatile buffered download failed for {}; returning 502:  {}",
                conn_details.debname,
                ErrorReport(&err)
            );
            SpliceProxyError::Upstream
        })?;

    let t_upstream_done = PreciseInstant::now();

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
            None,
        )
        .await
        .map_err(|err| SpliceProxyError::Client(err, "volatile zero-body 502"))?;
        return Ok(());
    };

    debug!(
        "splice proxy{tls_label}: buffered volatile download of {} from mirror {} for client {} ({} bytes)...",
        conn_details.debname, conn_details.mirror, conn_details.client, total_content_length
    );

    let prev_file_size = {
        let prev_path = conn_details.cache_file_path();

        match tokio::fs::symlink_metadata(&prev_path).await {
            Ok(m) if m.file_type().is_file() => m.len(),
            Ok(_) => {
                metrics::CACHE_NON_REGULAR.increment();
                error!(
                    "splice proxy: previous cache file `{}` is not a regular file; counting it as 0 bytes for the quota and overwriting it",
                    prev_path.display()
                );
                0
            }
            Err(err) if err.kind() == ErrorKind::NotFound => 0,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "splice proxy: failed to stat existing volatile file `{}`; returning 500:  {}",
                    prev_path.display(),
                    ErrorReport(&err)
                );
                return Err(SpliceProxyError::Cache);
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
                None,
            )
            .await
            .map_err(|err| SpliceProxyError::Client(err, "volatile quota 503"))?;
            return Ok(());
        }
    };

    // Parse client Range against the now-known total size.
    let cache_time = HttpDate::now();
    let client_range_result = client_range.range.map(|range| {
        let parsed = http_parse_range(
            range,
            client_range.if_range,
            total_content_length.get(),
            cache_time,
            upstream_resp.etag.as_deref(),
        );
        if matches!(parsed, ParsedRange::Invalid) {
            // Same as the streaming path: RFC 9110 says ignore and serve the
            // whole entity, but a client expecting a resume gets everything.
            warn_once_or_debug!(
                "splice proxy: ignoring malformed Range header `{}` from client {}; serving the full file",
                range.escape_debug(),
                conn_details.client
            );
        }
        parsed
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
        .map_err(|err| SpliceProxyError::Client(err, "volatile 416 response"))?;
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
            "splice proxy: failed to create cache directory `{}`; aborting the download:  {}",
            dest_dir.display(),
            ErrorReport(&err)
        );
        return Err(SpliceProxyError::Cache);
    }

    let filename = Path::new(&conn_details.debname);
    assert!(
        filename.is_relative(),
        "path construction must not contain absolute components"
    );

    let tmppath: PathBuf = [
        &global_config().cache_directory,
        Path::new(SUBDIR_TMP),
        filename,
    ]
    .iter()
    .collect();
    let (mut tempfile, temppath) = tokio_tempfile(&tmppath, 0o640).await.map_err(|err| {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to create temp file `{}`; aborting the download:  {}",
            tmppath.display(),
            ErrorReport(&err)
        );
        SpliceProxyError::Cache
    })?;

    // Write ETag xattr if present.
    if let Some(ref etag) = upstream_resp.etag {
        write_etag(&tempfile, &temppath, etag);
    }
    // Persist upstream Last-Modified to xattr (RFC 9110 §10.2.2: forward origin's value)
    if let Some(ref lm) = upstream_resp.last_modified {
        write_last_modified(&tempfile, &temppath, lm);
    }

    let download_meta = cache_metadata::UpstreamMetadata::from_upstream(
        upstream_resp.etag.clone(),
        upstream_resp.last_modified.clone(),
    );

    // Transition barrier: InitBarrier → DownloadBarrier.
    let mut dbarrier: DownloadBarrier = ibarrier
        .download(
            temppath.to_path_buf(),
            ContentLength::Exact(total_content_length),
            reservation,
            Arc::new(download_meta),
        )
        .await;

    let start = PreciseInstant::now();

    // The whole body is already buffered in memory, so — unlike the streaming
    // path (`splice_proxy_drive`) — the cache can be fully persisted BEFORE
    // serving the client. Caching costs nothing here and must not depend on the
    // client write, so a late client-write failure no longer discards an
    // already-downloaded body (late joiners and future requests keep it).

    // Write the full body to the cache temp file (best-effort).
    // `tokio::fs::File::write_all` only queues the write on the blocking
    // pool; the follow-up `flush` waits for it, so a failure (e.g. disk full)
    // surfaces here -- `sync_all` below never reports a deferred write error,
    // and without the flush a truncated file would be committed as a success.
    let write_res = match tempfile.write_all(&body).await {
        Ok(()) => tempfile.flush().await,
        Err(err) => Err(err),
    };
    let cache_write_ok = match write_res {
        Ok(()) => true,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to write volatile body to cache file `{}`; serving the buffered body to the client without caching it:  {}",
                temppath.display(),
                ErrorReport(&err)
            );
            false
        }
    };
    if cache_write_ok {
        dbarrier.ping();

        // Sync cache file.
        if let Err(err) = tempfile.sync_all().await {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to sync cache file `{}`; committing it to the cache anyway:  {}",
                temppath.display(),
                ErrorReport(&err)
            );
        }
    }
    drop(tempfile);

    // Persist via rename+commit, only if the body reached the temp file. When
    // the write failed, `dbarrier` is dropped here without a rename — its Drop
    // records the terminal aborted state, correct since nothing is on disk for
    // late joiners to serve.
    let dest_file_path = dest_dir.join(filename);
    let cache_committed = if cache_write_ok {
        // Move temp file to final cache path.
        let rbarrier = dbarrier.begin_rename().await;

        // On failure commit() logged the cause and dropped the barrier; the
        // temp-file guard removed the partial. The DB records below are
        // skipped because nothing was cached.
        rbarrier
            .commit(temppath, dest_file_path, total_content_length.get())
            .await
            .is_ok()
    } else {
        false
    };

    let elapsed = start.elapsed();

    if cache_committed {
        // Record download in database (mirrors download_file() in hyper_conn.rs).
        let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
            mirror: conn_details.mirror.clone(),
            debname: conn_details.debname.clone(),
            size: total_content_length.get(),
            elapsed,
            client_ip: conn_details.client.ip(),
            kind: TransferKind::Download,
        });
        send_db_command(cmd).await;

        // Record origin in database for this cached (volatile-buffered)
        // download.  As in `splice_proxy_drive`, this is an intentional
        // asymmetry with the hyper backend: in `hyper_conn.rs`, `Origin::from_path`
        // is only called from the simple-proxy passthrough; hyper's cache
        // paths (`download_file`/`serve_new_file`) never record an Origin row.
        // The splice path records Origins for cached downloads too, so it is
        // doing strictly more origin-recording work than hyper.  Use the
        // original (pre-redirect) client request path so the recorded origin
        // layout is stable across upstream redirects (the redirected
        // `upstream_path` would otherwise poison the DB with a different
        // origin row for the same logical download).
        if let Some(origin) = Origin::from_path(
            original_uri_path,
            conn_details.mirror.host().clone(),
            conn_details.mirror.port(),
        ) && !cache_layout::is_pseudo_arch(&origin.architecture)
        {
            let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
            send_db_command(cmd).await;
        }
    }

    // Serve the client from the in-memory body. The cache is already persisted
    // (best-effort above), so an early return on a client write failure no
    // longer loses the downloaded body.
    let last_modified_str = upstream_resp.last_modified.as_deref().unwrap_or("");
    let content_type = content_type_for_cached_file(&conn_details.debname);
    warn_on_content_type_mismatch(
        upstream_resp.content_type.as_deref(),
        &conn_details.mirror,
        &conn_details.debname,
    );
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
        last_modified_header = OptHeader(
            "Last-Modified",
            (!last_modified_str.is_empty()).then_some(last_modified_str),
        ),
        etag_header = OptHeader("ETag", upstream_resp.etag.as_deref()),
        content_range_header = OptHeader("Content-Range", content_range_hdr.as_ref()),
    );

    // Cork to coalesce headers + body into fewer TCP segments.
    let cork = CorkGuard::new_optional(client_stream);

    trace!("Outgoing {status_line} response:\n{response_headers}");

    metrics::record_client_status(if is_partial {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    });
    metrics::REQUESTS_SPLICE.increment();
    let t_client_first = PreciseInstant::now();
    write_all_to_stream(
        client_stream,
        response_headers.as_bytes(),
        WritePhase::Header,
    )
    .await
    .map_err(|err| SpliceProxyError::Client(err, "volatile response headers"))?;

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
        .map_err(|err| SpliceProxyError::AfterHeaderClient(err, "volatile body to client"))?;
        metrics::BYTES_SERVED_SPLICE.increment_by(body_slice.len() as u64);
    }
    let t_client_done = PreciseInstant::now();

    drop(cork);

    // The client was fully served (an early return above skips these).
    metrics::SERVED_SPLICE.increment();
    metrics::SERVED_TOTAL.increment();

    if cache_committed {
        let in_time = conn_details.request_received_at.elapsed();
        let volatile = if conn_details.cached_flavor == CachedFlavor::Volatile {
            "volatile "
        } else {
            ""
        };
        info!(
            "Served and cached {volatile}file {} from mirror {} for client {} in {} via splice{tls_label} ({}, {})",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client,
            HumanFmt::Time(in_time),
            rate_log::upstream_segment(
                total_content_length.get(),
                t_upstream_done.duration_since(t_req_sent),
            ),
            rate_log::client_segment(
                response_content_length as u64,
                t_client_done.duration_since(t_client_first),
            ),
        );

        // Record delivery in database.
        let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
            mirror: conn_details.mirror.clone(),
            debname: conn_details.debname.clone(),
            size: total_content_length.get(),
            elapsed,
            kind: TransferKind::Delivery {
                partial: is_partial,
            },
            client_ip: conn_details.client.ip(),
        });
        send_db_command(cmd).await;
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
    status_code: StatusCode,
) -> std::io::Result<String> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_UPSTREAM_HEADERS];
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

    // RFC 9110 §7.6.1: the Connection header nominates further connection-specific
    // field names that an intermediary must remove before forwarding.
    let mut connection_nominated: Vec<String> = Vec::new();
    for h in parsed.headers.iter() {
        if h.name.eq_ignore_ascii_case("connection")
            && let Ok(v) = std::str::from_utf8(h.value)
        {
            for tok in v.split(',') {
                let tok = tok.trim();
                if !tok.is_empty() {
                    connection_nominated.push(tok.to_ascii_lowercase());
                }
            }
        }
    }

    let mut buf = format!("{conn_version} {status_code}\r\nConnection: {conn_action}\r\n");
    for h in parsed.headers.iter() {
        if HOP_BY_HOP.iter().any(|n| h.name.eq_ignore_ascii_case(n)) {
            continue;
        }
        if connection_nominated
            .iter()
            .any(|n| h.name.eq_ignore_ascii_case(n))
        {
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
    client: ClientInfo,
    request_received_at: PreciseInstant,
) -> Result<(), SpliceProxyError> {
    let host_authority = mirror.format_authority();
    // Strip the query so cache identity (registry keys, Origin rows) stays
    // path-only; the query still rides on the upstream GET line via
    // `upstream_path`. Matches the hyper backend.
    let original_uri_path = upstream_path
        .split_once('?')
        .map_or(upstream_path, |(path, _)| path);

    // Account this passthrough under `ACTIVE_CLIENT_DOWNLOADS` for the
    // duration of the function (RAII drop on every return path). The hyper
    // passthrough is counted via `ClientCountedBody`; the splice passthrough
    // serves bytes synchronously inside this frame and would otherwise be
    // invisible to the counter.
    let _client_count = client_counter::ClientDownload::new();

    let UpstreamExchange {
        conn: mut upstream,
        response: resp,
        header_buf: hdr_buf,
        header_end: hdr_end,
        tls_label: _,
    } = standard_upstream_connect(mirror, &host_authority, upstream_path, 0, None, None, None)
        .await?;

    let t_req_sent = resp.request_sent_at.unwrap_or_else(PreciseInstant::now);

    debug!(
        "simple proxy: upstream returned {} for {upstream_path} from {host_authority}",
        resp.status_code
    );

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
            warn_once_or_info!(
                "simple proxy: failed to rewrite headers for {upstream_path} from {host_authority}; returning 502:  {}",
                ErrorReport(&err)
            );
            upstream.unset_poolable();
            return Err(SpliceProxyError::Upstream);
        }
    };

    trace!("Outgoing rewritten headers:\n{rewritten_headers}");

    metrics::record_client_status(resp.status_code);
    metrics::REQUESTS_PASSTHROUGH.increment();

    // Mirror the hyper simple-proxy passthrough: record an Origin row on
    // 2xx/3xx responses so the cleanup machinery can find the owning mirror
    // for uncached resources that happen to carry a pool-style path.
    if (resp.status_code.is_success() || resp.status_code.is_redirection())
        && let Some(origin) =
            Origin::from_path(original_uri_path, mirror.host().clone(), mirror.port())
        && !cache_layout::is_pseudo_arch(&origin.architecture)
    {
        let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
        send_db_command(cmd).await;
    }

    let t_client_first = PreciseInstant::now();
    write_all_to_stream(
        client_stream,
        rewritten_headers.as_bytes(),
        WritePhase::Header,
    )
    .await
    .map_err(|err| SpliceProxyError::Client(err, "simple-proxy headers"))?;

    // Forward the body that arrived with the headers plus the rest, framed
    // per the upstream's framing. Chunked precedence over Content-Length is
    // already resolved in the parser (RFC 9112 §6.1), and
    // `rewrite_simple_proxy_headers` above stripped the ignored
    // Content-Length, so the headers and the body framing agree.
    let body_prefix = &hdr_buf[hdr_end..];
    let forwarded: u64 = resp
        .framing
        .relay_to_client(&mut upstream, client_stream, body_prefix, VOLATILE_BODY_MAX)
        .await
        .map_err(|err| SpliceProxyError::AfterHeaderClient(err, "simple-proxy body"))?;

    let t_done = PreciseInstant::now();
    let in_time = request_received_at.elapsed();
    info!(
        "simple proxy: passed through {upstream_path} from host {host_authority} for client {client} in {} ({}, {})",
        HumanFmt::Time(in_time),
        rate_log::upstream_segment(forwarded, t_done.duration_since(t_req_sent)),
        rate_log::client_segment(forwarded, t_done.duration_since(t_client_first)),
    );

    metrics::SERVED_PASSTHROUGH.increment();
    metrics::SERVED_TOTAL.increment();

    // PoolGuard::drop handles returning the connection to pool if poolable
    Ok(())
}

/// Successful outcomes of [`splice_proxy`]. `Concurrent` is an alternate
/// success path, not an error: another download for the same key won the
/// originate race, and the carried `status` lets the caller serve the client
/// from the in-flight partial via the sendfile backend without falling back
/// to hyper. Late-joiner accounting was already performed inside
/// [`crate::active_downloads::ActiveDownloads::originate`].
pub(crate) enum SpliceProxyOutcome {
    Served,
    Concurrent {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    /// Origination refused by the `max_upstream_downloads` cap
    /// (`OriginateOutcome::AtCapacity`); nothing was written to the client.
    /// The sendfile caller answers with the canonical 503
    /// (`"Too many concurrent upstream downloads"`) — not an error, the
    /// connection stays usable.
    AtCapacity {
        max: NonZero<usize>,
    },
}

/// Errors that can occur during splice proxy.
pub(crate) enum SpliceProxyError {
    /// Error communicating with upstream
    Upstream,
    /// Error writing to client.  `&'static str` is a short code-location
    /// tag (e.g. "response headers", "416 response", "passthrough headers")
    /// that the outer arm in `sendfile_conn::try_sendfile_request` includes
    /// in the log so the operator sees which response phase broke without
    /// grep-walking the source.
    Client(std::io::Error, &'static str),
    /// Error with cache file operations
    Cache,
    /// Client-side I/O failure after response headers were written.  The
    /// caller must close the connection without emitting a new HTTP status.
    /// `&'static str` is a short code-location tag (e.g. "passthrough
    /// chunked body", "volatile body to client") that the outer arm
    /// includes in the log so the operator sees which delivery phase
    /// broke.  Logged at the outer arm with `is_peer_disconnect`-based
    /// severity (INFO for peer disconnects, WARN otherwise).
    AfterHeaderClient(std::io::Error, &'static str),
    /// Upstream-side I/O failure after response headers were written: the
    /// mirror stalled, hung up, or fell below `min_download_rate` mid-body.
    /// The caller must close the connection without emitting a new HTTP
    /// status -- the client has already received a 200/206 header.  Carries
    /// the same short code-location tag as `AfterHeaderClient`.  Logged at
    /// the outer arm at WARN: unlike a client hang-up there is no benign
    /// case, and the throw sites already bumped their dedicated counter
    /// (`HTTP_TIMEOUT_UPSTREAM_READ`, `RATE_LIMIT_UPSTREAM`,
    /// `UPSTREAM_PROTOCOL_VIOLATION`), so the line is counter-backed and
    /// bounded to one per connection.
    AfterHeaderUpstream(std::io::Error, &'static str),
    /// Cache-side I/O failure after response headers were written
    /// (tempfile write, rename, partial-file reopen, etc.).  The caller
    /// must close the connection.  Unlike `AfterHeaderClient`, the log
    /// is emitted at the inner throw site - which has the on-disk
    /// path(s) in scope - and the outer arm matches silently.
    AfterHeaderIo,
}

#[cfg(test)]
mod tests {
    use nix::fcntl::{FcntlArg, fcntl};

    use super::*;

    #[test]
    fn classify_tls_error_marks_deterministic_kinds_permanent() {
        // rustls surfaces a rejected certificate chain as InvalidData and an
        // unparsable server name as InvalidInput; both repeat identically.
        assert_eq!(
            classify_tls_error(ErrorKind::InvalidData),
            ConnectRetry::Permanent,
            "certificate rejection must not be retried"
        );
        assert_eq!(
            classify_tls_error(ErrorKind::InvalidInput),
            ConnectRetry::Permanent,
            "server-name parse failure must not be retried"
        );
    }

    #[test]
    fn classify_tls_error_marks_network_kinds_transient() {
        for kind in [
            ErrorKind::TimedOut,
            ErrorKind::ConnectionRefused,
            ErrorKind::UnexpectedEof,
        ] {
            assert_eq!(
                classify_tls_error(kind),
                ConnectRetry::Transient,
                "{kind:?} may succeed on retry"
            );
        }
    }

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
            StatusCode::OK,
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
            StatusCode::OK,
        )
        .expect("rewrite should succeed");
        assert!(!out.to_ascii_lowercase().contains("content-length:"));
        assert!(out.contains("Transfer-Encoding: chunked\r\n"));
    }

    #[test]
    fn test_rewrite_simple_proxy_headers_drops_connection_nominated() {
        // RFC 9110 §7.6.1: header fields nominated by the upstream Connection
        // header must be stripped before forwarding to the client.
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Connection: close, X-Custom-Hop\r\n\
                    X-Custom-Hop: secret\r\n\
                    Content-Type: text/plain\r\n\
                    \r\n";
        let out = rewrite_simple_proxy_headers(
            raw,
            ConnectionVersion::Http11,
            ConnectionAction::KeepAlive,
            StatusCode::OK,
        )
        .expect("rewrite should succeed");

        // The nominated field must not be forwarded.
        assert!(
            !out.to_ascii_lowercase().contains("x-custom-hop"),
            "Connection-nominated header leaked into output:\n{out}"
        );
        // End-to-end headers still pass through.
        assert!(out.contains("Content-Type: text/plain\r\n"));
        // Exactly one Connection header (ours), regardless of the upstream's.
        let connection_lines = out
            .split("\r\n")
            .filter(|line| line.to_ascii_lowercase().starts_with("connection:"))
            .count();
        assert_eq!(
            connection_lines, 1,
            "expected exactly one Connection header in rewritten output, got:\n{out}"
        );
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
            ClientHost::new("example.com".into()).unwrap(),
            None,
            String::new(),
            MirrorKind::Structured,
        );
        assert_eq!(mirror_port(&mirror, false), 80);
        assert_eq!(mirror_port(&mirror, true), 443);
    }

    #[test]
    fn test_mirror_port_explicit() {
        let mirror = Mirror::new(
            ClientHost::new("example.com".into()).unwrap(),
            Some(NonZero::new(8080).unwrap()),
            String::new(),
            MirrorKind::Structured,
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

    #[cfg(feature = "ktls")]
    #[test]
    fn record_framed_read_len_stops_at_record_boundary() {
        // Front record header declares a 16384-byte payload (length bytes
        // 3..5), so the whole record is 5 + 16384 bytes. The buffer is sized to
        // hold the full record, mirroring the call site where
        // `incoming_used <= incoming.len()`.
        let record_total: usize = 5 + 16 * 1024;
        let mut incoming = vec![0u8; record_total];
        incoming[0] = 0x17; // application_data
        incoming[1] = 0x03;
        incoming[2] = 0x03;
        incoming[3] = 0x40; // length hi
        incoming[4] = 0x00; // length lo

        // 100 bytes of the record buffered: ask for exactly the remainder,
        // never reaching into the following record.
        assert_eq!(record_framed_read_len(&incoming, 100), record_total - 100);

        // Exactly one full record buffered: nothing more to read for it.
        assert_eq!(record_framed_read_len(&incoming, record_total), 0);

        // A tiny record (length 0): the 5-byte header is the whole record.
        let hdr = [0x17u8, 0x03, 0x03, 0x00, 0x00];
        assert_eq!(record_framed_read_len(&hdr, 5), 0);
        assert_eq!(record_framed_read_len(&hdr, 2), 3);
    }

    #[cfg(feature = "ktls")]
    #[test]
    fn record_framed_read_len_asks_for_header_first() {
        // Fewer than 5 bytes buffered: the length field is not yet readable,
        // so ask only for enough to complete the 5-byte record header —
        // without indexing past what is present.
        assert_eq!(record_framed_read_len(&[], 0), 5);
        assert_eq!(record_framed_read_len(&[0x17u8, 0x03, 0x03], 3), 2);
    }

    #[test]
    fn test_dev_null_accessor_returns_writable_fd() {
        use std::os::fd::AsRawFd as _;
        let f1 = dev_null().expect("first call should open /dev/null");
        let f2 = dev_null().expect("second call should reuse cached fd");
        // Same underlying fd both calls (OnceLock returns the cached File).
        assert_eq!(f1.as_raw_fd(), f2.as_raw_fd());
        assert!(f1.as_raw_fd() >= 0);
    }

    #[test]
    fn test_dev_null_accessor_is_nonblocking() {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use std::os::fd::AsFd as _;
        let f = dev_null().expect("open /dev/null");
        let flags = fcntl(f.as_fd(), FcntlArg::F_GETFL).expect("F_GETFL");
        let flags = OFlag::from_bits_truncate(flags);
        assert!(
            flags.contains(OFlag::O_NONBLOCK),
            "dev_null fd must be O_NONBLOCK so splice(2) returns EAGAIN instead of blocking the runtime, got flags = {flags:?}",
        );
    }

    #[tokio::test]
    async fn test_drain_pipe_discards_exact_count() {
        use tokio::io::AsyncWriteExt as _;

        let (mut tx, rx) = create_pipe().expect("create_pipe");
        let payload = vec![0xABu8; 4096];
        tx.write_all(&payload).await.expect("write payload");

        drain_pipe(&rx, payload.len())
            .await
            .expect("drain should consume all bytes");

        // After draining, no more bytes are readable without further writes.
        // Drop the writer so a subsequent read sees EOF rather than hanging.
        drop(tx);
        let mut probe = [0u8; 16];
        // try_read must return Ok(0) (EOF) — the pipe is empty and the writer closed.
        // Loop past any spurious WouldBlock that can occur before the EOF is observed.
        loop {
            rx.readable().await.expect("readable");
            match rx.try_read(&mut probe) {
                Ok(0) => break,
                Ok(n) => {
                    assert_eq!(n, 0, "unexpected leftover bytes after drain");
                    break;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => unreachable!("unexpected read error: {e}"),
            }
        }
    }

    #[tokio::test]
    async fn test_drain_pipe_zero_count_is_noop() {
        let (_tx, rx) = create_pipe().expect("create_pipe");
        // Must not touch the pipe and must not await readability (which would hang).
        drain_pipe(&rx, 0)
            .await
            .expect("zero-count drain is a no-op");
    }

    #[tokio::test]
    async fn test_drain_pipe_eof_mid_drain_returns_unexpected_eof() {
        use tokio::io::AsyncWriteExt as _;

        let (mut tx, rx) = create_pipe().expect("create_pipe");
        // Write only half of what we'll ask to drain, then close the writer to
        // force EOF on the next splice attempt.
        tx.write_all(&[0u8; 1024]).await.expect("write half");
        drop(tx);

        let err = drain_pipe(&rx, 4096)
            .await
            .expect_err("drain must fail when pipe closes before count satisfied");
        assert_eq!(
            err.kind(),
            ErrorKind::UnexpectedEof,
            "expected UnexpectedEof, got {err:?}",
        );
    }

    #[tokio::test]
    async fn test_drain_pipe_crosses_multiple_readable_rounds() {
        use tokio::io::AsyncWriteExt as _;

        // Pick a total payload several pipe-buffers' worth so the kernel
        // cannot deliver it all in one splice round regardless of writer
        // scheduling: drain_pipe must loop, hitting `rx.readable().await`
        // at least `total / pipe_size` times, with at least one round
        // blocked until the writer task refills. The previous variant
        // (8 KiB total, default 64 KiB pipe, `yield_now()` between batches)
        // could pass even when drain consumed everything in a single
        // splice — exactly the regression this test is meant to catch.
        let (mut tx, rx) = create_pipe().expect("create_pipe");
        let _ignore = fcntl(rx.as_fd(), FcntlArg::F_SETPIPE_SZ(4096));
        let pipe_size = fcntl(rx.as_fd(), FcntlArg::F_GETPIPE_SZ).expect("pipe size");
        let total: usize = (pipe_size * 4).try_into().expect("pipe_size fits usize");

        let drain_handle = tokio::spawn(async move {
            drain_pipe(&rx, total).await.expect("drain succeeds");
            rx
        });

        let payload = vec![0xABu8; total];
        tx.write_all(&payload).await.expect("write full payload");
        drop(tx);

        let _rx = drain_handle.await.expect("drain task completes");
    }

    // Drive `buffered_dechunk_step` to completion over a single input buffer,
    // returning the decoded body and the count of bytes consumed.
    fn dechunk_once(input: &[u8], max_bytes: usize) -> std::io::Result<(Vec<u8>, usize)> {
        let mut state = BufferedDechunkState::ReadingSize;
        let mut size_buf = Vec::with_capacity(32);
        let mut body = Vec::new();
        let consumed =
            buffered_dechunk_step(&mut state, &mut size_buf, &mut body, input, max_bytes)?;
        Ok((body, consumed))
    }

    #[test]
    fn test_buffered_dechunk_consumes_closing_crlf() {
        // Well-formed chunked body: one 5-byte chunk "hello", then terminator.
        // The decoder must consume every byte (including the final \r\n) so
        // the upstream socket buffer is left empty and the connection can be
        // returned to the pool.
        let input: &[u8] = b"5\r\nhello\r\n0\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert_eq!(body, b"hello");
        assert_eq!(
            consumed,
            input.len(),
            "decoder must consume every byte of the chunked frame, including the closing CRLF",
        );
    }

    #[test]
    fn test_buffered_dechunk_empty_body() {
        // `0\r\n\r\n` -- a body that is purely the terminal chunk. Must
        // consume all 5 bytes and produce an empty body.
        let input: &[u8] = b"0\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert!(
            body.is_empty(),
            "empty chunked body should decode to no bytes"
        );
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn test_buffered_dechunk_multi_chunk() {
        // Two data chunks then terminator.
        let input: &[u8] = b"3\r\nfoo\r\n4\r\nbarz\r\n0\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert_eq!(body, b"foobarz");
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn test_buffered_dechunk_rejects_trailer_fields() {
        // Trailer fields between `0\r\n` and the final `\r\n` are not
        // supported (matches the streaming variant's policy). A header
        // line starting with `X` after `0\r\n` must be rejected because
        // the byte after `0\r\n` is expected to be `\r`.
        let input: &[u8] = b"0\r\nX-Trailer: foo\r\n\r\n";
        let err = dechunk_once(input, 1024).expect_err("trailer fields must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn test_buffered_dechunk_rejects_garbage_after_zero_chunk() {
        // The bytes following `0\r\n` must be exactly `\r\n`. Garbage in
        // place of the CR triggers a framing error rather than silently
        // succeeding (the pre-fix decoder did the latter, leaving the
        // garbage in the upstream socket buffer).
        let input: &[u8] = b"0\r\nXY";
        let err = dechunk_once(input, 1024).expect_err("garbage after 0-chunk must be rejected");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn test_buffered_dechunk_split_closing_crlf() {
        // The closing `\r\n` arrives in two separate buffers (the `\r` in
        // one read, the `\n` in the next). Verifies `Done { remaining }`
        // correctly counts down across buffer boundaries.
        let mut state = BufferedDechunkState::ReadingSize;
        let mut size_buf = Vec::with_capacity(32);
        let mut body = Vec::new();

        // First buffer: data chunk + terminal `0\r\n` + the `\r` of the
        // closing CRLF (1 byte short of the full terminator).
        let part1: &[u8] = b"5\r\nhello\r\n0\r\n\r";
        let c1 = buffered_dechunk_step(&mut state, &mut size_buf, &mut body, part1, 1024)
            .expect("part1 decode");
        assert_eq!(c1, part1.len());
        assert!(
            matches!(state, BufferedDechunkState::Done { remaining: 1 }),
            "after part1 the decoder must still be waiting for one more byte (the LF)",
        );

        // Second buffer: just the `\n` that finishes the closing CRLF.
        let part2: &[u8] = b"\n";
        let c2 = buffered_dechunk_step(&mut state, &mut size_buf, &mut body, part2, 1024)
            .expect("part2 decode");
        assert_eq!(c2, 1);
        assert!(matches!(state, BufferedDechunkState::Done { remaining: 0 }));
        assert_eq!(body, b"hello");
    }

    #[test]
    fn test_buffered_dechunk_stops_at_done_leaves_trailing_bytes() {
        // After fully consuming `0\r\n\r\n` the decoder must stop and
        // leave any trailing bytes in the input unconsumed -- the I/O
        // wrapper turns that into a framing-violation error so a
        // misbehaving upstream cannot poison the connection pool.
        let input: &[u8] = b"0\r\n\r\nGARBAGE";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert_eq!(body, [] as [u8; 0]);
        assert_eq!(
            consumed, 5,
            "decoder must stop right after the closing CRLF, not swallow trailing bytes",
        );
    }

    #[test]
    fn test_buffered_dechunk_chunk_extensions_ignored() {
        // RFC 9112 allows chunk extensions after `;` on the chunk-size
        // line; they must be parsed and ignored, matching the streaming
        // variant.
        let input: &[u8] = b"5;ext=foo\r\nhello\r\n0;final\r\n\r\n";
        let (body, consumed) = dechunk_once(input, 1024).expect("decode succeeds");
        assert_eq!(body, b"hello");
        assert_eq!(consumed, input.len());
    }
}
