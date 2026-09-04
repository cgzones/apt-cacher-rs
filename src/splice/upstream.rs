//! Upstream connection plumbing for the splice proxy: the [`UpstreamConn`]
//! enum (plain TCP, userspace TLS, kernel TLS) with its [`TlsMode`] and
//! [`ConnLabel`] log rendering, the per-host idle pool behind [`PoolGuard`]
//! and [`UnconsumedBodyGuard`], the TCP/TLS connect helpers
//! ([`connect_upstream`], [`tcp_connect`], `tls_connect`) and the
//! [`ConnectError`]/[`Transience`] classification consumed by the retry
//! loop in `acquire`. Also hosts the process-wide `TLS_CLIENT_CONFIG` that
//! `main.rs` initialises.
//!
//! Consumers: `acquire` (connect, pool checkout, labels), `http` and `body`
//! (read/write through the connection), `ktls_path` (`tcp_connect`).

#[cfg(feature = "tls_rustls")]
use std::sync::Arc;
use std::{
    io::ErrorKind,
    num::NonZero,
    os::fd::AsRawFd as _,
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll},
};

use hashbrown::hash_map::EntryRef;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tracing::debug;

use crate::deb_mirror::Mirror;
use crate::error::{ErrorReport, Transience};
use crate::humanfmt::HumanFmt;
use crate::{Scheme, global_config, metrics, warn_once_or_debug, warn_once_or_info};

/// Pre-computed TLS client config for use with `tls_rustls`.
/// Should only be initialized once from main.
#[cfg(feature = "tls_rustls")]
pub(crate) static TLS_CLIENT_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// How long an idle pooled connection is kept before eviction.
const POOL_IDLE_TIMEOUT: coarsetime::Duration = coarsetime::Duration::from_secs(90);

/// Maximum number of idle connections kept per host.
const POOL_MAX_IDLE_PER_HOST: usize = 4;

/// Buffer size for TLS upstream reads.  TLS records are at most 16 KiB, so
/// a larger buffer amortizes the per-chunk pwrite+write pair — 256 KiB
/// costs one allocation per concurrent userspace-TLS download (not per
/// connection) and quarters the loop iterations per MiB.
pub(super) const TLS_READ_BUF_SIZE: usize = 256 * 1024;

#[cfg_attr(
    feature = "tls_rustls",
    expect(
        clippy::large_enum_variant,
        reason = "tokio_rustls::client::TlsStream is the biggest variant, but also the one most likely to be used"
    )
)]
#[pin_project::pin_project(project = UpstreamConnProj)]
pub(super) enum UpstreamConn {
    Tcp(#[pin] TcpStream),
    Tls(#[pin] TlsStream),
    /// TLS with kernel RX offload configured for one session: the socket
    /// yields plaintext, but only for the request already on the wire.
    /// `PoolGuard::drop` never returns this variant to the pool.
    #[cfg(feature = "ktls")]
    Ktls(#[pin] TcpStream),
}

/// How an [`UpstreamConn`] is encrypted. Derived from the variant on demand,
/// never cached, so it cannot drift from the socket it describes.
#[derive(Clone, Copy)]
pub(super) enum TlsMode {
    /// Plain TCP.
    Plain,
    /// TLS terminated in userspace by [`TlsStream`].
    Userspace,
    /// TLS with kernel RX offload: the socket hands plaintext to `splice(2)`.
    #[cfg(feature = "ktls")]
    Kernel,
}

/// An upstream socket whose receive queue holds plaintext the kernel can
/// `splice(2)` straight into a pipe: plain TCP, or TLS with kernel RX
/// offload. Obtained via [`UpstreamConn::zero_copy`]; userspace TLS never
/// yields one.
#[derive(Clone, Copy)]
pub(super) struct ZeroCopyUpstream<'a> {
    pub(super) tcp: &'a TcpStream,
    /// Whether kTLS RX is configured on `tcp`, i.e. whether TLS control
    /// records can surface as `splice(2)` errors mid-stream.
    #[cfg(feature = "ktls")]
    pub(super) ktls: bool,
}

/// Log suffix naming an exchange's connection flavour -- [`TlsMode`] plus
/// pool reuse -- as in `" (TLS, reused)"`; empty for a fresh plain connection.
#[derive(Clone, Copy)]
pub(super) struct ConnLabel {
    pub(super) mode: TlsMode,
    pub(super) reused: bool,
}

impl std::fmt::Display for ConnLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { mode, reused } = *self;
        let mode = match mode {
            TlsMode::Plain => None,
            TlsMode::Userspace => Some("TLS"),
            #[cfg(feature = "ktls")]
            TlsMode::Kernel => Some("kTLS"),
        };
        match (mode, reused) {
            (None, false) => Ok(()),
            (None, true) => f.write_str(" (reused)"),
            (Some(mode), false) => write!(f, " ({mode})"),
            (Some(mode), true) => write!(f, " ({mode}, reused)"),
        }
    }
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
            #[cfg(feature = "ktls")]
            UpstreamConnProj::Ktls(s) => s.poll_read(cx, buf),
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
            #[cfg(feature = "ktls")]
            UpstreamConnProj::Ktls(s) => s.poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_flush(cx),
            UpstreamConnProj::Tls(s) => s.poll_flush(cx),
            #[cfg(feature = "ktls")]
            UpstreamConnProj::Ktls(s) => s.poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.project() {
            UpstreamConnProj::Tcp(s) => s.poll_shutdown(cx),
            UpstreamConnProj::Tls(s) => s.poll_shutdown(cx),
            #[cfg(feature = "ktls")]
            UpstreamConnProj::Ktls(s) => s.poll_shutdown(cx),
        }
    }
}

impl UpstreamConn {
    /// How this connection is encrypted.
    #[must_use]
    pub(super) const fn tls_mode(&self) -> TlsMode {
        match self {
            Self::Tcp(_) => TlsMode::Plain,
            Self::Tls(_) => TlsMode::Userspace,
            #[cfg(feature = "ktls")]
            Self::Ktls(_) => TlsMode::Kernel,
        }
    }

    /// Whether the connection is encrypted at all (userspace or kernel TLS):
    /// decides the upstream port and the pool key.
    #[must_use]
    pub(super) const fn is_tls(&self) -> bool {
        !matches!(self.tls_mode(), TlsMode::Plain)
    }

    /// The socket to `splice(2)` the response body from, when the kernel
    /// hands out plaintext (plain TCP, or kTLS with RX offload). `None` for
    /// userspace TLS, whose plaintext only ever exists in this process.
    #[must_use]
    pub(super) const fn zero_copy(&self) -> Option<ZeroCopyUpstream<'_>> {
        match self {
            Self::Tcp(tcp) => Some(ZeroCopyUpstream {
                tcp,
                #[cfg(feature = "ktls")]
                ktls: false,
            }),
            Self::Tls(_) => None,
            #[cfg(feature = "ktls")]
            Self::Ktls(tcp) => Some(ZeroCopyUpstream { tcp, ktls: true }),
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
pub(super) fn mirror_port(mirror: &Mirror, is_tls: bool) -> u16 {
    mirror
        .port()
        .map_or(if is_tls { 443 } else { 80 }, NonZero::get)
}

/// Try to retrieve an idle connection from the pool.
///
/// Pops from the back (most-recently-returned) and skips stale entries
/// without scanning the entire vec, keeping the lock held briefly.
pub(super) fn pool_checkout(host: &str, port: u16, is_tls: bool) -> Option<UpstreamConn> {
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
pub(super) struct PoolGuard {
    conn: Option<UpstreamConn>,
    host: String,
    port: u16,
    poolable: bool,
}

impl PoolGuard {
    /// Creates a new `PoolGuard` wrapping the given `UpstreamConn`.
    pub(super) fn new(conn: UpstreamConn, host: String, port: u16, poolable: bool) -> Self {
        Self {
            conn: Some(conn),
            host,
            port,
            poolable,
        }
    }

    /// Marks the connection as non-poolable, preventing it from being returned to the pool on drop.
    pub(super) fn unset_poolable(&mut self) {
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
            let is_tls = match conn.tls_mode() {
                TlsMode::Plain => false,
                TlsMode::Userspace => true,
                // kTLS connections must NOT be pooled: the socket has kernel TLS
                // RX configured for this specific session's keys and sequence
                // numbers. Reusing it for a new request would layer a new TLS
                // handshake on top of the kTLS socket, corrupting the stream.
                // Future optimization: kTLS sockets could be pooled as a separate
                // "kTLS-ready" type that writes plaintext (kernel encrypts via TX)
                // and splices responses (kernel decrypts via RX), skipping the TLS
                // handshake entirely. This requires a distinct pool entry type,
                // control-message draining between requests, and key-update handling.
                #[cfg(feature = "ktls")]
                TlsMode::Kernel => return,
            };
            pool_return(&self.host, self.port, is_tls, conn);
        }
    }
}

/// RAII poison for a pooled upstream connection whose response body has not
/// yet been fully drained from the socket. While this guard is alive, any
/// drop (i.e. any early return in the download body) marks the wrapped
/// `PoolGuard` non-poolable, so a half-read connection can never re-enter the
/// pool. Call [`UnconsumedBodyGuard::consumed`] once the body has been fully
/// read to defuse it.
pub(super) struct UnconsumedBodyGuard<'g> {
    upstream: &'g mut PoolGuard,
    consumed: bool,
}

impl<'g> UnconsumedBodyGuard<'g> {
    pub(super) fn new(upstream: &'g mut PoolGuard) -> Self {
        Self {
            upstream,
            consumed: false,
        }
    }

    /// Defuse: the response body has been fully drained, so the connection's
    /// existing `poolable` decision (from `Connection:` keep-alive) stands.
    pub(super) fn consumed(&mut self) {
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

impl UpstreamConn {
    /// Check if a pooled connection is still alive (not closed by the remote).
    ///
    /// For TLS connections on rustls we peek at the raw TCP socket: a closed
    /// peer (recv → 0) or error rules the connection out, while pending bytes
    /// on an idle pooled TLS connection almost certainly indicate a `close_notify`
    /// alert and are treated the same. The native-tls backend does not expose
    /// the underlying TCP fd cleanly, so we remain optimistic there.
    pub(super) fn check_alive(&self, host: &str, port: u16) -> bool {
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
            // Never pooled (`PoolGuard::drop`), so never checked; the kernel
            // session is spent after its one request anyway.
            #[cfg(feature = "ktls")]
            Self::Ktls(_) => false,
        }
    }
}

/// An upstream connect failure, tagged with whether retrying it can plausibly
/// succeed. Retrying a deterministic failure costs a full TCP connect plus a
/// full TLS handshake per attempt and buys nothing.
pub(super) struct ConnectError {
    pub(super) transience: Transience,
    pub(super) err: std::io::Error,
}

impl ConnectError {
    /// Pair an already-classified failure with the error it was derived from.
    fn new(transience: Transience, err: std::io::Error) -> Self {
        Self { transience, err }
    }

    /// DNS/TCP failure, timeout, or a network error mid-handshake -- retry may help.
    fn transient(err: std::io::Error) -> Self {
        Self::new(Transience::Transient, err)
    }

    /// Deterministic for this (host, scheme): unparsable server name, certificate
    /// rejection. Retrying re-runs the same handshake and fails identically.
    fn permanent(err: std::io::Error) -> Self {
        Self::new(Transience::Permanent, err)
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
/// reports its own kind and keeps the cause behind `source()`. Split out of
/// [`ConnectError`] so it stays unit-testable.
const fn classify_tls_error(kind: ErrorKind) -> Transience {
    if matches!(kind, ErrorKind::InvalidData | ErrorKind::InvalidInput) {
        Transience::Permanent
    } else {
        Transience::Transient
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
pub(super) async fn connect_upstream(
    mirror: &Mirror,
    scheme: Option<Scheme>,
) -> Result<(UpstreamConn, Scheme), ConnectError> {
    let host = mirror.host().as_str();

    match scheme {
        Some(Scheme::Http) => {
            let tcp = tcp_connect(host, mirror_port(mirror, false))
                .await
                .map_err(ConnectError::transient)?;
            Ok((UpstreamConn::Tcp(tcp), Scheme::Http))
        }
        Some(Scheme::Https) => {
            let tcp = tcp_connect(host, mirror_port(mirror, true))
                .await
                .map_err(ConnectError::transient)?;
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
                            ErrorReport(&err.err)
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
                .map_err(ConnectError::transient)?;
            Ok((UpstreamConn::Tcp(tcp), Scheme::Http))
        }
    }
}

/// Establish a TCP connection to the given host and port.
///
/// Times out after the configured HTTP timeout.
pub(super) async fn tcp_connect(host: &str, port: u16) -> std::io::Result<TcpStream> {
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

            #[cfg(debug_assertions)]
            {
                use nix::sys::socket::{
                    getsockopt,
                    sockopt::{RcvBuf, ReceiveTimeout, SendTimeout, SndBuf},
                };

                let send_buf_size = getsockopt(&tcp, SndBuf);
                let recv_buf_size = getsockopt(&tcp, RcvBuf);
                let send_timeout = getsockopt(&tcp, SendTimeout);
                let recv_timeout = getsockopt(&tcp, ReceiveTimeout);
                debug!(
                    "Connected to {host}:{port}: \
                    snd_buf_size={send_buf_size:?}, \
                    rcv_buf_size={recv_buf_size:?}, \
                    send_timeout={send_timeout:?}, \
                    recv_timeout={recv_timeout:?}"
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
        ConnectError::permanent(std::io::Error::new(
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
            ConnectError::transient(std::io::Error::new(
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
            ConnectError::new(
                classify_tls_error(err.kind()),
                std::io::Error::new(
                    err.kind(),
                    format!("failed to complete TLS handshake:  {err}"),
                ),
            )
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
        ConnectError::permanent(std::io::Error::other(err))
    })?;
    let connector = tokio_native_tls::TlsConnector::from(native_connector);

    debug!("splice proxy: starting TLS handshake with {host}");
    let http_timeout = global_config().http_timeout;
    let tls_stream = tokio::time::timeout(http_timeout, connector.connect(host, tcp))
        .await
        .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| {
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
            ConnectError::transient(std::io::Error::new(
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
            ConnectError::new(classify_tls_error(err.kind()), err)
        })?;
    debug!("splice proxy: TLS handshake completed with {host}");
    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use crate::config::ClientHost;
    use crate::deb_mirror::MirrorKind;

    use super::*;

    #[test]
    fn conn_label_renders_the_log_suffixes() {
        let label = |mode, reused| ConnLabel { mode, reused }.to_string();
        assert_eq!(label(TlsMode::Plain, false), "");
        assert_eq!(label(TlsMode::Plain, true), " (reused)");
        assert_eq!(label(TlsMode::Userspace, false), " (TLS)");
        assert_eq!(label(TlsMode::Userspace, true), " (TLS, reused)");
        #[cfg(feature = "ktls")]
        assert_eq!(label(TlsMode::Kernel, false), " (kTLS)");
    }

    #[test]
    fn classify_tls_error_marks_deterministic_kinds_permanent() {
        // rustls surfaces a rejected certificate chain as InvalidData and an
        // unparsable server name as InvalidInput; both repeat identically.
        assert_eq!(
            classify_tls_error(ErrorKind::InvalidData),
            Transience::Permanent,
            "certificate rejection must not be retried"
        );
        assert_eq!(
            classify_tls_error(ErrorKind::InvalidInput),
            Transience::Permanent,
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
                Transience::Transient,
                "{kind:?} may succeed on retry"
            );
        }
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
}
