//! Upstream connection plumbing for the splice proxy: the [`UpstreamConn`]
//! enum (plain TCP, userspace TLS) with its [`ConnLabel`] log rendering, the per-host idle pool behind [`PoolGuard`]
//! and [`UnconsumedBodyGuard`], the TCP/TLS connect helpers
//! ([`connect_upstream`], [`tcp_connect`], `tls_connect`) and the
//! [`ConnectError`]/[`Transience`] classification consumed by the retry
//! loop in `acquire`. Also hosts the process-wide `TLS_CLIENT_CONFIG` that
//! `main.rs` initialises.
//!
//! Consumers: `acquire` (connect, pool checkout, labels), `http` and `body`
//! (read/write through the connection).

#[cfg(feature = "tls_rustls")]
use std::sync::Arc;
use std::{
    io::ErrorKind,
    num::NonZero,
    os::fd::{AsRawFd as _, RawFd},
    pin::Pin,
    sync::OnceLock,
    task::{Context, Poll, Waker},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tracing::debug;

use crate::config::ClientHost;
use crate::deb_mirror::Mirror;
use crate::error::{ErrorReport, is_peer_disconnect};
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

/// Buffer size for TLS upstream reads: the `super::http` head scanners and
/// buffered-body collectors, and the userspace-TLS body loop
/// (`super::body::splice_proxy_body_tls`).  One `poll_read` on a `TlsStream`
/// yields about one 16 KiB TLS record however much capacity is offered, so
/// the body loop accumulates several reads into this buffer before each
/// `pwrite` and client write; 256 KiB costs one allocation per read site.
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
}

/// Log suffix naming an exchange's connection flavour -- TLS or plain, plus
/// pool reuse -- as in `" (TLS, reused)"`; empty for a fresh plain connection.
#[derive(Clone, Copy)]
pub(super) struct ConnLabel {
    pub(super) tls: bool,
    pub(super) reused: bool,
}

impl std::fmt::Display for ConnLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { tls, reused } = *self;
        match (tls, reused) {
            (false, false) => Ok(()),
            (false, true) => f.write_str(" (reused)"),
            (true, false) => f.write_str(" (TLS)"),
            (true, true) => f.write_str(" (TLS, reused)"),
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
    /// Whether the connection is encrypted: decides the upstream port, the
    /// pool key and the log label. Derived from the variant on demand, never
    /// cached, so it cannot drift from the socket it describes.
    #[must_use]
    pub(super) const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    /// The scheme the connection was dialled with, derived from the variant
    /// like [`Self::is_tls`].
    #[must_use]
    pub(super) const fn scheme(&self) -> Scheme {
        if self.is_tls() {
            Scheme::Https
        } else {
            Scheme::Http
        }
    }

    /// The socket to `splice(2)` the response body from, when the kernel
    /// hands out plaintext (plain TCP). `None` for userspace TLS, whose
    /// plaintext only ever exists in this process.
    #[must_use]
    pub(super) const fn zero_copy(&self) -> Option<&TcpStream> {
        match self {
            Self::Tcp(tcp) => Some(tcp),
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
/// non-default port — never get mixed up. The host is the refcounted
/// `ClientHost` the mirror already carries, so building a key for a lookup
/// is a refcount bump, not an allocation: no borrowed-key `Equivalent`
/// mirror is needed here.
type PoolKey = (ClientHost, u16, bool);

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

/// What [`pool_checkout`] found for a key.
#[cfg_attr(
    feature = "tls_rustls",
    expect(
        clippy::large_enum_variant,
        reason = "carries an UpstreamConn, whose TLS variant is the large one; a checkout is moved once"
    )
)]
pub(super) enum PoolCheckout {
    /// A connection whose peer has not hung up ([`UpstreamConn::check_alive`]).
    Live(UpstreamConn),
    /// Entries existed, but the peer had closed every one of them.
    Dead,
    /// No entry for the key (never pooled, or every entry idled out).
    Empty,
}

/// Pop one entry for the key, most recently returned first, discarding
/// entries past [`POOL_IDLE_TIMEOUT`]. `None` once the key is exhausted.
fn pool_pop(host: &ClientHost, port: u16, is_tls: bool) -> Option<UpstreamConn> {
    let mut map = upstream_pool().lock();
    let key = (host.clone(), port, is_tls);
    let conns = map.get_mut(&key)?;

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
        map.remove(&key);
    }
    conn
}

/// Try to retrieve a live idle connection from the pool.
///
/// Walks the key's entries most-recently-returned first and probes each
/// ([`UpstreamConn::check_alive`], one non-blocking syscall) outside the
/// lock: a server that closes after a request cap kills the busiest entry
/// first, and giving up on it would open a fresh connection while a live
/// one sat below it.
pub(super) fn pool_checkout(host: &ClientHost, port: u16, is_tls: bool) -> PoolCheckout {
    let mut saw_dead = false;
    while let Some(mut conn) = pool_pop(host, port, is_tls) {
        if conn.check_alive(host, port) {
            debug!("splice proxy: reusing pooled connection to {host}:{port} (tls={is_tls})");
            return PoolCheckout::Live(conn);
        }
        saw_dead = true;
    }
    if saw_dead {
        PoolCheckout::Dead
    } else {
        PoolCheckout::Empty
    }
}

/// Take every entry past [`POOL_IDLE_TIMEOUT`] out of the pool, for every
/// key, and hand them to the caller to drop *after* the lock is gone: a
/// `TcpStream` drop deregisters from the reactor and closes the socket, and
/// the map is contended by every checkout and return.
#[must_use]
fn pool_take_idle(
    map: &mut hashbrown::HashMap<PoolKey, Vec<PooledConn>>,
    now: coarsetime::Instant,
) -> Vec<PooledConn> {
    let mut expired = Vec::new();
    map.retain(|_, conns| {
        expired.extend(conns.extract_if(.., |e| {
            now.duration_since(e.idle_since) >= POOL_IDLE_TIMEOUT
        }));
        !conns.is_empty()
    });
    expired
}

/// Drop every pooled connection that idled past [`POOL_IDLE_TIMEOUT`].
///
/// Runs from [`pool_reaper`], independently of request traffic. Checkout
/// and return only inspect their own key, keeping full-map scans off the
/// per-request path.
fn reap_idle_pool() {
    let now = coarsetime::Instant::now();
    let expired = pool_take_idle(&mut upstream_pool().lock(), now);
    if !expired.is_empty() {
        debug!(
            "splice proxy: reaped {} idle pooled upstream connection(s)",
            expired.len()
        );
    }
    drop(expired);
}

/// The periodic sweep behind [`reap_idle_pool`]: one tick per
/// [`POOL_IDLE_TIMEOUT`], so an entry lives at most twice the timeout on an
/// otherwise idle proxy. Spawned once by the main loop; runs until the
/// runtime shuts down.
pub(crate) async fn pool_reaper() {
    let mut interval = tokio::time::interval(POOL_IDLE_TIMEOUT.into());
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick fires at once; nothing has idled out yet.
    interval.tick().await;
    #[expect(
        clippy::infinite_loop,
        reason = "a runtime-lifetime task: the main loop's return drops the runtime and the task with it"
    )]
    loop {
        interval.tick().await;
        reap_idle_pool();
    }
}

/// Return a connection to the pool for reuse.
///
/// Expires only this key's entries (at most [`POOL_MAX_IDLE_PER_HOST`]);
/// [`pool_reaper`] handles other keys. Drop removed sockets outside the lock.
fn pool_return(host: &ClientHost, port: u16, is_tls: bool, conn: UpstreamConn) {
    let mut map = upstream_pool().lock();
    let now = coarsetime::Instant::now();
    let conns = map.entry((host.clone(), port, is_tls)).or_default();
    let mut expired: Vec<_> = conns
        .extract_if(.., |entry| {
            now.duration_since(entry.idle_since) >= POOL_IDLE_TIMEOUT
        })
        .collect();

    if conns.len() >= POOL_MAX_IDLE_PER_HOST {
        debug!("splice proxy: evicting oldest pooled connection for {host}:{port} (pool full)");
        metrics::POOL_RETURN_EVICTED.increment();
        expired.push(conns.remove(0));
    }
    conns.push(PooledConn {
        conn,
        idle_since: now,
    });
    drop(map);
    drop(expired);
    debug!("splice proxy: returned connection to pool for {host}:{port} (tls={is_tls})");
}

/// Wraps an `UpstreamConn` and automatically returns it to the connection pool
/// on drop if `poolable` is true. Prevents connection leaks on early-return paths.
pub(super) struct PoolGuard {
    conn: Option<UpstreamConn>,
    host: ClientHost,
    port: u16,
    poolable: bool,
}

impl PoolGuard {
    /// Creates a new `PoolGuard` wrapping the given `UpstreamConn`.
    pub(super) fn new(conn: UpstreamConn, host: ClientHost, port: u16, poolable: bool) -> Self {
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

    /// Whether the connection goes back to the pool once released.
    #[must_use]
    pub(super) const fn poolable(&self) -> bool {
        self.poolable
    }
}

impl std::ops::Deref for PoolGuard {
    type Target = UpstreamConn;
    fn deref(&self) -> &UpstreamConn {
        self.conn
            .as_ref()
            .expect("live PoolGuard contains a connection")
    }
}

impl std::ops::DerefMut for PoolGuard {
    fn deref_mut(&mut self) -> &mut UpstreamConn {
        self.conn
            .as_mut()
            .expect("live PoolGuard contains a connection")
    }
}

impl Drop for PoolGuard {
    fn drop(&mut self) {
        // Taking the connection is private to Drop: a live guard always
        // contains its connection, including across replacement awaits.
        let conn = self
            .conn
            .take()
            .expect("live PoolGuard contains a connection");
        if self.poolable {
            let is_tls = conn.is_tls();
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

/// What the liveness probe found on a pooled connection.
enum Liveness {
    /// Idle and open: nothing arrived since the last response.
    Alive,
    /// The peer hung up (TCP FIN, reset, or a TLS `close_notify`).
    ClosedByPeer,
    /// Bytes no request asked for: the next head read would choke on them.
    UnexpectedData,
    /// Bytes wait on the socket, but tokio's readiness cache lags it, so
    /// they could not be read and told apart (a `close_notify` behind the
    /// last body record, a post-handshake TLS message, junk). Discarded
    /// like the rest, but nothing is known to be wrong with the peer.
    Uninterpreted,
    /// The probe itself failed; the connection is not trusted.
    Failed(std::io::Error),
}

impl Liveness {
    /// Log the verdict and reduce it to "reuse this connection?".
    fn report(self, host: &ClientHost, port: u16) -> bool {
        match self {
            Self::Alive => true,
            Self::ClosedByPeer => {
                debug!("splice proxy: pooled connection to {host}:{port} closed by peer");
                false
            }
            Self::UnexpectedData => {
                warn_once_or_debug!(
                    "splice proxy: pooled connection to {host}:{port} has unexpected data; discarding it and connecting fresh"
                );
                false
            }
            Self::Uninterpreted => {
                debug!(
                    "splice proxy: pooled connection to {host}:{port} has pending bytes the reactor has not seen yet; discarding it and connecting fresh"
                );
                false
            }
            Self::Failed(err) => {
                warn_once_or_info!(
                    "splice proxy: failed to check the pooled connection to {host}:{port}; discarding it and connecting fresh:  {}",
                    ErrorReport(&err)
                );
                false
            }
        }
    }
}

impl UpstreamConn {
    /// Whether a pooled connection is still usable: the peer has not hung
    /// up, and nothing has arrived on it since the last response.
    ///
    /// Three probes, each answering only what the one before it could not:
    ///
    /// 1. The TLS session's buffered plaintext, which can hold trailing
    ///    bytes even when the socket is empty. Rustls also exposes an
    ///    already processed `close_notify` here.
    /// 2. A `MSG_PEEK` on the socket. A raw syscall on purpose: every
    ///    tokio-level read (`poll_read`, `try_read`) is gated on tokio's
    ///    cached readiness, which does not reflect a FIN the driver has not
    ///    turned for yet, so it can report an idle socket as merely pending.
    ///    EOF is the peer's close, `EAGAIN` an idle connection.
    /// 3. If the peek found bytes, one `poll_read` on the connection itself
    ///    with a no-op waker, so the TLS layer can decrypt and interpret
    ///    them: a zero-length read is a `close_notify` (under TLS 1.3 an
    ///    encrypted record, indistinguishable from data at the socket);
    ///    bytes are junk the last response left behind. `Pending` here means
    ///    the readiness cache lags the socket, which leaves the bytes
    ///    uninterpreted ([`Liveness::Uninterpreted`]) and the connection
    ///    untrusted. The no-op waker leaves the readiness state intact for
    ///    the real read that may follow.
    pub(super) fn check_alive(&mut self, host: &ClientHost, port: u16) -> bool {
        if let Self::Tls(tls) = self
            && let Some(verdict) = tls_session_liveness(tls)
        {
            return verdict.report(host, port);
        }

        let verdict = match peek_socket(self.raw_fd()) {
            Ok(0) | Err(nix::errno::Errno::ECONNRESET) => Liveness::ClosedByPeer,
            Ok(_pending) => self.interpret_pending(),
            Err(nix::errno::Errno::EAGAIN) => Liveness::Alive,
            Err(errno) => Liveness::Failed(std::io::Error::from(errno)),
        };
        verdict.report(host, port)
    }

    /// Probe 3 of [`Self::check_alive`]: read the bytes the peek found
    /// through the connection, so a TLS alert is told from data.
    fn interpret_pending(&mut self) -> Liveness {
        let mut byte = [0u8; 1];
        let mut buf = ReadBuf::new(&mut byte);
        let mut cx = Context::from_waker(Waker::noop());
        match Pin::new(self).poll_read(&mut cx, &mut buf) {
            Poll::Ready(Ok(())) if buf.filled().is_empty() => Liveness::ClosedByPeer,
            Poll::Ready(Ok(())) => Liveness::UnexpectedData,
            Poll::Pending => Liveness::Uninterpreted,
            Poll::Ready(Err(err)) if is_peer_disconnect(&err) => Liveness::ClosedByPeer,
            Poll::Ready(Err(err)) => Liveness::Failed(err),
        }
    }

    /// The TCP socket under the connection.
    fn raw_fd(&self) -> RawFd {
        match self {
            Self::Tcp(tcp) => tcp.as_raw_fd(),
            #[cfg(feature = "tls_rustls")]
            Self::Tls(tls) => tls.get_ref().0.as_raw_fd(),
            #[cfg(not(feature = "tls_rustls"))]
            Self::Tls(tls) => tls.get_ref().get_ref().get_ref().as_raw_fd(),
        }
    }
}

/// Probe 1 of [`UpstreamConn::check_alive`]: what the rustls session has
/// already taken off the socket. `None` when nothing is buffered and the
/// socket has to be asked.
#[cfg(feature = "tls_rustls")]
fn tls_session_liveness(tls: &mut TlsStream) -> Option<Liveness> {
    use std::io::Read as _;

    let (_, session) = tls.get_mut();
    let mut buf = [0u8; 1];
    match session.reader().read(&mut buf) {
        Ok(0) => Some(Liveness::ClosedByPeer),
        Ok(_) => Some(Liveness::UnexpectedData),
        Err(err) if err.kind() == ErrorKind::WouldBlock => None,
        Err(err) if is_peer_disconnect(&err) => Some(Liveness::ClosedByPeer),
        Err(err) => Some(Liveness::Failed(err)),
    }
}

/// Native TLS buffers decrypted bytes separately from the TCP socket too.
/// A zero count leaves the socket probe to decide; no read is needed to
/// reject a session that already holds unsolicited plaintext.
#[cfg(not(feature = "tls_rustls"))]
fn tls_session_liveness(tls: &TlsStream) -> Option<Liveness> {
    match tls.get_ref().buffered_read_size() {
        Ok(0) => None,
        Ok(_) => Some(Liveness::UnexpectedData),
        Err(err) => Some(Liveness::Failed(std::io::Error::other(err))),
    }
}

/// Probe 2 of [`UpstreamConn::check_alive`]: how many bytes wait on the
/// socket (`0` is EOF), without consuming them or touching tokio's
/// readiness state.
fn peek_socket(fd: RawFd) -> nix::Result<usize> {
    use nix::sys::socket::{MsgFlags, recv};

    let mut buf = [0u8; 1];
    // EAGAIN/EWOULDBLOCK: see the static_assert in `super`.
    recv(fd, &mut buf, MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT)
}

/// Whether a failed connect is worth retrying. `Permanent` means the failure
/// is a deterministic function of its inputs (a rejected certificate, an
/// unparsable server name) and a retry re-runs it identically, so the retry
/// loop in `acquire` skips its budget; `Transient` means a transport hiccup
/// that may clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Transience {
    Transient,
    Permanent,
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
/// [`ConnectError`] so it stays unit-testable. The native-tls backend has no
/// kinds to classify (its error is opaque) and treats every failure as
/// transient.
#[cfg(feature = "tls_rustls")]
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
                    "TCP connect timed out after {}",
                    HumanFmt::Time(http_timeout)
                ),
            )
        })?
        .map_err(|err| {
            metrics::UPSTREAM_CONNECT_FAILED.increment();
            std::io::Error::new(
                err.kind(),
                format!("TCP connect failed:  {err}"),
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

/// The error a TLS handshake that outlived `http_timeout` fails with.
fn handshake_timed_out(http_timeout: Duration) -> ConnectError {
    metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
    ConnectError::transient(std::io::Error::new(
        ErrorKind::TimedOut,
        format!(
            "TLS handshake timed out after {}",
            HumanFmt::Time(http_timeout)
        ),
    ))
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
        .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| handshake_timed_out(http_timeout))?
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

/// The process-wide native-tls connector, built on first use.
///
/// One `SSL_CTX` for every upstream connection: building a connector loads
/// and parses the whole system CA bundle, and separate contexts share no
/// session cache, so a per-connect connector paid that parse on every dial
/// and could never resume a TLS session. The rustls backend gets the same
/// sharing from `TLS_CLIENT_CONFIG`. A build failure is not cached: it is
/// the local TLS stack refusing to initialise, reported per connect.
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
fn native_tls_connector() -> Result<tokio_native_tls::TlsConnector, ConnectError> {
    static CONNECTOR: OnceLock<tokio_native_tls::TlsConnector> = OnceLock::new();

    if let Some(connector) = CONNECTOR.get() {
        return Ok(connector.clone());
    }
    let native_connector = tokio_native_tls::native_tls::TlsConnector::new().map_err(|err| {
        // Building the connector touches no network: a failure here is the
        // local TLS stack refusing to initialise and repeats identically.
        ConnectError::permanent(std::io::Error::other(err))
    })?;
    let connector = tokio_native_tls::TlsConnector::from(native_connector);
    // Two first connects racing here both built one; whichever landed is
    // the one every connection shares from now on.
    Ok(CONNECTOR.get_or_init(|| connector).clone())
}

/// Perform TLS handshake over an established TCP connection with timeout.
///
/// Times out after the configured HTTP timeout.
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
async fn tls_connect(tcp: TcpStream, host: &str) -> Result<TlsStream, ConnectError> {
    let connector = native_tls_connector()?;

    debug!("splice proxy: starting TLS handshake with {host}");
    let http_timeout = global_config().http_timeout;
    let tls_stream = tokio::time::timeout(http_timeout, connector.connect(host, tcp))
        .await
        .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| handshake_timed_out(http_timeout))?
        // `native_tls::Error` is opaque: it carries no `io::ErrorKind`, so a
        // certificate rejection is indistinguishable from a transport error.
        // Classify conservatively (transient, keep retrying) rather than
        // guess from the message.
        .map_err(|err| ConnectError::transient(std::io::Error::other(err)))?;
    debug!("splice proxy: TLS handshake completed with {host}");
    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::config::ClientHost;
    use crate::deb_mirror::MirrorKind;

    use super::*;

    #[test]
    fn conn_label_renders_the_log_suffixes() {
        let label = |tls, reused| ConnLabel { tls, reused }.to_string();
        assert_eq!(label(false, false), "");
        assert_eq!(label(false, true), " (reused)");
        assert_eq!(label(true, false), " (TLS)");
        assert_eq!(label(true, true), " (TLS, reused)");
    }

    #[test]
    #[cfg(feature = "tls_rustls")]
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
    #[cfg(feature = "tls_rustls")]
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

    /// A loopback socket pair: the client side, the server side, and the
    /// client side's local address (to tell pooled connections apart).
    async fn tcp_pair(listener: &tokio::net::TcpListener) -> (TcpStream, TcpStream, SocketAddr) {
        let addr = listener.local_addr().unwrap();
        let (client, (server, _)) = tokio::try_join!(TcpStream::connect(addr), listener.accept())
            .expect("loopback connect");
        let local = client.local_addr().unwrap();
        (client, server, local)
    }

    fn test_host(name: &str) -> ClientHost {
        ClientHost::new(name.to_owned()).unwrap()
    }

    /// The most recently returned connection is popped first; if the peer
    /// has closed it, checkout must go on to the older live one rather than
    /// report a miss and leave that live socket idling.
    #[tokio::test]
    async fn pool_checkout_skips_a_dead_entry_for_a_live_one() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (live, _live_peer, live_addr) = tcp_pair(&listener).await;
        let (dead, dead_peer, _) = tcp_pair(&listener).await;
        drop(dead_peer);
        let host = test_host("pool-checkout-skips-dead.invalid");

        pool_return(&host, 80, false, UpstreamConn::Tcp(live));
        pool_return(&host, 80, false, UpstreamConn::Tcp(dead));

        let PoolCheckout::Live(conn) = pool_checkout(&host, 80, false) else {
            unreachable!("a live connection was in the pool");
        };
        assert_eq!(
            conn.zero_copy().unwrap().local_addr().unwrap(),
            live_addr,
            "checkout must hand out the live connection"
        );
        assert!(
            matches!(pool_checkout(&host, 80, false), PoolCheckout::Empty),
            "the dead entry was discarded, not left in the pool"
        );
    }

    /// A pool holding only closed connections is a `Dead` miss (the entries
    /// were there but unusable), distinct from an `Empty` one.
    #[tokio::test]
    async fn pool_checkout_reports_dead_when_every_entry_is_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (dead, dead_peer, _) = tcp_pair(&listener).await;
        drop(dead_peer);
        let host = test_host("pool-checkout-all-dead.invalid");

        pool_return(&host, 80, false, UpstreamConn::Tcp(dead));

        assert!(matches!(
            pool_checkout(&host, 80, false),
            PoolCheckout::Dead
        ));
        assert!(matches!(
            pool_checkout(&host, 80, false),
            PoolCheckout::Empty
        ));
    }

    /// Returning to a key expires its old sockets without waiting for the
    /// periodic sweep.
    #[tokio::test]
    async fn pool_return_reaps_idle_entries_of_same_host() {
        use tokio::io::AsyncReadExt as _;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

        let (stale, mut stale_peer, _) = tcp_pair(&listener).await;
        let (fresh, _fresh_peer, _) = tcp_pair(&listener).await;
        let stale_host = test_host("pool-reap-stale.invalid");
        let fresh_host = stale_host.clone();

        upstream_pool().lock().insert(
            (stale_host.clone(), 80, false),
            vec![PooledConn {
                conn: UpstreamConn::Tcp(stale),
                idle_since: coarsetime::Instant::now()
                    - (POOL_IDLE_TIMEOUT + coarsetime::Duration::from_secs(1)),
            }],
        );

        pool_return(&fresh_host, 80, false, UpstreamConn::Tcp(fresh));

        let count = upstream_pool()
            .lock()
            .get(&(fresh_host, 80, false))
            .unwrap()
            .len();
        assert_eq!(count, 1);
        let mut byte = [0u8; 1];
        assert_eq!(stale_peer.read(&mut byte).await.unwrap(), 0);
    }

    /// The periodic reaper sweeps every key, so a host that sees no more
    /// traffic (and so no `pool_return`) still loses its idled-out sockets.
    #[tokio::test]
    async fn reap_idle_pool_drops_expired_entries_without_a_return() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (stale, _stale_peer, _) = tcp_pair(&listener).await;
        let (fresh, _fresh_peer, _) = tcp_pair(&listener).await;
        let stale_host = test_host("pool-reap-idle-stale.invalid");
        let fresh_host = test_host("pool-reap-idle-fresh.invalid");

        let now = coarsetime::Instant::now();
        let mut map = upstream_pool().lock();
        map.insert(
            (stale_host.clone(), 80, false),
            vec![PooledConn {
                conn: UpstreamConn::Tcp(stale),
                idle_since: now - (POOL_IDLE_TIMEOUT + coarsetime::Duration::from_secs(1)),
            }],
        );
        map.insert(
            (fresh_host.clone(), 80, false),
            vec![PooledConn {
                conn: UpstreamConn::Tcp(fresh),
                idle_since: now,
            }],
        );
        drop(map);

        reap_idle_pool();

        let map = upstream_pool().lock();
        let stale_present = map.contains_key(&(stale_host, 80, false));
        let fresh_present = map.contains_key(&(fresh_host, 80, false));
        drop(map);
        assert!(!stale_present, "the expired entry must be gone");
        assert!(fresh_present);
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
