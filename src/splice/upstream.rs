//! Upstream connection plumbing for the splice proxy: the [`UpstreamConn`]
//! enum (plain TCP, userspace TLS), the per-host idle pool behind
//! [`ResponseBody`], the TCP/TLS connect helpers and the
//! [`ConnectError`]/[`Transience`] classification consumed by the retry
//! loop in `acquire`.

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
use crate::error::{ErrorReport, is_peer_disconnect, is_tls_certificate_rejection};
use crate::humanfmt::HumanFmt;
use crate::limits::UPSTREAM_POOL_MAX_IDLE_PER_HOST;
use crate::{
    Scheme, global_config, metrics, scheme_cache, upstream_dial, warn_once_or_debug,
    warn_once_or_info,
};

/// Pre-computed TLS client config for use with `tls_rustls`.
/// Should only be initialized once from main.
#[cfg(feature = "tls_rustls")]
pub(crate) static TLS_CLIENT_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

const POOL_IDLE_TIMEOUT: coarsetime::Duration = coarsetime::Duration::from_secs(90);

/// Buffer size for TLS upstream reads by the `super::http` head scanners and
/// buffered-body collectors. The userspace-TLS body loop reads into its cache
/// batch instead.
pub(super) const TLS_READ_BUF_SIZE: usize = 256 * 1024;

#[cfg_attr(
    feature = "tls_rustls",
    expect(
        clippy::large_enum_variant,
        reason = "tokio_rustls::client::TlsStream is the biggest variant, but also the one most likely to be used"
    )
)]
pub(super) enum UpstreamConn {
    Tcp(TcpStream),
    Tls(TlsStream),
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

/// Userspace-TLS upstream stream of the selected TLS backend.
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
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
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
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_flush(cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl UpstreamConn {
    #[must_use]
    pub(super) const fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

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

struct PooledConn {
    conn: UpstreamConn,
    idle_since: coarsetime::Instant,
}

/// Pool key includes TLS flag so HTTP and HTTPS connections to the same
/// (host, port) — possible on mirrors reachable via both protocols on a
/// non-default port — never get mixed up. `ClientHost` is refcounted, so
/// building a key for a lookup does not allocate.
type PoolKey = (ClientHost, u16, bool);

static UPSTREAM_POOL: OnceLock<parking_lot::Mutex<hashbrown::HashMap<PoolKey, Vec<PooledConn>>>> =
    OnceLock::new();

fn upstream_pool() -> &'static parking_lot::Mutex<hashbrown::HashMap<PoolKey, Vec<PooledConn>>> {
    UPSTREAM_POOL.get_or_init(|| parking_lot::Mutex::new(hashbrown::HashMap::new()))
}

/// Validated transport destination, independent of cache paths and identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct UpstreamEndpoint<'a> {
    pub(crate) host: &'a ClientHost,
    pub(crate) port: Option<NonZero<u16>>,
}

impl<'a> UpstreamEndpoint<'a> {
    pub(crate) fn format_authority(self) -> std::borrow::Cow<'a, str> {
        self.host.format_authority(self.port)
    }
}

impl<'a> From<&'a Mirror> for UpstreamEndpoint<'a> {
    fn from(mirror: &'a Mirror) -> Self {
        Self {
            host: mirror.host(),
            port: mirror.port(),
        }
    }
}

impl<'a> From<UpstreamEndpoint<'a>> for scheme_cache::SchemeKeyRef<'a> {
    fn from(endpoint: UpstreamEndpoint<'a>) -> Self {
        Self {
            host: endpoint.host.as_str(),
            port: endpoint.port.map(NonZero::get),
        }
    }
}

pub(super) fn endpoint_port(endpoint: UpstreamEndpoint<'_>, is_tls: bool) -> u16 {
    endpoint
        .port
        .map_or(if is_tls { 443 } else { 80 }, NonZero::get)
}

/// The inverse of [`endpoint_port`]: a dialled port as an endpoint names it,
/// `None` for the default of the connection's own scheme, like a [`Mirror`]
/// named without a port. An explicit `:443` would otherwise reach the `Host`
/// header and the authority of a URI resolved against the connection.
fn named_port(port: u16, is_tls: bool) -> Option<NonZero<u16>> {
    NonZero::new(port).filter(|port| port.get() != if is_tls { 443 } else { 80 })
}

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

/// Pop one entry for the key, most recently returned first. The caller
/// checks its age and liveness, and drops it outside the pool lock.
fn pool_pop(host: &ClientHost, port: u16, is_tls: bool) -> Option<PooledConn> {
    let mut map = upstream_pool().lock();
    let key = (host.clone(), port, is_tls);
    let conns = map.get_mut(&key)?;

    let conn = conns.pop();
    if conns.is_empty() {
        map.remove(&key);
    }
    conn
}

/// Try to retrieve a live idle connection from the pool.
///
/// Walks the key's entries most-recently-returned first and probes each
/// outside the lock: a server that closes after a request cap kills the
/// busiest entry first, and giving up on it would open a fresh connection
/// while a live one sat below it.
pub(super) fn pool_checkout(host: &ClientHost, port: u16, is_tls: bool) -> PoolCheckout {
    let mut saw_dead = false;
    while let Some(PooledConn {
        mut conn,
        idle_since,
    }) = pool_pop(host, port, is_tls)
    {
        if idle_since.elapsed() >= POOL_IDLE_TIMEOUT {
            debug!("splice proxy: discarding stale pooled connection to {host}:{port}");
            continue;
        }
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

/// Checkout and return only inspect their own key; this full-map scan runs
/// from [`pool_reaper`], off the per-request path.
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

/// One tick per [`POOL_IDLE_TIMEOUT`], so an entry lives at most twice the
/// timeout on an otherwise idle proxy.
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

/// Return a connection to the pool for reuse. Idle entries expire at
/// checkout and in [`pool_reaper`]; an evicted socket drops outside the lock.
fn pool_return(host: &ClientHost, port: u16, conn: UpstreamConn) {
    let is_tls = conn.is_tls();
    let mut map = upstream_pool().lock();
    let conns = map.entry((host.clone(), port, is_tls)).or_default();
    let evicted = (conns.len() >= UPSTREAM_POOL_MAX_IDLE_PER_HOST).then(|| {
        debug!("splice proxy: evicting oldest pooled connection for {host}:{port} (pool full)");
        metrics::POOL_RETURN_EVICTED.increment();
        conns.remove(0)
    });
    conns.push(PooledConn {
        conn,
        idle_since: coarsetime::Instant::now(),
    });
    drop(map);
    drop(evicted);
    debug!("splice proxy: returned connection to pool for {host}:{port} (tls={is_tls})");
}

/// Owns an unfinished response. Dropping it closes the connection, including
/// cancellation before a task is first polled. Only `complete` may pool it.
/// The header's keep-alive permission is separate from body completion.
pub(super) struct ResponseBody {
    conn: UpstreamConn,
    host: ClientHost,
    port: u16,
    keep_alive: bool,
}

impl ResponseBody {
    pub(super) fn new(conn: UpstreamConn, host: ClientHost, port: u16, keep_alive: bool) -> Self {
        Self {
            conn,
            host,
            port,
            keep_alive,
        }
    }

    /// The endpoint this response came from: after a followed redirect the
    /// redirect target, not the request's mirror. Its port is `None` for the
    /// scheme's default ([`named_port`]).
    pub(super) fn endpoint(&self) -> UpstreamEndpoint<'_> {
        UpstreamEndpoint {
            host: &self.host,
            port: named_port(self.port, self.conn.is_tls()),
        }
    }

    #[must_use]
    pub(super) const fn permits_reuse(&self) -> bool {
        self.keep_alive
    }

    /// Consume a response after its framing terminator has been read and
    /// validated. The unfinished owner cannot be accessed or moved again.
    pub(super) fn complete(self) {
        let Self {
            conn,
            host,
            port,
            keep_alive,
        } = self;
        if keep_alive {
            pool_return(&host, port, conn);
        }
    }
}

impl std::ops::Deref for ResponseBody {
    type Target = UpstreamConn;
    fn deref(&self) -> &UpstreamConn {
        &self.conn
    }
}

impl std::ops::DerefMut for ResponseBody {
    fn deref_mut(&mut self) -> &mut UpstreamConn {
        &mut self.conn
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
    fn check_alive(&mut self, host: &ClientHost, port: u16) -> bool {
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

pub(super) struct ConnectError {
    pub(super) transience: Transience,
    pub(super) err: std::io::Error,
    /// The TLS handshake failed because the upstream's certificate was
    /// rejected (`error::is_tls_certificate_rejection`): permanent, and the
    /// one TLS failure Auto mode must not answer with its HTTP fallback.
    pub(super) certificate_rejected: bool,
}

impl ConnectError {
    fn new(transience: Transience, err: std::io::Error) -> Self {
        Self {
            transience,
            err,
            certificate_rejected: false,
        }
    }

    fn certificate_rejection(err: std::io::Error) -> Self {
        Self {
            transience: Transience::Permanent,
            err,
            certificate_rejected: true,
        }
    }

    /// DNS/TCP failure, timeout, or a network error mid-handshake -- retry may help.
    fn transient(err: std::io::Error) -> Self {
        Self::new(Transience::Transient, err)
    }

    /// Deterministic for this (host, scheme), e.g. an unparsable server name.
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
/// reports its own kind and keeps the cause behind `source()`. The native-tls
/// backend has no kinds to classify (its error is opaque) and treats every
/// failure as transient.
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
/// a permanent TLS failure inside the Auto branch still falls back to HTTP,
/// a rejected certificate included -- unless HTTPS to the host verified
/// before (`scheme_cache::https_verified_before`): then the rejection is what
/// an interceptor presents, so it escapes as the terminal failure instead of
/// downgrading the download.
///
/// Times out after the configured HTTP timeout.
pub(super) async fn connect_upstream(
    endpoint: UpstreamEndpoint<'_>,
    scheme: Option<Scheme>,
) -> Result<UpstreamConn, ConnectError> {
    let host = endpoint.host;

    match scheme {
        Some(Scheme::Http) => {
            let tcp = tcp_connect(host, endpoint_port(endpoint, false))
                .await
                .map_err(ConnectError::transient)?;
            Ok(UpstreamConn::Tcp(tcp))
        }
        Some(Scheme::Https) => {
            let tcp = tcp_connect(host, endpoint_port(endpoint, true))
                .await
                .map_err(ConnectError::transient)?;
            let tls = tls_connect(tcp, host).await?;
            Ok(UpstreamConn::Tls(tls))
        }
        None => {
            // The fallback is remembered for `HTTP_SCHEME_TTL` only, after
            // which the next request probes HTTPS again.
            match tcp_connect(host, endpoint_port(endpoint, true)).await {
                Ok(tcp) => match tls_connect(tcp, host).await {
                    Ok(tls) => {
                        debug!(
                            "splice proxy: HTTPS upgrade succeeded for {}",
                            endpoint.format_authority()
                        );
                        return Ok(UpstreamConn::Tls(tls));
                    }
                    Err(err)
                        if err.certificate_rejected
                            && scheme_cache::https_verified_before(endpoint.into()) =>
                    {
                        debug!(
                            "splice proxy: TLS certificate of {} rejected although HTTPS to it verified before; not falling back to HTTP",
                            endpoint.format_authority()
                        );
                        return Err(err);
                    }
                    Err(err) => {
                        // Deliberately not propagated: the HTTP fallback below is
                        // the point of Auto mode, so even a permanent TLS failure
                        // (no TLS on the port, an unparsable server name, a
                        // certificate for another host) must not abort it.
                        if err.certificate_rejected {
                            warn_once_or_info!(
                                "splice proxy: HTTPS certificate of host {} failed verification; falling back to plain HTTP (list the host in `http_only_mirrors` to silence this, or fix the mirror's certificate):  {}",
                                endpoint.format_authority(),
                                ErrorReport(&err.err)
                            );
                        } else {
                            debug!(
                                "splice proxy: TLS handshake failed for {}, trying HTTP:  {}",
                                endpoint.format_authority(),
                                ErrorReport(&err.err)
                            );
                        }
                    }
                },
                Err(err) => {
                    debug!(
                        "splice proxy: HTTPS connect to {} failed, trying HTTP:  {}",
                        endpoint.format_authority(),
                        ErrorReport(&err)
                    );
                }
            }

            // The fallback dial is another connect attempt, counted like
            // hyper's Auto-mode revert iteration.
            metrics::UPSTREAM_RETRIES.increment();
            let tcp = tcp_connect(host, endpoint_port(endpoint, false))
                .await
                .map_err(ConnectError::transient)?;
            Ok(UpstreamConn::Tcp(tcp))
        }
    }
}

/// Races the host's IPv6 and IPv4 addresses (`upstream_dial`).
///
/// Times out after the configured HTTP timeout; a timeout counts in
/// `HTTP_TIMEOUT_UPSTREAM_CONNECT` per attempt, a request whose connect fails
/// for good once more in `UPSTREAM_CONNECT_FAILED` when its failure concludes.
async fn tcp_connect(host: &ClientHost, port: u16) -> std::io::Result<TcpStream> {
    upstream_dial::connect(host.as_str(), port, global_config().http_timeout)
        .await
        .map_err(|err| {
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
        })
}

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

#[cfg(feature = "tls_rustls")]
async fn tls_connect(tcp: TcpStream, host: &ClientHost) -> Result<TlsStream, ConnectError> {
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(
        TLS_CLIENT_CONFIG.get().expect("initialized in main()"),
    ));

    let server_name =
        rustls::pki_types::ServerName::try_from(host.as_str().to_owned()).map_err(|err| {
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
            // Classify before wrapping: the wrapper renders the cause into
            // its message, and only the original error tells a certificate
            // rejection or another deterministic failure (`InvalidData`)
            // from a transport error.
            let certificate_rejected = is_tls_certificate_rejection(&err);
            let wrapped = std::io::Error::new(
                err.kind(),
                format!("failed to complete TLS handshake:  {err}"),
            );
            if certificate_rejected {
                ConnectError::certificate_rejection(wrapped)
            } else {
                ConnectError::new(classify_tls_error(err.kind()), wrapped)
            }
        })?;
    debug!("splice proxy: TLS handshake completed with {host}");
    Ok(tls_stream)
}

/// The process-wide native-tls connector, built on first use.
///
/// One `SSL_CTX` for every upstream connection: building a connector loads
/// and parses the whole system CA bundle, and separate contexts share no
/// session cache. A build failure is not cached, but reported per connect.
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

#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
async fn tls_connect(tcp: TcpStream, host: &ClientHost) -> Result<TlsStream, ConnectError> {
    let connector = native_tls_connector()?;

    debug!("splice proxy: starting TLS handshake with {host}");
    let http_timeout = global_config().http_timeout;
    let tls_stream = tokio::time::timeout(http_timeout, connector.connect(host.as_str(), tcp))
        .await
        .map_err(|_timeout @ tokio::time::error::Elapsed { .. }| handshake_timed_out(http_timeout))?
        // `native_tls::Error` carries no `io::ErrorKind`; only a certificate
        // rejection is recognisable (through OpenSSL's error queue). Every
        // other failure is classified conservatively (transient, keep
        // retrying) rather than guessed from the message.
        .map_err(|err| {
            if is_tls_certificate_rejection(&err) {
                ConnectError::certificate_rejection(std::io::Error::other(err))
            } else {
                ConnectError::transient(std::io::Error::other(err))
            }
        })?;
    debug!("splice proxy: TLS handshake completed with {host}");
    Ok(tls_stream)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::config::ClientHost;
    use crate::deb_mirror::MirrorKind;
    use crate::test_support::connected_tcp_pair;

    use super::*;

    #[test]
    fn named_port_drops_only_the_connections_own_default() {
        let host = ClientHost::new("mirror.example").unwrap();
        for (port, is_tls, named) in [
            (80, false, None),
            (443, true, None),
            (443, false, Some(443)),
            (80, true, Some(80)),
            (8080, false, Some(8080)),
            (8443, true, Some(8443)),
        ] {
            let named = named.and_then(NonZero::new);
            assert_eq!(named_port(port, is_tls), named, "{port} tls={is_tls}");
            let endpoint = UpstreamEndpoint {
                host: &host,
                port: named,
            };
            assert_eq!(endpoint_port(endpoint, is_tls), port, "round trip");
        }
    }

    #[test]
    #[cfg(feature = "tls_rustls")]
    fn classify_tls_error_retries_only_transport_kinds() {
        // rustls surfaces a rejected certificate chain as InvalidData and an
        // unparsable server name as InvalidInput; both repeat identically.
        for (kind, expected) in [
            (ErrorKind::InvalidData, Transience::Permanent),
            (ErrorKind::InvalidInput, Transience::Permanent),
            (ErrorKind::TimedOut, Transience::Transient),
            (ErrorKind::ConnectionRefused, Transience::Transient),
            (ErrorKind::UnexpectedEof, Transience::Transient),
        ] {
            assert_eq!(classify_tls_error(kind), expected, "{kind:?}");
        }
    }

    /// Both endpoints identify a connection even when separate listeners
    /// allow its connecting-side port to be reused.
    fn connection_identity(conn: &TcpStream) -> (SocketAddr, SocketAddr) {
        (conn.local_addr().unwrap(), conn.peer_addr().unwrap())
    }

    fn test_host(name: &str) -> ClientHost {
        ClientHost::new(name).unwrap()
    }

    /// The proxy's end of the connection is closed: its peer reads EOF.
    async fn assert_closed(peer: &mut TcpStream) {
        use tokio::io::AsyncReadExt as _;
        let read = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0])).await;
        assert_eq!(read.unwrap().unwrap(), 0);
    }

    /// Dropping an unpolled future models cancellation of a detached download
    /// before it has a chance to install any task-local protection.
    #[tokio::test]
    async fn unfinished_response_is_closed_even_before_first_poll() {
        let (conn, mut peer) = connected_tcp_pair().await;
        let host = test_host("unfinished-response.invalid");
        let response = ResponseBody::new(UpstreamConn::Tcp(conn), host.clone(), 80, true);
        let unpolled = async move {
            std::future::pending::<()>().await;
            response.complete();
        };
        drop(unpolled);
        assert!(matches!(
            pool_checkout(&host, 80, false),
            PoolCheckout::Empty
        ));
        assert_closed(&mut peer).await;
    }

    #[tokio::test]
    async fn completed_response_reuses_only_keep_alive_connections() {
        let host = test_host("completed-response.invalid");
        let (conn, _peer) = connected_tcp_pair().await;
        let identity = connection_identity(&conn);
        ResponseBody::new(UpstreamConn::Tcp(conn), host.clone(), 80, true).complete();
        let conn = if let PoolCheckout::Live(conn) = pool_checkout(&host, 80, false) {
            Some(conn)
        } else {
            None
        };
        let conn = conn.expect("completed response should be reusable");
        assert_eq!(connection_identity(conn.zero_copy().unwrap()), identity);
        drop(conn);

        let (conn, mut peer) = connected_tcp_pair().await;
        ResponseBody::new(UpstreamConn::Tcp(conn), host.clone(), 80, false).complete();
        assert!(matches!(
            pool_checkout(&host, 80, false),
            PoolCheckout::Empty
        ));
        assert_closed(&mut peer).await;
    }

    /// The most recently returned connection is popped first; if the peer
    /// has closed it, checkout must go on to the older live one rather than
    /// report a miss and leave that live socket idling.
    #[tokio::test]
    async fn pool_checkout_skips_a_dead_entry_for_a_live_one() {
        let (live, _live_peer) = connected_tcp_pair().await;
        let live_identity = connection_identity(&live);
        let (dead, dead_peer) = connected_tcp_pair().await;
        drop(dead_peer);
        let host = test_host("pool-checkout-skips-dead.invalid");

        pool_return(&host, 80, UpstreamConn::Tcp(live));
        pool_return(&host, 80, UpstreamConn::Tcp(dead));

        let conn = if let PoolCheckout::Live(conn) = pool_checkout(&host, 80, false) {
            Some(conn)
        } else {
            None
        };
        let conn = conn.expect("a live connection was in the pool");
        assert_eq!(
            connection_identity(conn.zero_copy().unwrap()),
            live_identity,
            "checkout must hand out the live connection"
        );
        assert!(
            matches!(pool_checkout(&host, 80, false), PoolCheckout::Empty),
            "the dead entry was discarded, not left in the pool"
        );
    }

    #[tokio::test]
    async fn pool_checkout_reports_dead_when_every_entry_is_closed() {
        let (dead, dead_peer) = connected_tcp_pair().await;
        drop(dead_peer);
        let host = test_host("pool-checkout-all-dead.invalid");

        pool_return(&host, 80, UpstreamConn::Tcp(dead));

        assert!(matches!(
            pool_checkout(&host, 80, false),
            PoolCheckout::Dead
        ));
        assert!(matches!(
            pool_checkout(&host, 80, false),
            PoolCheckout::Empty
        ));
    }

    #[tokio::test]
    async fn pool_checkout_discards_expired_entries_without_counting_them_dead() {
        let host = test_host("pool-checkout-expired.invalid");
        for with_live in [false, true] {
            let (live, _live_peer) = connected_tcp_pair().await;
            let live_identity = connection_identity(&live);
            let (expired, mut expired_peer) = connected_tcp_pair().await;
            let now = coarsetime::Instant::now();
            let mut entries = Vec::new();
            if with_live {
                entries.push(PooledConn {
                    conn: UpstreamConn::Tcp(live),
                    idle_since: now,
                });
            }
            entries.push(PooledConn {
                conn: UpstreamConn::Tcp(expired),
                idle_since: now - (POOL_IDLE_TIMEOUT + coarsetime::Duration::from_secs(1)),
            });
            upstream_pool()
                .lock()
                .insert((host.clone(), 80, false), entries);

            match pool_checkout(&host, 80, false) {
                PoolCheckout::Live(conn) => {
                    assert!(with_live, "expired entries cannot be reused");
                    assert_eq!(
                        connection_identity(conn.zero_copy().unwrap()),
                        live_identity
                    );
                }
                PoolCheckout::Empty => assert!(!with_live, "the live entry must be found"),
                PoolCheckout::Dead => unreachable!("expiry is an empty miss, not a dead peer"),
            }
            assert_closed(&mut expired_peer).await;
        }
    }

    /// The periodic reaper sweeps every key, so a host that sees no more
    /// traffic (and so no `pool_return`) still loses its idled-out sockets.
    #[tokio::test]
    async fn reap_idle_pool_drops_expired_entries_without_a_return() {
        let (stale, _stale_peer) = connected_tcp_pair().await;
        let (fresh, _fresh_peer) = connected_tcp_pair().await;
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
    fn canonical_redirect_ports_follow_upgrade_policy() {
        use crate::config::{Config, HttpsUpgradeMode};
        use crate::uri_authority;
        for mode in [
            HttpsUpgradeMode::Never,
            HttpsUpgradeMode::Auto,
            HttpsUpgradeMode::Always,
        ] {
            let mut config = Config::default();
            config.https_upgrade_mode = mode;
            for (uri_text, expected_http, expected_tls) in [
                ("http://redirect-port-policy.invalid/package", 80, 443),
                ("http://redirect-port-policy.invalid:80/package", 80, 443),
                (
                    "http://redirect-port-policy.invalid:8080/package",
                    8080,
                    8080,
                ),
                ("https://redirect-port-policy.invalid:80/package", 80, 80),
                ("https://redirect-port-policy.invalid:443/package", 443, 443),
            ] {
                let uri: http::Uri = uri_text.parse().expect("URI");
                let port = uri_authority::port(uri.authority().expect("authority")).expect("port");
                let mirror = Mirror::new(
                    ClientHost::new("redirect-port-policy.invalid").expect("host"),
                    uri_authority::normalize_http_port(port, uri.scheme()),
                    "".into(),
                    MirrorKind::Structured,
                );
                let scheme = if uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
                    Scheme::Https
                } else {
                    scheme_cache::resolve((&mirror).into(), &config)
                        .fixed_scheme()
                        .unwrap_or(Scheme::Https)
                };
                let is_tls = scheme == Scheme::Https;
                assert_eq!(
                    endpoint_port((&mirror).into(), is_tls),
                    if is_tls { expected_tls } else { expected_http },
                    "{uri_text} with {mode:?}"
                );
            }
        }
    }

    #[test]
    fn alias_endpoint_preserves_canonical_cache_identity() {
        let mut details = crate::test_support::connection_details("package.deb");
        details.upstream_host = ClientHost::new("[2001:db8::1]").unwrap();
        let endpoint = details.upstream_endpoint();
        assert_eq!(endpoint.host.as_str(), "2001:db8::1");
        assert_eq!(endpoint.format_authority(), "[2001:db8::1]");
        assert_eq!(endpoint_port(endpoint, true), 443);
        let key: scheme_cache::SchemeKeyRef<'_> = endpoint.into();
        assert_eq!(key.host, "2001:db8::1");
        assert_eq!(key.port, None);
        assert_eq!(details.key().mirror.host().as_str(), "fixture.test");
    }
}
