//! Shared CONNECT-tunnel target validation and relay used by every HTTP
//! backend.
//!
//! Both the hyper and sendfile/splice backends call
//! [`validate_connect_target`] so their tunnel policy (enable flag, authority
//! bound, port ACL, mirror ACL) — and the metrics/log side effects — stay
//! identical. The per-request proxy-client ACL is *not* handled here; both
//! backends enforce `allowed_proxy_clients` for `CONNECT` in
//! `request_dispatch::preflight_method` before reaching this validator.
//!
//! The mirror ACL is fail-closed like `allowed_mirrors`: an empty
//! `https_tunnel_allowed_mirrors` permits no target.  A CONNECT relay is an
//! open TCP forwarder to any host on the permitted ports, so "no list" must
//! not mean "every host".  The *port* ACL is the deliberate opposite: an
//! empty `https_tunnel_allowed_ports` skips the port check entirely, because
//! the host list has already bounded the reachable targets by then.
//!
//! Established tunnels relay through [`copy_bidirectional_idle`], which
//! tears the tunnel down after `client_idle_timeout` without a byte in either
//! direction — otherwise a parked CONNECT socket pins two fds and an upstream
//! connection for as long as the peer likes.

use core::num::NonZero;
use std::{
    io::ErrorKind,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use http::{StatusCode, uri::Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{error, info};

use crate::{
    client_info::ClientInfo,
    config::Config,
    error::{ErrorReport, is_peer_disconnect},
    humanfmt::HumanFmt,
    limits, metrics, warn_once_or_info,
};

/// A rejected CONNECT target: the status/body the backend should return to the
/// client. All logging and metric bumping already happened inside
/// [`validate_connect_target`].
pub(crate) struct ConnectReject {
    pub status: StatusCode,
    pub msg: &'static str,
}

/// Validate a CONNECT request's authority against tunnel policy.
///
/// On success returns the parsed `(host, port)`. On rejection returns a
/// [`ConnectReject`] and has already emitted the matching log line and bumped
/// the relevant metric, so both backends behave identically.
pub(crate) fn validate_connect_target(
    config: &Config,
    client: &ClientInfo,
    uri: &Uri,
) -> Result<(String, NonZero<u16>), ConnectReject> {
    if !config.https_tunnel_enabled {
        info!(
            "Rejecting https tunnel request for client {client} to {uri}: https tunneling is disabled (`https_tunnel_enabled`)"
        );
        metrics::TUNNEL_REJECTED_POLICY.increment();
        return Err(ConnectReject {
            status: StatusCode::FORBIDDEN,
            msg: "HTTPS tunneling disabled",
        });
    }

    // Bound the authority length before any further work. hyper already
    // bounds the request line, but defending here keeps the CONNECT path
    // self-contained against any future relaxation of those limits.
    if let Some(auth) = uri.authority()
        && auth.as_str().len() > limits::MAX_AUTHORITY_LEN
    {
        warn_once_or_info!(
            "Oversized CONNECT authority from client {client} ({} bytes); rejecting the tunnel request with 400",
            auth.as_str().len()
        );
        return Err(ConnectReject {
            status: StatusCode::BAD_REQUEST,
            msg: "Invalid CONNECT address",
        });
    }

    let Some((host, port)) = uri.authority().and_then(|a| {
        a.port_u16()
            .and_then(NonZero::new)
            .map(|p| (a.host().to_string(), p))
    }) else {
        warn_once_or_info!(
            "Invalid CONNECT address `{uri}` from client {client}; rejecting the tunnel request with 400"
        );
        return Err(ConnectReject {
            status: StatusCode::BAD_REQUEST,
            msg: "Invalid CONNECT address",
        });
    };

    // Fail-open, unlike the mirror ACL below: an empty list narrows nothing.
    // `Config::validate` warns when tunneling is on and the list is empty.
    if !config.https_tunnel_allowed_ports.is_empty()
        && config
            .https_tunnel_allowed_ports
            .binary_search(&port)
            .is_err()
    {
        info!("Rejecting https tunnel request for client {client} to disallowed port {port}");
        metrics::TUNNEL_REJECTED_POLICY.increment();
        return Err(ConnectReject {
            status: StatusCode::FORBIDDEN,
            msg: "HTTPS tunnel port not permitted",
        });
    }

    // Fail-closed: an empty list permits nothing (see the module doc).
    if config
        .https_tunnel_allowed_mirrors
        .binary_search_by(|d| str::cmp(d, host.as_str()))
        .is_err()
    {
        info!("Rejecting https tunnel request for client {client} due to disallowed host {host}");
        metrics::AUTHZ_REJECTED_TUNNEL_MIRROR.increment();
        return Err(ConnectReject {
            status: StatusCode::FORBIDDEN,
            msg: "HTTPS tunnel target not permitted",
        });
    }

    Ok((host, port))
}

/// Why [`copy_bidirectional_idle`] stopped relaying.
#[derive(Debug)]
pub(crate) enum TunnelCopyError {
    /// No byte crossed the tunnel in either direction for the idle timeout.
    Idle(Duration),
    /// A read or write on either side failed.
    Io(std::io::Error),
}

/// Relay `client` and `upstream` into each other until one side closes or
/// the tunnel sits idle for `idle_timeout`.  Returns the bytes copied
/// client->upstream and upstream->client on a clean close.
///
/// The idle watchdog cancels `copy_bidirectional` only after a full
/// `idle_timeout` without progress, so no in-flight buffered bytes are lost:
/// by construction the copy loop has been parked on both `poll_read`s for
/// that long.
pub(crate) async fn copy_bidirectional_idle<C, U>(
    client: C,
    upstream: &mut U,
    buf_size: usize,
    idle_timeout: Duration,
) -> Result<(u64, u64), TunnelCopyError>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(ActivityClock::new());
    let mut client = IdleTracked {
        inner: client,
        activity: Arc::clone(&activity),
    };

    let watchdog = async {
        loop {
            let left = idle_timeout.saturating_sub(activity.since_last());
            if left.is_zero() {
                return TunnelCopyError::Idle(idle_timeout);
            }
            tokio::time::sleep(left).await;
        }
    };

    tokio::select! {
        copied = tokio::io::copy_bidirectional_with_sizes(&mut client, upstream, buf_size, buf_size) => {
            copied.map_err(TunnelCopyError::Io)
        }
        idle = watchdog => Err(idle),
    }
}

/// Log the outcome of a finished tunnel relay and bump its metrics.  Shared
/// by both backends so an idle close, a peer close and a transfer failure
/// carry the same wording and counters everywhere.
pub(crate) fn report_tunnel_outcome(
    outcome: &Result<(u64, u64), TunnelCopyError>,
    client: &ClientInfo,
    host: &str,
    port: NonZero<u16>,
    elapsed: Duration,
) {
    match outcome {
        Ok((from_client, from_server)) => {
            metrics::BYTES_TUNNELED_CLIENT_TO_UPSTREAM.increment_by(*from_client);
            metrics::BYTES_TUNNELED_UPSTREAM_TO_CLIENT.increment_by(*from_server);
            info!(
                "Tunneled client {client} wrote {} and received {} from {host}:{port} in {}",
                HumanFmt::Size(*from_client),
                HumanFmt::Size(*from_server),
                HumanFmt::Time(elapsed)
            );
        }
        Err(TunnelCopyError::Idle(idle)) => {
            metrics::TUNNEL_IDLE_CLOSED.increment();
            info!(
                "Closing idle tunnel for client {client} to {host}:{port} after {} without traffic (client_idle_timeout)",
                HumanFmt::Time(*idle)
            );
        }
        Err(TunnelCopyError::Io(err)) => {
            metrics::TUNNEL_TRANSFER_FAILED.increment();
            // OS-level `ETIMEDOUT` (TCP keepalive / `TCP_USER_TIMEOUT`) is a
            // network condition, not a code error; log at info.
            if err.kind() == ErrorKind::TimedOut {
                info!(
                    "Tunnel for client {client} to {host}:{port} timed out:  {}",
                    ErrorReport(err)
                );
            } else if is_peer_disconnect(err) {
                info!(
                    "Tunnel for client {client} to {host}:{port} closed by peer:  {}",
                    ErrorReport(err)
                );
            } else {
                error!(
                    "Failed to tunnel the connection for client {client} to {host}:{port}; closing the tunnel:  {}",
                    ErrorReport(err)
                );
            }
        }
    }
}

/// Coarse "last progress" stamp shared between the relay's client stream and
/// the idle watchdog.  Millisecond ticks of `coarsetime::Instant` since the
/// clock was created; an atomic so the hot `poll_read`/`poll_write` path
/// takes no lock.
struct ActivityClock {
    base: coarsetime::Instant,
    last_millis: AtomicU64,
}

impl ActivityClock {
    fn new() -> Self {
        Self {
            base: coarsetime::Instant::now(),
            last_millis: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let millis = self.base.elapsed().as_millis();
        self.last_millis.store(millis, Ordering::Relaxed);
    }

    fn since_last(&self) -> Duration {
        let now = self.base.elapsed().as_millis();
        let last = self.last_millis.load(Ordering::Relaxed);
        Duration::from_millis(now.saturating_sub(last))
    }
}

/// Stream wrapper stamping [`ActivityClock`] on every successful read or
/// write.  Wrapping the client side alone sees both directions: bytes from
/// the upstream are written *to* the client, bytes from the client are read
/// *from* it.
struct IdleTracked<S> {
    inner: S,
    activity: Arc<ActivityClock>,
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTracked<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(polled, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTracked<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(polled, Poll::Ready(Ok(n)) if n > 0) {
            self.activity.touch();
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
