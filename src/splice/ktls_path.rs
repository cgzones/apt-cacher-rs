//! The kTLS upstream path (`ktls` feature only; gated on the `mod` line):
//! [`try_unbuffered_ktls_connect`] drives the rustls unbuffered API through
//! the handshake, hands the traffic secrets to the kernel and issues the
//! request through [`KtlsHandshake`]/[`unbuffered_ktls_request`], yielding a
//! [`KtlsResult`] whose `Ready` state carries the parsed head plus the bytes
//! already decrypted in userspace. Also owns `KTLS_CLIENT_CONFIG` (the
//! secret-extracting rustls config `main.rs` initialises) and the per-host
//! kTLS block-list with its GC. kTLS has no retry loop of its own: it
//! fast-fails and `acquire::standard_upstream_connect` owns retry/backoff.
//!
//! Consumer: `acquire::acquire_upstream`.

use std::{
    io::ErrorKind,
    os::fd::AsFd as _,
    sync::{Arc, OnceLock},
    time::Duration,
};

use bytes::BytesMut;
use tokio::{io::AsyncReadExt as _, net::TcpStream};
use tracing::{debug, info, warn};

use crate::deb_mirror::Mirror;
use crate::error::{ErrorReport, Transience};
use crate::http_helpers::{ConnectionAction, WritePhase, write_all_to_stream};
use crate::humanfmt::HumanFmt;
use crate::ktls;
use crate::ktls::UlpAttachError;
use crate::ktls_handshake::{discard_incoming, encode_tls_data, grow_incoming};
use crate::limits::MAX_UPSTREAM_HEADER_SIZE;
use crate::precise_instant::PreciseInstant;
use crate::scheme_cache::SchemeDecision;
use crate::secure_vec::SecureVec;
use crate::{KTLS_BLOCKED, SchemeKey, SchemeKeyRef};
use crate::{
    global_config, metrics, scheme_cache, warn_once, warn_once_or_debug, warn_once_or_info,
};

use super::VolatileCondHeaders;
use super::http::{UpstreamResponse, format_http_request, parse_upstream_response};
use super::upstream::{mirror_port, tcp_connect};

/// Dedicated TLS client config for the kTLS handshake path, cloned from
/// `TLS_CLIENT_CONFIG` with `enable_secret_extraction` set. Secret extraction
/// hands raw traffic secrets to the kernel and is confined to this config —
/// the plain userspace-TLS fallback (`tls_connect`, via `TLS_CLIENT_CONFIG`)
/// never needs extractable secrets. Cloning shares the `resumption` session
/// store (an `Arc<ClientSessionMemoryCache>` internally) with
/// `TLS_CLIENT_CONFIG`, so session tickets learned on one path still benefit
/// the other.
/// Should only be initialized once from main.
pub(crate) static KTLS_CLIENT_CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();

/// How long to remember kTLS setup failures before retrying.
const KTLS_BLOCK_DURATION: coarsetime::Duration = coarsetime::Duration::from_secs(600);

/// Monotonic time (coarsetime ticks) of the last opportunistic GC of `KTLS_BLOCKED`
/// from the read path. Used to rate-limit GC sweeps to at most once per
/// `KTLS_BLOCK_DURATION` on cache misses.
static KTLS_BLOCKED_LAST_GC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Returns `true` if an opportunistic GC of `KTLS_BLOCKED` should run now,
/// updating the last-GC timestamp atomically. At most one caller per
/// `KTLS_BLOCK_DURATION` wins the swap and returns `true`.
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
// UpstreamConn: TCP, TLS or kTLS wrapper
// ---------------------------------------------------------------------------

/// Result of a successful unbuffered kTLS connection: the TCP stream is ready
/// for kTLS RX, response headers are parsed, and any extra body bytes are saved.
pub(super) struct KtlsReadyState {
    pub(super) response: UpstreamResponse,
    /// Response head plus every body byte already decrypted in userspace
    /// (bytes past the header terminator and the plaintext drained from
    /// buffered TLS records before RX offload took over). `header_buf[header_end..]`
    /// is therefore the body prefix, exactly as on the standard path.
    pub(super) header_buf: BytesMut,
    pub(super) header_end: usize,
}

/// Errors from unbuffered kTLS request, distinguishing failure stages.
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
    /// kTLS setup failed. `Transience::Permanent`: a reason that would
    /// repeat deterministically on a retry (unsupported cipher or TLS
    /// version, `TLS_RX` setsockopt failure, pathological peer state
    /// machines, internal invariant violations); blocks kTLS for the full
    /// `KTLS_BLOCK_DURATION`. `Transience::Transient`: a plausibly transient
    /// reason (network-flavored errors -- read/write failures, EOF,
    /// truncation -- errors triggered by peer-supplied TLS data, drain
    /// races); upstream flakiness says nothing about kTLS capability, so no
    /// block. ULP attach failures are handled earlier, at the
    /// attach-after-connect site in `try_unbuffered_ktls_connect`, and never
    /// reach this variant.
    KtlsSetupFailed {
        transience: Transience,
        err: std::io::Error,
    },
}

impl KtlsError {
    /// [`KtlsError::KtlsSetupFailed`] with `Transience::Permanent`.
    fn setup_permanent(err: std::io::Error) -> Self {
        Self::KtlsSetupFailed {
            transience: Transience::Permanent,
            err,
        }
    }

    /// [`KtlsError::KtlsSetupFailed`] with `Transience::Transient`.
    fn setup_transient(err: std::io::Error) -> Self {
        Self::KtlsSetupFailed {
            transience: Transience::Transient,
            err,
        }
    }
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
pub(super) enum KtlsResult {
    /// kTLS fully set up — ready for zero-copy splice. Carries a fresh
    /// socket that becomes `UpstreamConn::Ktls`, which `PoolGuard::drop`
    /// never pools (see the socket contract above).
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
pub(super) async fn try_unbuffered_ktls_connect(
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
            UlpAttachError::Failed {
                transience: Transience::Transient,
                err,
            } => {
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
            UlpAttachError::Failed {
                transience: Transience::Permanent,
                err,
            } => {
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
        Ok(Err(KtlsError::KtlsSetupFailed {
            transience: Transience::Permanent,
            err,
        })) => {
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
        Ok(Err(KtlsError::KtlsSetupFailed {
            transience: Transience::Transient,
            err,
        })) => {
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

/// State of the one-shot unbuffered kTLS exchange: the rustls state machine,
/// the socket it drives, and the two TLS record buffers. `unbuffered_ktls_request`
/// runs the phase methods in order -- [`handshake`](Self::handshake),
/// [`send_request`](Self::send_request), [`read_headers`](Self::read_headers),
/// [`drain_remaining`](Self::drain_remaining), [`extract_secrets`](Self::extract_secrets)
/// -- and each phase owns the classification of its own failures into
/// [`KtlsError`] (the principle is spelled out at the call site, between the
/// handshake and the request send).
///
/// Security (`ktls.rs`, module doc): both buffers are `SecureVec`s, so the key
/// material and partially decrypted data they hold are zeroized on drop --
/// whichever phase fails, and once `extract_secrets` has consumed the state.
/// The socket arrives with the TLS ULP already attached (`ktls::attach_ulp`);
/// until `setup_rx` the kernel context is `TLS_BASE` passthrough, so every
/// read and write below behaves as plain TCP.
struct KtlsHandshake<'a> {
    conn: rustls::client::UnbufferedClientConnection,
    tcp: &'a mut TcpStream,
    incoming: SecureVec,
    incoming_used: usize,
    outgoing: SecureVec,
    outgoing_used: usize,
}

/// What [`KtlsHandshake::extract_secrets`] handed to the kernel, for the
/// completion log.
struct KtlsRxOffload {
    version: rustls::ProtocolVersion,
    secret_name: &'static str,
    cipher_suite: rustls::SupportedCipherSuite,
    rx_seq: u64,
}

impl<'a> KtlsHandshake<'a> {
    /// Build the rustls state machine for `host` over `tcp`. Nothing has been
    /// exchanged with the peer yet, so a failure is `TlsFailed`.
    fn new(tcp: &'a mut TcpStream, host: &str) -> Result<Self, KtlsError> {
        let tls_config = Arc::clone(KTLS_CLIENT_CONFIG.get().expect("initialized in main()"));

        let server_name =
            rustls::pki_types::ServerName::try_from(host.to_owned()).map_err(|err| {
                KtlsError::TlsFailed(std::io::Error::new(ErrorKind::InvalidInput, err))
            })?;

        let conn = rustls::client::UnbufferedClientConnection::new(tls_config, server_name)
            .map_err(|err| {
                KtlsError::TlsFailed(std::io::Error::other(format!("unbuffered TLS new:  {err}")))
            })?;

        Ok(Self {
            conn,
            tcp,
            // Use SecureVec to zeroize TLS record buffers (containing key
            // material and partially-decrypted data) on drop.
            incoming: SecureVec::new(32 * 1024),
            incoming_used: 0,
            outgoing: SecureVec::new(8 * 1024),
            outgoing_used: 0,
        })
    }

    /// Phase 1 of 5: drive the TLS handshake to completion. Every failure
    /// here is a TLS handshake failure (`TlsFailed`): the connection cannot
    /// be reused.
    async fn handshake(&mut self, host_authority: &str) -> Result<(), KtlsError> {
        use rustls::unbuffered::ConnectionState;

        let handshake_result: std::io::Result<()> = async {
            loop {
                let status = self
                    .conn
                    .process_tls_records(&mut self.incoming[..self.incoming_used]);
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
                        encode_tls_data(&mut etd, &mut self.outgoing, &mut self.outgoing_used);
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                    }
                    ConnectionState::TransmitTlsData(ttd) => {
                        transmit_tls_data(ttd, self.tcp, &self.outgoing, &mut self.outgoing_used)
                            .await?;
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                    }
                    ConnectionState::BlockedHandshake => {
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                        // Need more data from the server
                        grow_incoming(&mut self.incoming, self.incoming_used, "handshake")?;
                        let n = self.tcp.read(&mut self.incoming[self.incoming_used..]).await?;
                        if n == 0 {
                            return Err(std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "server closed during TLS handshake",
                            ));
                        }
                        self.incoming_used += n;
                    }
                    ConnectionState::WriteTraffic(_) => {
                        // Handshake complete
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
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
        handshake_result.map_err(KtlsError::TlsFailed)
    }

    /// Phase 2 of 5: process any pending records (e.g. NewSessionTickets from
    /// TLS 1.3), then encrypt and send the HTTP request. Returns the instant
    /// the encrypted request was transmitted -- the start of the
    /// upstream-rate window.
    ///
    /// Does NOT reset `outgoing_used` on entry. Any bytes still pending from
    /// Phase 1 are correctly transmitted by the next `TransmitTlsData` arm
    /// (`encode_tls_data` appends at `outgoing[outgoing_used..]`); the
    /// `WriteTraffic` arm fail-closes if bytes are still pending by the time
    /// it runs.
    async fn send_request(
        &mut self,
        host_authority: &str,
        upstream_path: &str,
        resume_offset: u64,
        resume_if_range: Option<&str>,
        volatile_cond: Option<&VolatileCondHeaders>,
    ) -> Result<PreciseInstant, KtlsError> {
        use rustls::unbuffered::{ConnectionState, EncryptError};

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
                return Err(KtlsError::setup_permanent(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "kTLS: post-handshake state machine did not reach WriteTraffic \
                         after {MAX_POST_HANDSHAKE_ROUNDS} iterations"
                    ),
                )));
            }

            let status = self
                .conn
                .process_tls_records(&mut self.incoming[..self.incoming_used]);
            let discard = status.discard;
            // Triggered by peer-supplied TLS data — transient, no host block.
            let state = status.state.map_err(|err| {
                KtlsError::setup_transient(std::io::Error::other(format!(
                    "TLS post-handshake error:  {err}"
                )))
            })?;

            #[expect(
                clippy::wildcard_enum_match_arm,
                reason = "all known variants are matched; the @-binding on the terminal arm hides them from the lint"
            )]
            match state {
                ConnectionState::EncodeTlsData(mut etd) => {
                    encode_tls_data(&mut etd, &mut self.outgoing, &mut self.outgoing_used);
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                }
                ConnectionState::TransmitTlsData(ttd) => {
                    transmit_tls_data(ttd, self.tcp, &self.outgoing, &mut self.outgoing_used)
                        .await
                        .map_err(KtlsError::setup_transient)?;
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
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
                        self.outgoing_used, 0,
                        "un-transmitted TLS bytes pending at WriteTraffic"
                    );
                    if self.outgoing_used != 0 {
                        return Err(KtlsError::setup_permanent(std::io::Error::new(
                            ErrorKind::InvalidData,
                            format!(
                                "kTLS: {} un-transmitted TLS bytes pending at \
                                 WriteTraffic; request encryption would clobber them",
                                self.outgoing_used
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
                        match wt.encrypt(plaintext, &mut self.outgoing) {
                            Ok(n) => break n,
                            Err(EncryptError::InsufficientSize(isz)) => {
                                self.outgoing.resize(isz.required_size, 0);
                            }
                            Err(err) => {
                                return Err(KtlsError::setup_permanent(std::io::Error::other(
                                    format!("TLS encrypt error:  {err}"),
                                )));
                            }
                        }
                    };

                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                    write_all_to_stream(self.tcp, &self.outgoing[..enc_len], WritePhase::Header)
                        .await
                        .map_err(KtlsError::setup_transient)?;
                    return Ok(PreciseInstant::now());
                }
                ConnectionState::BlockedHandshake => {
                    // Post-handshake state machine needs more data (e.g., key update).
                    // Read from network to avoid spinning through the iteration limit.
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                    grow_incoming(&mut self.incoming, self.incoming_used, "post-handshake")
                        .map_err(KtlsError::setup_permanent)?;
                    let n = self
                        .tcp
                        .read(&mut self.incoming[self.incoming_used..])
                        .await
                        .map_err(KtlsError::setup_transient)?;
                    if n == 0 {
                        return Err(KtlsError::setup_transient(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "server closed during post-handshake processing",
                        )));
                    }
                    self.incoming_used += n;
                }
                unexpected_state @ (ConnectionState::ReadTraffic(_)
                | ConnectionState::PeerClosed
                | ConnectionState::Closed
                | ConnectionState::ReadEarlyData(_)) => {
                    warn_once!(
                        "splice proxy: unexpected ConnectionState during post-handshake request send to upstream {host_authority} (peer closed or sent data before request?): {unexpected_state:?}; discarding the buffered TLS records and retrying the send"
                    );
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                }
                other => {
                    warn_once!(
                        "splice proxy: unexpected ConnectionState variant during post-handshake request to upstream {host_authority}: {other:?}; discarding the buffered TLS records and retrying the send"
                    );
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                }
            }
        }
    }

    /// Phase 3 of 5: read and decrypt until the response header terminator.
    /// Returns the head (`header_buf[..header_end]`, truncated at the
    /// terminator); any decrypted bytes past it go to `extra_body`, so the
    /// head and the body prefix stay separate until `drain_remaining` has
    /// appended everything else that was already in flight.
    async fn read_headers(
        &mut self,
        host_authority: &str,
        extra_body: &mut Vec<u8>,
    ) -> Result<(BytesMut, usize), KtlsError> {
        use rustls::unbuffered::{AppDataRecord, ConnectionState};

        let mut header_buf = BytesMut::with_capacity(MAX_UPSTREAM_HEADER_SIZE);
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
                return Err(KtlsError::setup_permanent(std::io::Error::new(
                    ErrorKind::TimedOut,
                    format!(
                        "Phase 3 header-read loop exceeded {MAX_PHASE3_ROUNDS} iterations without completion"
                    ),
                )));
            }

            // Process any TLS records already in the incoming buffer
            let need_more_data = loop {
                if self.incoming_used == 0 {
                    break true;
                }
                let status = self
                    .conn
                    .process_tls_records(&mut self.incoming[..self.incoming_used]);
                let discard = status.discard;
                // Triggered by peer-supplied TLS data — transient, no host block.
                let state = status.state.map_err(|err| {
                    KtlsError::setup_transient(std::io::Error::other(format!(
                        "TLS read error:  {err}"
                    )))
                })?;

                #[expect(clippy::wildcard_enum_match_arm, reason = "clippy false-positive")]
                match state {
                    ConnectionState::ReadTraffic(mut rt) => {
                        let mut total_discard = discard;
                        while let Some(result) = rt.next_record() {
                            let AppDataRecord { payload, discard } = result.map_err(|err| {
                                KtlsError::setup_transient(std::io::Error::other(format!(
                                    "TLS record error:  {err}"
                                )))
                            })?;
                            header_buf.extend_from_slice(payload);
                            total_discard += discard;
                        }
                        discard_incoming(
                            &mut self.incoming,
                            &mut self.incoming_used,
                            total_discard,
                        );

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
                            return Err(KtlsError::setup_permanent(std::io::Error::new(
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
                        encode_tls_data(&mut etd, &mut self.outgoing, &mut self.outgoing_used);
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                    }
                    ConnectionState::TransmitTlsData(ttd) => {
                        transmit_tls_data(ttd, self.tcp, &self.outgoing, &mut self.outgoing_used)
                            .await
                            .map_err(KtlsError::setup_transient)?;
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                    }
                    ConnectionState::BlockedHandshake | ConnectionState::WriteTraffic(_) => {
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                        break true; // Need more data from network
                    }
                    state @ (ConnectionState::PeerClosed
                    | ConnectionState::Closed
                    | ConnectionState::ReadEarlyData(_)) => {
                        warn_once_or_debug!(
                            "kTLS: connection to upstream {host_authority} in terminal state during header read (upstream closed before headers complete?): {state:?}; retrying the upstream read"
                        );
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                        break true;
                    }
                    other => {
                        warn_once_or_debug!(
                            "kTLS: unexpected ConnectionState variant during header read from upstream {host_authority}: {other:?}; retrying the upstream read"
                        );
                        discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                        break true;
                    }
                }
            };

            if headers_complete {
                break;
            }
            if need_more_data {
                grow_incoming(&mut self.incoming, self.incoming_used, "header read")
                    .map_err(KtlsError::setup_permanent)?;
                let n = self
                    .tcp
                    .read(&mut self.incoming[self.incoming_used..])
                    .await
                    .map_err(KtlsError::setup_transient)?;
                if n == 0 {
                    return Err(KtlsError::setup_transient(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        "server closed before sending complete response headers",
                    )));
                }
                self.incoming_used += n;
            }
        }

        Ok((header_buf, header_end))
    }

    /// Drain all complete TLS records from the incoming buffer, appending decrypted
    /// plaintext to `output`. Handles `EncodeTlsData` and `TransmitTlsData` states
    /// as side-effects (post-handshake messages). Stops when the buffer is empty or
    /// a terminal/blocked state is reached.
    ///
    /// Shared drain loop used by Phase 4 (`drain_remaining`), called once
    /// after the initial response is parsed and again per iteration of the
    /// post-response read loop until the incoming buffer is empty.
    ///
    /// Times out after the configured HTTP timeout.
    async fn drain_buffered_records(&mut self, output: &mut Vec<u8>) -> Result<(), KtlsError> {
        use rustls::unbuffered::{AppDataRecord, ConnectionState, UnbufferedStatus};

        while self.incoming_used > 0 {
            let UnbufferedStatus { discard, state } = self
                .conn
                .process_tls_records(&mut self.incoming[..self.incoming_used]);
            // Triggered by peer-supplied TLS data — transient, no host block.
            let state = state.map_err(|err| {
                KtlsError::setup_transient(std::io::Error::other(format!(
                    "TLS drain error:  {err}"
                )))
            })?;

            match state {
                ConnectionState::ReadTraffic(mut rt) => {
                    let mut total_discard = discard;
                    while let Some(result) = rt.next_record() {
                        let AppDataRecord { payload, discard } = result.map_err(|err| {
                            KtlsError::setup_transient(std::io::Error::new(
                                ErrorKind::InvalidData,
                                format!("TLS record error:  {err}"),
                            ))
                        })?;
                        total_discard += discard;
                        output.extend_from_slice(payload);
                    }
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, total_discard);
                }
                ConnectionState::EncodeTlsData(mut etd) => {
                    // Do NOT reset `outgoing_used` here.  The rustls state
                    // machine may emit several `EncodeTlsData` states in a row
                    // before a single `TransmitTlsData` (e.g. a ClientHello
                    // followed by an early-data finished message), and
                    // `encode_tls_data` appends at `outgoing[*outgoing_used..]`.
                    // Zeroing would silently drop any bytes still waiting to be
                    // written.
                    encode_tls_data(&mut etd, &mut self.outgoing, &mut self.outgoing_used);
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                }
                ConnectionState::TransmitTlsData(ttd) => {
                    transmit_tls_data(ttd, self.tcp, &self.outgoing, &mut self.outgoing_used)
                        .await
                        .map_err(KtlsError::setup_transient)?;
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                }
                ConnectionState::PeerClosed
                | ConnectionState::Closed
                | ConnectionState::ReadEarlyData(_)
                | ConnectionState::BlockedHandshake
                | ConnectionState::WriteTraffic(_) => {
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                    break;
                }
                other => {
                    warn_once!(
                        "splice proxy: unexpected ConnectionState variant while draining buffered records: {other:?}; stopping the drain"
                    );
                    discard_incoming(&mut self.incoming, &mut self.incoming_used, discard);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Phase 4 of 5: drain the incoming buffer to a TLS record boundary.
    /// Decrypts every complete record already buffered into `extra_body`,
    /// then -- if a partial record remains -- keeps reading record-framed
    /// until the buffer drains empty. The overall `http_timeout` (applied at
    /// the call site) caps the total wait; each read has its own backstop.
    async fn drain_remaining(&mut self, extra_body: &mut Vec<u8>) -> Result<(), KtlsError> {
        // Process any remaining complete TLS records in the incoming buffer.
        // Their plaintext goes into extra_body.
        self.drain_buffered_records(extra_body).await?;

        // If there are still unprocessed bytes (partial TLS record), loop reading
        // from TCP until all records are drained or a per-read timeout fires.
        // The overall http_timeout (applied at the call site) caps total wait time.
        if self.incoming_used > 0 {
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

            let per_read_timeout = Duration::from_secs(5);

            // Log how many bytes the current partial TLS record needs.
            // TLS record header is 5 bytes: [content_type, version_hi, version_lo, length_hi, length_lo].
            // We skip the first 3 bytes and read the 2-byte big-endian length.
            if let Some(&[_, _, _, hi, lo, ..]) = self.incoming.get(..self.incoming_used) {
                let record_len = u16::from_be_bytes([hi, lo]) as usize;
                debug!(
                    "kTLS: draining with {} bytes buffered, \
                     current record needs {} bytes total",
                    self.incoming_used,
                    5 + record_len
                );
            }

            let mut drain_stop_reason = "";
            'drain: while self.incoming_used > 0 {
                grow_incoming(&mut self.incoming, self.incoming_used, "drain")
                    .map_err(KtlsError::setup_permanent)?;

                // Bound this read to the end of the current record so it never pulls
                // the following partial record in — that is what would keep us
                // perpetually mid-record against a fast upstream. `.max(1)` guards
                // the abnormal case where a whole record is already buffered but
                // undrained: a zero-length read slice would misread as EOF.
                let want = record_framed_read_len(&self.incoming, self.incoming_used).max(1);
                let read_end = (self.incoming_used + want).min(self.incoming.len());

                match tokio::time::timeout(
                    per_read_timeout,
                    self.tcp
                        .read(&mut self.incoming[self.incoming_used..read_end]),
                )
                .await
                {
                    Ok(Ok(n @ 1..)) => {
                        self.incoming_used += n;
                    }
                    Ok(Ok(0)) => {
                        drain_stop_reason = "upstream EOF";
                        debug!(
                            "kTLS: drain stopped ({drain_stop_reason}) with {} bytes buffered",
                            self.incoming_used
                        );
                        break;
                    }
                    Ok(Err(ref err)) => {
                        drain_stop_reason = "read error";
                        debug!(
                            "kTLS: drain stopped ({drain_stop_reason}) with {} bytes buffered:  {}",
                            self.incoming_used,
                            ErrorReport(err)
                        );
                        break;
                    }
                    Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                        drain_stop_reason = "per-read timeout";
                        debug!(
                            "kTLS: drain stopped ({drain_stop_reason}) with {} bytes buffered",
                            self.incoming_used
                        );
                        break;
                    }
                }

                self.drain_buffered_records(extra_body).await?;
                if extra_body.len() > MAX_KTLS_EXTRA_BODY {
                    return Err(KtlsError::setup_transient(std::io::Error::other(format!(
                        "kTLS: buffered {} bytes of decrypted body without reaching \
                             TLS record alignment; falling back to the streaming path",
                        extra_body.len()
                    ))));
                }
                if self.incoming_used == 0 {
                    break 'drain;
                }
            }

            if self.incoming_used > 0 {
                // Upstream truncation (EOF/reset/stall mid-record) — transient,
                // no host block.
                return Err(KtlsError::setup_transient(std::io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "kTLS: {} bytes remain in buffer after drain \
                         ({drain_stop_reason}, partial TLS record could not be completed)",
                        self.incoming_used
                    ),
                )));
            }
        }

        Ok(())
    }

    /// Phase 5 of 5: hand the RX secrets to the kernel. Consumes the state:
    /// the rustls connection is dismantled for its secrets, and the record
    /// buffers are zeroized on the way out. After this the socket belongs to
    /// the kernel context and must not be read through userspace TLS again.
    fn extract_secrets(self) -> Result<KtlsRxOffload, KtlsError> {
        let Self {
            conn,
            tcp,
            incoming: _incoming,
            incoming_used,
            outgoing: _outgoing,
            outgoing_used: _,
        } = self;

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
            return Err(KtlsError::setup_permanent(std::io::Error::new(
                ErrorKind::InvalidData,
                format!(
                    "kTLS: incoming buffer has {incoming_used} unprocessed bytes \
                     before secret extraction (rx_seq would be stale)"
                ),
            )));
        }

        let (secrets, kernel_conn) = conn.dangerous_into_kernel_connection().map_err(|err| {
            KtlsError::setup_permanent(std::io::Error::other(format!(
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
        // setsockopt deterministically, so reject up front as permanent
        // (the caller's 600s host block is correct for a deterministic failure)
        // rather than discover it after a full upstream request per host.
        if !ktls::rx_supported(version, rx_secrets) {
            return Err(KtlsError::setup_permanent(std::io::Error::new(
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
        ktls::setup_rx(&*tcp, rx_seq, rx_secrets, version).map_err(KtlsError::setup_permanent)?;
        drop(rx);

        // drain_control_messages can fail for transient reasons (e.g. EAGAIN
        // between peek and consume). Treat those as transient so a one-off race
        // does not suppress kTLS for the full KTLS_BLOCK_DURATION. We have not
        // polled the socket here, so the "no data ready" case is the expected
        // outcome and is not an error — pass `MaybeIdle`.
        ktls::drain_control_messages(tcp.as_fd(), ktls::DrainExpect::MaybeIdle)
            .map_err(KtlsError::setup_transient)?;

        Ok(KtlsRxOffload {
            version,
            secret_name,
            cipher_suite,
            rx_seq,
        })
    }
}

/// Drive an unbuffered TLS handshake, send an HTTP request, read response
/// headers, drain the buffer to record alignment, and set up kTLS RX -- the
/// five phases of [`KtlsHandshake`], in order.
///
/// Precondition: `tcp` already has the TLS ULP attached
/// (`ktls::attach_ulp`). The kernel context is in `TLS_BASE` passthrough
/// mode until `setup_rx`, so all handshake I/O below behaves as plain TCP.
async fn unbuffered_ktls_request(
    tcp: &mut TcpStream,
    host: &str,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> Result<KtlsReadyState, KtlsError> {
    let mut hs = KtlsHandshake::new(tcp, host)?;

    // --- Phase 1 of 5: TLS Handshake ---
    hs.handshake(host_authority).await?;
    debug!(
        "kTLS: TLS handshake completed with {host} \
         (shared ClientSessionMemoryCache enables resumption for subsequent connections)"
    );

    // TLS handshake succeeded. From here on, classification follows one
    // principle: a permanent KtlsSetupFailed (600s host block) is reserved for failures
    // that would repeat deterministically on a retry — pathological peer
    // state machines (round caps), oversized headers/buffers, internal
    // invariant violations, and kernel setup_rx rejection. Network-flavored
    // failures (read/write errors, EOF, truncation) and errors triggered by
    // peer-supplied TLS data map to a transient KtlsSetupFailed: upstream
    // flakiness says nothing about this host's kTLS capability and must not
    // disable kTLS for 600s. Routing outcomes keep their own variants:
    // ResponseNotSpliceable (non-200/no-CL), UpstreamProtocolError
    // (malformed HTTP, no block).

    // --- Phase 2 of 5: Send HTTP Request ---
    let req_sent = hs
        .send_request(
            host_authority,
            upstream_path,
            resume_offset,
            resume_if_range,
            volatile_cond,
        )
        .await?;

    // --- Phase 3 of 5: Read Response Headers ---
    let mut extra_body = Vec::new();
    let (mut header_buf, header_end) = hs.read_headers(host_authority, &mut extra_body).await?;

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
    response.request_sent_at = Some(req_sent);

    if response.status_code != 200 || response.content_length().is_none_or(|ct| ct == 0) {
        // Non-spliceable response: the caller will reconnect via the standard
        // path for a complete fetch, so no need to drain the remaining TLS
        // records from this one-shot kTLS connection.
        return Err(KtlsError::ResponseNotSpliceable {
            response: Box::new(response),
        });
    }

    // --- Phase 4 of 5: Drain Remaining Buffer ---
    hs.drain_remaining(&mut extra_body).await?;

    // --- Phase 5 of 5: kTLS Setup ---
    let KtlsRxOffload {
        version,
        secret_name,
        cipher_suite,
        rx_seq,
    } = hs.extract_secrets()?;

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

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn record_framed_read_len_asks_for_header_first() {
        // Fewer than 5 bytes buffered: the length field is not yet readable,
        // so ask only for enough to complete the 5-byte record header —
        // without indexing past what is present.
        assert_eq!(record_framed_read_len(&[], 0), 5);
        assert_eq!(record_framed_read_len(&[0x17u8, 0x03, 0x03], 3), 2);
    }
}
