//! Body transfer for the splice proxy: the zero-copy loop
//! [`splice_proxy_body`] (socket -> pipe -> tee -> client + cache file) and
//! the userspace-TLS loop [`splice_proxy_body_tls`], both keeping only their
//! read and deliver steps while every shared piece lives on [`BodyTransfer`]
//! and comes back as [`BodyOutcome`]. Also owns client demotion to file
//! serving ([`write_client_or_demote`], [`spawn_file_serve_task`],
//! [`DemotedClientHandle`]), the [`SpliceRangeFilter`] applied to the client
//! stream, [`BodyTransferError`]/[`BodyFailureSide`] attribution, and the
//! pipe and `/dev/null` helpers ([`create_pipe`], [`drain_pipe`],
//! [`splice_pipe_to_file`], [`range_slice`]).
//!
//! Both loops also run client-less: a `None` client (the parallel-hack
//! nudge's detached download, `super::detached`) starts the transfer in
//! [`ClientStatus::Absent`], which every client-facing step already treats
//! as cache-only.
//!
//! Consumers: the drive in `mod.rs` (body loops, `range_slice`, the outcome
//! and handle types) and `super::detached` (the client-less form plus
//! [`BodyTransferError::log_detached`]).

use std::{
    io::ErrorKind,
    ops::Range,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    time::Duration,
};

use nix::fcntl::{SpliceFFlags, splice, tee};
use tokio::{
    io::AsyncReadExt as _,
    net::{TcpStream, unix::pipe},
};
use tracing::{debug, error, info};

use crate::error::{ErrorReport, errno_to_io_error, is_peer_disconnect};
use crate::fs_open::{hint_sequential_read, nofollow_options};
use crate::guards::DownloadBarrier;
use crate::humanfmt::HumanFmt;
#[cfg(feature = "ktls")]
use crate::ktls;
use crate::log_once::Logged;
use crate::rate_checker::{RateCheckDirection, RateChecker};
use crate::sendfile_conn::{
    async_sendfile_unfinished, clear_tcp_readable_cache, clear_tcp_writable_cache,
    wait_readable_rated, wait_writable_rated, write_all_to_stream_rated,
};
#[cfg(feature = "ktls")]
use crate::warn_once;
use crate::{
    Never, active_downloads::ActiveDownloadStatus, client_counter, global_config, metrics,
    static_assert, warn_once_or_debug, warn_once_or_info,
};

use super::upstream::{TLS_READ_BUF_SIZE, UpstreamConn, ZeroCopyUpstream};
use super::{AfterHeaderSide, SpliceProxyError};

/// Pre-computed byte offsets for range-filtering the splice loop output.
/// `skip` bytes are suppressed at the start, then `send` bytes are forwarded.
pub(super) struct SpliceRangeFilter {
    pub(super) skip: u64,
    pub(super) send: u64,
}

/// Default pipe buffer size on Linux is 16 pages (64 KiB on most systems).
/// We increase it to 1 MiB to reduce the number of splice syscall pairs needed.
const PIPE_BUFFER_SIZE: i32 = 1024 * 1024;

/// Cadence of the upstream rate-check tick in `splice_proxy_body_tls`'s
/// read loop.
const RATE_TICK_PERIOD: Duration = Duration::from_secs(1);

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
    } else if cfg!(debug_assertions) {
        let receiver_buf_size = fcntl(receiver.as_fd(), FcntlArg::F_GETPIPE_SZ)?;

        if receiver_buf_size != PIPE_BUFFER_SIZE {
            warn_once_or_debug!(
                "splice proxy: pipe buffer size mismatch: sender={PIPE_BUFFER_SIZE}, receiver={receiver_buf_size}; continuing with the mismatched sizes"
            );
        }
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

pub(super) enum DeliveryResult {
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

    /// Attribute this failure for the outer arm. The peer sides hand their
    /// error over unchanged; the proxy-local sides are logged here, where
    /// `temppath` -- the cache file being written -- is in scope, and hand
    /// over the proof instead. `phase` names the transfer for both the log
    /// line and the outer arm's tag.
    pub(super) fn into_after_header(
        self,
        phase: &'static str,
        temppath: &Path,
    ) -> SpliceProxyError {
        let Self { side, err } = self;
        let side = match side {
            BodyFailureSide::Upstream => AfterHeaderSide::Upstream(err),
            BodyFailureSide::Client => AfterHeaderSide::Client(err),
            BodyFailureSide::Cache => {
                AfterHeaderSide::Cache(Logged::cache_io_failure(format_args!(
                    "splice proxy: failed to write the cache file `{}` in {phase}; aborting the transfer and closing the connection:  {}",
                    temppath.display(),
                    ErrorReport(&err)
                )))
            }
            // Splice pipes / fd duplication -- not a cached-file syscall, so
            // `CACHE_IO_FAILURE` stays out of it.
            BodyFailureSide::Proxy => AfterHeaderSide::Proxy(Logged::error(format_args!(
                "splice proxy: proxy-side I/O failure in {phase} for `{}`; aborting the transfer and closing the connection:  {}",
                temppath.display(),
                ErrorReport(&err)
            ))),
        };
        SpliceProxyError::AfterHeader { phase, side }
    }

    /// Attribute this failure for a detached, client-less download
    /// ([`super::detached::DetachedDownload`]).
    ///
    /// The sibling of [`Self::into_after_header`] -- same `match` shape, so
    /// the two attribution tables sit together -- for the one caller with no
    /// connection to report to: nothing is handed upward, so every arm logs
    /// here and the [`Logged`] proof is discarded on the spot. The outer
    /// arm's "closing the connection" tail is replaced by "abandoning the
    /// download": no client is waiting and the partial is removed by the
    /// temp-file guard.
    pub(super) fn log_detached(self, phase: &'static str, temppath: &Path) {
        let Self { side, err } = self;
        let _logged: Logged = match side {
            // Same policy as the outer arm's upstream arm: no
            // `is_peer_disconnect` demotion, and counter-backed by the
            // dedicated counter the throw site already bumped.
            BodyFailureSide::Upstream => Logged::warn(format_args!(
                "splice proxy: upstream failed in {phase} for `{}`; abandoning the download:  {}",
                temppath.display(),
                ErrorReport(&err)
            )),
            BodyFailureSide::Cache => Logged::cache_io_failure(format_args!(
                "splice proxy: failed to write the cache file `{}` in {phase}; abandoning the download:  {}",
                temppath.display(),
                ErrorReport(&err)
            )),
            BodyFailureSide::Proxy => Logged::error(format_args!(
                "splice proxy: proxy-side I/O failure in {phase} for `{}`; abandoning the download:  {}",
                temppath.display(),
                ErrorReport(&err)
            )),
            // Unreachable by construction: a client-less transfer runs in
            // `ClientStatus::Absent`, which no client-facing step enters.
            // Reported rather than panicked so a future caller wiring a
            // client into this path is a log line, not a crash.
            BodyFailureSide::Client => Logged::error(format_args!(
                "splice proxy: client-side failure in {phase} for `{}` without an attached client; abandoning the download:  {}",
                temppath.display(),
                ErrorReport(&err)
            )),
        };
    }
}

/// The caller must `.await` the join handle after the download barrier has
/// been consumed (so the spawned task can observe a terminal
/// `ActiveDownloadStatus` -- `Verifying` while integrity hashing is in
/// flight, then `Finished` once `RenameBarrier::commit` flips the variant).
pub(super) type DemotedClientHandle = tokio::task::JoinHandle<DeliveryResult>;

/// Per-body bookkeeping shared by the two body loops.
///
/// [`splice_proxy_body`] (zero-copy splice/tee) and [`splice_proxy_body_tls`]
/// (userspace `read_buf` + `pwrite`) differ only in how they pull a chunk
/// from upstream and how they hand it to the cache file and the client.
/// Everything around that -- the client-download accounting, the two rate
/// checkers, the upstream-rate gate, the byte cursors, the client state
/// machine and the demotion hand-off -- lives here so it exists once.
///
/// A `None` client starts the state machine in [`ClientStatus::Absent`] and
/// leaves the client-side accounting (`counter`, `client_rate_checker`)
/// unarmed; every client-facing step branches on [`ClientStatus::Active`],
/// so the client-less form needs no arms of its own.
struct BodyTransfer<'a> {
    /// Dropped at the demotion transition so the spawned
    /// `serve_remaining_from_file` task's own `ClientDownload` (in
    /// `async_sendfile_unfinished`) takes over the accounting cleanly; see
    /// [`Self::maybe_demote`]. `Option` because it is taken exactly once --
    /// and `None` from the start for a client-less transfer, which ships no
    /// bytes to any client and so must not bump `ACTIVE_CLIENT_DOWNLOADS`.
    counter: Option<client_counter::ClientDownload>,
    /// `None` only after [`Self::check_upstream_rate`] consumed it into
    /// `Aborted(MirrorDownloadRate)` on the error path, where the whole
    /// transfer is dropped next.
    dbarrier: Option<DownloadBarrier>,
    rate_checker: Option<RateChecker>,
    client_rate_checker: Option<RateChecker>,
    /// Body bytes still to be pulled from upstream.
    remaining: u64,
    /// Cache-file offset of the next byte to write.
    file_offset: i64,
    client_status: ClientStatus,
    /// Body bytes pulled from upstream so far (the next chunk starts here).
    bytes_done: u64,
    /// Absolute cache-file offset of the next byte the client expects.
    /// Maintained together with `client_remaining` across the tee, boundary
    /// and userspace delivery paths so that on demotion the file-serve task
    /// gets the exact resume point and length regardless of resume offset,
    /// body-prefix advance, or 206 range filtering.
    client_file_pos: u64,
    /// Bytes still owed to the client.
    client_remaining: u64,
    demoted_handle: Option<DemotedClientHandle>,
    range_filter: &'a SpliceRangeFilter,
    pub(super) cache_path: &'a Path,
    /// `None` for a client-less transfer; read only through
    /// [`Self::active_client`], which the [`ClientStatus::Absent`] state
    /// keeps unreachable.
    client: Option<&'a TcpStream>,
}

/// What a body loop hands back to `splice_proxy_drive`.
pub(super) struct BodyOutcome {
    /// Returned for the rename step.
    pub(super) dbarrier: DownloadBarrier,
    /// Set when the client was demoted to a file-serve task; the caller
    /// awaits it after consuming `dbarrier`.
    pub(super) demoted_handle: Option<DemotedClientHandle>,
    /// The client went away mid-body (as opposed to being demoted).
    pub(super) client_disconnected: bool,
    /// Bytes this loop delivered to the client.
    pub(super) client_bytes: u64,
}

impl<'a> BodyTransfer<'a> {
    fn new(
        client: Option<&'a TcpStream>,
        dbarrier: DownloadBarrier,
        range_filter: &'a SpliceRangeFilter,
        cache_path: &'a Path,
        content_length: u64,
        file_start_offset: i64,
    ) -> Self {
        // `REQUESTS_SPLICE` is bumped by `splice_proxy_drive` alongside the
        // response-headers emission (next to `record_client_status`), since
        // the body loops are skipped when the entire response fits in the
        // body prefix and we still need to count it. A client-less transfer
        // has no response of its own to count and no client to account for.
        let counter = client.map(|_stream| client_counter::ClientDownload::new());

        let config = global_config();
        let rate_checker = config
            .min_download_rate
            .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
        let client_rate_checker = client.and_then(|_stream| {
            config
                .min_download_rate
                .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe))
        });

        Self {
            counter,
            dbarrier: Some(dbarrier),
            rate_checker,
            client_rate_checker,
            remaining: content_length,
            file_offset: file_start_offset,
            client_status: if client.is_some() {
                ClientStatus::Active
            } else {
                ClientStatus::Absent
            },
            bytes_done: 0,
            client_file_pos: u64::try_from(file_start_offset)
                .expect("file_start_offset is non-negative by construction")
                + range_filter.skip,
            client_remaining: range_filter.send,
            demoted_handle: None,
            range_filter,
            cache_path,
            client,
        }
    }

    /// The client socket, for a step that has established
    /// [`ClientStatus::Active`].
    fn active_client(&self) -> &'a TcpStream {
        self.client
            .expect("client I/O only happens in ClientStatus::Active, which requires a client")
    }

    fn barrier(&mut self) -> &mut DownloadBarrier {
        self.dbarrier
            .as_mut()
            .expect("the barrier is only taken on the upstream-rate abort path")
    }

    /// Hand the barrier out for a consuming abort (the TLS read step's rate
    /// tick); the transfer is dropped right after.
    fn take_barrier(&mut self) -> DownloadBarrier {
        self.dbarrier
            .take()
            .expect("the barrier is only taken on the upstream-rate abort path")
    }

    /// Upstream-rate gate: at the top of every iteration, and again before
    /// accepting a demotion (see [`Self::maybe_demote`]). On failure the
    /// barrier is consumed into `Aborted(MirrorDownloadRate)`.
    async fn check_upstream_rate(&mut self) -> Result<(), BodyTransferError> {
        let dbarrier = self.take_barrier();
        self.dbarrier = Some(
            dbarrier
                .check_upstream_rate(self.rate_checker.as_ref())
                .await
                .map_err(BodyTransferError::upstream)?,
        );
        Ok(())
    }

    /// Account a chunk just pulled from upstream and return the body-offset
    /// range it covers.
    ///
    /// The upstream RC is fed up-front (the bytes have already arrived) so
    /// any `check_fail` later in this iteration -- in particular the
    /// `DemoteRequested` adjudication in [`Self::maybe_demote`] -- sees the
    /// freshest window. Without this the upstream RC would still be one
    /// chunk behind the client RC at the moment a slow upstream causes the
    /// client check to trip.
    fn note_chunk(&mut self, got: usize) -> Range<u64> {
        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(got as u64);
        if let Some(ref mut rate_checker) = self.rate_checker {
            rate_checker.add(got);
        }
        let start = self.bytes_done;
        let end = start + got as u64;
        self.bytes_done = end;
        self.remaining = self
            .remaining
            .checked_sub(got as u64)
            .expect("upstream should not deliver more than requested");
        start..end
    }

    /// `pwrite` a userspace chunk to the cache file at the current offset
    /// and notify concurrent clients. Always done before the client send so
    /// late joiners are not gated on this client's send speed.
    async fn write_cache_chunk(
        &mut self,
        cache_file: &tokio::fs::File,
        buf: &mut Vec<u8>,
        got: usize,
    ) -> Result<(), BodyTransferError> {
        pwrite_buf_to_file(cache_file, buf, got, self.file_offset)
            .await
            .map_err(BodyTransferError::cache)?;
        self.file_offset +=
            i64::try_from(got).expect("a chunk is bounded by its read buffer, which fits in i64");
        self.barrier().ping_batched(got as u64);
        Ok(())
    }

    /// Splice `count` bytes from `rx` into the cache file at the current
    /// offset and notify concurrent clients.
    async fn splice_cache_chunk(
        &mut self,
        rx: &pipe::Receiver,
        cache_file: &tokio::fs::File,
        count: usize,
    ) -> Result<(), BodyTransferError> {
        splice_pipe_to_file(rx, cache_file, count, &mut self.file_offset)
            .await
            .map_err(BodyTransferError::cache)?;
        self.barrier().ping_batched(count as u64);
        Ok(())
    }

    /// Record bytes just delivered to the client.
    fn note_client_bytes(&mut self, sent: usize) {
        metrics::BYTES_SERVED_SPLICE.increment_by(sent as u64);
        self.client_file_pos += sent as u64;
        self.client_remaining = self
            .client_remaining
            .checked_sub(sent as u64)
            .expect("client_remaining tracks bytes still owed to the client");
    }

    /// The client RC tripped after progress: the cache already has the
    /// bytes, so hand off to [`Self::maybe_demote`] for adjudication.
    fn request_demote(&mut self) {
        self.client_status = ClientStatus::DemoteRequested {
            client_file_pos: self.client_file_pos,
            client_remaining: self.client_remaining,
        };
    }

    /// The client hung up mid-body: count it, log it once, and carry on
    /// cache-only so late joiners still complete.
    fn client_disconnected(&mut self) {
        metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
        let client_total = self.range_filter.send;
        let client_sent = client_total - self.client_remaining;
        #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
        let client_sent_percent = 100.0 * client_sent as f32 / client_total as f32;
        info!(
            "splice proxy: client disconnected after {} out of {} ({:.1}%), continuing cache-only",
            HumanFmt::Size(client_sent),
            HumanFmt::Size(client_total),
            client_sent_percent,
        );
        self.client_status = ClientStatus::Disconnected;
    }

    /// Adjudicate a `DemoteRequested` client: no-op in every other state.
    ///
    /// Slow upstream is the most common reason the client RC trips, so the
    /// upstream rate is checked first and its `MirrorDownloadRate` abort
    /// surfaces the root cause instead of spinning up a doomed demoted
    /// file-serve task. Only when the upstream is healthy is the client
    /// really the bottleneck: accounting is handed to the spawned task (its
    /// `async_sendfile_unfinished` creates its own `ClientDownload`, so net
    /// `ACTIVE_CLIENT_DOWNLOADS` stays at 1 across the transition).
    async fn maybe_demote(&mut self) -> Result<(), BodyTransferError> {
        let ClientStatus::DemoteRequested {
            client_file_pos: demote_pos,
            client_remaining: demote_remaining,
        } = self.client_status
        else {
            return Ok(());
        };

        self.check_upstream_rate().await?;

        let client_total = self.range_filter.send;
        #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
        let demote_remaining_percent = 100.0 * demote_remaining as f32 / client_total as f32;
        info!(
            "splice proxy: demoting slow client to file-serve of `{}` at cache offset {} with {} remaining out of {} ({:.1}%)",
            self.cache_path.display(),
            HumanFmt::Size(demote_pos),
            HumanFmt::Size(demote_remaining),
            HumanFmt::Size(client_total),
            demote_remaining_percent,
        );
        drop(self.counter.take());
        self.demoted_handle = Some(
            spawn_file_serve_task(
                self.active_client(),
                self.cache_path,
                demote_pos,
                demote_remaining,
                self.barrier(),
            )
            .map_err(BodyTransferError::proxy)?,
        );
        self.client_status = ClientStatus::Demoted;
        Ok(())
    }

    fn finish(self) -> BodyOutcome {
        let Self {
            counter: _counter,
            dbarrier,
            rate_checker: _,
            client_rate_checker: _,
            remaining,
            file_offset: _,
            client_status,
            bytes_done: _,
            client_file_pos: _,
            client_remaining,
            demoted_handle,
            range_filter,
            cache_path: _,
            client: _,
        } = self;
        debug_assert_eq!(
            remaining, 0,
            "the body loop runs until the body is exhausted"
        );
        BodyOutcome {
            dbarrier: dbarrier.expect("the barrier is only taken on the upstream-rate abort path"),
            demoted_handle,
            client_disconnected: matches!(client_status, ClientStatus::Disconnected),
            client_bytes: range_filter.send - client_remaining,
        }
    }
}

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
pub(super) async fn splice_proxy_body(
    upstream: ZeroCopyUpstream<'_>,
    client: Option<&TcpStream>,
    cache_file: &tokio::fs::File,
    content_length: u64,
    file_start_offset: i64,
    dbarrier: DownloadBarrier,
    range_filter: &SpliceRangeFilter,
    cache_path: &Path,
) -> Result<BodyOutcome, BodyTransferError> {
    #[cfg(feature = "ktls")]
    let upstream_is_ktls = upstream.ktls;
    let upstream = upstream.tcp;
    let mut xfer = BodyTransfer::new(
        client,
        dbarrier,
        range_filter,
        cache_path,
        content_length,
        file_start_offset,
    );

    let (upstream_pipe_sender, mut upstream_pipe_receiver) =
        create_pipe().map_err(BodyTransferError::proxy)?;
    let (cache_pipe_sender, cache_pipe_receiver) =
        create_pipe().map_err(BodyTransferError::proxy)?;

    let config = global_config();

    // Budget for draining kTLS control records that arrive mid-stream (e.g. a
    // late NewSessionTicket) — see the drain-retry arm in the splice loop.
    // Multiple bursts over a long download are plausible; each drain consumes
    // a whole burst.
    #[cfg(feature = "ktls")]
    let mut ktls_drain_retries: u32 = 8;

    let client_skip = range_filter.skip;
    let client_range_end = range_filter.skip + range_filter.send;

    while xfer.remaining > 0 {
        xfer.check_upstream_rate().await?;

        static_assert!(PIPE_BUFFER_SIZE > 0 && (PIPE_BUFFER_SIZE as u64) < usize::MAX as u64);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "PIPE_BUFFER_SIZE is checked to be < usize::MAX above"
        )]
        let chunk_size = std::cmp::min(xfer.remaining, PIPE_BUFFER_SIZE as u64) as usize;

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
                            "splice proxy: upstream closed prematurely (remaining={}, chunk_size={chunk_size})",
                            xfer.remaining
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
                            &mut xfer.rate_checker,
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

        // Determine how this chunk overlaps with the client range.
        let chunk = xfer.note_chunk(got);

        if !matches!(xfer.client_status, ClientStatus::Active)
            || chunk.end <= client_skip
            || chunk.start >= client_range_end
        {
            // Chunk is entirely outside client range, or the client is
            // absent/gone/demoted — cache only
            xfer.splice_cache_chunk(&upstream_pipe_receiver, cache_file, got)
                .await?;
        } else if chunk.start >= client_skip && chunk.end <= client_range_end {
            // Chunk is entirely inside client range — normal tee
            tee_and_splice(
                &mut xfer,
                &upstream_pipe_receiver,
                &cache_pipe_receiver,
                &cache_pipe_sender,
                cache_file,
                got,
            )
            .await?;
            xfer.maybe_demote().await?;
        } else {
            // Boundary chunk — read into userspace, slice for client, pwrite for cache
            let mut buf = read_pipe_to_buf(&mut upstream_pipe_receiver, got)
                .await
                .map_err(BodyTransferError::proxy)?;

            debug_assert!(
                matches!(xfer.client_status, ClientStatus::Active),
                "outer condition excludes non-active"
            );
            debug_assert!(
                client_range_end > chunk.start,
                "boundary chunk must overlap client range"
            );
            debug_assert_eq!(buf.len(), got, "read_pipe_to_buf reads exactly `got` bytes");

            // Write full chunk to cache via pwrite first, so concurrent clients
            // see progress without being gated on the first client's send speed.
            xfer.write_cache_chunk(cache_file, &mut buf, got).await?;

            // Then send to client (may be slow). `Active` is established
            // above, so the client socket is there.
            let client = xfer.active_client();
            let client_slice = range_slice(&buf, chunk.start, range_filter.skip, range_filter.send);
            if !client_slice.is_empty() {
                match write_all_to_stream_rated(
                    client,
                    client_slice,
                    &mut xfer.client_rate_checker,
                    RateCheckDirection::Client,
                    config.http_timeout,
                )
                .await
                {
                    Ok(()) => xfer.note_client_bytes(client_slice.len()),
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
                        xfer.client_status = ClientStatus::Disconnected;
                    }
                    Err(err) if is_peer_disconnect(&err) => xfer.client_disconnected(),
                    Err(err) => return Err(BodyTransferError::client(err)),
                }
            }
        }
    }

    Ok(xfer.finish())
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
pub(super) async fn splice_proxy_body_tls(
    upstream: &mut UpstreamConn,
    client: Option<&TcpStream>,
    cache_file: &tokio::fs::File,
    content_length: u64,
    file_start_offset: i64,
    dbarrier: DownloadBarrier,
    range_filter: &SpliceRangeFilter,
    cache_path: &Path,
) -> Result<BodyOutcome, BodyTransferError> {
    let mut xfer = BodyTransfer::new(
        client,
        dbarrier,
        range_filter,
        cache_path,
        content_length,
        file_start_offset,
    );

    let config = global_config();

    // `Vec::with_capacity` reserves uninitialized backing storage; `read_buf`
    // writes into the spare capacity via `BufMut` so the buffer never has
    // to be zero-initialized before being overwritten by upstream data.
    let mut read_buf: Vec<u8> = Vec::with_capacity(TLS_READ_BUF_SIZE);

    // One pinned re-armable sleep per body for the http_timeout deadline
    // and one for the 1 s rate-check tick — the previous version built two
    // fresh `Timeout` futures per chunk (see `wait_socket_rated` for the
    // same pattern and rationale).
    let outer = tokio::time::sleep(config.http_timeout);
    tokio::pin!(outer);
    let tick = tokio::time::sleep(RATE_TICK_PERIOD);
    tokio::pin!(tick);

    while xfer.remaining > 0 {
        xfer.check_upstream_rate().await?;

        // Step 1: async read from TLS stream into userspace buffer
        // The outer http_timeout ensures a fully stalled connection is killed even if
        // rate_check_timeframe > http_timeout.
        debug_assert_eq!(
            read_buf.capacity(),
            TLS_READ_BUF_SIZE,
            "buffer capacity should remain constant"
        );
        read_buf.clear();
        let to_read = std::cmp::min(xfer.remaining, TLS_READ_BUF_SIZE as u64);
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
                    () = &mut tick, if xfer.rate_checker.is_some() => {
                        let rc = xfer
                            .rate_checker
                            .as_mut()
                            .expect("guarded by rate_checker.is_some()");
                        rc.add(0);
                        if let Some(rate) = rc.check_fail(RateCheckDirection::Upstream) {
                            return Err(BodyTransferError::upstream(
                                xfer.take_barrier().abort_with_rate_timeout(rate).await,
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

        // Determine how this chunk overlaps with the client range.
        let chunk = xfer.note_chunk(got);

        // Write the full chunk to cache via pwrite first, so concurrent
        // clients see progress without being gated on this client's send
        // speed.
        xfer.write_cache_chunk(cache_file, &mut read_buf, got)
            .await?;

        // Then send the overlap with the client range (may be slow)
        let client_slice = range_slice(
            &read_buf[..got],
            chunk.start,
            range_filter.skip,
            range_filter.send,
        );
        if matches!(xfer.client_status, ClientStatus::Active) && !client_slice.is_empty() {
            write_client_or_demote(&mut xfer, client_slice)
                .await
                .map_err(BodyTransferError::client)?;
            xfer.maybe_demote().await?;
        }
    }

    Ok(xfer.finish())
}

/// Write `slice` to the client with rate checking, translating client
/// failures into [`ClientStatus`] transitions instead of hard errors:
/// the cache already holds these bytes, so a slow or gone client must
/// not abort the download (late joiners depend on it).
///
/// Mirrors the `tee_and_splice` client-splice semantics: a client
/// rate-check trip after progress leaves `DemoteRequested` (the caller
/// adjudicates via [`BodyTransfer::maybe_demote`]), a peer disconnect
/// leaves `Disconnected` (bumping `CLIENT_DISCONNECTED_MID_BODY`), and a
/// rated wait timeout abandons the client (`Disconnected`, no metric — the
/// timeout counters were already bumped at rejection) so the download
/// continues cache-only. Only unexpected I/O errors are returned as
/// `Err`.
async fn write_client_or_demote(xfer: &mut BodyTransfer<'_>, slice: &[u8]) -> std::io::Result<()> {
    // Only ever called with the client established as `Active`.
    let client = xfer.active_client();
    let mut written = 0;
    while written < slice.len() {
        // `try_write` clears tokio's cached writability itself on
        // `WouldBlock`, so the rated wait below parks properly.
        match client.try_write(&slice[written..]) {
            Ok(n) => {
                written += n;
                xfer.note_client_bytes(n);
                if let Some(rc) = &mut xfer.client_rate_checker {
                    rc.add(n);
                    if rc.check_fail(RateCheckDirection::Client).is_some() {
                        // Client RC tripped — the cache already has the
                        // bytes, hand off to the caller for demote
                        // adjudication.
                        xfer.request_demote();
                        return Ok(());
                    }
                }
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                match wait_writable_rated(
                    client,
                    &mut xfer.client_rate_checker,
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
                        xfer.client_status = ClientStatus::Disconnected;
                        return Ok(());
                    }
                    Err(err) if is_peer_disconnect(&err) => {
                        xfer.client_disconnected();
                        return Ok(());
                    }
                    Err(err) => return Err(err),
                }
            }
            Err(err) if is_peer_disconnect(&err) => {
                xfer.client_disconnected();
                return Ok(());
            }
            Err(err) => return Err(err),
        }
    }

    Ok(())
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
    let std_file = match nofollow_options().read(true).open(&cache_path) {
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
    /// No client was ever attached (parallel-hack nudge): cache-only from
    /// the first byte. Unlike [`Self::Disconnected`] there is no metric and
    /// no log line -- nothing was lost -- and
    /// [`BodyOutcome::client_disconnected`] stays false. Every client-facing
    /// step branches on `Active`, so this needs no arms of its own.
    Absent,
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
/// drained and the client is left in `ClientStatus::DemoteRequested` so the
/// caller ([`BodyTransfer::maybe_demote`]) can either promote it to
/// `ClientStatus::Demoted` (spawn a file-serve task) or abort the splice with
/// an upstream-rate timeout when the upstream is the actual bottleneck.
async fn tee_and_splice(
    xfer: &mut BodyTransfer<'_>,
    upstream_pipe_rx: &pipe::Receiver,
    cache_pipe_rx: &pipe::Receiver,
    cache_pipe_tx: &pipe::Sender,
    cache_file: &tokio::fs::File,
    got: usize,
) -> Result<(), BodyTransferError> {
    let mut remaining = got;

    while remaining > 0 {
        if matches!(xfer.client_status, ClientStatus::Active) {
            // The client socket, which `Active` guarantees is there.
            let client = xfer.active_client();
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

            // Step 3: splice pipe_B → cache file first (fast, local disk I/O),
            // notifying concurrent clients that new data is on disk.
            xfer.splice_cache_chunk(cache_pipe_rx, cache_file, teed)
                .await?;

            // Step 4: splice pipe_A → client (may be slow, but no longer blocks cache)
            // pipe_A always has data on entry (just filled by tee), so try the
            // splice optimistically and only park on EAGAIN. This keeps
            // `wait_writable_rated`'s rc.add(0) ticks and http_timeout intact
            // — they only run when the client is actually back-pressuring,
            // not on every busy iteration where pipe-readable would otherwise
            // win the `select!` race and cancel them mid-flight.
            // Tracks how many of the just-teed bytes are still sitting in
            // `pipe_A` waiting to be spliced to the client. Distinct from the
            // transfer's `client_remaining` (response-level total).
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
                        xfer.client_disconnected();
                        drain_pipe(upstream_pipe_rx, teed_remaining)
                            .await
                            .map_err(BodyTransferError::proxy)?;
                        break;
                    }
                    Ok(n) => {
                        teed_remaining -= n;
                        xfer.note_client_bytes(n);
                        if let Some(rc) = &mut xfer.client_rate_checker {
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

                                xfer.request_demote();
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
                                &mut xfer.client_rate_checker,
                                RateCheckDirection::Client,
                                global_config().http_timeout,
                            ) => match w {
                                Ok(()) => {}
                                // Rate-stall / HTTP per-op timeout on the client
                                // write: abandon the client but keep the download
                                // alive for the cache and the late joiners, like
                                // every sibling delivery site. Propagating here
                                // would drop the barrier and truncate every
                                // joiner's body -- a stalled client must not
                                // abort a shared transfer.
                                Err(err) if err.kind() == ErrorKind::TimedOut => {
                                    info!(
                                        "splice proxy: client {} timed out during zero-copy body; abandoning the client:  {}",
                                        client
                                            .peer_addr()
                                            .map_or_else(|_| String::from("<unknown>"), |a| a.to_string()),
                                        ErrorReport(&err)
                                    );
                                    xfer.client_status = ClientStatus::Disconnected;
                                    drain_pipe(upstream_pipe_rx, teed_remaining)
                                        .await
                                        .map_err(BodyTransferError::proxy)?;
                                    break;
                                }
                                Err(err) => return Err(BodyTransferError::client(err)),
                            },
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
            // Client is absent, gone or demoted — splice pipe_A directly to
            // cache (no tee needed)
            xfer.splice_cache_chunk(upstream_pipe_rx, cache_file, remaining)
                .await?;
            remaining = 0;
        }
    }

    Ok(())
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
pub(super) fn range_slice(
    buf: &[u8],
    buf_file_start: u64,
    range_start: u64,
    range_len: u64,
) -> &[u8] {
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
        // Optimistic-then-park: the bytes to drain are already sitting in
        // the pipe (nothing else feeds it while a chunk is being fanned
        // out), and the caller may have just cleared tokio's readiness
        // cache for it. Parking on `readable()` first would then wait for
        // an edge event no writer will ever produce; splice first and only
        // park on a genuine EAGAIN.
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
                rx.readable().await?;
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

#[cfg(test)]
mod tests {
    use nix::fcntl::{FcntlArg, fcntl};

    use super::*;

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
}
