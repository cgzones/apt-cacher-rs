//! Body transfer for the splice proxy: the zero-copy loop
//! [`splice_proxy_body`] (socket -> pipe -> tee -> client + cache file) and
//! the userspace-TLS loop [`splice_proxy_body_tls`], both keeping only their
//! read and deliver steps while every shared piece lives on [`BodyTransfer`]
//! and comes back as [`BodyOutcome`]. Also owns client demotion to file
//! serving ([`write_client_or_demote`], [`spawn_file_serve_task`],
//! [`DemotedClientHandle`]), the [`SpliceRangeFilter`] applied to the client
//! stream, [`BodyTransferError`]/[`BodyFailureSide`] attribution, and the
//! pipe and `/dev/null` helpers ([`create_pipe`], [`drain_pipe`],
//! [`drain_pipe_to_file`], [`range_slice`]). [`CacheBatch`] is the zero-copy
//! loop's cache-file sink: `pipe_B` and the policy for when its teed bytes are
//! drained to the file.
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
    future::Future as _,
    io::ErrorKind,
    ops::Range,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd},
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
    task::Poll,
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

/// The client's peer address for a log line. The three client-abandoned
/// lines below name the client this way rather than through `ClientInfo`,
/// which the body loops do not carry; a socket already torn down reports
/// `<unknown>`.
fn peer_addr_for_log(client: &TcpStream) -> String {
    client
        .peer_addr()
        .map_or_else(|_err| String::from("<unknown>"), |addr| addr.to_string())
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
/// unarmed; the socket itself is reachable only through
/// [`ClientStatus::client_to_write`], so the client-less form needs no arms
/// of its own.
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
    client_status: ClientStatus<'a>,
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
    cache_path: &'a Path,
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
        let rate_checker = RateChecker::from_config(config);
        let client_rate_checker = client.and_then(|_stream| RateChecker::from_config(config));

        Self {
            counter,
            dbarrier: Some(dbarrier),
            rate_checker,
            client_rate_checker,
            remaining: content_length,
            file_offset: file_start_offset,
            client_status: client.map_or(ClientStatus::Absent, ClientStatus::Active),
            bytes_done: 0,
            client_file_pos: u64::try_from(file_start_offset)
                .expect("file_start_offset is non-negative by construction")
                + range_filter.skip,
            client_remaining: range_filter.send,
            demoted_handle: None,
            range_filter,
            cache_path,
        }
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
    /// range it covers. `BYTES_DOWNLOADED_UPSTREAM` is not bumped here but
    /// where the bytes arrive, in the accumulation loops: a chunk can fail
    /// between arriving and being noted, and the exit salvage that lands it
    /// then must not have to know whether it was counted.
    ///
    /// The upstream RC is fed up-front (the bytes have already arrived) so
    /// any `check_fail` later in this iteration -- in particular the
    /// `DemoteRequested` adjudication in [`Self::maybe_demote`] -- sees the
    /// freshest window. Without this the upstream RC would still be one
    /// chunk behind the client RC at the moment a slow upstream causes the
    /// client check to trip.
    fn note_chunk(&mut self, got: usize) -> Range<u64> {
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

    /// Drain a pipe into the cache file at the current offset and notify
    /// concurrent clients. Count-free like [`drain_pipe_to_file`]: the pipe
    /// holds exactly the bytes to land.
    async fn drain_pipe_to_cache(
        &mut self,
        rx: &pipe::Receiver,
        cache_file: &tokio::fs::File,
    ) -> Result<(), BodyTransferError> {
        let landed = drain_pipe_to_file(rx, cache_file, &mut self.file_offset)
            .await
            .map_err(BodyTransferError::cache)?;
        self.barrier().ping_batched(landed as u64);
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
    fn request_demote(&mut self, client: &'a TcpStream) {
        self.client_status = ClientStatus::DemoteRequested {
            client,
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
            client,
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
                client,
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
    let mut cache = CacheBatch::new(&cache_pipe_receiver, &cache_pipe_sender);

    // The one exit: whatever the loop leaves in either pipe reaches the cache
    // file here, on success as the last flush and on failure as the salvage.
    let driven = drive_batches(
        &mut xfer,
        &mut cache,
        upstream,
        &upstream_pipe_sender,
        &mut upstream_pipe_receiver,
        cache_file,
    )
    .await;
    match driven {
        Ok(()) => cache.flush(&mut xfer, cache_file).await?,
        Err(err) => {
            cache
                .salvage(&mut xfer, &upstream_pipe_receiver, cache_file)
                .await;
            return Err(err);
        }
    }

    Ok(xfer.finish())
}

/// The batch loop of [`splice_proxy_body`]: pull a batch from upstream into
/// `pipe_A`, fan it out, repeat until the body is exhausted.
///
/// Split out so that every way the loop can fail -- the upstream-rate gate,
/// the rated park, a terminal splice error, a client or cache failure inside
/// the fan-out -- returns through the one [`CacheBatch::salvage`] at the call
/// site. No failure path in here has to remember what either pipe holds.
async fn drive_batches(
    xfer: &mut BodyTransfer<'_>,
    cache: &mut CacheBatch<'_>,
    upstream: ZeroCopyUpstream<'_>,
    upstream_pipe_sender: &pipe::Sender,
    upstream_pipe_receiver: &mut pipe::Receiver,
    cache_file: &tokio::fs::File,
) -> Result<(), BodyTransferError> {
    #[cfg(feature = "ktls")]
    let upstream_is_ktls = upstream.ktls;
    let upstream = upstream.tcp;

    let config = global_config();

    // Budget for draining kTLS control records that arrive mid-stream (e.g. a
    // late NewSessionTicket) — see the drain-retry arm in the splice loop.
    // Multiple bursts over a long download are plausible; each drain consumes
    // a whole burst.
    #[cfg(feature = "ktls")]
    let mut ktls_drain_retries: u32 = 8;

    let range_filter = xfer.range_filter;
    // Only the kTLS control-record arms name the path.
    #[cfg(feature = "ktls")]
    let cache_path = xfer.cache_path;
    let client_skip = range_filter.skip;
    let client_range_end = range_filter.skip + range_filter.send;

    while xfer.remaining > 0 {
        // `pipe_A` is empty here -- every fan-out consumes its whole batch --
        // so from now until the fan-out touches it, whatever the accumulation
        // puts there belongs right after `pipe_B`'s pending bytes. Staging
        // *before* the accumulation, not after, is what keeps a batch that
        // ends in EOF or a splice error salvageable.
        cache.stage();
        xfer.check_upstream_rate().await?;

        // Cap the batch at the next client-range edge so a batch is either
        // wholly inside or wholly outside the range: accumulating across an
        // edge would push up to a whole pipe through the userspace boundary
        // path below. `bytes_done` does not move during the accumulation --
        // `note_chunk` runs once, after it -- so the cap is computed here.
        // For a non-Range transfer (`skip == 0`, `send` spanning the whole
        // splice region) the edge is the end of the body and the cap is
        // `min(remaining, PIPE_BUFFER_SIZE)`.
        let edge = if xfer.bytes_done < client_skip {
            client_skip
        } else if xfer.bytes_done < client_range_end {
            client_range_end
        } else {
            u64::MAX
        };
        static_assert!(PIPE_BUFFER_SIZE > 0 && (PIPE_BUFFER_SIZE as u64) < usize::MAX as u64);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "PIPE_BUFFER_SIZE is checked to be < usize::MAX above"
        )]
        let batch_cap = xfer
            .remaining
            .min(PIPE_BUFFER_SIZE as u64)
            .min(edge - xfer.bytes_done) as usize;

        // Step 1: splice upstream → pipe_A, accumulating until the socket runs
        // dry or the batch cap is reached.
        // Both fds are non-blocking; splice() never waits on I/O and reads
        // kernel buffer state directly rather than Tokio's userspace ready-flag.
        // Try the syscall optimistically and only park on EAGAIN — that way the
        // rated wait (with its rc.add(0) ticks and http_timeout budget) only
        // runs when we're actually about to park, instead of being cancelled
        // mid-flight by `select!` on every busy iteration.
        //
        // Accumulating is what keeps the fan-out off the per-record treadmill:
        // a kTLS upstream hands back exactly one TLS record (~1378 bytes) per
        // splice(2) however much is queued, so one fan-out per splice would
        // mean one tee, one blocking-pool splice-to-file and one client splice
        // per record. Never park to fill the pipe, though -- the
        // EAGAIN-with-bytes break below is what keeps the loop streaming
        // instead of turning a sub-cap download into store-and-forward.
        //
        // A terminal error simply returns, whatever the batch already holds:
        // the bytes in `pipe_A` were consumed from the socket, and the
        // caller's `CacheBatch::salvage` lands them in the `.partial` on the
        // way out. That is why EOF is reported at once instead of fanning the
        // partial batch out first -- the client's response is truncated either
        // way, and the cache file is what a later attempt resumes from.
        let mut got: usize = 0;
        loop {
            let budget = batch_cap - got;
            if budget == 0 {
                // Batch cap reached, or the body is exhausted. `batch_cap` is
                // at least one byte while `remaining > 0`, so `got > 0` here.
                break;
            }

            let res = splice(
                upstream,
                None,
                upstream_pipe_sender,
                None,
                budget,
                SpliceFFlags::SPLICE_F_MOVE | SpliceFFlags::SPLICE_F_MORE,
            );

            let _: Never = match res {
                Ok(0) => {
                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                    return Err(BodyTransferError::upstream(std::io::Error::new(
                        ErrorKind::UnexpectedEof,
                        format!(
                            "splice proxy: upstream closed prematurely (remaining={}, batched={got}, budget={budget})",
                            xfer.remaining
                        ),
                    )));
                }
                Ok(n) => {
                    metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);
                    got += n;
                    continue;
                }
                Err(nix::errno::Errno::EINTR) => continue,
                // The socket ran dry and the batch already holds bytes: fan
                // them out now instead of parking. With `got == 0` this falls
                // through to the park arm below, so the rated wait keeps
                // exactly its old meaning -- it runs when the transfer is
                // genuinely stalled, never mid-batch.
                Err(nix::errno::Errno::EAGAIN) if got > 0 => break,
                // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                Err(nix::errno::Errno::EAGAIN) => {
                    // We can't tell from EAGAIN which side is the blocker, so
                    // clear both caches and wake on whichever next produces a
                    // fresh epoll event. The third arm is the batch-age
                    // bound of [`CacheBatch`]: a stale batch is flushed
                    // *during* the park, not merely checked before it, so a
                    // client joining a long stall never reads a file more
                    // than `MAX_BATCH_AGE` behind. The flush restarts the
                    // rated wait, so its http_timeout then counts from the
                    // flush rather than the last byte; that happens at most
                    // once per park (the batch is empty afterwards) and
                    // within `MAX_BATCH_AGE` of the park's start, which
                    // bounds the slack by the same constant.
                    clear_tcp_readable_cache(upstream);
                    clear_pipe_writable_cache(upstream_pipe_sender);
                    let batch_is_stale = tokio::select! {
                        r = wait_readable_rated(
                            upstream,
                            &mut xfer.rate_checker,
                            RateCheckDirection::Upstream,
                            config.http_timeout,
                        ) => {
                            r.map_err(BodyTransferError::upstream)?;
                            false
                        }
                        w = upstream_pipe_sender.writable() => {
                            w.map_err(BodyTransferError::proxy)?;
                            false
                        }
                        () = cache.until_stale(), if !cache.is_empty() => true,
                    };
                    if batch_is_stale {
                        cache.flush(xfer, cache_file).await?;
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
        }
        debug_assert!(got > 0, "a batch only ends with bytes; every failure returns");

        // Determine how this chunk overlaps with the client range.
        let chunk = xfer.note_chunk(got);
        debug_assert!(
            chunk.end <= client_skip
                || chunk.start >= client_range_end
                || (chunk.start >= client_skip && chunk.end <= client_range_end),
            "the batch cap keeps every chunk on one side of both client-range edges"
        );

        if let Some(client) = xfer.client_status.client_to_write()
            && chunk.end > client_skip
            && chunk.start < client_range_end
        {
            if chunk.start >= client_skip && chunk.end <= client_range_end {
                // Chunk is entirely inside client range — normal tee
                tee_and_splice(xfer, upstream_pipe_receiver, cache, cache_file, got).await?;
                xfer.maybe_demote().await?;
                continue;
            }

            // Boundary chunk -- read into userspace, slice for client, pwrite
            // for cache. The batch cap above stops a batch at a range edge, so
            // this is unreachable in practice; it stays as the release-mode
            // fail-safe, because a wrong cap would otherwise tee out-of-range
            // bytes straight to the client and corrupt a 206. Once the read
            // starts, whatever is left in `pipe_A` is a tail whose head lives
            // in `buf`, so the salvage must not land it.
            cache.unstage();
            let mut buf = read_pipe_to_buf(upstream_pipe_receiver, got)
                .await
                .map_err(BodyTransferError::proxy)?;

            debug_assert_eq!(buf.len(), got, "read_pipe_to_buf reads exactly `got` bytes");

            // Write full chunk to cache via pwrite first, so concurrent clients
            // see progress without being gated on the first client's send speed.
            // The pwrite lands at `file_offset`, so the batched `pipe_B` bytes
            // (which come earlier in the body) have to be there already.
            cache.flush(xfer, cache_file).await?;
            xfer.write_cache_chunk(cache_file, &mut buf, got).await?;

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
                            peer_addr_for_log(client),
                            ErrorReport(&err)
                        );
                        xfer.client_status = ClientStatus::Disconnected;
                    }
                    Err(err) if is_peer_disconnect(&err) => xfer.client_disconnected(),
                    Err(err) => return Err(BodyTransferError::client(err)),
                }
            }
        } else {
            // Chunk is entirely outside the client range, or the client is
            // absent/gone/demoted — cache only. `pipe_A` holds exactly the
            // batch, so draining it is the chunk write.
            cache
                .write_through(xfer, upstream_pipe_receiver, cache_file)
                .await?;
        }
    }

    Ok(())
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

    // Set once by whichever arm ends the loop; the buffer is handed back to
    // the caller after it, on every path.
    let mut outcome: std::io::Result<()> = Ok(());

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
                outcome = Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "pwrite returned 0",
                ));
                break;
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
                outcome = Err(errno_to_io_error(errno, "pwrite(2) failed"));
                break;
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
    if outcome.is_ok() {
        debug_assert_eq!(
            written, size,
            "should have written the requested number of bytes"
        );
    } else {
        debug_assert!(
            written < size,
            "should have written less than the requested number of bytes"
        );
    }

    outcome
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
/// Same exit shape as [`splice_proxy_body`]: the read loop returns the
/// moment it sees an error, and the one exit here lands whatever the buffer
/// still holds ([`salvage_read_buf`]). The buffer holds exactly the bytes
/// not yet in the cache file -- [`drive_reads`] takes it away before the
/// client delivery and hands it back empty -- so that salvage can never
/// write a byte twice.
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

    // `Vec::with_capacity` reserves uninitialized backing storage; `read_buf`
    // writes into the spare capacity via `BufMut` so the buffer never has
    // to be zero-initialized before being overwritten by upstream data.
    let mut read_buf: Vec<u8> = Vec::with_capacity(TLS_READ_BUF_SIZE);

    let driven = drive_reads(&mut xfer, upstream, &mut read_buf, cache_file).await;
    if let Err(err) = driven {
        salvage_read_buf(&mut xfer, &mut read_buf, cache_file).await;
        return Err(err);
    }

    Ok(xfer.finish())
}

/// The read loop of [`splice_proxy_body_tls`]: accumulate a batch into
/// `read_buf`, write it to the cache file, deliver it, repeat until the body
/// is exhausted.
///
/// Every failure returns straight out, leaving the not-yet-written bytes in
/// `read_buf` for the caller's [`salvage_read_buf`]; nothing in here has to
/// remember them.
async fn drive_reads(
    xfer: &mut BodyTransfer<'_>,
    upstream: &mut UpstreamConn,
    read_buf: &mut Vec<u8>,
    cache_file: &tokio::fs::File,
) -> Result<(), BodyTransferError> {
    let config = global_config();
    let range_filter = xfer.range_filter;

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
        debug_assert!(
            read_buf.is_empty() && read_buf.capacity() == TLS_READ_BUF_SIZE,
            "the buffer is handed back empty, at its original capacity"
        );
        let to_read = std::cmp::min(xfer.remaining, TLS_READ_BUF_SIZE as u64);
        outer
            .as_mut()
            .reset(tokio::time::Instant::now() + config.http_timeout);

        loop {
            let filled = read_buf.len();
            let budget = to_read - filled as u64;
            if budget == 0 {
                // Buffer full, or the body is exhausted.
                break;
            }
            let mut taken = (&mut *upstream).take(budget);
            let read_fut = taken.read_buf(&mut *read_buf);
            tokio::pin!(read_fut);

            if filled > 0 {
                // Bytes in hand: probe the stream once and hand them on the
                // moment it runs dry. One `poll_read` on a `TlsStream` yields
                // about one 16 KiB TLS record however much capacity it is
                // offered, so without this the loop paid a `pwrite` and a
                // client write per record. Never *park* to fill the buffer,
                // though -- that would turn a sub-buffer download into
                // store-and-forward. (Dropping a `Pending` `read_buf` future
                // loses nothing: it polls the stream once and any decrypted
                // plaintext stays in the TLS session's own buffer.)
                match std::future::poll_fn(|cx| Poll::Ready(read_fut.as_mut().poll(cx))).await {
                    Poll::Pending => break,
                    Poll::Ready(Ok(0)) => return Err(tls_premature_eof()),
                    Poll::Ready(Ok(n)) => {
                        metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);
                        continue;
                    }
                    Poll::Ready(Err(err)) => return Err(BodyTransferError::upstream(err)),
                }
            }

            // Empty buffer: this is the transfer's genuine stall point, so it
            // keeps the rate tick and the `http_timeout` deadline.
            let n = loop {
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
            };
            if n == 0 {
                return Err(tls_premature_eof());
            }
            metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(n as u64);
        }
        let got = read_buf.len();
        debug_assert!(got > 0, "a batch only ends with bytes; every failure returns");

        // Determine how this chunk overlaps with the client range.
        let chunk = xfer.note_chunk(got);

        // Write the full chunk to cache via pwrite first, so concurrent
        // clients see progress without being gated on this client's send
        // speed.
        xfer.write_cache_chunk(cache_file, read_buf, got).await?;

        // From here on the bytes are on disk: take them out of `read_buf` for
        // the delivery, so a failure in it leaves the buffer empty and the
        // exit salvage has nothing to write twice. The allocation comes back
        // at the end of the iteration.
        let landed = std::mem::take(read_buf);
        let client_slice = range_slice(&landed[..got], chunk.start, range_filter.skip, range_filter.send);
        if let Some(client) = xfer.client_status.client_to_write()
            && !client_slice.is_empty()
        {
            write_client_or_demote(xfer, client, client_slice)
                .await
                .map_err(BodyTransferError::client)?;
            xfer.maybe_demote().await?;
        }
        *read_buf = landed;
        read_buf.clear();
    }

    Ok(())
}

/// The upstream closed before delivering `content_length` bytes.
fn tls_premature_eof() -> BodyTransferError {
    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
    BodyTransferError::upstream(std::io::Error::new(
        ErrorKind::UnexpectedEof,
        "splice proxy: TLS upstream closed prematurely",
    ))
}

/// Land the bytes a failing transfer left in `read_buf` in the cache file:
/// the userspace mirror of `CacheBatch::salvage`, for the one exit of
/// [`splice_proxy_body_tls`].
///
/// They were consumed from the upstream socket, so nothing delivers them
/// again; without this the `.partial` a later attempt resumes from would be
/// short of what was received. `read_buf` holds only bytes not yet written
/// (see [`drive_reads`]), so nothing lands twice. The barrier is not pinged:
/// on the upstream-rate abort path it is already consumed, and the joiners
/// it would wake have been told the download failed. Nothing is counted
/// either: the bytes were counted as downloaded when they arrived, whether
/// or not `note_chunk` got to run. A failed salvage is reported here and
/// does not replace the transfer's own error.
async fn salvage_read_buf(
    xfer: &mut BodyTransfer<'_>,
    read_buf: &mut Vec<u8>,
    cache_file: &tokio::fs::File,
) {
    let got = read_buf.len();
    if got == 0 {
        return;
    }
    match pwrite_buf_to_file(cache_file, read_buf, got, xfer.file_offset).await {
        Ok(()) => {
            xfer.file_offset +=
                i64::try_from(got).expect("a chunk is bounded by its read buffer, which fits in i64");
        }
        Err(err) => {
            let _logged = Logged::cache_io_failure(format_args!(
                "splice proxy: failed to land the last received bytes of `{}` in the partial file; a later attempt resumes from a shorter partial:  {}",
                xfer.cache_path.display(),
                ErrorReport(&err)
            ));
        }
    }
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
async fn write_client_or_demote<'a>(
    xfer: &mut BodyTransfer<'a>,
    client: &'a TcpStream,
    slice: &[u8],
) -> std::io::Result<()> {
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
                        xfer.request_demote(client);
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
                            peer_addr_for_log(client),
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

/// The zero-copy loop's cache-file sink: `pipe_B` plus the policy for when
/// the teed bytes sitting in it are drained to the file.
///
/// Draining `pipe_B` after every `tee` costs one blocking-pool round trip per
/// fan-out ([`drain_pipe_to_file`] runs on the pool), which on a kTLS
/// upstream used to mean one per TLS record. Letting the bytes sit turns that
/// into one per [`Self::FLUSH_THRESHOLD`]. The flush points, and why each
/// exists:
///
/// - the threshold, and the very first bytes of the transfer -- eager,
///   mirroring `DownloadBarrier::ping_batched`'s unbatched first ping: a
///   download below the threshold would otherwise put nothing on disk until
///   it finished, and a joiner or a demoted client, both of which read the
///   partial file, would see pure store-and-forward latency;
/// - `pipe_B` full, where the tee would otherwise park on a pipe nothing else
///   drains;
/// - before parking on a back-pressuring client: nothing grows the partial
///   while the loop waits there, so a slow client would otherwise throttle
///   every other reader;
/// - before the demotion hand-off: the file-serve task reads the partial
///   from `client_file_pos`;
/// - before anything else writes the cache file (the cache-only path's
///   direct `pipe_A` drain, the boundary chunk's `pwrite`):
///   `BodyTransfer::file_offset` is one cursor and the pending bytes come
///   earlier in the body ([`Self::write_through`] pairs the two drains);
/// - a batch older than [`Self::MAX_BATCH_AGE`] while parked for upstream.
///   That park is deliberately not an unconditional flush point: every batch
///   ends on an EAGAIN probe, so flushing there would give back all of the
///   batching, and joiners already blocked in `receiver.changed()` lose
///   nothing, since `ping_batched` wakes them at this granularity anyway. A
///   client that *joins* during the park reads the file's current size,
///   though, so the age bounds how far behind the received bytes that size
///   may be;
/// - loop end ([`Self::flush`] at the exit of `splice_proxy_body`), and the
///   exit [`Self::salvage`] on failure.
///
/// `pending` is a heuristic for that policy, never a splice count: the
/// drains empty the pipe whatever it says, so a drift could only mis-time a
/// flush, not wedge one.
///
/// The one piece of `pipe_A` state kept here is [`Self::stage`]: whether
/// `pipe_A` still holds exactly the bytes that belong at the cursor after
/// the pending `pipe_B` ones, which is what makes it salvageable. That is
/// true from the start of an accumulation until the fan-out touches the
/// batch, and false as soon as a `tee` duplicates it into `pipe_B` (the
/// untee'd tail is still unique, but the teed head is not) or the boundary
/// path starts moving it into userspace (its head is then in a buffer that
/// dies with the frame, so the tail alone would land at the wrong offset).
struct CacheBatch<'a> {
    rx: &'a pipe::Receiver,
    tx: &'a pipe::Sender,
    /// Bytes teed into `pipe_B` since the last flush.
    pending: usize,
    /// When the oldest byte of the current batch was teed; `None` while the
    /// batch is empty.
    queued_at: Option<coarsetime::Instant>,
    flushed_once: bool,
    /// `pipe_A` holds an untouched batch that [`Self::salvage`] may land.
    pipe_a_staged: bool,
}

impl<'a> CacheBatch<'a> {
    /// Matches `PIPE_BUFFER_SIZE` (so a full `pipe_B` is exactly a due
    /// batch) and `DownloadBarrier::ping_batched`'s threshold (so the file
    /// grows on the same granularity joiners are woken at).
    const FLUSH_THRESHOLD: usize = PIPE_BUFFER_SIZE as usize;

    /// How stale the on-disk file may get while the loop is parked waiting
    /// for upstream. Long enough that a saturated upstream fills a whole
    /// batch first (so the batching is untouched where it pays), short
    /// enough that a client joining a trickling download reads a file that
    /// is current to within a fraction of a second.
    const MAX_BATCH_AGE: coarsetime::Duration = coarsetime::Duration::from_millis(200);

    const fn new(rx: &'a pipe::Receiver, tx: &'a pipe::Sender) -> Self {
        Self {
            rx,
            tx,
            pending: 0,
            queued_at: None,
            flushed_once: false,
            pipe_a_staged: false,
        }
    }

    /// `pipe_A` is empty and about to be filled by the accumulation loop;
    /// until the fan-out touches the batch, everything in it is salvageable.
    const fn stage(&mut self) {
        self.pipe_a_staged = true;
    }

    /// The fan-out is about to move the batch out of `pipe_A` in a way that
    /// leaves what remains there unsalvageable (see the type doc).
    const fn unstage(&mut self) {
        self.pipe_a_staged = false;
    }

    const fn is_empty(&self) -> bool {
        self.pending == 0
    }

    /// Account `teed` bytes just duplicated into `pipe_B`. From here on
    /// `pipe_A` holds copies of them until the client splice consumes them,
    /// so it is no longer salvageable.
    fn queue(&mut self, teed: usize) {
        self.unstage();
        self.pending += teed;
        self.queued_at.get_or_insert_with(coarsetime::Instant::now);
    }

    /// Drain `pipe_B` to the cache file and notify concurrent clients. A
    /// no-op while nothing is pending, so it is free to call at every point
    /// that needs the file current.
    async fn flush(
        &mut self,
        xfer: &mut BodyTransfer<'_>,
        cache_file: &tokio::fs::File,
    ) -> Result<(), BodyTransferError> {
        if self.pending == 0 {
            return Ok(());
        }
        self.pending = 0;
        self.queued_at = None;
        self.flushed_once = true;
        xfer.drain_pipe_to_cache(self.rx, cache_file).await
    }

    /// Flush once the batch is due: at the threshold, or on the very first
    /// bytes of the transfer.
    async fn flush_if_due(
        &mut self,
        xfer: &mut BodyTransfer<'_>,
        cache_file: &tokio::fs::File,
    ) -> Result<(), BodyTransferError> {
        if self.pending >= Self::FLUSH_THRESHOLD || !self.flushed_once {
            self.flush(xfer, cache_file).await?;
        }
        Ok(())
    }

    /// Write `pipe_A` straight to the cache file, after the pending `pipe_B`
    /// bytes that precede it in the body.
    async fn write_through(
        &mut self,
        xfer: &mut BodyTransfer<'_>,
        upstream_pipe_rx: &pipe::Receiver,
        cache_file: &tokio::fs::File,
    ) -> Result<(), BodyTransferError> {
        self.flush(xfer, cache_file).await?;
        xfer.drain_pipe_to_cache(upstream_pipe_rx, cache_file).await
    }

    /// Sleep until the current batch reaches [`Self::MAX_BATCH_AGE`]; for
    /// the `select!` of the upstream park, guarded by `!is_empty()`.
    fn until_stale(&self) -> tokio::time::Sleep {
        let age = self
            .queued_at
            .map_or(coarsetime::Duration::from_secs(0), |at| at.elapsed());
        tokio::time::sleep(Self::MAX_BATCH_AGE.saturating_sub(age).into())
    }

    /// Land everything a failing transfer left in the pipes in the cache
    /// file: the pending `pipe_B` bytes, then the batch still in `pipe_A` if
    /// it is still [staged](Self::stage).
    ///
    /// All of it was consumed from the upstream socket, so nothing delivers
    /// it again: dropping it would leave the `.partial` a later attempt
    /// resumes from short of what was actually received. This runs once, at
    /// the exit of `splice_proxy_body`, for every failure out of
    /// `drive_batches` -- so no failure path inside the loop has to remember
    /// the pipes, and neither does the accumulation loop, which reports an
    /// error the moment it sees one.
    ///
    /// An unstaged `pipe_A` is left alone rather than drained: once a batch
    /// has been teed, its head sits in `pipe_B` (or is on disk already) and
    /// landing `pipe_A` too would write it twice -- a `.partial` a later
    /// attempt resumes from at the wrong length. What is lost is the untee'd
    /// tail of one batch, which the resume re-fetches. Failures inside a
    /// fan-out are the rare case; a truncating upstream, the common one,
    /// fails in the accumulation loop with the batch staged and keeps it.
    ///
    /// The barrier is not pinged: on the upstream-rate abort path it is
    /// already consumed, and the joiners it would wake have been told the
    /// download failed. Nothing is counted either: every byte was counted
    /// as downloaded when it arrived, and `bytes_done` / `remaining`, which
    /// describe the fanned-out body, are not read after a failure.
    ///
    /// A failed salvage is reported here, with the on-disk path, and does not
    /// replace the transfer's own error: `file_offset` still describes what
    /// landed, so a shorter `.partial` is the only consequence.
    async fn salvage(
        self,
        xfer: &mut BodyTransfer<'_>,
        upstream_pipe_rx: &pipe::Receiver,
        cache_file: &tokio::fs::File,
    ) {
        if let Err(err) = self
            .salvage_into(upstream_pipe_rx, cache_file, &mut xfer.file_offset)
            .await
        {
            let _logged = Logged::cache_io_failure(format_args!(
                "splice proxy: failed to land the last received bytes of `{}` in the partial file; a later attempt resumes from a shorter partial:  {}",
                xfer.cache_path.display(),
                ErrorReport(&err)
            ));
        }
    }

    /// The drains of [`Self::salvage`], without the reporting.
    async fn salvage_into(
        self,
        upstream_pipe_rx: &pipe::Receiver,
        cache_file: &tokio::fs::File,
        file_offset: &mut i64,
    ) -> std::io::Result<()> {
        drain_pipe_to_file(self.rx, cache_file, file_offset).await?;
        if !self.pipe_a_staged {
            return Ok(());
        }
        drain_pipe_to_file(upstream_pipe_rx, cache_file, file_offset).await?;
        Ok(())
    }
}

/// Status of the first (splice) client after a tee+splice iteration.
///
/// The socket lives in the two variants that still own one, so "is there a
/// client to write to" and "where is it" are one question -- answered by
/// [`Self::client_to_write`], the only way to reach the socket at all.
#[derive(Clone, Copy)]
enum ClientStatus<'a> {
    /// Client is still connected and receiving data at acceptable speed.
    Active(&'a TcpStream),
    /// No client was ever attached (parallel-hack nudge): cache-only from
    /// the first byte. Unlike [`Self::Disconnected`] there is no metric and
    /// no log line -- nothing was lost -- and
    /// [`BodyOutcome::client_disconnected`] stays false.
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
        /// The socket the spawned file-serve task takes over.
        client: &'a TcpStream,
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

impl<'a> ClientStatus<'a> {
    /// The socket this transfer may still write body bytes to.  `None`
    /// once the client is absent, gone, or owned by a file-serve task --
    /// all of which mean "carry on cache-only".
    const fn client_to_write(self) -> Option<&'a TcpStream> {
        // `DemoteRequested` still holds the socket, but the bytes it owes are
        // the file-serve task's to send once `maybe_demote` hands it over;
        // every other non-`Active` state has nothing attached at all.
        match self {
            Self::Active(client) => Some(client),
            Self::Absent | Self::Disconnected | Self::DemoteRequested { .. } | Self::Demoted => {
                None
            }
        }
    }
}

/// Shared tee+splice fan-out: consume `got` bytes from `pipe_A`, duplicate to `pipe_B`,
/// splice `pipe_A→client` and, once the batch is due, `pipe_B→cache`.
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
    cache: &mut CacheBatch<'_>,
    cache_file: &tokio::fs::File,
    got: usize,
) -> Result<(), BodyTransferError> {
    let mut remaining = got;

    while remaining > 0 {
        if let Some(client) = xfer.client_status.client_to_write() {
            // Tee pipe_A → pipe_B, flush pipe_B → cache when the batch is
            // due, then splice pipe_A → client.

            // Step 2: tee pipe_A → pipe_B (duplicates without consuming from pipe_A)
            // Same optimistic-then-park pattern as Step 1: try tee first and
            // only `select!`-park on EAGAIN, after clearing both caches.
            let teed: usize = loop {
                let res = tee(upstream_pipe_rx, cache.tx, remaining, SpliceFFlags::empty());

                let _: Never = match res {
                    Ok(0) => {
                        return Err(BodyTransferError::proxy(std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "splice proxy: tee returned 0",
                        )));
                    }
                    Ok(n) => break n,
                    Err(nix::errno::Errno::EINTR) => continue,
                    // `pipe_B` is full: nothing but this loop drains it, so
                    // parking on its writability would hang. This is also the
                    // path that keeps the batch correct when `F_SETPIPE_SZ`
                    // failed and the pipe is smaller than
                    // `CacheBatch::FLUSH_THRESHOLD`.
                    Err(nix::errno::Errno::EAGAIN) if !cache.is_empty() => {
                        cache.flush(xfer, cache_file).await?;
                        continue;
                    }
                    // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                    Err(nix::errno::Errno::EAGAIN) => {
                        clear_pipe_readable_cache(upstream_pipe_rx);
                        clear_pipe_writable_cache(cache.tx);
                        tokio::select! {
                            r = upstream_pipe_rx.readable() => r.map_err(BodyTransferError::proxy)?,
                            w = cache.tx.writable() => w.map_err(BodyTransferError::proxy)?,
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

            // Step 3: hand the teed bytes to the cache batch, which drains
            // `pipe_B` to the file once the batch is due (see [`CacheBatch`]).
            // A due batch is written before the client splice below, so
            // concurrent clients still see progress without being gated on a
            // potentially slow first client.
            cache.queue(teed);
            cache.flush_if_due(xfer, cache_file).await?;

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

                                // The file-serve task the caller may spawn
                                // takes over from `client_file_pos` by reading
                                // the partial file, so every byte delivered so
                                // far has to be on disk first.
                                cache.flush(xfer, cache_file).await?;
                                xfer.request_demote(client);
                                break;
                            }
                        }

                        continue;
                    }
                    Err(nix::errno::Errno::EINTR) => continue,
                    // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                    Err(nix::errno::Errno::EAGAIN) => {
                        // About to park on a back-pressuring client. Land the
                        // batch first: a joiner reads the partial file, and
                        // nothing else grows it while this task waits here, so
                        // deferring would let one slow client throttle every
                        // other reader until it recovers, times out or is
                        // demoted. Parking on *upstream* is deliberately not a
                        // flush point -- see [`CacheBatch`].
                        cache.flush(xfer, cache_file).await?;
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
                                        peer_addr_for_log(client),
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
            // cache (no tee needed). The batch's `remaining` bytes are all
            // `pipe_A` holds, so draining it is exactly that write.
            cache
                .write_through(xfer, upstream_pipe_rx, cache_file)
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

/// Splice everything a pipe holds into the cache file at `file_offset`,
/// advance the offset by what landed, and return that count.
///
/// Count-free by design. Every caller wants the pipe emptied -- a batch on the
/// cache-only path, `pipe_B` after a tee, either pipe on the exit salvage --
/// and taking a byte count instead would make the caller's bookkeeping a
/// correctness input: a count larger than the pipe's contents waits for bytes
/// nobody will ever write (the write ends live in the caller's frame) and
/// wedges the download with every joiner behind its barrier. The pipe is
/// `O_NONBLOCK` (tokio owns it) and the destination is a regular file, which
/// never returns `EAGAIN`, so `EAGAIN` here means exactly "the pipe is empty"
/// and ends the drain; `Ok(0)` (write end closed and pipe empty) cannot happen
/// while the caller holds the write end, and ends it too.
///
/// One blocking-pool hop per call: splicing into a file is a disk write, and
/// the whole loop runs inside the closure rather than one splice per hop.
///
/// On an error the offset has still advanced by what landed before it, so
/// the caller's `.partial` accounting stays exact.
async fn drain_pipe_to_file(
    rx: &pipe::Receiver,
    file: &tokio::fs::File,
    file_offset: &mut i64,
) -> std::io::Result<usize> {
    let pipe_r_fd = rx.as_raw_fd();
    let file_fd = file.as_raw_fd();
    let start = *file_offset;

    let (landed, off, outcome) = tokio::task::spawn_blocking(move || {
        // SAFETY: pipe_r_fd is valid because the caller holds the OwnedFd,
        // and the spawn_blocking result is awaited without cancellation
        let src = unsafe { BorrowedFd::borrow_raw(pipe_r_fd) };
        // SAFETY: file_fd is valid because the caller holds a reference to the File,
        // and the spawn_blocking result is awaited without cancellation
        let dst = unsafe { BorrowedFd::borrow_raw(file_fd) };

        let mut off = start;
        let mut landed: usize = 0;
        let outcome = loop {
            static_assert!(PIPE_BUFFER_SIZE > 0);
            let res = splice(
                src,
                None,
                dst,
                Some(&mut off),
                PIPE_BUFFER_SIZE as usize,
                SpliceFFlags::SPLICE_F_MOVE,
            );
            match res {
                // EAGAIN/EWOULDBLOCK: see module-level static_assert.
                Ok(0) | Err(nix::errno::Errno::EAGAIN) => break Ok(()),
                Ok(n) => landed += n,
                Err(nix::errno::Errno::EINTR) => {}
                Err(err) => break Err(errno_to_io_error(err, "splice to cache file failed")),
            }
        };
        (landed, off, outcome)
    })
    .await
    .expect("spawn_blocking should not panic");

    debug_assert_eq!(
        off - start,
        i64::try_from(landed).expect("a pipe holds far less than i64::MAX bytes"),
        "the offset advances by exactly what landed"
    );
    *file_offset = off;
    outcome.map(|()| landed)
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

    /// A cache file for the salvage tests, plus its contents so far.
    struct ScratchFile {
        _dir: tempfile::TempDir,
        path: PathBuf,
        file: tokio::fs::File,
    }

    impl ScratchFile {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("salvage.partial");
            let file = tokio::fs::File::from_std(
                std::fs::File::create(&path).expect("create the scratch file"),
            );
            Self {
                _dir: dir,
                path,
                file,
            }
        }

        fn contents(&self) -> Vec<u8> {
            std::fs::read(&self.path).expect("read the scratch file")
        }
    }

    /// Put `bytes` into `pipe_A` the way the accumulation loop does: stage,
    /// then fill.
    fn accumulate(pipe_a_tx: &pipe::Sender, cache: &mut CacheBatch<'_>, bytes: &[u8]) {
        cache.stage();
        // A raw write, like the splice(2) that fills it for real: tokio's
        // `try_write` answers WouldBlock until the reactor has seen the pipe.
        let written = nix::unistd::write(pipe_a_tx.as_fd(), bytes).expect("write into pipe_A");
        assert_eq!(written, bytes.len(), "the batch fits in the pipe");
    }

    /// The reviewed P1: a batch that was teed into `pipe_B` and partly
    /// delivered must not be landed from `pipe_A` a second time. With
    /// `abcdefgh` teed and `abc` delivered, the salvage used to produce
    /// `abcdefghdefgh`, and a later resume started from that length.
    #[tokio::test]
    async fn salvage_does_not_land_a_batch_that_was_already_teed() {
        let (pipe_a_tx, pipe_a_rx) = create_pipe().expect("pipe_A");
        let (pipe_b_tx, pipe_b_rx) = create_pipe().expect("pipe_B");
        let scratch = ScratchFile::new();
        let mut cache = CacheBatch::new(&pipe_b_rx, &pipe_b_tx);

        accumulate(&pipe_a_tx, &mut cache, b"abcdefgh");
        // The fan-out: tee the whole batch, deliver three bytes to the
        // "client" (drain them), then fail before the rest is delivered.
        let teed = tee(&pipe_a_rx, &pipe_b_tx, 8, SpliceFFlags::empty()).expect("tee");
        assert_eq!(teed, 8);
        cache.queue(teed);
        drain_pipe(&pipe_a_rx, 3).await.expect("deliver three bytes");

        let mut file_offset = 0;
        cache
            .salvage_into(&pipe_a_rx, &scratch.file, &mut file_offset)
            .await
            .expect("salvage");

        assert_eq!(scratch.contents(), b"abcdefgh");
        assert_eq!(file_offset, 8);
    }

    /// The case the salvage exists for: the accumulation loop fails with a
    /// staged batch in `pipe_A`, behind bytes still pending in `pipe_B` from
    /// the previous batch. Both land, in body order.
    #[tokio::test]
    async fn salvage_lands_a_staged_batch_after_the_pending_bytes() {
        let (pipe_a_tx, pipe_a_rx) = create_pipe().expect("pipe_A");
        let (pipe_b_tx, pipe_b_rx) = create_pipe().expect("pipe_B");
        let scratch = ScratchFile::new();
        let mut cache = CacheBatch::new(&pipe_b_rx, &pipe_b_tx);

        // Previous batch: teed, fully delivered, its cache write deferred.
        accumulate(&pipe_a_tx, &mut cache, b"abc");
        let teed = tee(&pipe_a_rx, &pipe_b_tx, 3, SpliceFFlags::empty()).expect("tee");
        cache.queue(teed);
        drain_pipe(&pipe_a_rx, 3).await.expect("deliver the batch");
        // Current batch: accumulated, then the upstream fails.
        accumulate(&pipe_a_tx, &mut cache, b"defgh");

        let mut file_offset = 0;
        cache
            .salvage_into(&pipe_a_rx, &scratch.file, &mut file_offset)
            .await
            .expect("salvage");

        assert_eq!(scratch.contents(), b"abcdefgh");
        assert_eq!(file_offset, 8);
    }

    /// The boundary path moves the batch into userspace; a tail left in
    /// `pipe_A` after that has no head to follow and must stay there.
    #[tokio::test]
    async fn salvage_leaves_an_unstaged_tail_alone() {
        let (pipe_a_tx, pipe_a_rx) = create_pipe().expect("pipe_A");
        let (pipe_b_tx, pipe_b_rx) = create_pipe().expect("pipe_B");
        let scratch = ScratchFile::new();
        let mut cache = CacheBatch::new(&pipe_b_rx, &pipe_b_tx);

        accumulate(&pipe_a_tx, &mut cache, b"abcdefgh");
        cache.unstage();
        drain_pipe(&pipe_a_rx, 3).await.expect("the head went into a buffer");

        let mut file_offset = 0;
        cache
            .salvage_into(&pipe_a_rx, &scratch.file, &mut file_offset)
            .await
            .expect("salvage");

        assert!(scratch.contents().is_empty(), "the tail must not land");
        assert_eq!(file_offset, 0);
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
