//! The tail of a finished splice download: the commit, and what it reports.
//!
//! The order is the hyper backend's (`hyper_conn.rs::download_file`): the
//! connection task ends the download with [`CacheTarget::begin_rename`] --
//! the final ping, the `max_upstream_downloads` slot drop, the `Download ->
//! Verifying` flip and the watch sender's drop, none of which touch the disk
//! -- and everything after that (`fsync`, verify + rename, the `Download`
//! and `Delivery` rows, the completion line) is a [`CommitTail`]
//! built from the [`Committable`] that step returns. Its three callers are the
//! three ways a download finishes:
//!
//! - [`CommitTail::spawn`]: the streaming drive, which hands the tail to its
//!   own task as soon as upstream finishes. The returned [`ClientSettlement`]
//!   awaits any demoted writer on the connection task and sends its verdict
//!   for reporting; neither the commit nor the client waits for the other.
//! - [`CommitTail::finish`]: the detached download ([`super::detached`]),
//!   already off the connection, which runs the same steps in place.
//! - [`CommitTail::commit`] then [`Committed::report`]: the buffered volatile
//!   path ([`super::volatile`]), which commits *before* it serves -- its body
//!   is already in memory, so caching it costs the client nothing and must
//!   not depend on the client write -- and so only knows the client's fate
//!   afterwards.
//!
//! A demoted client (`body::spawn_file_serve_task`) is still writing this
//! response through a `dup(2)` of the connection's socket, so the connection
//! must not read its next request before that task ends. The task parks in
//! `receiver.changed()` with no timeout whenever it has drained the file but
//! still owes bytes, and its guaranteed wake-up is the watch sender's drop
//! inside `DownloadBarrier::begin_rename`. Awaiting the task while a
//! `DownloadBarrier` is still owned would therefore deadlock. That is why the
//! only await is [`ClientSettlement::settle`]: its token is returned only by
//! `CommitTail::spawn`, after `begin_rename` ran and the commit was spawned.
//! Cancellation drops the verdict sender, so the commit continues and the
//! reporter treats the delivery as lost.

use std::num::NonZero;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::oneshot;
use tracing::{error, info};

use crate::cache_layout::{CachedFlavor, ConnectionDetails};
use crate::database_task::{DatabaseCommand, DbCmdTransfer, TransferKind, send_db_command};
use crate::error::ErrorReport;
use crate::guards::RenameBarrier;
use crate::humanfmt::HumanFmt;
use crate::index_parser::StreamHasher;
use crate::partial_file::TempPath;
use crate::precise_instant::PreciseInstant;
use crate::{metrics, rate_log};

use super::CacheTarget;
use super::RateTimestamps;
use super::body::{ClientEnd, DeliveryResult};
use super::upstream::ConnLabel;

/// The three byte counts a completed download reports with.
#[derive(Clone, Copy)]
pub(super) struct CompletionBytes {
    /// The whole cached file, as the `Delivery` row records it.
    pub(super) total: NonZero<u64>,
    /// The wire body -- the remainder only, on a resume.
    pub(super) upstream: u64,
    /// Where the wire body started in the file; `0` unless resumed.
    pub(super) resume_offset: u64,
}

/// What the client's response promised, for a client that received all of
/// it: the payload of [`CompletionClient::Served`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Served {
    /// The response's `Content-Length`.
    pub(super) bytes: u64,
    /// Whether that response was a `206`; the `partial` flag of the
    /// `Delivery` row.
    pub(super) partial: bool,
}

/// What became of the client a completed download was fetched for; selects
/// the event wording and the client rate segment of the completion line,
/// and on the `Served` arm the `partial` flag of the `Delivery` row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompletionClient {
    /// The client received the whole response body.
    Served(Served),
    /// The client was lost mid-body -- disconnect, stall, or a failed
    /// demoted file-serve -- and that failure was logged at its source.
    Lost,
    /// No client was ever attached: the parallel-hack nudge answered the
    /// request and the download ran detached ([`super::detached`]). Reports
    /// the upstream side only, in hyper's "Finished download of ..." wording
    /// plus the splice mechanism token -- there is no fused serve to name.
    Nudged,
}

/// A download past [`CacheTarget::begin_rename`]: every body byte is in the
/// temp file, the registry entry says `Verifying`, the watch sender and the
/// `max_upstream_downloads` slot are gone, and the [`RenameBarrier`] is what
/// is left to commit. Built only by that method and consumed only by
/// [`CommitTail::new`], so nothing can commit a download that has not been
/// through the flip.
#[must_use = "a download past begin_rename must be committed or dropped as aborted"]
pub(super) struct Committable {
    tempfile: tokio::fs::File,
    temppath: TempPath,
    dest_path: PathBuf,
    rbarrier: RenameBarrier,
    /// The incremental digest, if one was kept.
    hasher: Option<StreamHasher>,
}

impl CacheTarget {
    /// End the download on the calling task: the `Download -> Verifying`
    /// flip that drops the `max_upstream_downloads` slot and the watch sender
    /// (`DownloadBarrier::begin_rename`, which also flushes the final ping).
    /// No I/O happens here, which is why it belongs on the connection task
    /// rather than in the spawned tail: the slot goes back at the same point
    /// as in the hyper backend, and a demoted file-serve task parked on the
    /// sender is awake before anyone can await it.
    pub(super) async fn begin_rename(self) -> Committable {
        let Self {
            tempfile,
            temppath,
            dest_path,
            dbarrier,
            hasher,
        } = self;
        let rbarrier = dbarrier.begin_rename().await;
        Committable {
            tempfile,
            temppath,
            dest_path,
            rbarrier,
            hasher,
        }
    }
}

/// A finished download's commit, owned rather than borrowed so it can
/// outlive the connection task: the sync, the verify + rename, the
/// `Download` row, and -- through [`Committed`] -- the completion line and
/// the `Delivery` row.
#[must_use = "the download is only committed once the tail is spawned, finished or committed"]
pub(super) struct CommitTail {
    target: Committable,
    conn_details: ConnectionDetails,
    conn_label: ConnLabel,
    bytes: CompletionBytes,
    /// Start of the download window the `Download` and `Delivery` rows share.
    start: PreciseInstant,
}

/// A download that landed in the cache, waiting to be reported once the
/// client's fate is known ([`Self::report`]).
#[must_use = "a committed download reports a completion line and its Delivery row"]
pub(super) struct Committed {
    conn_details: ConnectionDetails,
    conn_label: ConnLabel,
    bytes: CompletionBytes,
    /// The download duration, from the tail's `start` to the commit; the
    /// `Download` row recorded it and the `Delivery` row shares it.
    elapsed: Duration,
}

/// The connection's remaining work, returned only after the commit is
/// spawned and the download's watch sender has been dropped. Owns no cache
/// resources: a slow or cancelled client cannot hold up the commit.
#[must_use = "settle the client before reusing its connection"]
pub(super) struct ClientSettlement {
    end: ClientEnd,
    served: Served,
    rates: RateTimestamps,
    report: oneshot::Sender<ClientReport>,
}

struct ClientReport {
    rates: RateTimestamps,
    client: CompletionClient,
}

impl ClientSettlement {
    /// Await the demoted writer before the connection reads its next request:
    /// that writer owns a dup of the same socket. Reporting the verdict is a
    /// synchronous send, so a slow or failed commit cannot delay the client.
    pub(super) async fn settle(self) -> CompletionClient {
        let Self {
            end,
            served,
            mut rates,
            report,
        } = self;
        let client = settle(end, served, &mut rates).await;
        // The receiver is gone when committing failed; the client must still
        // finish even though there is no cached download to report.
        if let Err(ClientReport {
            rates: _,
            client: _,
        }) = report.send(ClientReport { rates, client })
        {}
        client
    }
}

/// A cancelled connection supplies no verdict. Keep the last known byte
/// count (demoted bytes are unknown) and never claim a successful delivery.
async fn receive_client_report(
    receiver: oneshot::Receiver<ClientReport>,
    mut rates: RateTimestamps,
) -> ClientReport {
    receiver.await.unwrap_or_else(|_err| {
        rates.t_client_done = PreciseInstant::now();
        ClientReport {
            rates,
            client: CompletionClient::Lost,
        }
    })
}

impl CommitTail {
    pub(super) fn new(
        target: Committable,
        conn_details: &ConnectionDetails,
        conn_label: ConnLabel,
        bytes: CompletionBytes,
        start: PreciseInstant,
    ) -> Self {
        Self {
            target,
            conn_details: conn_details.clone(),
            conn_label,
            bytes,
            start,
        }
    }

    /// Fire-and-forget, like `DetachedDownload::spawn` and the hyper
    /// backend's `download_file`: the connection task returns to its next
    /// request while this one commits. A request arriving meanwhile still
    /// late-joins the `Verifying` entry rather than missing the cache -- the
    /// entry only retires inside the commit.
    ///
    /// Nothing bounds how many of these run at once, deliberately and unlike
    /// the download they follow: the slot this download held went back in
    /// `begin_rename`, exactly where the hyper backend gives its own back, so
    /// a burst of simultaneous completions can queue an unbounded number of
    /// tails, each holding an open temp-file fd, a `TempPath` and a
    /// `QuotaReservation` until its `fsync` + verify + rename drains. That is
    /// the exposure the hyper backend has always had, and capping it would
    /// only push the wait back onto whatever holds the cap -- but do not
    /// read the released slot as a bound that is still in force.
    pub(super) fn spawn(
        self,
        rates: RateTimestamps,
        end: ClientEnd,
        served: Served,
    ) -> ClientSettlement {
        let (report, receiver) = oneshot::channel();
        tokio::task::spawn(async move {
            // Commit before receiving the verdict: awaiting it first would
            // put slow clients back in charge of verification and rename.
            if let Some(committed) = self.commit().await {
                let ClientReport { rates, client } = receive_client_report(receiver, rates).await;
                committed.report(&rates, client).await;
            }
        });
        ClientSettlement {
            end,
            served,
            rates,
            report,
        }
    }

    /// Commit, then report: the completion line and, for a client that got
    /// everything, the `Delivery` row. A commit failure already logged its
    /// cause (the rename ERROR, or the mismatch / verify failure inside
    /// `RenameBarrier::commit`) and dropped the barrier; nothing is cached,
    /// so nothing is reported.
    pub(super) async fn finish(self, rates: RateTimestamps, client: CompletionClient) {
        if let Some(committed) = self.commit().await {
            committed.report(&rates, client).await;
        }
    }

    /// Sync and commit the fully written download into the cache, then
    /// record the `Download` transfer.
    ///
    /// `Some` when the file landed in the cache. `None` means the commit
    /// failed: it logged the cause and dropped the barrier, the temp-file
    /// guard removed the partial, and nothing is cached (future requests
    /// re-download), so no DB row is written.
    pub(super) async fn commit(self) -> Option<Committed> {
        let Self {
            target,
            conn_details,
            conn_label,
            bytes,
            start,
        } = self;
        let elapsed = commit_target(target, bytes.total, start).await?;

        // Record download in database (mirrors download_file() in hyper_conn.rs).
        let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
            mirror: conn_details.mirror.clone(),
            debname: conn_details.debname.clone(),
            size: bytes.total.get(),
            elapsed,
            client_ip: conn_details.client.ip(),
            kind: TransferKind::Download,
        });
        send_db_command(cmd).await;

        // No `Origin` row here: the request earned it at the upstream-head
        // site (`ConnectionDetails::record_origin` in `splice_proxy_drive`,
        // the same point as in the hyper backend), with its cleanup-synthetic
        // exemption. A second send from the tail was only ever a duplicate.

        Some(Committed {
            conn_details,
            conn_label,
            bytes,
            elapsed,
        })
    }
}

/// The fold behind [`ClientSettlement::settle`], kept free of the tail so
/// it can be unit-tested with a spawned stand-in for the file-serve task.
async fn settle(end: ClientEnd, served: Served, rates: &mut RateTimestamps) -> CompletionClient {
    match end {
        ClientEnd::Served => CompletionClient::Served(served),
        // `Absent` is the detached path's arm; that path never settles a
        // client, so here it can only be read as "nobody got the body".
        ClientEnd::Disconnected | ClientEnd::Absent => CompletionClient::Lost,
        ClientEnd::Demoted(handle) => {
            if await_demoted_client(handle, rates).await {
                CompletionClient::Served(served)
            } else {
                CompletionClient::Lost
            }
        }
    }
}

/// Wait for a demoted client's file-serve task to finish sending, and fold
/// its byte count and end time into the rate timestamps.
async fn await_demoted_client(
    handle: tokio::task::JoinHandle<DeliveryResult>,
    rates: &mut RateTimestamps,
) -> bool {
    let succeeded = match handle.await {
        Ok(DeliveryResult::Success(bytes)) => {
            rates.client_bytes_sent += bytes;
            true
        }
        Ok(DeliveryResult::Failure(bytes)) => {
            rates.client_bytes_sent += bytes;
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
    rates.t_client_done = PreciseInstant::now();
    succeeded
}

/// The on-disk half of the commit: `sync_all`, then the verify + rename
/// through `RenameBarrier::commit`. Returns the download duration when the
/// file landed in the cache.
async fn commit_target(
    target: Committable,
    total_content_length: NonZero<u64>,
    start: PreciseInstant,
) -> Option<Duration> {
    let Committable {
        tempfile,
        temppath,
        dest_path,
        rbarrier,
        hasher,
    } = target;

    // `Some` only when every byte of the finished file went through the
    // digest: the download started at offset 0 and its body took the
    // userspace-TLS loop. `verify_temp_file` re-checks the algorithm and the
    // byte count before trusting it and re-reads the file when it cannot.
    let streamed_digest = hasher.map(StreamHasher::finalize);

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

    let cache_committed = rbarrier
        .commit(
            temppath,
            dest_path,
            total_content_length.get(),
            streamed_digest,
        )
        .await
        .is_ok();

    let elapsed = start.elapsed();

    cache_committed.then_some(elapsed)
}

impl Committed {
    /// The completion line, then the `Delivery` row.
    ///
    /// Kept together on purpose: which arms write a `Delivery` row is a
    /// decision that must not drift between the streaming tail and the
    /// volatile path. A `Delivery` row is exactly "this client received the
    /// whole body", which is exactly the `Served` arm: `Lost` lost it and
    /// `Nudged` never had a client.
    pub(super) async fn report(self, rates: &RateTimestamps, client: CompletionClient) {
        let Self {
            conn_details,
            conn_label,
            bytes,
            elapsed,
        } = self;
        log_splice_completion(&conn_details, conn_label, rates, bytes, client);

        if let CompletionClient::Served(Served { bytes: _, partial }) = client {
            let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
                mirror: conn_details.mirror.clone(),
                debname: conn_details.debname.clone(),
                size: bytes.total.get(),
                elapsed,
                kind: TransferKind::Delivery { partial },
                client_ip: conn_details.client.ip(),
            });
            send_db_command(cmd).await;
        }
    }
}

/// The completion line of a download that landed in the cache: "Served and
/// cached ..." when the client got the whole response, "Cached ..." when the
/// client was lost mid-body, "Finished download of ..." when there was no
/// client.
fn log_splice_completion(
    conn_details: &ConnectionDetails,
    conn_label: ConnLabel,
    rates: &RateTimestamps,
    bytes: CompletionBytes,
    client: CompletionClient,
) {
    let CompletionBytes {
        total: _,
        upstream: upstream_bytes,
        resume_offset,
    } = bytes;
    let in_time = conn_details.request_received_at.elapsed();
    let volatile = if conn_details.cached_flavor() == CachedFlavor::Volatile {
        "volatile "
    } else {
        ""
    };
    let upstream = rate_log::upstream_segment(upstream_bytes, rates.upstream_window());
    let (event, segments) = match client {
        CompletionClient::Served(Served { bytes, partial: _ }) => (
            "Served and cached",
            format!(
                "{upstream}, {}",
                rate_log::client_segment(bytes, rates.client_window())
            ),
        ),
        CompletionClient::Lost => (
            "Cached",
            format!(
                "{upstream}, {}",
                rate_log::client_disconnect_segment(rates.client_bytes_sent, rates.client_window())
            ),
        ),
        CompletionClient::Nudged => ("Finished download of", upstream),
    };
    info!(
        "{event} {volatile}file {} from mirror {} for client {} in {} via splice{conn_label} ({segments}){}",
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

#[cfg(test)]
mod tests {
    use super::*;

    const SERVED: Served = Served {
        bytes: 42,
        partial: false,
    };

    fn rates() -> RateTimestamps {
        RateTimestamps::new(PreciseInstant::now())
    }

    #[tokio::test]
    async fn served_and_lost_settle_without_awaiting_anything() {
        let mut rates = rates();
        assert_eq!(
            settle(ClientEnd::Served, SERVED, &mut rates).await,
            CompletionClient::Served(SERVED)
        );
        assert_eq!(
            settle(ClientEnd::Disconnected, SERVED, &mut rates).await,
            CompletionClient::Lost
        );
        assert_eq!(
            settle(ClientEnd::Absent, SERVED, &mut rates).await,
            CompletionClient::Lost
        );
        assert_eq!(rates.client_bytes_sent, 0);
    }

    /// A demoted client's fate is the file-serve task's, and its bytes count
    /// towards the client rate segment either way.
    #[tokio::test]
    async fn demoted_client_settles_on_the_file_serve_verdict() {
        let mut rates = rates();
        let ok = tokio::task::spawn(async { DeliveryResult::Success(7) });
        assert_eq!(
            settle(ClientEnd::Demoted(ok), SERVED, &mut rates).await,
            CompletionClient::Served(SERVED)
        );
        assert_eq!(rates.client_bytes_sent, 7);

        let failed = tokio::task::spawn(async { DeliveryResult::Failure(3) });
        assert_eq!(
            settle(ClientEnd::Demoted(failed), SERVED, &mut rates).await,
            CompletionClient::Lost
        );
        assert_eq!(rates.client_bytes_sent, 10);
    }

    #[tokio::test]
    async fn settlement_reports_bytes_without_waiting_for_the_commit() {
        let (report, receiver) = oneshot::channel();
        let settlement = ClientSettlement {
            end: ClientEnd::Demoted(tokio::task::spawn(async { DeliveryResult::Success(7) })),
            served: SERVED,
            rates: rates(),
            report,
        };
        // No receiver is polled until settlement completes, like a commit
        // still waiting for fsync. The client must not wait for reporting.
        assert_eq!(settlement.settle().await, CompletionClient::Served(SERVED));
        let report = receive_client_report(receiver, rates()).await;
        assert_eq!(report.client, CompletionClient::Served(SERVED));
        assert_eq!(report.rates.client_bytes_sent, 7);
    }

    #[tokio::test]
    async fn cancelled_settlement_reports_lost() {
        let (report, receiver) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let handle = tokio::task::spawn(async move {
            finished.await.expect("test finishes the demoted writer");
            DeliveryResult::Success(7)
        });
        let mut rates = rates();
        rates.client_bytes_sent = 3;
        let settlement = ClientSettlement {
            end: ClientEnd::Demoted(handle),
            served: SERVED,
            rates,
            report,
        };
        let task = tokio::task::spawn(settlement.settle());
        task.abort();
        assert!(task.await.expect_err("settlement cancelled").is_cancelled());
        let report = receive_client_report(receiver, rates).await;
        assert_eq!(report.client, CompletionClient::Lost);
        assert_eq!(report.rates.client_bytes_sent, 3);
        finish.send(()).expect("demoted writer remains independent");
    }

    #[tokio::test]
    async fn failed_commit_does_not_cancel_client_settlement() {
        let (report, receiver) = oneshot::channel();
        let settlement = ClientSettlement {
            end: ClientEnd::Demoted(tokio::task::spawn(async { DeliveryResult::Success(7) })),
            served: SERVED,
            rates: rates(),
            report,
        };
        // A failed commit drops the receiver. The socket must still finish
        // its response before the connection can be reused.
        drop(receiver);
        assert_eq!(settlement.settle().await, CompletionClient::Served(SERVED));
    }
}
