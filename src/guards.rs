//! The barrier chain every download is registered, driven and finished
//! through, shared by all backends.
//!
//! One barrier at a time owns a download's `active_downloads` entry, and each
//! step consumes its predecessor, so an entry is ended exactly once:
//!
//! - [`InitBarrier`] (registered, nothing fetched) ends at one sink:
//!   [`InitBarrier::finished`] (the file on disk stays valid),
//!   [`InitBarrier::decline`] (joiners answer what the originator answered)
//!   or [`InitBarrier::download`] (takes the `QuotaReservation` by value).
//!   One merely dropped publishes `Cancelled`, which joiners report as a
//!   failure of unknown cause -- so hyper's `InitBarrier::run_settled`
//!   worker must return the [`Settled`] proof of a sink, and splice's
//!   `InitBarrier::run` publishes a failing worker's concluded cause itself.
//! - [`DownloadBarrier`] (bytes flowing, readers ping-woken): a failure
//!   turns it into a [`FailedDownload`], which can be salvaged (skipped when
//!   the cache write is what failed) but never run again or renamed, and
//!   whose drop publishes the concluded cause.
//! - [`DownloadBarrier::begin_rename`] drops the `max_upstream_downloads`
//!   slot and the watch sender before verification starts. Nothing else
//!   releases the slot of a live download; a barrier that ends any other way
//!   drops it with its state.
//! - [`RenameBarrier::commit`] is the only way a download finishes and the
//!   only constructor of an `integrity::RenamePlan`, so a new plan field is a
//!   compile error there and nowhere else. It also arms or clears
//!   `verify_throttle`.
//!
//! No backend commits on its connection task, so a completed response never
//! proves the cache file exists: hyper spawns `download_file`, splice spawns
//! `splice/commit.rs::CommitTail`, `splice/detached.rs` is already
//! off-connection, and `splice/volatile.rs` spawns the tail
//! (`CommitTail::spawn_before_serving`) and serves from memory while it
//! commits.

use std::{
    fmt,
    path::PathBuf,
    sync::{Arc, LazyLock},
};

use hashbrown::Equivalent as _;
use tracing::{error, info};

use crate::{
    active_downloads::{
        AbortReason, ActiveDownloadStatus, ActiveDownloads, Declined, Origination, UpstreamSlot,
    },
    cache_layout::{CacheEntryKey, CacheEntryKeyRef, CacheLayout, ConnectionDetails, ResourceKind},
    cache_metadata::{self, UpstreamMetadata},
    cache_paths::MirrorSite,
    cache_quota::QuotaReservation,
    deb_mirror::Mirror,
    global_verify_throttle,
    humanfmt::HumanFmt,
    integrity::{self, CommitError, CommitFailure, RenamePlan},
    metrics,
    mirror_health::{self, MirrorFault},
    partial_file::TempPath,
    sticky,
    transfer_error::{DownloadFailure, ReportedDownloadFailure},
    upstream_head::ContentLength,
};
/// The shared `Cancelled` every unexplained drop publishes.
pub(crate) static CANCELLED_DOWNLOAD: LazyLock<Arc<DownloadFailure>> =
    LazyLock::new(|| Arc::new(DownloadFailure::Cancelled));

/// What the caller does after the runner reported the failure. It ends the
/// abort log line as the consequence clause `docs/logging.md` requires.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Consequence {
    /// Nothing went out yet, so the failure still becomes a response.
    Respond,
    /// The response head is already on the wire.
    #[cfg_attr(
        not(any(feature = "splice", test)),
        expect(dead_code, reason = "only the splice backend serves past its own head")
    )]
    CloseConnection,
    /// No response depends on the download any more: the detached download
    /// has no client, the buffered volatile path serves its client from
    /// memory.
    Abandon,
}

/// Publish `failure` as the entry's terminal status and count the abort.
/// Registry retirement is separate: a download's write lease can outlive its
/// failure notification.
///
/// Synchronous on purpose: `Drop` cannot await, and in the runners an await
/// between concluding the failure and publishing it would let a cancellation
/// publish `Cancelled` in its place.
fn publish_abort(
    status: &Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    failure: Arc<DownloadFailure>,
) {
    tokio::task::block_in_place(|| {
        let cause = match failure.as_ref() {
            DownloadFailure::Upstream(_) => &metrics::DOWNLOADS_ABORTED_UPSTREAM,
            DownloadFailure::Cache(_) => &metrics::DOWNLOADS_ABORTED_CACHE,
            DownloadFailure::Internal(_) => &metrics::DOWNLOADS_ABORTED_INTERNAL,
            DownloadFailure::Cancelled => &metrics::DOWNLOADS_ABORTED_CANCELLED,
        };
        *status.blocking_write() = ActiveDownloadStatus::Aborted(AbortReason::Failed(failure));
        count_abort(cause);
    });
}

/// Bumps `DOWNLOADS_ABORTED` with its cause, so the causes sum to the total.
fn count_abort(cause: &metrics::Signal) {
    metrics::DOWNLOADS_ABORTED.increment();
    cause.increment();
}

fn conclude(
    failure: DownloadFailure,
    key: CacheEntryKeyRef<'_>,
    consequence: Consequence,
) -> ReportedDownloadFailure {
    let status = failure.response_parts().0.as_u16();
    let consequence = fmt::from_fn(|f| match consequence {
        Consequence::Respond => write!(f, "; returning {status}"),
        Consequence::CloseConnection => f.write_str("; closing the connection"),
        Consequence::Abandon => f.write_str("; abandoning the download"),
    });
    failure.conclude(
        key.mirror,
        format_args!(
            "Aborted downloading file {} from mirror {}{consequence}",
            key.debname, key.mirror,
        ),
    )
}

/// Proof that an [`InitBarrier`] reached a sink. A worker driven by
/// `InitBarrier::run_settled` returns one on every success path, so an
/// answered request cannot leave the entry to `Drop`'s `Cancelled`.
#[must_use = "the init barrier's sink is only proven by handing this on"]
pub(crate) struct Settled(());

/// Exclusive ownership of a download's registry entry. Splice's cache file
/// and blocking writes share this lease with the barrier, so a failed
/// download stays registered until its last writer has stopped touching the
/// partial: notifying readers of an abort cannot admit a replacement writer
/// during salvage or while a blocking write is outstanding.
pub(crate) struct DownloadWriteLease {
    active_downloads: ActiveDownloads,
    key: Arc<CacheEntryKey>,
}

impl DownloadWriteLease {
    /// Keep this entry reserved until the actual blocking operation finishes,
    /// even if its awaiting future or returned handle is dropped.
    pub(crate) fn spawn_blocking<F, T>(self: Arc<Self>, operation: F) -> tokio::task::JoinHandle<T>
    where
        F: FnOnce(&Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(move || operation(&self))
    }

    /// A successful rename changes the bytes even if the async commit owner
    /// has been cancelled. Invalidate old validators before releasing its
    /// registry entry so the next request reloads the new inode's metadata.
    pub(crate) fn invalidate_metadata(&self) {
        cache_metadata::store().invalidate(&self.key.as_ref().as_ref());
    }
}

impl Drop for DownloadWriteLease {
    fn drop(&mut self) {
        self.active_downloads.remove(self.key.as_ref().as_ref());
    }
}

struct InitBarrierData {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: ActiveDownloads,
    slot: UpstreamSlot,
    resource_kind: ResourceKind,
    raw_uri_path: String,
    /// Unused, receivers just need to get notified by drop.
    _tx: tokio::sync::watch::Sender<()>,
}

#[must_use]
pub(crate) struct InitBarrier {
    data: Option<InitBarrierData>,
    /// Outside `data`: every sink takes `data`, and a worker may reach a sink
    /// and only then fail, so the key that names the entry in the abort
    /// report has to outlive them.
    key: Arc<CacheEntryKey>,
}

impl InitBarrier {
    /// `raw_uri_path` is the client's request path exactly as received
    /// (pre-normalisation, and for the splice backend pre-redirect and
    /// query-stripped) - both backends must agree, or registry keys diverge.
    pub(crate) fn new(
        origination: Origination,
        active_downloads: ActiveDownloads,
        conn_details: &ConnectionDetails,
        raw_uri_path: &str,
    ) -> Self {
        let Origination {
            key,
            init_tx,
            status,
            slot,
        } = origination;
        debug_assert!(
            conn_details.key().equivalent(key.as_ref()),
            "the origination was registered for this request's key"
        );
        Self {
            key,
            data: Some(InitBarrierData {
                status,
                active_downloads,
                slot,
                resource_kind: conn_details.resource_kind,
                raw_uri_path: raw_uri_path.to_owned(),
                _tx: init_tx,
            }),
        }
    }

    /// Drive one fallible step of registered-download setup, handing the
    /// barrier back for the next step. A worker failure is concluded and
    /// published before this returns, and consumes the barrier. The worker
    /// may have reached a sink before failing.
    #[cfg(feature = "splice")]
    pub(crate) async fn run<T>(
        mut self,
        worker: impl AsyncFnOnce(&mut Self) -> Result<T, DownloadFailure>,
    ) -> Result<(Self, T), ReportedDownloadFailure> {
        match worker(&mut self).await {
            Ok(result) => Ok((self, result)),
            Err(failure) => Err(self.fail(failure)),
        }
    }

    /// `Self::run` for a worker that owns the whole setup: every success
    /// path returns the [`Settled`] proof of the sink it reached.
    #[cfg(feature = "hyper")]
    pub(crate) async fn run_settled<T>(
        mut self,
        worker: impl AsyncFnOnce(&mut Self) -> Result<(Settled, T), DownloadFailure>,
    ) -> Result<T, ReportedDownloadFailure> {
        match worker(&mut self).await {
            Ok((Settled(()), result)) => Ok(result),
            Err(failure) => Err(self.fail(failure)),
        }
    }

    fn fail(mut self, failure: DownloadFailure) -> ReportedDownloadFailure {
        let reported = conclude(failure, self.key.as_ref().as_ref(), Consequence::Respond);
        if let Some(data) = self.data.take() {
            publish_abort(&data.status, reported.shared());
            data.active_downloads.remove(self.key.as_ref().as_ref());
        }
        reported
    }

    /// Finalise the entry without going through `Download` (e.g. a
    /// volatile-revalidation 304 from upstream — the existing on-disk
    /// file remains valid).  No upstream metadata is published; readers
    /// that observe `Finished { meta: None }` fall through to the cache,
    /// which lazy-loads it from the xattrs.
    pub(crate) async fn finished(&mut self, path: PathBuf) -> Settled {
        self.settle(ActiveDownloadStatus::Finished { path, meta: None })
            .await
    }

    /// End the entry without a download: the upstream answered with nothing
    /// to cache, or this proxy refused to fetch it. Joiners answer from
    /// `why` what the originator answered. Counted in `DOWNLOADS_DECLINED`
    /// only once settled: a future cancelled while `settle` waits for the
    /// status lock leaves `Drop` to count a cancellation, and the download
    /// must not count as both.
    pub(crate) async fn decline(&mut self, why: Declined) -> Settled {
        let settled = self
            .settle(ActiveDownloadStatus::Aborted(AbortReason::Declined(why)))
            .await;
        metrics::DOWNLOADS_DECLINED.increment();
        settled
    }

    /// Publish a final status and retire the entry. `data` is taken only
    /// under the status write lock, so a future cancelled while waiting for it
    /// leaves `Drop` armed.
    async fn settle(&mut self, final_status: ActiveDownloadStatus) -> Settled {
        let status = Arc::clone(&self.data().status);
        let mut state = status.write().await;
        let data = self.data.take().expect("every sink consumes the instance");
        *state = final_status;
        drop(state);
        data.active_downloads.remove(self.key.as_ref().as_ref());
        Settled(())
    }

    pub(crate) async fn download(
        &mut self,
        path: PathBuf,
        content_length: ContentLength,
        quota_reservation: QuotaReservation,
        meta: Arc<UpstreamMetadata>,
    ) -> (Settled, DownloadBarrier) {
        let status = Arc::clone(&self.data().status);
        let mut state = status.write().await;
        let data = self.data.take().expect("every sink consumes the instance");
        let (tx, rx) = tokio::sync::watch::channel(());

        *state = ActiveDownloadStatus::Download {
            path,
            content_length,
            rx,
            meta,
        };
        drop(state);

        let download = DownloadBarrier {
            data: Some(DownloadBarrierData {
                status: Arc::clone(&data.status),
                lease: Arc::new(DownloadWriteLease {
                    active_downloads: data.active_downloads,
                    key: Arc::clone(&self.key),
                }),
                slot: data.slot,
                resource_kind: data.resource_kind,
                raw_uri_path: data.raw_uri_path,
                tx,
                quota_reservation,
                bytes_since_ping: 0,
                pinged_once: sticky::Bool::new(),
            }),
        };
        (Settled(()), download)
    }

    fn data(&self) -> &InitBarrierData {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
    }

    #[must_use]
    pub(crate) fn debname(&self) -> &str {
        &self.key.debname
    }

    #[must_use]
    pub(crate) fn mirror(&self) -> &Mirror {
        &self.key.mirror
    }

    /// Read before [`Self::download`] takes the state, so a download can
    /// decide up front which digest it will be verified against
    /// (`integrity::stream_hash_algo_for_download`) using the very string the
    /// verifier later derives its registry key from.
    #[cfg(feature = "splice")]
    #[must_use]
    pub(crate) fn raw_uri_path(&self) -> &str {
        &self.data().raw_uri_path
    }

    #[must_use]
    pub(crate) fn layout(&self) -> CacheLayout {
        self.key.layout
    }

    /// The alias-resolved on-disk identity of the download's mirror, the
    /// same site `ConnectionDetails::site` resolves, so the `.partial` lands
    /// in the same tree as the eventual rename target.
    #[must_use]
    pub(crate) fn site(&self) -> MirrorSite<'_> {
        self.key.mirror.site()
    }
}

impl fmt::Debug for InitBarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { data, key } = self;
        f.debug_struct("InitBarrier")
            .field("key", key)
            .field("live", &data.is_some())
            .finish()
    }
}

impl Drop for InitBarrier {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            publish_abort(&data.status, Arc::clone(&CANCELLED_DOWNLOAD));
            data.active_downloads.remove(self.key.as_ref().as_ref());
        }
    }
}

struct DownloadBarrierData {
    /// Minted through `CacheQuota::acquire`, so holding a barrier proves
    /// admission succeeded; `commit` finalises it, `Drop` reverts it.
    /// Declared (so dropped) before `lease`: an unfinalised reservation keeps
    /// what the partial holds, which it reads while the lease still keeps
    /// every other writer off the path (and its own share of the partial's
    /// claim keeps cleanup's reap off it, `partial_claim`).
    quota_reservation: QuotaReservation,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    lease: Arc<DownloadWriteLease>,
    /// Held until [`DownloadBarrier::begin_rename`], where every backend has
    /// finished reading the upstream body; never reaches the `RenameBarrier`.
    slot: UpstreamSlot,
    resource_kind: ResourceKind,
    raw_uri_path: String,
    tx: tokio::sync::watch::Sender<()>,
    bytes_since_ping: u64,
    /// Whether any ping was sent yet — the first one is unbatched.
    pinged_once: sticky::Bool,
}

impl DownloadBarrierData {
    fn flush_batched_ping(&mut self) {
        if self.bytes_since_ping > 0 {
            self.internal_ping();
        }
    }

    fn internal_ping(&mut self) {
        // A send error only means there are no receivers.
        if let Err(_err @ tokio::sync::watch::error::SendError(())) = self.tx.send(()) {}
        self.bytes_since_ping = 0;
        self.pinged_once.set();
    }
}

#[must_use]
pub(crate) struct DownloadBarrier {
    data: Option<DownloadBarrierData>,
}

impl DownloadBarrier {
    fn data_mut(&mut self) -> &mut DownloadBarrierData {
        self.data
            .as_mut()
            .expect("every sink consumes the instance")
    }

    /// Accumulate `bytes` and ping receivers once `PING_BATCH_THRESHOLD` is
    /// crossed. The very first ping is sent unbatched: the originating client
    /// reads the partial file itself, so a download smaller than the
    /// threshold would otherwise deliver its first byte only when finished.
    pub(crate) fn ping_batched(&mut self, bytes: u64) {
        /// Roughly 1 MiB; tunes between wake-up overhead and joiner latency.
        const PING_BATCH_THRESHOLD: u64 = 1024 * 1024;

        let data = self.data_mut();
        data.bytes_since_ping = data.bytes_since_ping.saturating_add(bytes);
        if !data.pinged_once.get() || data.bytes_since_ping >= PING_BATCH_THRESHOLD {
            data.internal_ping();
        }
    }

    /// A worker failure is concluded before this returns, and the barrier
    /// becomes the [`FailedDownload`] that publishes it. `consequence` is
    /// what the caller does once this returns; it ends the reported line.
    pub(crate) async fn run<T>(
        mut self,
        consequence: Consequence,
        worker: impl AsyncFnOnce(&mut Self) -> Result<T, DownloadFailure>,
    ) -> Result<(Self, T), FailedDownload> {
        match worker(&mut self).await {
            Ok(result) => Ok((self, result)),
            Err(failure) => {
                // Only `begin_rename(self)` consumes the data, so a worker
                // holding `&mut self` cannot have emptied it.
                let data = self.data.take().expect("live download barrier");
                let reported = conclude(failure, data.lease.key.as_ref().as_ref(), consequence);
                Err(FailedDownload { data, reported })
            }
        }
    }

    pub(crate) async fn begin_rename(mut self) -> RenameBarrier {
        let data = self.data_mut();

        // Ordering matters: flush the final ping, flip `Download -> Verifying`
        // under the status write lock, release the lock, then drop `tx`. A
        // reader woken by the sender drop (`RecvError`) re-reads `status` and
        // so sees `Verifying`, `Finished` or `Aborted`, never a stale
        // `Download`. The lock is held only for the swap, not for the
        // hashing in `RenameBarrier::commit`.
        data.flush_batched_ping();
        {
            let mut lock = data.status.write().await;
            if let ActiveDownloadStatus::Download { path, meta, .. } = &mut *lock {
                let path = std::mem::take(path);
                let meta = Arc::clone(meta);
                *lock = ActiveDownloadStatus::Verifying { path, meta };
            } else {
                error!(
                    "Download barrier begin_rename reached with non-Download status for {} from mirror {}; leaving the status untouched: {lock:?}",
                    data.lease.key.debname, data.lease.key.mirror
                );
            }
            drop(lock);
        }
        // No await after taking the state: cancellation while acquiring the
        // status lock still publishes an abort through this barrier's Drop.
        let data = self.data.take().expect("every sink consumes the instance");
        drop(data.slot);
        drop(data.tx);

        RenameBarrier {
            data: Some(RenameBarrierData {
                status: data.status,
                lease: data.lease,
                resource_kind: data.resource_kind,
                raw_uri_path: data.raw_uri_path,
                quota_reservation: Some(data.quota_reservation),
            }),
        }
    }
}

#[cfg(feature = "splice")]
impl DownloadBarrier {
    fn data(&self) -> &DownloadBarrierData {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
    }

    /// Retain the registry entry through salvage and every blocking write.
    /// The lease carries no progress sender, so failed readers wake promptly.
    pub(crate) fn write_lease(&self) -> Arc<DownloadWriteLease> {
        Arc::clone(&self.data().lease)
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.data().tx.subscribe()
    }

    pub(crate) fn status(&self) -> &Arc<tokio::sync::RwLock<ActiveDownloadStatus>> {
        &self.data().status
    }
}

impl fmt::Debug for DownloadBarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { data } = self;
        f.debug_struct("DownloadBarrier")
            .field("key", &data.as_ref().map(|data| &data.lease.key))
            .finish()
    }
}

impl Drop for DownloadBarrier {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            publish_abort(&data.status, Arc::clone(&CANCELLED_DOWNLOAD));
        }
    }
}

/// A download whose runner concluded a terminal failure. It still owns the
/// barrier state -- the registry entry, the write lease, the progress sender
/// and the upstream slot -- so readers keep waiting and no replacement writer
/// is admitted while the partial is salvaged; dropping it (after salvage, or
/// on cancellation of it) publishes the concluded cause, never `Cancelled`.
#[must_use = "dropping a failed download publishes its failure; salvage it first"]
pub(crate) struct FailedDownload {
    data: DownloadBarrierData,
    reported: ReportedDownloadFailure,
}

impl FailedDownload {
    pub(crate) fn failure(&self) -> &DownloadFailure {
        self.reported.failure()
    }

    /// Land what the transfer already received so a later request can resume
    /// from it, then publish the failure. Skipped when the cache itself is what
    /// failed: re-attempting the write that just failed would repeat it, count
    /// `CACHE_IO_FAILURE` twice and log a second error for one condition.
    pub(crate) async fn salvage(self, salvage: impl AsyncFnOnce()) -> ReportedDownloadFailure {
        if !matches!(self.failure(), DownloadFailure::Cache(_)) {
            salvage().await;
        }
        self.into_reported()
    }

    /// Publish the failure now and hand its proof on.
    pub(crate) fn into_reported(self) -> ReportedDownloadFailure {
        self.reported.clone()
    }
}

impl fmt::Debug for FailedDownload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { data, reported } = self;
        f.debug_struct("FailedDownload")
            .field("key", &data.lease.key)
            .field("failure", reported.failure())
            .finish()
    }
}

impl Drop for FailedDownload {
    fn drop(&mut self) {
        publish_abort(&self.data.status, self.reported.shared());
    }
}

struct RenameBarrierData {
    /// `Some` until `commit` hands it to `integrity::verify_and_rename`,
    /// which finalises it in the rename step; `None` only for the rest of
    /// that one `commit` call. Reverted by drop on every other path, before
    /// `lease` (see `DownloadBarrierData::quota_reservation`).
    quota_reservation: Option<QuotaReservation>,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    lease: Arc<DownloadWriteLease>,
    resource_kind: ResourceKind,
    raw_uri_path: String,
}

#[must_use]
pub(crate) struct RenameBarrier {
    data: Option<RenameBarrierData>,
}

impl RenameBarrier {
    fn data(&self) -> &RenameBarrierData {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
    }

    fn data_mut(&mut self) -> &mut RenameBarrierData {
        self.data
            .as_mut()
            .expect("every sink consumes the instance")
    }

    /// Verify the finished temp file, rename it into the cache, flip the
    /// status to `Finished`, publish upstream metadata and retire the entry.
    /// On any `CommitError` the status becomes `Aborted`; a checksum mismatch
    /// also arms the re-download throttle and removes the bad partial before
    /// the registry entry is retired.
    ///
    /// All disk work -- `prepare` (splice's `fsync`; hyper passes none), the
    /// `fstat` that sizes the quota finalisation, verification and the
    /// `rename(2)` -- is one blocking job (`verify_and_rename`) that runs
    /// before the status write lock is taken, so late joiners are not
    /// stalled while the file is hashed.
    ///
    /// Cancellation: once spawned, that job runs to completion and holds its
    /// own registry lease, so a dropped `commit` future still ends with a
    /// verified file renamed into the cache (or a rejected one left behind)
    /// and the quota finalised. Only the `Verifying -> Finished` flip is
    /// lost; `Drop` publishes `Aborted` instead.
    ///
    /// On a re-download the metadata store still holds the previous
    /// version's validators, and `resolve` answers from it without stat'ing
    /// the file, so the blocking job invalidates the entry after the rename,
    /// before it releases its lease. Aborts before the rename invalidate
    /// nothing: the cached file is untouched, and on a filesystem without
    /// xattrs the store is the validators' only carrier.
    ///
    /// `finished` must be idle (every write flushed). On success the
    /// `temp_path` guard is defused, on a checksum mismatch the file is
    /// unlinked, and on a transient verify/rename failure the guard's
    /// `OnDrop::Keep` keeps it for resumption. Every failure is counted and
    /// logged by `verify_and_rename`.
    pub(crate) async fn commit(
        mut self,
        finished: integrity::FinishedCacheFile,
        temp_path: TempPath,
        dest_path: PathBuf,
    ) -> Result<(), CommitError> {
        let data = self.data_mut();
        let plan = RenamePlan {
            dest_path,
            resource_kind: data.resource_kind,
            key: Arc::clone(&data.lease.key),
            raw_uri_path: std::mem::take(&mut data.raw_uri_path),
        };
        let reservation = data
            .quota_reservation
            .take()
            .expect("commit runs once per barrier");
        let lease = Arc::clone(&data.lease);
        if let Err(CommitFailure { error: err, guard }) =
            integrity::verify_and_rename(&plan, finished, temp_path, reservation, lease).await
        {
            // Retire the entry here, not in `Drop`, which runs only after
            // the `TempPath` guard is dropped: a request joining an entry
            // still in `Verifying` would be served the mismatching partial
            // as a finished file. Under the status write lock, so no joiner
            // sees an intermediate state: arm the throttle (content
            // mismatch only; VerifyIo and Rename are transient local
            // problems), then publish `Aborted(Discarded)`. `Discarded`,
            // not a failure: every byte is on disk, so readers that already
            // hold the file drain it instead of truncating the body.
            let data = self.data();
            let checksum_mismatch = matches!(err, CommitError::ChecksumMismatch);
            let throttle = {
                let mut status = data.status.write().await;
                let throttle = if checksum_mismatch {
                    global_verify_throttle().record_failure(data.lease.key.as_ref().as_ref())
                } else {
                    None
                };
                *status =
                    ActiveDownloadStatus::Aborted(AbortReason::Discarded { checksum_mismatch });
                throttle
            };
            // A mismatch is the mirror's content; a verify read or rename
            // failure is this disk's.
            if checksum_mismatch {
                count_abort(&metrics::DOWNLOADS_ABORTED_CHECKSUM);
                mirror_health::record(&data.lease.key.mirror, MirrorFault::Checksum);
            } else {
                count_abort(&metrics::DOWNLOADS_ABORTED_CACHE);
            }
            // Publication is complete, so Drop must not replace Discarded
            // with a generic abort. Keep the lease until the last mutation
            // of the partial has finished, including a detached unlink.
            let data = self.data.take().expect("every sink consumes the instance");
            // A mismatch always hands the guard back; only a job that died
            // (never a mismatch) loses it.
            if checksum_mismatch && let Some(guard) = guard {
                discard_partial(guard, Arc::clone(&data.lease)).await;
            }
            let key = Arc::clone(&data.lease.key);
            drop(data.lease);
            if let Some((window, failures)) = throttle {
                // Integration tests use this line as the "throttle is
                // observable" sync point: it must stay after the entry
                // removal above.
                info!(
                    "Throttling downloads of {} from mirror {} for {} after checksum verification failure (consecutive failures: {failures})",
                    key.debname,
                    key.mirror,
                    HumanFmt::Time(window),
                );
            }
            return Err(err);
        }

        // `self.data` stays populated across the lock `.await`, so a future
        // cancelled while waiting still retires the entry through `Drop`.
        // It is taken only past the last await, where no cancellation can
        // turn a `Finished` entry back into an `Aborted` one.
        let meta_for_status: Option<Arc<UpstreamMetadata>> = {
            let data = self.data();
            let mut lock = data.status.write().await;
            let meta = match &*lock {
                ActiveDownloadStatus::Verifying { path: _, meta } => Some(Arc::clone(meta)),
                ActiveDownloadStatus::Init(_)
                | ActiveDownloadStatus::Download { .. }
                | ActiveDownloadStatus::Finished { .. }
                | ActiveDownloadStatus::Aborted(_) => {
                    error!(
                        "RenameBarrier::commit reached with non-Verifying status for {} from mirror {}; finishing the download without publishing cache metadata: {:?}",
                        data.lease.key.debname, data.lease.key.mirror, *lock
                    );
                    // Nothing to publish; the rename job already dropped the
                    // previous version's validators.
                    None
                }
            };
            *lock = ActiveDownloadStatus::Finished {
                path: plan.dest_path,
                meta: meta.clone(),
            };
            meta
        };

        let data = self.data.take().expect("every sink consumes the instance");
        if let Some(meta) = meta_for_status {
            cache_metadata::store().set(&data.lease.key.as_ref().as_ref(), meta);
        }
        global_verify_throttle().record_success(data.lease.key.as_ref().as_ref());
        drop(data.lease);

        Ok(())
    }
}

/// Known-bad bytes cannot be resumed. The blocking unlink owns the registry
/// lease so cancellation cannot admit a new writer at the same partial path
/// while that unlink is still queued. The reservation already kept the
/// partial's bytes when it dropped, and the unlink releases them again.
async fn discard_partial(temp_path: TempPath, lease: Arc<DownloadWriteLease>) {
    lease
        .spawn_blocking(move |_lease| {
            temp_path.remove_blocking();
        })
        .await
        .expect("partial removal should not panic");
}

impl Drop for RenameBarrier {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            // No metadata invalidation here: before the rename the memoized
            // validators still describe the cached file, and after it the
            // blocking job invalidates them itself.
            publish_abort(&data.status, Arc::clone(&CANCELLED_DOWNLOAD));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "splice")]
    use crate::test_support::pause_blocking_pool;
    use crate::{config::ClientHost, deb_mirror::MirrorKind, test_support::levels_during};

    fn key(debname: &str) -> CacheEntryKey {
        key_on("guards.test", debname)
    }

    fn key_on(host: &str, debname: &str) -> CacheEntryKey {
        CacheEntryKey {
            mirror: Mirror::new(
                ClientHost::new(host).expect("valid host"),
                std::num::NonZero::new(80),
                "/debian".into(),
                MirrorKind::Structured,
            ),
            debname: debname.into(),
            layout: CacheLayout::StructuredPool,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_during_cleanup_preserves_the_worker_failure() {
        use crate::transfer_error::CacheError;
        let active = ActiveDownloads::new();
        let key = key("failed-before-cleanup.deb");
        let barrier = downloading(&active, &key).await;
        let data = barrier.data.as_ref().expect("live barrier");
        let status = Arc::clone(&data.status);
        let mut progress = data.tx.subscribe();
        let (failed, observed) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let result = barrier
                .run(
                    Consequence::CloseConnection,
                    async |_barrier| -> Result<(), DownloadFailure> {
                        let operation: Result<(), CacheError> = Err(CacheError::io(
                            "injected cache write",
                            std::io::ErrorKind::StorageFull.into(),
                        ));
                        operation?;
                        Ok(())
                    },
                )
                .await;
            let failure = result.expect_err("worker failed");
            failed
                .send(failure.reported.shared())
                .expect("receiver live");
            // Model an uncompleted salvage flush after the runner returned.
            std::future::pending::<()>().await;
            drop(failure);
        });
        let expected = observed.await.expect("worker reached cleanup");
        task.abort();
        assert!(task.await.expect_err("cancelled task").is_cancelled());
        assert!(
            progress.changed().await.is_err(),
            "terminal publication closes sender"
        );
        let state = status.read().await;
        let actual = match &*state {
            ActiveDownloadStatus::Aborted(AbortReason::Failed(failure)) => Some(failure),
            ActiveDownloadStatus::Init(_)
            | ActiveDownloadStatus::Download { .. }
            | ActiveDownloadStatus::Verifying { .. }
            | ActiveDownloadStatus::Finished { .. }
            | ActiveDownloadStatus::Aborted(
                AbortReason::Discarded { .. } | AbortReason::Declined(_),
            ) => None,
        };
        assert!(
            actual.is_some(),
            "cancelled cleanup must publish its failure: {state:?}"
        );
        assert!(
            Arc::ptr_eq(actual.expect("asserted above"), &expected),
            "Drop must publish the retained allocation, including after cancellation"
        );
        drop(state);
        assert_eq!(active.len(), 0, "writer lease retires the entry");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dropping_a_worker_without_observed_failure_is_cancelled() {
        let active = ActiveDownloads::new();
        let key = key("cancelled-worker.deb");
        let barrier = downloading(&active, &key).await;
        let status = Arc::clone(&barrier.data.as_ref().expect("live barrier").status);
        drop(barrier);
        assert!(matches!(&*status.read().await,
            ActiveDownloadStatus::Aborted(AbortReason::Failed(failure))
                if matches!(failure.as_ref(), DownloadFailure::Cancelled)
                    && Arc::ptr_eq(failure, &CANCELLED_DOWNLOAD)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_init_transitions_keep_the_owner_until_status_publication() {
        use std::task::{Context, Waker};
        for download in [false, true] {
            let active = ActiveDownloads::new();
            let key = key("cancelled-init-transition.deb");
            let details = details_for(&key);
            let origination = active.originate_uncapped(key.as_ref());
            let status = Arc::clone(&origination.status);
            let mut barrier = InitBarrier::new(
                origination,
                active.clone(),
                &details,
                "/debian/pool/test.deb",
            );
            let held = status.write().await;
            if download {
                let length = ContentLength::Exact(std::num::NonZero::new(1024).unwrap());
                let quota = crate::cache_quota::CacheQuota::new(0, None)
                    .acquire(&details.client, length, 0, None, &key.debname)
                    .await
                    .expect("unlimited quota");
                let mut transition = Box::pin(barrier.download(
                    PathBuf::from("test.partial"),
                    length,
                    quota,
                    Arc::new(UpstreamMetadata::default()),
                ));
                assert!(
                    transition
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                drop(transition);
            } else {
                let mut transition = Box::pin(barrier.finished(PathBuf::from("test.deb")));
                assert!(
                    transition
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending()
                );
                drop(transition);
            }
            assert!(
                barrier.data.is_some(),
                "the pending transition cannot disarm its owner"
            );
            drop(held);
            drop(barrier);
            assert!(matches!(&*status.read().await,
                ActiveDownloadStatus::Aborted(AbortReason::Failed(failure))
                    if matches!(failure.as_ref(), DownloadFailure::Cancelled)));
            assert_eq!(
                active.len(),
                0,
                "cancellation retires the initialized entry"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn failed_download_salvages_unless_the_cache_failed() {
        use crate::transfer_error::{CacheError, InternalError};
        let active = ActiveDownloads::new();
        let key = key("salvage.deb");
        for (failure, salvages, cause) in [
            (
                DownloadFailure::from(CacheError::io(
                    "write download cache file",
                    std::io::ErrorKind::StorageFull.into(),
                )),
                false,
                &metrics::DOWNLOADS_ABORTED_CACHE,
            ),
            (
                InternalError::invalid("pipe", "broken").into(),
                true,
                &metrics::DOWNLOADS_ABORTED_INTERNAL,
            ),
        ] {
            let barrier = downloading(&active, &key).await;
            let status = Arc::clone(&barrier.data.as_ref().expect("live barrier").status);
            let (aborted, caused) = (metrics::DOWNLOADS_ABORTED.get(), cause.get());
            let failed = barrier
                .run(Consequence::Abandon, async |_barrier| Err::<(), _>(failure))
                .await
                .expect_err("worker failed");
            let mut ran = false;
            let reported = failed.salvage(async || ran = true).await;
            // Published (and counted) once the salvage settled the failure.
            assert!(metrics::DOWNLOADS_ABORTED.get() > aborted);
            assert!(cause.get() > caused, "the abort names its cause");
            assert_eq!(ran, salvages, "{:?}", reported.failure());
            assert!(matches!(&*status.read().await,
                ActiveDownloadStatus::Aborted(AbortReason::Failed(published))
                    if Arc::ptr_eq(published, &reported.shared())));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn declined_setup_tells_joiners_what_the_originator_answered() {
        use crate::active_downloads::{JoinFailure, await_serveable};
        let active = ActiveDownloads::new();
        let key = key("declined.deb");
        let details = details_for(&key);
        let aborted = metrics::DOWNLOADS_ABORTED.get();
        let declined = metrics::DOWNLOADS_DECLINED.get();
        let status = decline(
            &active,
            &key,
            Declined::Passthrough(http::StatusCode::NOT_FOUND),
        )
        .await;
        assert_eq!(metrics::DOWNLOADS_ABORTED.get(), aborted);
        assert!(metrics::DOWNLOADS_DECLINED.get() > declined);
        assert_eq!(active.len(), 0, "the declined entry is retired");
        let failure = await_serveable(&status, &details).await.err();
        assert!(
            matches!(failure, Some(JoinFailure::Declined(_))),
            "{failure:?}"
        );
        assert_eq!(
            failure.expect("asserted above").response_parts(),
            (http::StatusCode::NOT_FOUND, "Not Found")
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_throttled_decline_counts_its_joiners() {
        use crate::active_downloads::{JoinFailure, await_serveable};
        let active = ActiveDownloads::new();
        let key = key("throttled.deb");
        let details = details_for(&key);
        let status = decline(&active, &key, THROTTLED).await;
        let rejected = metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.get();
        let failure = await_serveable(&status, &details).await.err();
        assert!(
            matches!(
                failure,
                Some(JoinFailure::Declined(Declined::VerifyThrottled { .. }))
            ),
            "{failure:?}"
        );
        assert_eq!(
            metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.get(),
            rejected + 1
        );
    }

    /// Cleanup's synthetic client skips the pre-upstream verify-throttle
    /// gate, so a throttled originator's decline neither rejects nor counts
    /// it: the joiner is told to fetch the file itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_throttled_decline_exempts_a_cleanup_joiner() {
        use crate::active_downloads::await_serveable;
        use crate::client_info::ClientInfo;
        let active = ActiveDownloads::new();
        let key = key("cleanup-throttled.deb");
        let details = details_for(&key);
        let status = decline(&active, &key, THROTTLED).await;
        let cleanup = ConnectionDetails {
            client: ClientInfo::new_cleanup(),
            ..details_for(&key)
        };
        let rejected = metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.get();
        let failure = await_serveable(&status, &cleanup)
            .await
            .err()
            .expect("a declined download serves nothing");
        assert!(failure.exempts(&cleanup.client), "{failure:?}");
        assert!(!failure.exempts(&details.client), "{failure:?}");
        assert_eq!(metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.get(), rejected);
    }

    #[cfg(feature = "splice")]
    #[test]
    fn cancelled_rename_job_keeps_the_partial_registered_until_it_finishes() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let source = directory.path().join("download.partial");
            let destination = directory.path().join("download.deb");
            std::fs::write(&source, b"verified body").unwrap();
            let active = ActiveDownloads::new();
            let key = key("queued-rename.deb");
            let old_metadata = Arc::new(UpstreamMetadata::from_upstream(
                Some("\"previous-version\""),
                None,
            ));
            cache_metadata::store().set(&key.as_ref(), Arc::clone(&old_metadata));
            let barrier = downloading(&active, &key).await.begin_rename().await;
            let status = Arc::clone(&barrier.data.as_ref().unwrap().status);
            let lease = Arc::clone(&barrier.data.as_ref().unwrap().lease);
            let resume = pause_blocking_pool(&runtime);
            let renamed = destination.clone();
            let job = lease.spawn_blocking(move |lease| {
                std::fs::rename(source, renamed).map(|()| lease.invalidate_metadata())
            });

            drop(job);
            drop(barrier);
            assert!(matches!(
                *status.read().await,
                ActiveDownloadStatus::Aborted(_)
            ));
            assert!(
                Arc::ptr_eq(&active.insert_uncapped(key.as_ref()), &status,),
                "cancellation cannot admit a writer before the queued rename"
            );

            resume.send(()).unwrap();
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert_eq!(active.len(), 0, "the completed rename releases the entry");
            assert_eq!(std::fs::read(destination).unwrap(), b"verified body");
            assert_eq!(
                Arc::strong_count(&old_metadata),
                1,
                "the detached rename invalidates the previous version's validators"
            );
        });
    }

    #[cfg(feature = "splice")]
    #[test]
    fn cancelled_discard_keeps_the_partial_registered_until_unlink_finishes() {
        use std::{
            future::Future as _,
            task::{Context, Waker},
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let directory = tempfile::tempdir().unwrap();
            let (file, path) =
                crate::partial_file::tokio_tempfile(&directory.path().join("bad.partial"), 0o600)
                    .await
                    .unwrap();
            drop(file);
            let original_path = path.to_path_buf();
            let active = ActiveDownloads::new();
            let key = key("queued-unlink.deb");
            let barrier = downloading(&active, &key).await.begin_rename().await;
            let status = Arc::clone(&barrier.data.as_ref().unwrap().status);
            let lease = Arc::clone(&barrier.data.as_ref().unwrap().lease);
            let resume = pause_blocking_pool(&runtime);
            let mut discard = Box::pin(discard_partial(path, lease));
            assert!(
                discard
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );

            drop(discard);
            drop(barrier);
            assert!(original_path.exists(), "unlink is still queued");
            assert!(
                Arc::ptr_eq(&active.insert_uncapped(key.as_ref()), &status,),
                "cancellation cannot admit a writer before the queued unlink"
            );

            resume.send(()).unwrap();
            tokio::task::spawn_blocking(|| ()).await.unwrap();
            assert!(!original_path.exists(), "the detached unlink ran");
            assert_eq!(active.len(), 0, "unlink completion permits a retry");
        });
    }

    fn details_for(key: &CacheEntryKey) -> ConnectionDetails {
        ConnectionDetails {
            client: crate::test_support::local_client(),
            request_received_at: crate::precise_instant::PreciseInstant::now(),
            upstream_host: key.mirror.host().clone(),
            mirror: key.mirror.clone(),
            debname: key.debname.clone(),
            resource_kind: ResourceKind::Pool,
            origin_fields: None,
        }
    }

    const THROTTLED: Declined = Declined::VerifyThrottled {
        remaining: std::time::Duration::from_secs(5),
    };

    /// Originate `key` and decline it with `why`; returns the status its
    /// joiners wait on.
    async fn decline(
        active: &ActiveDownloads,
        key: &CacheEntryKey,
        why: Declined,
    ) -> Arc<tokio::sync::RwLock<ActiveDownloadStatus>> {
        let origination = active.originate_uncapped(key.as_ref());
        let status = Arc::clone(&origination.status);
        let mut barrier = InitBarrier::new(
            origination,
            active.clone(),
            &details_for(key),
            "/debian/pool/test.deb",
        );
        let _settled = barrier.decline(why).await;
        drop(barrier);
        status
    }

    async fn downloading(active: &ActiveDownloads, key: &CacheEntryKey) -> DownloadBarrier {
        let details = details_for(key);
        let length = ContentLength::Exact(std::num::NonZero::new(1024).unwrap());
        let quota = crate::cache_quota::CacheQuota::new(0, None)
            .acquire(&details.client, length, 0, None, &key.debname)
            .await
            .expect("unlimited quota");
        InitBarrier::new(
            active.originate_uncapped(key.as_ref()),
            active.clone(),
            &details,
            "/debian/pool/test.deb",
        )
        .download(
            PathBuf::from("test.partial"),
            length,
            quota,
            Arc::new(UpstreamMetadata::default()),
        )
        .await
        .1
    }

    #[cfg(feature = "splice")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborted_download_reserves_partial_until_last_writer_finishes() {
        let active = ActiveDownloads::new();
        let key = key("salvaging.deb");
        let barrier = downloading(&active, &key).await;
        let status = Arc::clone(barrier.status());
        let mut progress = barrier.subscribe();
        let writer = barrier.write_lease();
        let blocking_write = Arc::clone(&writer);

        drop(barrier);
        assert!(progress.changed().await.is_err(), "readers wake on failure");
        assert!(matches!(
            *status.read().await,
            ActiveDownloadStatus::Aborted(_)
        ));
        assert_eq!(active.upstream_slots(), 0, "the upstream slot is released");
        assert!(
            Arc::ptr_eq(&active.insert_uncapped(key.as_ref()), &status,),
            "a retry must still join the failed writer's entry"
        );

        drop(writer);
        assert_eq!(active.len(), 1, "the blocking write still owns the partial");
        drop(blocking_write);
        assert_eq!(active.len(), 0, "a retry may now originate a new writer");
    }

    #[cfg(feature = "splice")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_download_passes_its_lease_to_verification() {
        let active = ActiveDownloads::new();
        let key = key("verifying.deb");
        let barrier = downloading(&active, &key).await;
        let status = Arc::clone(barrier.status());
        let mut progress = barrier.subscribe();
        let writer = barrier.write_lease();

        let rename = barrier.begin_rename().await;
        assert!(progress.changed().await.is_err());
        assert!(matches!(
            *status.read().await,
            ActiveDownloadStatus::Verifying { .. }
        ));
        assert_eq!(active.upstream_slots(), 0);
        drop(writer);
        assert_eq!(active.len(), 1, "verification still owns the entry");
        drop(rename);
        assert_eq!(active.len(), 0);
    }

    /// A barrier over a real registry entry, in the state a download
    /// abandoned before the rename leaves behind.
    fn abandoned_rename_barrier(key: &CacheEntryKey) -> RenameBarrier {
        let active_downloads = ActiveDownloads::new();
        let status = active_downloads.insert_uncapped(key.as_ref());
        RenameBarrier {
            data: Some(RenameBarrierData {
                status,
                lease: Arc::new(DownloadWriteLease {
                    active_downloads,
                    key: Arc::new(key.clone()),
                }),
                resource_kind: ResourceKind::Pool,
                raw_uri_path: String::from("/debian/pool/main/t/test/test.deb"),
                // No reservation: the drop path under test never consults it.
                quota_reservation: None,
            }),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn barrier_transitions_share_identity_without_retaining_the_write_lease() {
        use crate::cache_quota::CacheQuota;

        let active = ActiveDownloads::new();
        let key = key("shared-key.deb");
        let details = details_for(&key);
        let mut init = InitBarrier::new(
            active.originate_uncapped(key.as_ref()),
            active.clone(),
            &details,
            "/test.deb",
        );
        let identity = Arc::clone(&init.key);
        let length = ContentLength::Exact(std::num::NonZero::new(1024).unwrap());
        let quota = CacheQuota::new(0, None)
            .acquire(&details.client, length, 0, None, &key.debname)
            .await
            .expect("unlimited quota");
        let (_settled, download) = init
            .download(
                PathBuf::from("test.partial"),
                length,
                quota,
                Arc::new(UpstreamMetadata::default()),
            )
            .await;
        assert!(Arc::ptr_eq(
            &identity,
            &download.data.as_ref().unwrap().lease.key
        ));
        let rename = download.begin_rename().await;
        assert!(Arc::ptr_eq(
            &identity,
            &rename.data.as_ref().unwrap().lease.key
        ));
        drop(rename);
        assert_eq!(
            active.len(),
            0,
            "the consumed init barrier's key must not retain the write lease"
        );
        assert_eq!(active.upstream_slots(), 0);
        drop(init);
        assert_eq!(Arc::strong_count(&identity), 1);
    }

    #[cfg(feature = "splice")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn runner_reports_after_a_consumed_sink() {
        let active = ActiveDownloads::new();
        let key = key("consumed-then-failed.deb");
        let details = details_for(&key);
        let origination = active.originate_uncapped(key.as_ref());
        let barrier = InitBarrier::new(
            origination,
            active.clone(),
            &details,
            "/debian/pool/test.deb",
        );
        let result = barrier
            .run(async |barrier| {
                let _settled = barrier.finished(PathBuf::from("test.deb")).await;
                Err::<(), _>(DownloadFailure::Cancelled)
            })
            .await;
        let reported = result.expect_err("worker failed after consuming the sink");
        assert!(matches!(reported.failure(), DownloadFailure::Cancelled));
    }

    #[test]
    fn connect_failures_are_once_gated_per_host_and_body_failures_are_not() {
        use crate::{transfer_error::UpstreamError, upstream_retry::RetryLimit};

        // Hosts no other test uses, so this test owns their gates.
        let key = key_on("gated-a.guards.test", "gated.deb");
        let other = key_on("gated-b.guards.test", "gated.deb");
        let connect = || {
            DownloadFailure::Upstream(UpstreamError::connect(
                "connect upstream",
                std::io::ErrorKind::ConnectionRefused.into(),
                2,
                RetryLimit::Attempts.into(),
            ))
        };
        let body = || DownloadFailure::Upstream(UpstreamError::protocol("short body"));
        let levels = levels_during(|| {
            drop(conclude(connect(), key.as_ref(), Consequence::Respond));
            drop(conclude(connect(), key.as_ref(), Consequence::Respond));
            drop(conclude(connect(), other.as_ref(), Consequence::Respond));
            drop(conclude(body(), key.as_ref(), Consequence::CloseConnection));
            drop(conclude(body(), key.as_ref(), Consequence::CloseConnection));
        });
        assert_eq!(
            levels,
            [
                tracing::Level::WARN, // first connect failure of host a
                tracing::Level::INFO, // its repeat
                tracing::Level::WARN, // host b's first is not demoted by a's
                tracing::Level::WARN, // body failures are ungated
                tracing::Level::WARN,
            ]
        );
    }

    /// On a filesystem without xattrs the store is the validators' only
    /// carrier and `resolve` negatively caches a miss for the life of the
    /// process, so dropping them before the rename would make every
    /// `If-None-Match` on that file re-send the whole body.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn dropping_a_rename_barrier_keeps_the_cached_validators() {
        let store = cache_metadata::store();
        let key = key("kept-validators.deb");
        let metadata = Arc::new(UpstreamMetadata::from_upstream(
            Some("\"current-version\""),
            None,
        ));
        store.set(&key.as_ref(), Arc::clone(&metadata));
        // Count ownership of this unique entry, independent of concurrent
        // tests; resolve would reload the entry and hide accidental removal.
        assert_eq!(Arc::strong_count(&metadata), 2, "the store owns the entry");

        drop(abandoned_rename_barrier(&key));

        assert_eq!(
            Arc::strong_count(&metadata),
            2,
            "the cached file is unchanged, so its memoized validators must survive"
        );
    }
}
