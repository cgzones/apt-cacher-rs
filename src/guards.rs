use std::{path::PathBuf, sync::Arc};

use tracing::{error, info, warn};

use crate::{
    active_downloads::{
        AbortReason, ActiveDownloadStatus, ActiveDownloads, Origination, UpstreamSlot,
    },
    cache_layout::{CacheEntryKey, CacheEntryKeyRef, CacheLayout, ConnectionDetails, ResourceKind},
    cache_metadata::{self, UpstreamMetadata},
    cache_paths::MirrorSite,
    cache_quota::QuotaReservation,
    error::ErrorReport,
    global_verify_throttle,
    humanfmt::HumanFmt,
    index_parser::StreamedDigest,
    integrity::{self, CommitError, RenamePlan},
    metrics,
    partial_file::TempPath,
    upstream_head::ContentLength,
};
#[cfg(feature = "splice")]
use crate::{
    error::MirrorDownloadRate,
    rate_checker::{InsufficientRate, RateCheckDirection, RateChecker},
};

/// The abort every barrier performs when its owner is dropped without
/// reaching a sink: publish `Aborted` and count it. Registry retirement is
/// separate: a download's write lease can outlive its failure notification.
/// Shared so the three `Drop` impls cannot drift apart.
///
/// Synchronous by necessity: `Drop` cannot await and the status handle is an
/// `Arc<RwLock<...>>` (not an owned write guard), so the write lock is taken
/// under `block_in_place`.
fn abort_on_drop(status: &Arc<tokio::sync::RwLock<ActiveDownloadStatus>>) {
    tokio::task::block_in_place(|| {
        *status.blocking_write() =
            ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
        metrics::DOWNLOADS_ABORTED.increment();
    });
}

/// Exclusive ownership of a download's registry entry. A failed download
/// remains registered until its last writer has stopped touching the partial.
/// Splice's cache file and blocking writes share this lease with the barrier;
/// notifying readers of an abort therefore cannot admit a replacement writer
/// during salvage or after cancellation of an outstanding blocking write.
/// Successful downloads carry the same lease into their rename barrier.
pub(crate) struct DownloadWriteLease {
    active_downloads: ActiveDownloads,
    key: CacheEntryKey,
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
        cache_metadata::store().invalidate(&self.key.as_ref());
    }
}

impl Drop for DownloadWriteLease {
    fn drop(&mut self) {
        self.active_downloads.remove(self.key.as_ref());
    }
}

struct InitBarrierData<'a> {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: &'a ActiveDownloads,
    /// The download's `max_upstream_downloads` slot, travelling with the
    /// barrier chain: `download` hands it to the `DownloadBarrier`, every
    /// other sink drops it here with the rest.
    slot: UpstreamSlot,
    key: CacheEntryKeyRef<'a>,
    resource_kind: ResourceKind,
    /// The raw client request URI path (pre-normalisation, pre-redirect),
    /// carried through to `RenameBarrier::commit`'s `RenamePlan`.
    raw_uri_path: &'a str,
    /// Unused, receivers just need to get notified by drop.
    _tx: tokio::sync::watch::Sender<()>,
}

#[must_use]
pub(crate) struct InitBarrier<'a> {
    data: Option<InitBarrierData<'a>>,
}

impl<'a> InitBarrier<'a> {
    /// `raw_uri_path` is the client's request path exactly as received
    /// (pre-normalisation, and for the splice backend pre-redirect and
    /// query-stripped) - both backends must agree, or registry keys diverge.
    ///
    /// Takes the whole [`Origination`], slot included: the barrier chain is
    /// what carries the slot from here on, and a backend that registered a
    /// download cannot end up holding its slot loose.
    pub(crate) fn new(
        origination: Origination,
        active_downloads: &'a ActiveDownloads,
        conn_details: &'a ConnectionDetails,
        raw_uri_path: &'a str,
    ) -> Self {
        let Origination {
            init_tx,
            status,
            slot,
        } = origination;
        Self {
            data: Some(InitBarrierData {
                status,
                active_downloads,
                slot,
                key: conn_details.key(),
                resource_kind: conn_details.resource_kind,
                raw_uri_path,
                _tx: init_tx,
            }),
        }
    }

    /// Finalise the entry without going through `Download` (e.g. a
    /// volatile-revalidation 304 from upstream — the existing on-disk
    /// file remains valid).  No upstream metadata is published; readers
    /// that observe `Finished { meta: None }` fall through to the
    /// post-flight cache, which will lazy-load from xattr if needed.
    pub(crate) async fn finished(mut self, path: PathBuf) {
        let data = self.data.take().expect("every sink consumes the instance");

        *data.status.write().await = ActiveDownloadStatus::Finished { path, meta: None };
        data.active_downloads.remove(data.key);
    }

    pub(crate) async fn download(
        mut self,
        path: PathBuf,
        content_length: ContentLength,
        quota_reservation: QuotaReservation,
        meta: Arc<UpstreamMetadata>,
    ) -> DownloadBarrier {
        let data = self.data.take().expect("every sink consumes the instance");

        let (tx, rx) = tokio::sync::watch::channel(());

        *data.status.write().await = ActiveDownloadStatus::Download {
            path,
            content_length,
            rx,
            meta,
        };

        DownloadBarrier {
            data: Some(DownloadBarrierData {
                status: Arc::clone(&data.status),
                lease: Arc::new(DownloadWriteLease {
                    active_downloads: data.active_downloads.clone(),
                    key: data.key.to_owned(),
                }),
                slot: data.slot,
                key: data.key.to_owned(),
                resource_kind: data.resource_kind,
                raw_uri_path: data.raw_uri_path.to_owned(),
                tx,
                quota_reservation,
                bytes_since_ping: 0,
                pinged_once: false,
            }),
        }
    }

    /// The live barrier state. `finished`, `download` and `Drop` are the only
    /// sinks and each takes it, so it is `Some` for the barrier's whole
    /// observable lifetime.
    fn data(&self) -> &InitBarrierData<'a> {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
    }

    #[must_use]
    pub(crate) fn debname(&self) -> &str {
        self.data().key.debname
    }

    /// The raw client request path this barrier will hand to `RenamePlan`.
    /// Read before [`Self::download`] consumes the barrier, so a download can
    /// decide up front which digest it will be verified against
    /// (`integrity::stream_hash_algo`) using the very string the verifier
    /// later reads its by-hash algorithm segment from.
    ///
    /// Splice-only: it is the sole backend that hashes as it writes.
    #[cfg(feature = "splice")]
    #[must_use]
    pub(crate) fn raw_uri_path(&self) -> &str {
        self.data().raw_uri_path
    }

    #[must_use]
    pub(crate) fn layout(&self) -> CacheLayout {
        self.data().key.layout
    }

    /// The alias-resolved on-disk identity of the download's mirror - the
    /// same site `ConnectionDetails::site` resolves (alias' `main` host when
    /// the request was redirected, else the mirror's own host), so
    /// `partial_path_for_barrier` places the `.partial` in the same tree
    /// as the eventual rename target.
    #[must_use]
    pub(crate) fn site(&self) -> MirrorSite<'_> {
        // `key.mirror` is the canonical (alias-resolved) mirror, so this is
        // the same projection as `ConnectionDetails::site`.
        let mirror = self.data().key.mirror;
        MirrorSite {
            host: mirror.host().as_cache_host(),
            port: mirror.port(),
            path: mirror.path(),
        }
    }
}

impl Drop for InitBarrier<'_> {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            abort_on_drop(&data.status);
            data.active_downloads.remove(data.key);
        }
        // `data` (and with it the `UpstreamSlot`) drops with the struct.
    }
}

struct DownloadBarrierData {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    lease: Arc<DownloadWriteLease>,
    /// The download's `max_upstream_downloads` slot, held until
    /// [`DownloadBarrier::begin_rename`] -- where every backend has
    /// necessarily finished reading the upstream body -- and dropped with the
    /// rest on every other exit. Never reaches the `RenameBarrier`.
    slot: UpstreamSlot,
    key: CacheEntryKey,
    resource_kind: ResourceKind,
    raw_uri_path: String,
    tx: tokio::sync::watch::Sender<()>,
    /// Minted only by `CacheQuota::try_acquire`, so holding a barrier proves
    /// the quota was checked; `commit` finalises it, `Drop` reverts it.
    quota_reservation: QuotaReservation,
    /// Single-owner via `&mut DownloadBarrier`; no atomic needed.
    bytes_since_ping: u64,
    /// Whether any ping was sent yet — the first one is unbatched.
    pinged_once: bool,
}

impl DownloadBarrierData {
    fn flush_batched_ping(&mut self) {
        if self.bytes_since_ping > 0 {
            self.internal_ping();
        }
    }

    fn internal_ping(&mut self) {
        // Send error means no receivers; not cached because send() is a cheap atomic load.
        if let Err(_err @ tokio::sync::watch::error::SendError(())) = self.tx.send(()) {}
        self.bytes_since_ping = 0;
        self.pinged_once = true;
    }
}

#[must_use]
pub(crate) struct DownloadBarrier {
    data: Option<DownloadBarrierData>,
}

impl DownloadBarrier {
    /// Accumulate `bytes` and ping receivers once `PING_BATCH_THRESHOLD` is crossed.
    /// `&mut self` enforces single-writer access at compile time.
    ///
    /// The very first ping is sent unbatched: the originating client reads
    /// the partial file itself, so without it a download smaller than the
    /// batch threshold would deliver its first byte only when the whole
    /// download finished (pure store-and-forward latency, no wake-up-storm
    /// justification).
    pub(crate) fn ping_batched(&mut self, bytes: u64) {
        /// Roughly 1 MiB; tunes between wake-up overhead and joiner latency.
        const PING_BATCH_THRESHOLD: u64 = 1024 * 1024;

        let data = self
            .data
            .as_mut()
            .expect("every sink consumes the instance");
        data.bytes_since_ping = data.bytes_since_ping.saturating_add(bytes);
        if !data.pinged_once || data.bytes_since_ping >= PING_BATCH_THRESHOLD {
            data.internal_ping();
        }
    }

    pub(crate) async fn abort_with_reason(mut self, reason: AbortReason) {
        let data = self
            .data
            .as_ref()
            .expect("every sink consumes the instance");

        *data.status.write().await = ActiveDownloadStatus::Aborted(reason);
        metrics::DOWNLOADS_ABORTED.increment();
        // Keep self armed while awaiting the status lock. After publishing,
        // dropping the sender wakes readers, but writers retain the lease.
        drop(self.data.take());
    }

    pub(crate) async fn begin_rename(mut self) -> RenameBarrier {
        let data = self
            .data
            .as_mut()
            .expect("every sink consumes the instance");

        // Ordering matters: flush the final ping, flip `Download -> Verifying`
        // under the status write lock, release the lock, then drop `tx`.
        //
        // The flip is what closes the late-joiner race: any reader that wakes
        // from `receiver.changed().await` with `RecvError` (sender dropped)
        // re-reads `status` and is guaranteed to see `Verifying`, `Finished`,
        // or `Aborted` — never a stale `Download`. The reader paths in
        // `hyper_conn.rs` and `sendfile_conn.rs` treat `Verifying` as "all
        // bytes are on disk; drain the open file handle" rather than as an
        // error.
        //
        // The write lock is only held for the brief variant swap, NOT for the
        // subsequent SHA-256/-512 hashing in `RenameBarrier::commit` (which can
        // take hundreds of ms for a large `.deb`). Late-joiner readers are
        // therefore not stalled during verification.
        data.flush_batched_ping();
        {
            let mut lock = data.status.write().await;
            let prev = std::mem::replace(
                &mut *lock,
                ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail),
            );
            *lock = match prev {
                ActiveDownloadStatus::Download {
                    path,
                    content_length: _,
                    rx: _,
                    meta,
                } => ActiveDownloadStatus::Verifying { path, meta },
                other @ (ActiveDownloadStatus::Init(_)
                | ActiveDownloadStatus::Verifying { .. }
                | ActiveDownloadStatus::Finished { .. }
                | ActiveDownloadStatus::Aborted(_)) => {
                    error!(
                        "Download barrier begin_rename reached with non-Download status for {} from mirror {}; leaving the status untouched: {other:?}",
                        data.key.debname, data.key.mirror
                    );
                    other
                }
            };
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
                key: data.key,
                resource_kind: data.resource_kind,
                raw_uri_path: data.raw_uri_path,
                quota_reservation: Some(data.quota_reservation),
            }),
        }
    }
}

#[cfg(feature = "splice")]
impl DownloadBarrier {
    /// Retain the registry entry through salvage and every blocking write.
    /// The lease carries no progress sender, so failed readers wake promptly.
    pub(crate) fn write_lease(&self) -> Arc<DownloadWriteLease> {
        Arc::clone(&self.data.as_ref().expect("live download barrier").lease)
    }

    /// Subscribe a `watch::Receiver` for handoff to a spawned file-serve task.
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        let data = self
            .data
            .as_ref()
            .expect("every sink consumes the instance");
        data.tx.subscribe()
    }

    pub(crate) fn status(&self) -> &Arc<tokio::sync::RwLock<ActiveDownloadStatus>> {
        let data = self
            .data
            .as_ref()
            .expect("every sink consumes the instance");
        &data.status
    }

    /// Upstream-rate check that consumes the barrier on failure (into
    /// `Aborted(MirrorDownloadRate)`) and returns the `io::Error` to propagate.
    /// Bundling the check and the abort in one by-value call removes the
    /// "remember to also abort" maintenance burden at every splice loop top.
    pub(crate) async fn check_upstream_rate(
        self,
        rate_checker: Option<&RateChecker>,
    ) -> Result<Self, std::io::Error> {
        let Some(rate) = rate_checker.and_then(|rc| rc.check_fail(RateCheckDirection::Upstream))
        else {
            return Ok(self);
        };
        Err(self.abort_with_rate_timeout(rate).await)
    }

    /// Mid-stream variant of [`Self::check_upstream_rate`] for callers that already
    /// obtained an `InsufficientRate` outside of an awaitable barrier-owning
    /// context (e.g. surfaced from a closure that does not own the barrier).
    pub(crate) async fn abort_with_rate_timeout(
        self,
        download_rate_err: InsufficientRate,
    ) -> std::io::Error {
        // The `io::Error` only ever surfaces inside a splice log line that
        // already names the file and mirror (`splice_error_outcome`'s
        // subject, or the tmp path of a detached download), so its own
        // context names just the side, like the sendfile and
        // `splice/http.rs` rate-timeout sites.  The `AbortReason` below keeps
        // the mirror and file: hyper joiners render it on their own.
        let io_err = download_rate_err.to_timeout_io_error(format_args!(" for upstream"));
        #[cfg(feature = "hyper")]
        let reason = {
            let data = self
                .data
                .as_ref()
                .expect("every sink consumes the instance");
            AbortReason::MirrorDownloadRate(MirrorDownloadRate {
                download_rate_err,
                mirror: data.key.mirror.clone(),
                debname: data.key.debname.clone(),
            })
        };
        #[cfg(not(feature = "hyper"))]
        let reason = AbortReason::MirrorDownloadRate(MirrorDownloadRate {});
        self.abort_with_reason(reason).await;
        io_err
    }
}

impl Drop for DownloadBarrier {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            abort_on_drop(&data.status);
        }
    }
}

struct RenameBarrierData {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    lease: Arc<DownloadWriteLease>,
    key: CacheEntryKey,
    resource_kind: ResourceKind,
    raw_uri_path: String,
    /// `Some` until `commit` hands it to `integrity::verify_and_rename`,
    /// which finalises it in the rename step; `None` only for the rest of
    /// that one `commit` call. Reverted by drop on every other path.
    quota_reservation: Option<QuotaReservation>,
}

#[must_use]
pub(crate) struct RenameBarrier {
    data: Option<RenameBarrierData>,
}

impl RenameBarrier {
    /// Verify the finished temp file, rename it into the cache, transition the
    /// barrier to `Finished`, publish upstream metadata, and clear the
    /// active-downloads entry.
    ///
    /// Verification is delegated to `integrity::verify_and_rename`; this is the
    /// **only** way to finish a `RenameBarrier`, so no download backend can
    /// commit a download without it. On any `CommitError` the status becomes
    /// `Aborted`; a checksum mismatch also arms the re-download throttle and
    /// removes the bad partial before the registry entry is retired. The
    /// error is returned to the caller; `Drop` stays the safety net for a
    /// cancelled future, while blocking jobs retain the registry lease.
    ///
    /// Lock ordering: `verify_and_rename` runs *before* the status write lock
    /// is acquired, so late-joiner readers (`status.read().await`) can proceed
    /// concurrently while the temp file is being hashed on a blocking
    /// thread. The lock is only held for the brief `Verifying -> Finished`
    /// status flip after verification succeeds. The preceding `Download ->
    /// Verifying` flip happens in `DownloadBarrier::begin_rename`.
    ///
    /// Cancellation window: if the `commit` future is dropped between the
    /// rename completing and the status-write lock being acquired, the
    /// renamed file is already in the cache but the `Verifying -> Finished`
    /// flip never runs; `Drop for RenameBarrier` then flips status to
    /// `Aborted` and releases its registry lease. Outstanding blocking jobs
    /// retain their lease until they finish. The quota stays
    /// right: the reservation is finalised inside the rename's blocking
    /// closure, which runs to completion regardless of the cancellation.
    /// The metadata does *not* take care of itself: on a re-download the
    /// store still holds the previous version's validators, and `resolve`'s
    /// hot path answers from that map without ever stat'ing the file -- so
    /// the daemon would serve a stale `ETag` / `Last-Modified` for the new
    /// bytes, and honour an `If-None-Match` on the old tag with a 304, until
    /// the process exits. The metadata entry is therefore invalidated in the
    /// blocking rename job itself before it releases its registry lease, so
    /// the next `resolve` lazy-loads the renamed file's own xattrs.
    ///
    /// Aborts *before* the rename invalidate nothing: the cached file is
    /// untouched and its memoized validators still describe it. On a
    /// filesystem without xattrs the store is their only carrier, so
    /// invalidating there would lose them for the life of the process
    /// (`resolve` negatively caches the resulting `(None, None)`).
    ///
    /// `temp_path` is the finished `.partial` / temp file; on success its
    /// guard is defused (the file now lives at `dest_path`), on a checksum
    /// mismatch the file is unlinked (its bytes are known-bad, resuming them
    /// cannot succeed), on a transient verify/rename failure the guard's
    /// `OnDrop::Keep` keeps it for resumption. `declared_bytes` is the fallback for
    /// quota finalisation when the temp file cannot be stat'ed. Rename
    /// failures are logged here (with `CACHE_IO_FAILURE`); mismatch and
    /// verify-IO failures are logged by `verify_and_rename`.
    pub(crate) async fn commit(
        mut self,
        temp_path: TempPath,
        dest_path: PathBuf,
        declared_bytes: u64,
        streamed_digest: Option<StreamedDigest>,
    ) -> Result<(), CommitError> {
        // Use the actual on-disk size rather than the declared length.
        // Earlier validation ensures these match today, but the defensive
        // stat keeps the quota-finalisation input honest if a future change
        // weakens an upstream invariant.
        let bytes_received = match tokio::fs::metadata(temp_path.as_ref()).await {
            Ok(m) => m.len(),
            Err(err) => {
                warn!(
                    "Failed to stat temp file `{}` before rename; using the declared size:  {}",
                    temp_path.display(),
                    ErrorReport(&err)
                );
                declared_bytes
            }
        };
        let plan = {
            let data = self
                .data
                .as_ref()
                .expect("every sink consumes the instance");
            RenamePlan {
                temp_path: temp_path.to_path_buf(),
                dest_path,
                bytes_received,
                resource_kind: data.resource_kind,
                debname: data.key.debname.clone(),
                host: data.key.mirror.host().as_str().to_owned(),
                mirror_path: data.key.mirror.path().to_owned(),
                raw_uri_path: data.raw_uri_path.clone(),
                streamed_digest,
            }
        };
        let reservation = self
            .data
            .as_mut()
            .expect("every sink consumes the instance")
            .quota_reservation
            .take()
            .expect("commit runs once per barrier");
        let lease = Arc::clone(
            &self
                .data
                .as_ref()
                .expect("every sink consumes the instance")
                .lease,
        );
        if let Err(err) = integrity::verify_and_rename(&plan, reservation, lease).await {
            if let CommitError::Rename(io_err) = &err {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to rename temp file `{}` to `{}`; leaving the download uncached:  {}",
                    plan.temp_path.display(),
                    plan.dest_path.display(),
                    ErrorReport(io_err)
                );
            }
            // Retire the entry here, not in `Drop` (which runs only after
            // the `TempPath` parameter is dropped and a blocking write lock
            // is won): a request arriving while the entry was still
            // joinable in `Verifying` state was served the mismatching
            // partial as a finished file. Ordering, all under the status
            // write lock so no joiner can observe an intermediate state:
            // arm the throttle (genuine content mismatch only; VerifyIo and
            // Rename are transient local problems), then publish
            // `Aborted(Discarded)`. A joiner reading the new status finds
            // the throttle armed and answers its 503 (`await_serveable`);
            // a request arriving after the removal below originates anew
            // and hits the pre-upstream throttle gate. `Discarded` (not
            // `AlreadyLoggedJustFail`): every byte is on disk, so readers
            // that already hold the file drain it instead of truncating the
            // body they were promised.
            let data = self
                .data
                .as_ref()
                .expect("every sink consumes the instance");
            let checksum_mismatch = matches!(err, CommitError::ChecksumMismatch);
            let throttle = {
                let mut status = data.status.write().await;
                let throttle = if checksum_mismatch {
                    global_verify_throttle().record_failure(data.key.as_ref())
                } else {
                    None
                };
                *status =
                    ActiveDownloadStatus::Aborted(AbortReason::Discarded { checksum_mismatch });
                throttle
            };
            metrics::DOWNLOADS_ABORTED.increment();
            // Publication is complete, so Drop must not replace Discarded
            // with a generic abort. Keep the lease until the last mutation
            // of the partial has finished, including a detached unlink.
            let data = self.data.take().expect("every sink consumes the instance");
            if checksum_mismatch {
                discard_partial(temp_path, Arc::clone(&data.lease)).await;
            }
            drop(data.lease);
            if let Some((window, failures)) = throttle {
                // Integration tests use this line as the "throttle is
                // observable" sync point: it must stay after the entry
                // removal above.
                info!(
                    "Throttling downloads of {} from mirror {} for {} after checksum verification failure (consecutive failures: {failures})",
                    data.key.debname,
                    data.key.mirror,
                    HumanFmt::Time(window),
                );
            }
            // `data` drops here; the reservation was reverted when
            // `verify_and_rename` dropped it.
            return Err(err);
        }

        // Verified and renamed: the temp file no longer exists under its
        // old name, so the guard must not try to remove it.
        TempPath::defuse(temp_path);

        // The quota was finalised in the rename step. Take the write lock
        // briefly for the `Verifying -> Finished` status flip.
        //
        // `self.data` stays populated across that `.await` so `Drop` really
        // is the safety net the doc above promises: a future cancelled while
        // waiting for the lock leaves the entry `Verifying` and unretired
        // otherwise. It is taken only past the last await, where no
        // cancellation can turn a `Finished` entry back into an `Aborted`
        // one.
        let meta_for_status: Option<Arc<UpstreamMetadata>> = {
            let data = self
                .data
                .as_ref()
                .expect("every sink consumes the instance");
            let mut lock = data.status.write().await;
            let meta = match &*lock {
                ActiveDownloadStatus::Verifying { path: _, meta } => Some(Arc::clone(meta)),
                ActiveDownloadStatus::Init(_)
                | ActiveDownloadStatus::Download { .. }
                | ActiveDownloadStatus::Finished { .. }
                | ActiveDownloadStatus::Aborted(_) => {
                    error!(
                        "RenameBarrier::commit reached with non-Verifying status for {} from mirror {}; finishing the download without publishing cache metadata: {:?}",
                        data.key.debname, data.key.mirror, *lock
                    );
                    // Nothing to publish; the invalidate above already
                    // dropped the previous version's validators.
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
            cache_metadata::store().set(data.key.clone(), meta);
        }
        global_verify_throttle().record_success(data.key.as_ref());
        drop(data.lease);

        Ok(())
    }
}

/// Known-bad bytes cannot be resumed. The blocking unlink owns the registry
/// lease so cancellation cannot admit a new writer at the same partial path
/// while that unlink is still queued. Open readers keep their inode as usual.
async fn discard_partial(temp_path: TempPath, lease: Arc<DownloadWriteLease>) {
    lease
        .spawn_blocking(move |_lease| {
            let path = TempPath::defuse(temp_path);
            if let Err(err) = std::fs::remove_file(&path) {
                if err.kind() == std::io::ErrorKind::NotFound {
                    warn!(
                        "Failed to remove partial file `{}`; continuing without it:  {}",
                        path.display(),
                        ErrorReport(&err)
                    );
                } else {
                    error!(
                        "Failed to remove partial file `{}`; it stays on disk:  {}",
                        path.display(),
                        ErrorReport(&err)
                    );
                }
            }
        })
        .await
        .expect("partial removal should not panic");
}

impl Drop for RenameBarrier {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            // Before rename, the cached file is untouched and its memoized
            // validators still describe it. After rename, the blocking job
            // already invalidates them before releasing its lease. Invalidating
            // here would discard valid metadata on an earlier abort; on a
            // filesystem without xattrs the store is its only carrier.
            abort_on_drop(&data.status);
        }
        // `data` (and with it any still-held `QuotaReservation`) drops with
        // the struct right after this, reverting the reservation.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::ClientHost, deb_mirror::MirrorKind};

    fn key(debname: &str) -> CacheEntryKey {
        CacheEntryKey {
            mirror: crate::deb_mirror::Mirror::new(
                ClientHost::new(String::from("guards.test")).expect("valid host"),
                std::num::NonZero::new(80),
                "/debian".into(),
                MirrorKind::Structured,
            ),
            debname: debname.into(),
            layout: CacheLayout::StructuredPool,
        }
    }

    #[cfg(feature = "splice")]
    fn pause_blocking_pool(runtime: &tokio::runtime::Runtime) -> std::sync::mpsc::Sender<()> {
        let (resume, paused) = std::sync::mpsc::channel();
        let (started, ready) = std::sync::mpsc::channel();
        drop(runtime.spawn_blocking(move || {
            started.send(()).unwrap();
            let _released = paused.recv();
        }));
        ready.recv().unwrap();
        resume
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
            match cache_metadata::init() {
                Ok(()) | Err(_) => {}
            }
            let old_metadata = Arc::new(UpstreamMetadata::from_upstream(
                Some(String::from("\"previous-version\"")),
                None,
            ));
            cache_metadata::store().set(key.clone(), Arc::clone(&old_metadata));
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

    #[cfg(feature = "splice")]
    async fn downloading(active: &ActiveDownloads, key: &CacheEntryKey) -> DownloadBarrier {
        let details = ConnectionDetails {
            client: crate::test_support::local_client(),
            request_received_at: crate::precise_instant::PreciseInstant::now(),
            upstream_host: key.mirror.host().clone(),
            mirror: key.mirror.clone(),
            debname: key.debname.clone(),
            resource_kind: ResourceKind::Pool,
            origin_fields: None,
        };
        let length = ContentLength::Exact(std::num::NonZero::new(1024).unwrap());
        let quota = crate::cache_quota::CacheQuota::new(0, None)
            .try_acquire(length, 0, &key.debname)
            .ok()
            .expect("unlimited quota");
        InitBarrier::new(
            active.originate_uncapped(key.as_ref()),
            active,
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

        barrier
            .abort_with_reason(AbortReason::AlreadyLoggedJustFail)
            .await;
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
    async fn dropped_download_keeps_its_writer_lease() {
        let active = ActiveDownloads::new();
        let key = key("cancelled.deb");
        let barrier = downloading(&active, &key).await;
        let status = Arc::clone(barrier.status());
        let mut progress = barrier.subscribe();
        let writer = barrier.write_lease();

        drop(barrier);
        assert!(progress.changed().await.is_err());
        assert!(matches!(
            *status.read().await,
            ActiveDownloadStatus::Aborted(_)
        ));
        assert_eq!(active.len(), 1);
        drop(writer);
        assert_eq!(active.len(), 0);
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
    /// abandoned *before* the rename leaves behind: the entry is still
    /// registered and joinable, and `Drop` must retire it.
    fn abandoned_rename_barrier(key: &CacheEntryKey) -> RenameBarrier {
        let active_downloads = ActiveDownloads::new();
        let status = active_downloads.insert_uncapped(key.as_ref());
        RenameBarrier {
            data: Some(RenameBarrierData {
                status,
                lease: Arc::new(DownloadWriteLease {
                    active_downloads,
                    key: key.clone(),
                }),
                key: key.clone(),
                resource_kind: ResourceKind::Pool,
                raw_uri_path: String::from("/debian/pool/main/t/test/test.deb"),
                // No reservation: the drop path under test never consults it.
                quota_reservation: None,
            }),
        }
    }

    /// Before rename, the cached file is the one the memoized validators
    /// already describe, and dropping them would be a
    /// regression, not a safety measure: on a filesystem without xattrs the
    /// store is their only carrier and `resolve` negatively caches the
    /// resulting `(None, None)` for the life of the process, so every
    /// `If-None-Match` on that file would miss and re-send the whole body.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn dropping_a_rename_barrier_keeps_the_cached_validators() {
        // The store is a process-global installed by `main`; install it here
        // and tolerate another test in the same process having won the race.
        match cache_metadata::init() {
            Ok(()) | Err(_) => {}
        }
        let store = cache_metadata::store();
        let key = key("kept-validators.deb");
        let metadata = Arc::new(UpstreamMetadata::from_upstream(
            Some(String::from("\"current-version\"")),
            None,
        ));
        store.set(key.clone(), Arc::clone(&metadata));
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
