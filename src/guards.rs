use std::{path::PathBuf, sync::Arc};

use tracing::{error, info};

use crate::{
    ContentLength,
    active_downloads::{AbortReason, ActiveDownloadStatus, ActiveDownloads},
    cache_layout::CacheLayout,
    cache_metadata::{self, CacheMetadataKey, UpstreamMetadata},
    cache_quota::QuotaReservation,
    config::CacheHost,
    deb_mirror::Mirror,
    global_verify_throttle,
    humanfmt::HumanFmt,
    integrity::{self, CommitError, RenamePlan},
    metrics,
};
#[cfg(feature = "splice")]
use crate::{
    error::MirrorDownloadRate,
    rate_checker::{InsufficientRate, RateCheckDirection, RateChecker},
};

struct InitBarrierData<'a> {
    status: &'a Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: &'a ActiveDownloads,
    mirror: &'a Mirror,
    /// When the request was resolved against an alias mapping, the on-disk
    /// host directory is the alias' main host (not `mirror.host()`).  Kept
    /// here so that `partial_path_for_barrier` lays the `.partial` next to
    /// the eventual rename target produced by
    /// `ConnectionDetails::cache_dir_path`, which also uses this host.
    aliased_host: Option<&'static CacheHost>,
    debname: &'a str,
    layout: CacheLayout,
    /// Unused, receivers just need to get notified by drop.
    _tx: tokio::sync::watch::Sender<()>,
}

#[must_use]
pub(crate) struct InitBarrier<'a> {
    data: Option<InitBarrierData<'a>>,
}

impl<'a> InitBarrier<'a> {
    pub(crate) fn new(
        tx: tokio::sync::watch::Sender<()>,
        status: &'a Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
        active_downloads: &'a ActiveDownloads,
        mirror: &'a Mirror,
        aliased_host: Option<&'static CacheHost>,
        debname: &'a str,
        layout: CacheLayout,
    ) -> Self {
        Self {
            data: Some(InitBarrierData {
                status,
                active_downloads,
                mirror,
                aliased_host,
                debname,
                layout,
                _tx: tx,
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
        data.active_downloads
            .remove(data.mirror, data.debname, data.layout);
    }

    pub(crate) async fn download(
        mut self,
        path: PathBuf,
        content_length: ContentLength,
        quota_reservation: Option<QuotaReservation>,
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
                status: Arc::clone(data.status),
                active_downloads: data.active_downloads.clone(),
                mirror: data.mirror.clone(),
                debname: data.debname.to_owned(),
                layout: data.layout,
                tx,
                quota_reservation,
                bytes_since_ping: 0,
            }),
        }
    }

    #[must_use]
    pub(crate) fn mirror(&self) -> &Mirror {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
            .mirror
    }

    #[must_use]
    pub(crate) fn debname(&self) -> &str {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
            .debname
    }

    #[must_use]
    pub(crate) fn layout(&self) -> CacheLayout {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
            .layout
    }

    /// Aliased host the request was redirected to, if any.  Matches the
    /// host used by `ConnectionDetails::cache_dir_path` so callers (notably
    /// `partial_path_for_barrier`) can place the `.partial` file in the
    /// same host directory as the eventual rename target.
    #[must_use]
    pub(crate) fn aliased_host(&self) -> Option<&'static CacheHost> {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
            .aliased_host
    }
}

impl Drop for InitBarrier<'_> {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            tokio::task::block_in_place(|| {
                *data.status.blocking_write() =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                metrics::DOWNLOADS_ABORTED.increment();
                data.active_downloads
                    .remove(data.mirror, data.debname, data.layout);
            });
        }
    }
}

struct DownloadBarrierData {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: ActiveDownloads,
    mirror: Mirror,
    debname: String,
    layout: CacheLayout,
    tx: tokio::sync::watch::Sender<()>,
    quota_reservation: Option<QuotaReservation>,
    /// Single-owner via `&mut DownloadBarrier`; no atomic needed.
    bytes_since_ping: u64,
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
    }
}

#[must_use]
pub(crate) struct DownloadBarrier {
    data: Option<DownloadBarrierData>,
}

impl DownloadBarrier {
    /// Accumulate `bytes` and ping receivers once `PING_BATCH_THRESHOLD` is crossed.
    /// `&mut self` enforces single-writer access at compile time.
    pub(crate) fn ping_batched(&mut self, bytes: u64) {
        /// Roughly 1 MiB; tunes between wake-up overhead and joiner latency.
        const PING_BATCH_THRESHOLD: u64 = 1024 * 1024;

        let data = self
            .data
            .as_mut()
            .expect("every sink consumes the instance");
        data.bytes_since_ping = data.bytes_since_ping.saturating_add(bytes);
        if data.bytes_since_ping >= PING_BATCH_THRESHOLD {
            data.internal_ping();
        }
    }

    pub(crate) async fn abort_with_reason(mut self, reason: AbortReason) {
        let data = self.data.take().expect("every sink consumes the instance");

        *data.status.write().await = ActiveDownloadStatus::Aborted(reason);
        metrics::DOWNLOADS_ABORTED.increment();
        data.active_downloads
            .remove(&data.mirror, &data.debname, data.layout);
    }

    pub(crate) async fn begin_rename(mut self) -> RenameBarrier {
        let mut data = self.data.take().expect("every sink consumes the instance");

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
                    content_length,
                    rx: _,
                    meta,
                } => ActiveDownloadStatus::Verifying {
                    path,
                    content_length,
                    meta,
                },
                other @ (ActiveDownloadStatus::Init(_)
                | ActiveDownloadStatus::Verifying { .. }
                | ActiveDownloadStatus::Finished { .. }
                | ActiveDownloadStatus::Aborted(_)) => {
                    error!("begin_rename reached with non-Download status: {other:?}");
                    other
                }
            };
        }
        drop(data.tx);

        RenameBarrier {
            data: Some(RenameBarrierData {
                status: data.status,
                active_downloads: data.active_downloads,
                mirror: data.mirror,
                debname: data.debname,
                layout: data.layout,
                quota_reservation: data.quota_reservation,
            }),
        }
    }
}

#[cfg(feature = "splice")]
impl DownloadBarrier {
    /// Unconditional ping (e.g. startup prefix, kTLS extra body).
    pub(crate) fn ping(&mut self) {
        let data = self
            .data
            .as_mut()
            .expect("every sink consumes the instance");
        data.internal_ping();
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

    /// Mid-stream variant of [`check_upstream_rate`] for callers that already
    /// obtained an `InsufficientRate` outside of an awaitable barrier-owning
    /// context (e.g. surfaced from a closure that does not own the barrier).
    pub(crate) async fn abort_with_rate_timeout(
        self,
        download_rate_err: InsufficientRate,
    ) -> std::io::Error {
        let data = self
            .data
            .as_ref()
            .expect("every sink consumes the instance");
        let io_err = download_rate_err.to_timeout_io_error(format_args!(
            " for mirror {} downloading file {}",
            data.mirror, data.debname,
        ));
        let reason = AbortReason::MirrorDownloadRate(MirrorDownloadRate {
            download_rate_err,
            mirror: data.mirror.clone(),
            debname: data.debname.clone(),
        });
        self.abort_with_reason(reason).await;
        io_err
    }
}

impl Drop for DownloadBarrier {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            tokio::task::block_in_place(|| {
                *data.status.blocking_write() =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                metrics::DOWNLOADS_ABORTED.increment();
                data.active_downloads
                    .remove(&data.mirror, &data.debname, data.layout);
            });
        }
    }
}

struct RenameBarrierData {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: ActiveDownloads,
    mirror: Mirror,
    debname: String,
    layout: CacheLayout,
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
    /// commit a download without it. On any `CommitError` the barrier is
    /// dropped (its `Drop` runs the abort / signal-waiters path, exactly as a
    /// failed rename does today) and the error is returned to the caller.
    ///
    /// Lock ordering: `verify_and_rename` runs *before* the status write lock
    /// is acquired, so late-joiner readers (`status.read().await`) can proceed
    /// concurrently while the temp file is being hashed on a blocking
    /// thread. The lock is only held for the brief `Verifying -> Finished`
    /// status flip after verification succeeds. The preceding `Download ->
    /// Verifying` flip happens in `DownloadBarrier::begin_rename`.
    ///
    /// Cancellation window: if the `commit` future is dropped between the
    /// `tokio::fs::rename` completing and the status-write lock being
    /// acquired, the renamed file is already in the cache but the
    /// `Verifying -> Finished` flip never runs; `Drop for RenameBarrier`
    /// then flips status to `Aborted` and removes the active-downloads
    /// entry. The xattr-backed metadata persists on disk regardless, so
    /// post-flight readers lazy-load `ETag` / `Last-Modified` via
    /// `cache_metadata::store().resolve(...)` instead of from the in-process
    /// Arc -- benign for correctness, just slightly slower for the first
    /// read after cancellation.
    pub(crate) async fn commit(mut self, plan: RenamePlan) -> Result<(), CommitError> {
        if let Err(err) = integrity::verify_and_rename(&plan).await {
            // Arm the re-download throttle only on a genuine content
            // mismatch; VerifyIo/Rename are transient local problems.
            if matches!(err, CommitError::ChecksumMismatch) {
                let data = self
                    .data
                    .as_ref()
                    .expect("every sink consumes the instance");
                if let Some((window, failures)) = global_verify_throttle().record_failure(
                    &data.mirror,
                    &data.debname,
                    data.layout,
                ) {
                    info!(
                        "Throttling downloads of {} from mirror {} for {} after checksum verification failure (consecutive failures: {failures})",
                        data.debname,
                        data.mirror,
                        HumanFmt::Time(window),
                    );
                }
            }
            // `self.data` is still held: Drop runs the abort path.
            return Err(err);
        }

        // Verified and renamed. Finalise quota outside the lock, then take the
        // write lock briefly for the `Verifying -> Finished` status flip.
        let data = self.data.take().expect("every sink consumes the instance");

        if let Some(reservation) = data.quota_reservation {
            reservation.finalize(plan.bytes_received);
        }

        let meta_for_status: Option<Arc<UpstreamMetadata>> = {
            let mut lock = data.status.write().await;
            let meta = match &*lock {
                ActiveDownloadStatus::Verifying {
                    path: _,
                    content_length: _,
                    meta,
                } => Some(Arc::clone(meta)),
                ActiveDownloadStatus::Init(_)
                | ActiveDownloadStatus::Download { .. }
                | ActiveDownloadStatus::Finished { .. }
                | ActiveDownloadStatus::Aborted(_) => {
                    error!(
                        "RenameBarrier::commit reached with non-Verifying status: {:?}",
                        *lock
                    );
                    None
                }
            };
            *lock = ActiveDownloadStatus::Finished {
                path: plan.dest_path,
                meta: meta.clone(),
            };
            meta
        };

        if let Some(meta) = meta_for_status {
            cache_metadata::store().set(
                CacheMetadataKey::new(data.mirror.clone(), data.debname.clone(), data.layout),
                meta,
            );
        }
        global_verify_throttle().record_success(&data.mirror, &data.debname, data.layout);
        data.active_downloads
            .remove(&data.mirror, &data.debname, data.layout);

        Ok(())
    }
}

impl Drop for RenameBarrier {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            // Mirrors `Drop for DownloadBarrier`: the status handle is now an
            // `Arc<RwLock<...>>` (not an `OwnedRwLockWriteGuard`), so the
            // write lock has to be acquired synchronously here.
            tokio::task::block_in_place(|| {
                *data.status.blocking_write() =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                metrics::DOWNLOADS_ABORTED.increment();
                data.active_downloads
                    .remove(&data.mirror, &data.debname, data.layout);
            });
        }
    }
}
