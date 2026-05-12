use std::{path::PathBuf, sync::Arc};

use crate::{
    AbortReason, ActiveDownloadStatus, ActiveDownloads, ContentLength,
    cache_layout::CacheLayout,
    cache_metadata::{self, CacheMetadataKey, UpstreamMetadata},
    cache_quota::QuotaReservation,
    config::CacheHost,
    deb_mirror::Mirror,
    metrics,
};
#[cfg(feature = "splice")]
use crate::{
    error::MirrorDownloadRate,
    rate_checked_body::{InsufficientRate, RateCheckDirection, RateChecker},
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
    /// Unused, receivers just needs to get notified by drop
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

        // Ordering matters: flush the final ping, drop `tx`, then take the status
        // write lock. The watch channel retains the last sent value after sender drop,
        // so a racing receiver either wakes from `.changed()` Ok (saw the ping) or
        // RecvError then observes Finished after `RenameBarrier::release`.
        data.flush_batched_ping();
        drop(data.tx);

        let lock = data.status.write_owned().await;

        RenameBarrier {
            data: Some(RenameBarrierData {
                lock,
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
    lock: tokio::sync::OwnedRwLockWriteGuard<ActiveDownloadStatus>,
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
    /// Transition the barrier to `Finished`, publish the upstream metadata
    /// to the post-flight [`cache_metadata`] cache, and clear the
    /// active-downloads entry.
    ///
    /// Ordering matters: the cache is populated **before** the entry
    /// is removed, so workers that miss the entry always find it
    /// primed.  Workers that still see the entry observe `Finished
    /// { meta: Some(_) }` and read from status.  The non-`Download`
    /// fallback below is a logic-bug path: logs, sets `meta: None`,
    /// skips the cache publish; observers fall through to
    /// `cache_metadata::resolve` like `InitBarrier::finished`.
    pub(crate) fn release(mut self, path: PathBuf, bytes_received: u64) {
        let mut data = self.data.take().expect("every sink consumes the instance");

        if let Some(reservation) = data.quota_reservation {
            reservation.finalize(bytes_received);
        }

        // Carry the in-flight metadata over to the post-flight cache and
        // the `Finished` status before we tear the active-downloads entry
        // down.  The barrier reached this point via `DownloadBarrier`
        // (which set the status to `Download { meta }`); any other shape
        // is a logic bug — log it, fall back to no metadata, and proceed
        // with the status / cache transitions so the active-downloads
        // entry doesn't leak.
        let meta_for_status: Option<Arc<UpstreamMetadata>> = match &*data.lock {
            ActiveDownloadStatus::Download {
                path: _,
                content_length: _,
                rx: _,
                meta,
            } => Some(Arc::clone(meta)),
            ActiveDownloadStatus::Init(_)
            | ActiveDownloadStatus::Finished { .. }
            | ActiveDownloadStatus::Aborted(_) => {
                log::error!(
                    "RenameBarrier::release reached with non-Download status: {:?}",
                    *data.lock
                );
                None
            }
        };

        *data.lock = ActiveDownloadStatus::Finished {
            path,
            meta: meta_for_status.clone(),
        };
        drop(data.lock);

        if let Some(meta) = meta_for_status {
            cache_metadata::store().set(
                CacheMetadataKey::new(data.mirror.clone(), data.debname.clone(), data.layout),
                meta,
            );
        }
        data.active_downloads
            .remove(&data.mirror, &data.debname, data.layout);
    }
}

impl Drop for RenameBarrier {
    fn drop(&mut self) {
        if let Some(mut data) = self.data.take() {
            *data.lock = ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
            metrics::DOWNLOADS_ABORTED.increment();
            drop(data.lock);

            data.active_downloads
                .remove(&data.mirror, &data.debname, data.layout);
        }
    }
}
