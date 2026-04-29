use std::{path::PathBuf, sync::Arc};

use crate::{
    AbortReason, ActiveDownloadStatus, ActiveDownloads, ContentLength,
    cache_quota::QuotaReservation, deb_mirror::Mirror, metrics,
};

struct InitBarrierData<'a> {
    status: &'a Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: &'a ActiveDownloads,
    mirror: &'a Mirror,
    debname: &'a str,
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
        debname: &'a str,
    ) -> Self {
        Self {
            data: Some(InitBarrierData {
                status,
                active_downloads,
                mirror,
                debname,
                _tx: tx,
            }),
        }
    }

    pub(crate) async fn finished(mut self, path: PathBuf) {
        let data = self.data.take().expect("every sink consumes the instance");

        *data.status.write().await = ActiveDownloadStatus::Finished(path);
        data.active_downloads.remove(data.mirror, data.debname);
    }

    pub(crate) async fn download(
        mut self,
        path: PathBuf,
        content_length: ContentLength,
        quota_reservation: Option<QuotaReservation>,
    ) -> DownloadBarrier {
        let data = self.data.take().expect("every sink consumes the instance");

        let (tx, rx) = tokio::sync::watch::channel(());

        *data.status.write().await = ActiveDownloadStatus::Download(path, content_length, rx);

        DownloadBarrier {
            data: Some(DownloadBarrierData {
                status: Arc::clone(data.status),
                active_downloads: data.active_downloads.clone(),
                mirror: data.mirror.clone(),
                debname: data.debname.to_owned(),
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
}

impl Drop for InitBarrier<'_> {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            tokio::task::block_in_place(|| {
                *data.status.blocking_write() =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                metrics::DOWNLOADS_ABORTED.increment();
                data.active_downloads.remove(data.mirror, data.debname);
            });
        }
    }
}

struct DownloadBarrierData {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: ActiveDownloads,
    mirror: Mirror,
    debname: String,
    tx: tokio::sync::watch::Sender<()>,
    quota_reservation: Option<QuotaReservation>,
    /// Bytes written since the last ping.  Single-owner (the download task
    /// exclusively mutates via `&mut DownloadBarrier`), so a plain `u64`
    /// suffices — no atomic is needed.
    bytes_since_ping: u64,
}

impl DownloadBarrierData {
    /// Send a pending batched notification if any bytes have accumulated.
    fn flush_batched_ping(&mut self) {
        if self.bytes_since_ping > 0 {
            self.internal_ping();
        }
    }

    /// Internal helper to send a ping notification and reset the bytes counter.
    fn internal_ping(&mut self) {
        if let Err(_err @ tokio::sync::watch::error::SendError(())) = self.tx.send(()) {
            // ignore send error — receivers are gone
            // Don't cache disconnected state, since send() with no receivers is just an atomic usize load.
        }
        self.bytes_since_ping = 0;
    }
}

#[must_use]
pub(crate) struct DownloadBarrier {
    data: Option<DownloadBarrierData>,
}

impl DownloadBarrier {
    /// Unconditional ping — notifies all waiting receivers immediately.
    /// Use for one-off notifications (startup prefix, kTLS extra body).
    #[cfg(feature = "splice")]
    pub(crate) fn ping(&mut self) {
        let data = self
            .data
            .as_mut()
            .expect("every sink consumes the instance");
        data.internal_ping();
    }

    /// Create a new `watch::Receiver` that will observe future pings.
    /// Used to hand off progress notifications to a spawned file-serve task.
    #[cfg(feature = "splice")]
    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        let data = self
            .data
            .as_ref()
            .expect("every sink consumes the instance");
        data.tx.subscribe()
    }

    /// Get a reference to the shared download status.
    #[cfg(feature = "splice")]
    pub(crate) fn status(&self) -> &Arc<tokio::sync::RwLock<ActiveDownloadStatus>> {
        let data = self
            .data
            .as_ref()
            .expect("every sink consumes the instance");
        &data.status
    }

    /// Accumulate `bytes` of newly written data and only send a notification
    /// once the total since the last ping reaches [`PING_BATCH_THRESHOLD`].
    /// This avoids excessive wake-ups for small writes.
    ///
    /// `&mut self` enforces single-writer access at compile time.
    pub(crate) fn ping_batched(&mut self, bytes: u64) {
        /// Minimum bytes accumulated before `ping_batched()` sends a notification.
        /// This avoids excessive wake-ups for small writes — receivers will be notified
        /// once roughly 1 MiB of new data is available on disk.
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
        data.active_downloads.remove(&data.mirror, &data.debname);
    }

    pub(crate) async fn begin_rename(mut self) -> RenameBarrier {
        let mut data = self.data.take().expect("every sink consumes the instance");

        // Flush pending notification before dropping the sender, so
        // receivers can read the tail of the file before seeing the
        // channel close.
        //
        // Ordering invariant: we flush the final ping, then drop `tx`
        // explicitly, then take the status write lock.  The tokio watch
        // channel retains the last sent value even after all senders drop,
        // so a receiver that races with the drop either (a) wakes from
        // `.changed()` with Ok because it saw the ping, or (b) wakes with
        // RecvError and then observes the status transitioning to Finished
        // once `RenameBarrier::release` is called.
        data.flush_batched_ping();
        drop(data.tx);

        let lock = data.status.write_owned().await;

        RenameBarrier {
            data: Some(RenameBarrierData {
                lock,
                active_downloads: data.active_downloads,
                mirror: data.mirror,
                debname: data.debname,
                quota_reservation: data.quota_reservation,
            }),
        }
    }
}

impl Drop for DownloadBarrier {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            tokio::task::block_in_place(|| {
                *data.status.blocking_write() =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                metrics::DOWNLOADS_ABORTED.increment();
                data.active_downloads.remove(&data.mirror, &data.debname);
            });
        }
    }
}

struct RenameBarrierData {
    lock: tokio::sync::OwnedRwLockWriteGuard<ActiveDownloadStatus>,
    active_downloads: ActiveDownloads,
    mirror: Mirror,
    debname: String,
    quota_reservation: Option<QuotaReservation>,
}

#[must_use]
pub(crate) struct RenameBarrier {
    data: Option<RenameBarrierData>,
}

impl RenameBarrier {
    pub(crate) fn release(mut self, path: PathBuf, bytes_received: u64) {
        let mut data = self.data.take().expect("every sink consumes the instance");

        if let Some(reservation) = data.quota_reservation {
            reservation.finalize(bytes_received);
        }

        *data.lock = ActiveDownloadStatus::Finished(path);
        drop(data.lock);

        data.active_downloads.remove(&data.mirror, &data.debname);
    }
}

impl Drop for RenameBarrier {
    fn drop(&mut self) {
        if let Some(mut data) = self.data.take() {
            *data.lock = ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
            metrics::DOWNLOADS_ABORTED.increment();
            drop(data.lock);

            data.active_downloads.remove(&data.mirror, &data.debname);
        }
    }
}
