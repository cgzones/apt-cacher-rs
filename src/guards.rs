use std::{path::PathBuf, sync::Arc};

use crate::{
    AbortReason, ActiveDownloadStatus, ActiveDownloads, ContentLength, deb_mirror::Mirror,
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
        let data = self.data.take().expect("finished() is a sink");

        *data.status.write().await = ActiveDownloadStatus::Finished(path);
        data.active_downloads.remove(data.mirror, data.debname);
    }

    pub(crate) async fn download(
        mut self,
        path: PathBuf,
        content_length: ContentLength,
    ) -> DownloadBarrier {
        let data = self.data.take().expect("download() is a sink");

        let (tx, rx) = tokio::sync::watch::channel(());

        *data.status.write().await = ActiveDownloadStatus::Download(path, content_length, rx);

        DownloadBarrier {
            data: Some(DownloadBarrierData {
                status: Arc::clone(data.status),
                active_downloads: data.active_downloads.clone(),
                mirror: data.mirror.clone(),
                debname: data.debname.to_owned(),
                tx,
            }),
        }
    }
}

impl Drop for InitBarrier<'_> {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            tokio::task::block_in_place(|| {
                *data.status.blocking_write() =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
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
}

#[must_use]
pub(crate) struct DownloadBarrier {
    data: Option<DownloadBarrierData>,
}

impl DownloadBarrier {
    pub(crate) fn ping(&self) -> Result<(), tokio::sync::watch::error::SendError<()>> {
        self.data
            .as_ref()
            .expect("data is only extracted in a sink")
            .tx
            .send(())
    }

    pub(crate) async fn abort_with_reason(mut self, reason: AbortReason) {
        let data = self.data.take().expect("abort_with_reason() is a sink");

        *data.status.write().await = ActiveDownloadStatus::Aborted(reason);
        data.active_downloads.remove(&data.mirror, &data.debname);
    }

    pub(crate) async fn begin_rename(mut self) -> RenameBarrier {
        let data = self.data.take().expect("begin_rename() is a sink");

        let lock = data.status.write_owned().await;

        RenameBarrier {
            data: Some(RenameBarrierData {
                lock,
                active_downloads: data.active_downloads,
                mirror: data.mirror,
                debname: data.debname,
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
}

#[must_use]
pub(crate) struct RenameBarrier {
    data: Option<RenameBarrierData>,
}

impl RenameBarrier {
    pub(crate) fn release(mut self, path: PathBuf) {
        let mut data = self.data.take().expect("release() is a sink");

        *data.lock = ActiveDownloadStatus::Finished(path);
        drop(data.lock);

        data.active_downloads.remove(&data.mirror, &data.debname);
    }
}

impl Drop for RenameBarrier {
    fn drop(&mut self) {
        if let Some(mut data) = self.data.take() {
            *data.lock = ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
            drop(data.lock);

            data.active_downloads.remove(&data.mirror, &data.debname);
        }
    }
}
