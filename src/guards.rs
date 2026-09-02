use std::{path::PathBuf, sync::Arc};

use tracing::{error, info, warn};

use crate::{
    active_downloads::{AbortReason, ActiveDownloadStatus, ActiveDownloads},
    cache_layout::{CacheEntryKey, CacheEntryKeyRef, CacheLayout, ConnectionDetails, ResourceKind},
    cache_metadata::{self, UpstreamMetadata},
    cache_paths::MirrorSite,
    cache_quota::QuotaReservation,
    config::CacheHost,
    error::ErrorReport,
    global_verify_throttle,
    humanfmt::HumanFmt,
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

struct InitBarrierData<'a> {
    status: &'a Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: &'a ActiveDownloads,
    key: CacheEntryKeyRef<'a>,
    /// When the request was resolved against an alias mapping, the on-disk
    /// host directory is the alias' main host (not `mirror.host()`).  Kept
    /// here so that [`InitBarrier::site`] resolves the same site as
    /// `ConnectionDetails::site` and `partial_path_for_barrier` lays the
    /// `.partial` next to the eventual rename target.
    aliased_host: Option<&'static CacheHost>,
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
    pub(crate) fn new(
        tx: tokio::sync::watch::Sender<()>,
        status: &'a Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
        active_downloads: &'a ActiveDownloads,
        conn_details: &'a ConnectionDetails,
        raw_uri_path: &'a str,
    ) -> Self {
        Self {
            data: Some(InitBarrierData {
                status,
                active_downloads,
                key: conn_details.key(),
                aliased_host: conn_details.aliased_host,
                resource_kind: conn_details.resource_kind,
                raw_uri_path,
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
        data.active_downloads.remove(data.key);
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

    #[must_use]
    pub(crate) fn debname(&self) -> &str {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
            .key
            .debname
    }

    #[must_use]
    pub(crate) fn layout(&self) -> CacheLayout {
        self.data
            .as_ref()
            .expect("every sink consumes the instance")
            .key
            .layout
    }

    /// The alias-resolved on-disk identity of the download's mirror - the
    /// same site `ConnectionDetails::site` resolves (alias' `main` host when
    /// the request was redirected, else the mirror's own host), so
    /// `partial_path_for_barrier` places the `.partial` in the same tree
    /// as the eventual rename target.
    #[must_use]
    pub(crate) fn site(&self) -> MirrorSite<'_> {
        let data = self
            .data
            .as_ref()
            .expect("every sink consumes the instance");
        let mirror = data.key.mirror;
        let host = match data.aliased_host {
            Some(cache) => cache,
            None => mirror.host().as_cache_host(),
        };
        MirrorSite {
            host,
            port: mirror.port(),
            path: mirror.path(),
        }
    }
}

impl Drop for InitBarrier<'_> {
    fn drop(&mut self) {
        if let Some(data) = &self.data {
            tokio::task::block_in_place(|| {
                *data.status.blocking_write() =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                metrics::DOWNLOADS_ABORTED.increment();
                data.active_downloads.remove(data.key);
            });
        }
    }
}

struct DownloadBarrierData {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: ActiveDownloads,
    key: CacheEntryKey,
    resource_kind: ResourceKind,
    raw_uri_path: String,
    tx: tokio::sync::watch::Sender<()>,
    quota_reservation: Option<QuotaReservation>,
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
        let data = self.data.take().expect("every sink consumes the instance");

        *data.status.write().await = ActiveDownloadStatus::Aborted(reason);
        metrics::DOWNLOADS_ABORTED.increment();
        data.active_downloads.remove(data.key.as_ref());
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
                    error!(
                        "Download barrier begin_rename reached with non-Download status for {} from mirror {}; leaving the status untouched: {other:?}",
                        data.key.debname, data.key.mirror
                    );
                    other
                }
            };
        }
        drop(data.tx);

        RenameBarrier {
            data: Some(RenameBarrierData {
                status: data.status,
                active_downloads: data.active_downloads,
                key: data.key,
                resource_kind: data.resource_kind,
                raw_uri_path: data.raw_uri_path,
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

    /// Mid-stream variant of [`Self::check_upstream_rate`] for callers that already
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
            data.key.mirror, data.key.debname,
        ));
        #[cfg(feature = "hyper")]
        let reason = AbortReason::MirrorDownloadRate(MirrorDownloadRate {
            download_rate_err,
            mirror: data.key.mirror.clone(),
            debname: data.key.debname.clone(),
        });
        #[cfg(not(feature = "hyper"))]
        let reason = AbortReason::MirrorDownloadRate(MirrorDownloadRate {});
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
                data.active_downloads.remove(data.key.as_ref());
            });
        }
    }
}

struct RenameBarrierData {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    active_downloads: ActiveDownloads,
    key: CacheEntryKey,
    resource_kind: ResourceKind,
    raw_uri_path: String,
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
    /// commit a download without it. On any `CommitError` the entry is
    /// retired right here (status `Aborted`, active-downloads entry removed)
    /// *before* a checksum mismatch arms the re-download throttle, and the
    /// error is returned to the caller; `Drop` stays the safety net for a
    /// cancelled future.
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
    ///
    /// `temp_path` is the finished `.partial` / temp file; on success its
    /// guard is defused (the file now lives at `dest_path`), on a checksum
    /// mismatch the file is unlinked (its bytes are known-bad, resuming them
    /// cannot succeed), on a transient verify/rename failure the guard's
    /// `keep_on_drop` keeps it for resumption. `declared_bytes` is the fallback for
    /// quota finalisation when the temp file cannot be stat'ed. Rename
    /// failures are logged here (with `CACHE_IO_FAILURE`); mismatch and
    /// verify-IO failures are logged by `verify_and_rename`.
    pub(crate) async fn commit(
        mut self,
        temp_path: TempPath,
        dest_path: PathBuf,
        declared_bytes: u64,
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
                host: data.key.mirror.host().to_string(),
                mirror_path: data.key.mirror.path().to_owned(),
                raw_uri_path: data.raw_uri_path.clone(),
            }
        };
        if let Err(err) = integrity::verify_and_rename(&plan).await {
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
            let data = self.data.take().expect("every sink consumes the instance");
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
            data.active_downloads.remove(data.key.as_ref());
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
            // A content mismatch makes the partial worthless: a later resume
            // would extend the same wrong bytes and fail verification again,
            // so unlink it now (attached readers keep their open fd and
            // drain to EOF). Transient VerifyIo/Rename failures keep the
            // partial for resumption via the `TempPath` guard's
            // `keep_on_drop`.
            if checksum_mismatch {
                temp_path.remove().await;
            }
            // `data` (and its quota reservation) drops here.
            return Err(err);
        }

        // Verified and renamed: the temp file no longer exists under its
        // old name, so the guard must not try to remove it.
        TempPath::defuse(temp_path);

        // Finalise quota outside the lock, then take the write lock briefly
        // for the `Verifying -> Finished` status flip.
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
                        "RenameBarrier::commit reached with non-Verifying status for {} from mirror {}; finishing the download without publishing cache metadata: {:?}",
                        data.key.debname, data.key.mirror, *lock
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
            cache_metadata::store().set(data.key.clone(), meta);
        }
        global_verify_throttle().record_success(data.key.as_ref());
        data.active_downloads.remove(data.key.as_ref());

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
                data.active_downloads.remove(data.key.as_ref());
            });
        }
    }
}
