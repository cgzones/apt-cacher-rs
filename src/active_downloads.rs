//! Coordinated state for in-flight downloads.
//!
//! [`ActiveDownloads`] is the single source of truth for "is a download for
//! this (mirror, debname) currently in flight?", shared between the hyper,
//! splice, and sendfile delivery backends. It is also the single enforcement
//! site for `max_upstream_downloads`: a new origination at the cap returns
//! `AtCapacity` from `ActiveDownloads::insert` /
//! `ActiveDownloads::originate` (late joiners are exempt — they open no new
//! upstream connection), which every backend maps to the canonical 503. It
//! also drives the related metric accounting so callers don't have to:
//!
//! - Late-joiner counts ([`metrics::LATE_JOINERS_TOTAL`] /
//!   [`metrics::LATE_JOINER_PEAK_PER_DOWNLOAD`]) — bumped atomically when
//!   `ActiveDownloads::insert` joins, `ActiveDownloads::attach` hits, or
//!   `ActiveDownloads::originate` returns `Concurrent`.
//! - Saturation transitions for `max_upstream_downloads`
//!   ([`metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS`]) — debounced via the
//!   module-private [`AT_CAP`] latch so each saturation episode counts once.
//! - Cap rejections ([`metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP`]) — bumped
//!   for every refused origination.
//!
//! The cap counts [`UpstreamSlot`]s, not entries. A slot is minted with the
//! origination and released by dropping it, so the count is exactly the
//! number of alive tokens: no derived subtraction, no flag to remember to
//! set. An entry outlives its slot on purpose -- it stays mapped through
//! verification and rename so a joiner arriving in that window finds it
//! rather than missing both the entry and the cache file -- which is why
//! [`ActiveDownloads::len`] (the shutdown summary, the dashboard: "what
//! would be dropped now") and [`ActiveDownloads::upstream_slots`] (the cap,
//! the parallel-hack probability) are two different numbers.

use std::num::NonZero;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hashbrown::{HashMap, hash_map::Entry};
use http::StatusCode;
use tracing::{error, info};

use crate::cache_layout::{CacheEntryKey, CacheEntryKeyRef, ConnectionDetails};
use crate::cache_metadata::UpstreamMetadata;
use crate::error::{ErrorReport, MirrorDownloadRate};
use crate::fs_open::tokio_nofollow_options;
use crate::humanfmt::HumanFmt;
use crate::upstream_head::ContentLength;
use crate::{global_config, global_verify_throttle, metrics, warn_once_or_info};

#[derive(Debug)]
pub(crate) enum AbortReason {
    /// The writer gave up on a stalled mirror (`min_download_rate`); the
    /// file on disk is incomplete.
    MirrorDownloadRate(MirrorDownloadRate),
    /// The writer failed for an already-logged reason before all bytes
    /// were on disk (or its future was cancelled); the file is incomplete.
    AlreadyLoggedJustFail,
    /// Every upstream byte was written, but `RenameBarrier::commit`
    /// discarded the download (checksum mismatch, verify I/O or rename
    /// failure). Readers holding an open handle drain it exactly like
    /// `Verifying` (the clients attached before the verdict get the bytes
    /// they were promised; apt verifies them itself), while anyone still
    /// looking for the file fails like the other abort reasons — the temp
    /// file may already be unlinked. `checksum_mismatch` marks the verdict
    /// that armed the verify throttle (under the same status write lock),
    /// so a joiner reading this status answers with the throttle's 503
    /// instead of a generic abort.
    Discarded { checksum_mismatch: bool },
}

#[derive(Debug)]
pub(crate) enum ActiveDownloadStatus {
    Init(tokio::sync::watch::Receiver<()>),
    /// In-flight download; `meta` carries upstream-supplied `ETag` /
    /// Last-Modified for late joiners that need them for response headers
    /// or conditional-request decisions, avoiding xattr reads on the temp
    /// file while it's still being written.
    Download {
        path: PathBuf,
        content_length: ContentLength,
        rx: tokio::sync::watch::Receiver<()>,
        meta: Arc<UpstreamMetadata>,
    },
    /// All upstream bytes have been written to `path` (the partial / temp
    /// file) but the file is still being hashed and renamed by
    /// `RenameBarrier::commit` on a blocking thread. Readers that observe
    /// this state can treat the file as a complete, drainable copy of the
    /// resource: existing late-joiner file handles remain valid across the
    /// upcoming rename (Linux keeps the inode open). The watch sender has
    /// already been dropped by `begin_rename`, so this is the variant
    /// late-joiners see after `RecvError` instead of a stale `Download`.
    Verifying {
        path: PathBuf,
        meta: Arc<UpstreamMetadata>,
    },
    /// Rename-completed (or revalidation-confirmed) cached file.
    /// `meta` is `Some` when the values came from a fresh upstream
    /// response (`RenameBarrier::commit`); `None` when the entry was
    /// produced by `InitBarrier::finished` (e.g. volatile-revalidation
    /// 304) — in that case readers fall through to the post-flight
    /// [`crate::cache_metadata`] cache, which lazy-loads from xattrs.
    Finished {
        path: PathBuf,
        meta: Option<Arc<UpstreamMetadata>>,
    },
    Aborted(AbortReason),
}

/// A late joiner's view of an in-flight download once it has left `Init`,
/// with the file already open. Produced by [`await_serveable`].
pub(crate) enum Serveable {
    /// The writer is still streaming: serve from the growing partial file,
    /// tailing `rx` for progress pings (see `DownloadBarrier::ping`).
    InProgress {
        file: tokio::fs::File,
        path: PathBuf,
        content_length: ContentLength,
        rx: tokio::sync::watch::Receiver<()>,
        meta: Arc<UpstreamMetadata>,
    },
    /// Every byte is on disk (`Verifying` or `Finished`): serve `file` as a
    /// complete cached copy. `meta` is `None` only for a `Finished` entry
    /// produced by `InitBarrier::finished` (see `ActiveDownloadStatus`).
    Complete {
        file: tokio::fs::File,
        path: PathBuf,
        meta: Option<Arc<UpstreamMetadata>>,
    },
}

/// Why a late joiner could not be served. Every variant was already logged
/// (and metered where applicable) by [`await_serveable`]; callers only map
/// it to their transport's response via [`Self::response_parts`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum JoinFailure {
    /// The writer aborted; `rate_timeout` when it gave up on a stalled
    /// mirror (`min_download_rate`), which is the client's 504.
    Aborted { rate_timeout: bool },
    /// The writer discarded the download on a checksum mismatch and the
    /// verify throttle is armed for the resource: the same 503 the
    /// pre-upstream gate answers, with `Retry-After`.
    VerifyThrottled { remaining: std::time::Duration },
    /// Still `Init` after the writer signalled - a logic error.
    StateCorrupted,
    /// Opening the file failed (`CACHE_IO_FAILURE` bumped).
    CacheAccess,
}

impl JoinFailure {
    /// The canonical status + body both backends answer with.
    #[must_use]
    pub(crate) fn response_parts(self) -> (StatusCode, &'static str) {
        match self {
            Self::Aborted { rate_timeout: true } => {
                (StatusCode::GATEWAY_TIMEOUT, "Upstream Download Timeout")
            }
            Self::Aborted {
                rate_timeout: false,
            } => (StatusCode::INTERNAL_SERVER_ERROR, "Download Aborted"),
            Self::VerifyThrottled { remaining: _ } => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Recently failed checksum verification",
            ),
            Self::StateCorrupted => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Download State Corrupted",
            ),
            Self::CacheAccess => (StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure"),
        }
    }

    /// `Retry-After` value for the response, when the failure carries one.
    #[must_use]
    pub(crate) fn retry_after(self) -> Option<std::time::Duration> {
        match self {
            Self::VerifyThrottled { remaining } => Some(remaining),
            Self::Aborted { rate_timeout: _ } | Self::StateCorrupted | Self::CacheAccess => None,
        }
    }
}

/// Wait for an in-flight download to leave `Init`, then open the file a late
/// joiner serves from. The one implementation of the late-joiner state
/// machine shared by the hyper and sendfile backends.
///
/// `Download` opens the partial under the status read lock: the writer can
/// only move the file after flipping to `Verifying`, which needs the write
/// lock, so the path cannot go stale mid-open. `Verifying` and `Finished`
/// open after releasing the lock; a `Verifying` open that loses the race
/// with the rename (`ENOENT`) re-reads the status and picks up `Finished`
/// with the new path.
pub(crate) async fn await_serveable(
    status: &Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    conn_details: &ConnectionDetails,
) -> Result<Serveable, JoinFailure> {
    async fn open(
        what: &str,
        path: &std::path::Path,
        conn_details: &ConnectionDetails,
    ) -> std::io::Result<tokio::fs::File> {
        tokio_nofollow_options()
            .read(true)
            .open(path)
            .await
            .inspect_err(|err| {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to open {what} file `{}` for joining client {}; returning 500:  {}",
                    path.display(),
                    conn_details.client,
                    ErrorReport(err)
                );
            })
    }

    let mut init_waited = false;

    loop {
        let st = status.read().await;

        match &*st {
            ActiveDownloadStatus::Init(init_rx) => {
                let mut init_rx = init_rx.clone();
                drop(st);

                debug_assert!(
                    !init_waited,
                    "state should change once a ping is received or the downloading task dropped the sender"
                );
                if init_waited {
                    error!(
                        "Download state still Init after waiting for download of {} from mirror {}{}; returning 500",
                        conn_details.debname,
                        conn_details.mirror,
                        conn_details.alias_suffix()
                    );
                    return Err(JoinFailure::StateCorrupted);
                }

                // Either the state changed manually by the downloading task,
                // or the downloading task just dropped the sender.
                if let Err(_err @ tokio::sync::watch::error::RecvError { .. }) =
                    init_rx.changed().await
                {}
                init_waited = true;
            }
            ActiveDownloadStatus::Download {
                path,
                content_length,
                rx,
                meta,
            } => {
                let Ok(file) = open("downloading", path, conn_details).await else {
                    return Err(JoinFailure::CacheAccess);
                };
                let serveable = Serveable::InProgress {
                    file,
                    path: path.clone(),
                    content_length: *content_length,
                    rx: rx.clone(),
                    meta: Arc::clone(meta),
                };
                drop(st);
                return Ok(serveable);
            }
            ActiveDownloadStatus::Verifying { path, meta } => {
                let path = path.clone();
                let meta = Some(Arc::clone(meta));
                drop(st);
                let file = match tokio_nofollow_options().read(true).open(&path).await {
                    Ok(f) => f,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        // Lost the rename race; re-read status.
                        continue;
                    }
                    Err(err) => {
                        metrics::CACHE_IO_FAILURE.increment();
                        error!(
                            "Failed to open verifying file `{}` for joining client {}; returning 500:  {}",
                            path.display(),
                            conn_details.client,
                            ErrorReport(&err)
                        );
                        return Err(JoinFailure::CacheAccess);
                    }
                };
                return Ok(Serveable::Complete { file, path, meta });
            }
            ActiveDownloadStatus::Finished { path, meta } => {
                let path = path.clone();
                let meta = meta.clone();
                drop(st);
                let Ok(file) = open("finished", &path, conn_details).await else {
                    return Err(JoinFailure::CacheAccess);
                };
                return Ok(Serveable::Complete { file, path, meta });
            }
            ActiveDownloadStatus::Aborted(reason) => {
                let rate_timeout = matches!(reason, AbortReason::MirrorDownloadRate(_));
                let checksum_mismatch = matches!(
                    reason,
                    AbortReason::Discarded {
                        checksum_mismatch: true
                    }
                );
                drop(st);
                // The writer armed the throttle before publishing this
                // status (same write lock), so a joiner landing here gets
                // the answer it would get from the pre-upstream gate a
                // moment later; cleanup's synthetic client is exempt there
                // and stays exempt here.
                if checksum_mismatch
                    && !conn_details.client.is_cleanup_synthetic()
                    && let Some(throttled) = global_verify_throttle().check(conn_details.key())
                {
                    warn_once_or_info!(
                        "Rejecting request for {} from client {}: recently failed checksum verification ({} consecutive failures), retry in {}",
                        conn_details.debname,
                        conn_details.client,
                        throttled.failures,
                        HumanFmt::Time(throttled.remaining)
                    );
                    metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.increment();
                    return Err(JoinFailure::VerifyThrottled {
                        remaining: throttled.remaining,
                    });
                }
                let failure = JoinFailure::Aborted { rate_timeout };
                info!(
                    "Download of {} from mirror {}{} was aborted; returning {} to joining client {}",
                    conn_details.debname,
                    conn_details.mirror,
                    conn_details.alias_suffix(),
                    failure.response_parts().0.as_u16(),
                    conn_details.client
                );
                return Err(failure);
            }
        }
    }
}

#[derive(Debug)]
struct ActiveDownloadEntry {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    /// Number of late joiners that have attached to this download. Updated
    /// under `inner`'s write-lock on every late-join insert and on each
    /// `attach()` call.
    late_joiners: usize,
}

/// The locked state: the entries, and the number of [`UpstreamSlot`]s alive.
///
/// The two are deliberately independent counts rather than one derived from
/// the other. An entry outlives its upstream connection (it stays mapped
/// through verification and rename so a joiner in that window still finds
/// it), and the slot is what `max_upstream_downloads` caps -- so the cap
/// reads `upstream_slots`, never `entries.len()`, and neither count is ever
/// computed by subtracting the other.
#[derive(Debug)]
struct Registry {
    entries: HashMap<CacheEntryKey, ActiveDownloadEntry>,
    /// Alive [`UpstreamSlot`] tokens. Written only by [`UpstreamSlot::mint`]
    /// and [`UpstreamSlot`]'s `Drop`, which are also the only places that
    /// move the saturation latch: a count that can only change through those
    /// two cannot change without the latch seeing it.
    upstream_slots: usize,
}

#[derive(Clone)]
pub(crate) struct ActiveDownloads {
    inner: Arc<parking_lot::RwLock<Registry>>,
}

impl std::fmt::Debug for ActiveDownloads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.inner.read();
        f.debug_struct("ActiveDownloads")
            .field("entries", &guard.entries)
            .field("upstream_slots", &guard.upstream_slots)
            .finish()
    }
}

/// The unit `max_upstream_downloads` counts: one upstream connection opened
/// on behalf of a download. Minted by the origination that opens it
/// ([`LookupResult::Originator`]) and released by drop, so it can neither
/// be forgotten nor released twice -- whoever holds it holds the slot.
///
/// The barrier chain in `guards.rs` carries it from `InitBarrier::new` and
/// drops it in `DownloadBarrier::begin_rename`, which is where every backend
/// has necessarily finished reading the upstream body and which comes before
/// the `fsync`, verify and rename that follow. The entry stays mapped until
/// that commit ends, because joiners still need to find it: a released slot
/// says "no upstream connection", not "no download".
#[must_use = "dropping the slot is what frees it; hold it for as long as the upstream connection is open"]
pub(crate) struct UpstreamSlot {
    registry: ActiveDownloads,
}

impl std::fmt::Debug for UpstreamSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamSlot").finish_non_exhaustive()
    }
}

impl UpstreamSlot {
    /// Mint the slot for a new origination, under the registry's write lock
    /// (`upstream_slots` is the locked count). The caller has already refused
    /// the origination if the count is at `max`.
    fn mint(
        upstream_slots: &mut usize,
        registry: &ActiveDownloads,
        max: Option<NonZero<usize>>,
    ) -> Self {
        *upstream_slots += 1;
        record_cap_saturation(*upstream_slots, max);
        Self {
            registry: registry.clone(),
        }
    }
}

impl Drop for UpstreamSlot {
    fn drop(&mut self) {
        let mut guard = self.registry.inner.write();
        guard.upstream_slots = guard
            .upstream_slots
            .checked_sub(1)
            .expect("every released slot was minted");
        record_cap_drain(guard.upstream_slots);
    }
}

/// What a successful origination hands its backend: the `Init` ping sender
/// the barrier drops when it leaves `Init`, the status handle, and the
/// [`UpstreamSlot`] the download counts against `max_upstream_downloads`
/// with. Consumed whole by `InitBarrier::new`, so no backend can register a
/// download without also taking custody of its slot.
pub(crate) struct Origination {
    pub(crate) init_tx: tokio::sync::watch::Sender<()>,
    pub(crate) status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    pub(crate) slot: UpstreamSlot,
}

/// Outcome of `ActiveDownloads::insert`: either this caller originates the
/// download, or it attaches as a late joiner to one already in flight. The
/// late-joiner accounting (per-entry count + global metrics) is performed
/// inside `insert()` itself — callers do not need any follow-up helper.
#[cfg(feature = "hyper")]
pub(crate) enum InsertOutcome {
    Originator(Origination),
    Joined {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    /// See [`LookupResult::AtCapacity`].
    AtCapacity {
        max: NonZero<usize>,
    },
}

/// Outcome of `ActiveDownloads::originate`: either this caller originates
/// the download, or another download is already in flight for the same key.
/// `Concurrent` carries the existing download's status so the caller can hand
/// it straight to the sendfile late-joiner path without a separate `attach()`
/// — the `Arc<RwLock<…>>` outlives any subsequent `remove()` of the entry.
#[cfg(feature = "splice")]
pub(crate) enum OriginateOutcome {
    Originator(Origination),
    Concurrent {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    /// See [`LookupResult::AtCapacity`].
    AtCapacity {
        max: NonZero<usize>,
    },
}

/// Neutral result of [`ActiveDownloads::lookup_or_insert`], the shared
/// body of `ActiveDownloads::insert` and `ActiveDownloads::originate`.
/// Each public method maps this onto its own outcome enum.
///
/// Late-joiner metrics (`LATE_JOINERS_TOTAL`, `LATE_JOINER_PEAK_PER_DOWNLOAD`)
/// have already been bumped inside `lookup_or_insert` when this returns
/// `LateJoiner`; the public adapters do not need to bump them.
enum LookupResult {
    /// A new entry, and with it the [`UpstreamSlot`] it counts against
    /// `max_upstream_downloads` with.
    Originator(Origination),
    LateJoiner {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    /// A new origination was refused because `max` downloads were already in
    /// flight; nothing was inserted. Carries the enforced cap so callers can
    /// log the actual value the decision was made against. The caller answers
    /// with the canonical 503 (`"Too many concurrent upstream downloads"`);
    /// the `UPSTREAM_DOWNLOAD_REJECTED_CAP` bump already happened here.
    AtCapacity { max: NonZero<usize> },
}

/// Saturation-transition latch for `max_upstream_downloads`, used exclusively
/// by [`record_cap_saturation`] and [`record_cap_drain`] -- which in turn are
/// called only by [`UpstreamSlot::mint`] and [`UpstreamSlot`]'s `Drop`, under
/// the registry's write lock, so the latch moves in lockstep with the slot
/// count it describes.
static AT_CAP: AtomicBool = AtomicBool::new(false);

/// Mint-side cap tracking: latch `AT_CAP` and bump the transition counter
/// the first time the slot count hits `max_upstream_downloads`.
/// `max_upstream_downloads` is read per-call so config reloads take effect.
/// `AcqRel` pairs with `Release` in [`record_cap_drain`] so two threads
/// racing the saturation cannot both observe `false` and double-increment
/// the transition counter.
fn record_cap_saturation(upstream_slots: usize, max: Option<NonZero<usize>>) {
    let Some(max) = max else {
        return;
    };
    if upstream_slots >= max.get() && !AT_CAP.swap(true, Ordering::AcqRel) {
        metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS.increment();
    }
}

/// Release-side cap tracking: clear the latch when the last slot is given
/// back so the next saturation episode can be counted. A release can only
/// decrease the count, so the latch-set branch is unreachable from here and
/// is omitted.
///
/// `max_upstream_downloads` is deliberately not consulted: with no cap
/// configured [`record_cap_saturation`] never sets the latch, so the store
/// is a no-op — and clearing unconditionally also releases a latch left
/// armed by a config reload that dropped the cap. Keeping the read out of
/// here is what makes [`UpstreamSlot`]'s drop global-free (and so
/// unit-testable).
fn record_cap_drain(upstream_slots: usize) {
    if upstream_slots == 0 {
        AT_CAP.store(false, Ordering::Release);
    }
}

impl ActiveDownloads {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(Registry {
                entries: HashMap::new(),
                upstream_slots: 0,
            })),
        }
    }

    /// Every mapped entry, whether or not its upstream connection is still
    /// open: "downloads this process would drop if it stopped now", which is
    /// what the shutdown summary and the dashboard mean. The cap and the
    /// parallel-hack probability want [`Self::upstream_slots`] instead.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.inner.read().entries.len()
    }

    /// Downloads with an upstream connection open right now: the number of
    /// alive [`UpstreamSlot`]s, i.e. what `max_upstream_downloads` is
    /// compared against. Smaller than [`Self::len`] by the entries that are
    /// past their body and only verifying, renaming or being retired.
    #[must_use]
    pub(crate) fn upstream_slots(&self) -> usize {
        self.inner.read().upstream_slots
    }

    /// Common locked-region body shared by `Self::insert` and
    /// `Self::originate`: pre-allocate channel + status, perform the
    /// `entry()` Occupied / Vacant transition, do the cap-saturation +
    /// peak + late-joiner accounting, return the neutral [`LookupResult`].
    ///
    /// This is also the single enforcement site for
    /// `max_upstream_downloads`: a new origination while `upstream_slots` is
    /// at the cap returns [`LookupResult::AtCapacity`] without inserting.
    /// Late joiners are exempt by construction (an occupied entry opens no
    /// new upstream connection), and the check happens under the same write
    /// lock as the insert and the slot mint, so the cap is exact — no
    /// check-then-insert race can overshoot it. Both backends inherit the
    /// cap through their public adapters and must map `AtCapacity` to the
    /// canonical 503.
    ///
    /// `max_upstream_downloads` is threaded in by the public callers
    /// (which read it from `global_config()`) so this helper can be
    /// driven from unit tests without standing up a full configuration.
    /// The helper is not side-effect-free: minting the slot latches the
    /// module-private [`AT_CAP`] flag via [`record_cap_saturation`], and it
    /// bumps the `ACTIVE_UPSTREAM_DOWNLOADS_PEAK`, `LATE_JOINERS_TOTAL`,
    /// `LATE_JOINER_PEAK_PER_DOWNLOAD`, and (on a refused origination)
    /// `UPSTREAM_DOWNLOAD_REJECTED_CAP` global metrics.
    fn lookup_or_insert(
        &self,
        keyref: CacheEntryKeyRef<'_>,
        max_upstream_downloads: Option<NonZero<usize>>,
    ) -> LookupResult {
        // First pass with the borrowed key: joining an in-flight download
        // allocates nothing (no owned key, no channel, no status Arc).
        {
            let mut guard = self.inner.write();
            if let Some(entry) = guard.entries.get_mut(&keyref) {
                entry.late_joiners += 1;
                let peak = entry.late_joiners;
                let status = Arc::clone(&entry.status);
                drop(guard);

                metrics::LATE_JOINERS_TOTAL.increment();
                metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.update(peak as u64);
                return LookupResult::LateJoiner { status };
            }
        }

        let key = keyref.to_owned();

        // Pre-allocate channel + status outside the write lock so the
        // critical section stays as short as possible.
        let (tx, rx) = tokio::sync::watch::channel(());
        let status = Arc::new(tokio::sync::RwLock::new(ActiveDownloadStatus::Init(rx)));

        // Re-checked via entry(): another task may have originated the same
        // download between the two lock acquisitions — then we join late
        // after all and the pre-allocations are discarded (rare race).
        let mut guard = self.inner.write();
        let Registry {
            entries,
            upstream_slots,
        } = &mut *guard;
        // Only the Vacant arm consults it — joins are exempt from the cap.
        // The slot count, not the map length: an entry whose upstream
        // connection is already back in the pool holds nothing the cap
        // protects.
        let at_capacity = max_upstream_downloads.filter(|max| *upstream_slots >= max.get());
        let (outcome, late_joiner_peak) = match entries.entry(key) {
            Entry::Occupied(mut oentry) => {
                let entry = oentry.get_mut();
                entry.late_joiners += 1;
                let peak = entry.late_joiners;
                let existing_status = Arc::clone(&entry.status);
                (
                    LookupResult::LateJoiner {
                        status: existing_status,
                    },
                    Some(peak),
                )
            }
            Entry::Vacant(ventry) => {
                if let Some(max) = at_capacity {
                    // Refused origination: nothing inserted, the
                    // pre-allocations are discarded like on the Occupied
                    // race-loser path.
                    (LookupResult::AtCapacity { max }, None)
                } else {
                    ventry.insert(ActiveDownloadEntry {
                        status: Arc::clone(&status),
                        late_joiners: 0,
                    });
                    (
                        LookupResult::Originator(Origination {
                            init_tx: tx,
                            status,
                            // Under the same lock as the insert and the
                            // capacity check above, so the cap is exact.
                            slot: UpstreamSlot::mint(upstream_slots, self, max_upstream_downloads),
                        }),
                        None,
                    )
                }
            }
        };
        let upstream_slots = *upstream_slots;
        drop(guard);

        metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.update(upstream_slots as u64);
        if matches!(outcome, LookupResult::AtCapacity { max: _ }) {
            metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP.increment();
        }
        if let Some(peak) = late_joiner_peak {
            metrics::LATE_JOINERS_TOTAL.increment();
            metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.update(peak as u64);
        }
        outcome
    }

    /// Originate a new download or attach as a late joiner if one is already
    /// in flight. Late-joiner accounting (`LATE_JOINERS_TOTAL`,
    /// `LATE_JOINER_PEAK_PER_DOWNLOAD`) is performed atomically when joining,
    /// so callers do not need to follow up with any metric helper.
    /// `AtCapacity` means the `max_upstream_downloads` cap refused a new
    /// origination — the caller answers with the canonical 503.
    #[cfg(feature = "hyper")]
    #[must_use]
    pub(crate) fn insert(&self, key: CacheEntryKeyRef<'_>) -> InsertOutcome {
        let max = global_config().max_upstream_downloads;
        match self.lookup_or_insert(key, max) {
            LookupResult::Originator(origination) => InsertOutcome::Originator(origination),
            LookupResult::LateJoiner { status } => InsertOutcome::Joined { status },
            LookupResult::AtCapacity { max } => InsertOutcome::AtCapacity { max },
        }
    }

    /// Register `key` and hand back its status handle, skipping the
    /// `max_upstream_downloads` gate that makes [`Self::insert`] read the
    /// config globals. Exists so tests elsewhere in the crate can build a
    /// barrier over a *real* registry entry - `Drop` asserts the entry it
    /// retires was registered. The slot is dropped on the spot: those
    /// barriers are built by hand and never carry one.
    #[cfg(test)]
    pub(crate) fn insert_uncapped(
        &self,
        key: CacheEntryKeyRef<'_>,
    ) -> Arc<tokio::sync::RwLock<ActiveDownloadStatus>> {
        match self.lookup_or_insert(key, None) {
            LookupResult::Originator(Origination {
                init_tx: _,
                status,
                slot: _,
            })
            | LookupResult::LateJoiner { status } => Some(status),
            LookupResult::AtCapacity { max: _ } => None,
        }
        .expect("no cap was passed, so origination cannot be refused")
    }

    /// Build the ordinary slot-owning origination without process globals.
    #[cfg(all(test, feature = "splice"))]
    pub(crate) fn originate_uncapped(&self, key: CacheEntryKeyRef<'_>) -> Origination {
        match self.lookup_or_insert(key, None) {
            LookupResult::Originator(origination) => origination,
            LookupResult::LateJoiner { .. } | LookupResult::AtCapacity { .. } => {
                unreachable!("test key must be newly registered")
            }
        }
    }

    /// Originate-only variant of `Self::insert`: returns `Concurrent`
    /// when a download for the same key is already in flight, while still
    /// bumping the existing entry's late-joiner accounting to mirror
    /// [`Self::attach`]. `Concurrent` carries the existing entry's status,
    /// which the sendfile caller serves the partial file from directly — no
    /// separate `attach()`, no re-check race. `AtCapacity` means the
    /// `max_upstream_downloads` cap refused a new origination — the caller
    /// answers with the canonical 503.
    #[cfg(feature = "splice")]
    #[must_use]
    pub(crate) fn originate(&self, key: CacheEntryKeyRef<'_>) -> OriginateOutcome {
        let max = global_config().max_upstream_downloads;
        match self.lookup_or_insert(key, max) {
            LookupResult::Originator(origination) => OriginateOutcome::Originator(origination),
            LookupResult::LateJoiner { status } => OriginateOutcome::Concurrent { status },
            LookupResult::AtCapacity { max } => OriginateOutcome::AtCapacity { max },
        }
    }

    /// Retire `key`'s entry. Touches the entries only: the cap and its
    /// latch follow the [`UpstreamSlot`], which the owning barrier drops on
    /// its own schedule (and which every barrier has dropped by the time it
    /// removes its entry).
    pub(crate) fn remove(&self, key: CacheEntryKeyRef<'_>) {
        let was_present = self.inner.write().entries.remove(&key);
        assert!(
            was_present.is_some(),
            "callers must own active downloads they are removing"
        );
    }

    /// Attach as a late joiner to an in-flight download, atomically bumping
    /// the per-entry `late_joiners` count and the global late-joiner metrics
    /// under a write lock. Returns `None` if no download is in flight for
    /// this key.
    ///
    /// When `serve_unfinished_sendfile` cannot frame the response (upstream
    /// omitted Content-Length) the returned status travels to hyper inside
    /// `HandoffPlan::JoinDownload`, so the joiner is never re-registered via
    /// `insert()`.
    #[cfg(feature = "sendfile")]
    #[must_use]
    pub(crate) fn attach(
        &self,
        key: CacheEntryKeyRef<'_>,
    ) -> Option<Arc<tokio::sync::RwLock<ActiveDownloadStatus>>> {
        // Fast path under the shared lock: this runs on every cacheable
        // sendfile request and almost always misses (nothing in flight for
        // the key), so don't pay the exclusive lock for a pure lookup.
        if !self.inner.read().entries.contains_key(&key) {
            return None;
        }

        // Re-check under the write lock — the entry may have been removed
        // between the two acquisitions.
        let mut guard = self.inner.write();
        let entry = guard.entries.get_mut(&key)?;
        entry.late_joiners += 1;
        let peak = entry.late_joiners;
        let status = Arc::clone(&entry.status);
        drop(guard);

        metrics::LATE_JOINERS_TOTAL.increment();
        metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.update(peak as u64);
        Some(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_layout::CacheLayout;
    use crate::deb_mirror::Mirror;
    use crate::test_support::structured_mirror;

    fn test_mirror() -> Mirror {
        structured_mirror("deb.debian.org", "")
    }

    #[test]
    fn lookup_or_insert_originator_on_empty() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let result = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "foo.deb", CacheLayout::StructuredPool),
            None,
        );
        assert!(matches!(result, LookupResult::Originator(_)));
    }

    #[test]
    fn lookup_or_insert_late_joiner_on_existing() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        // First call: originator.
        let first = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "foo.deb", CacheLayout::StructuredPool),
            None,
        );
        assert!(matches!(first, LookupResult::Originator(_)));
        // Second call on the same key: late joiner.
        let second = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "foo.deb", CacheLayout::StructuredPool),
            None,
        );
        assert!(matches!(second, LookupResult::LateJoiner { .. }));
    }

    #[test]
    fn lookup_or_insert_late_joiner_peak_counts_per_entry() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        // 1 originator + 3 late joiners. After 4 calls total, the
        // entry's late_joiners field should equal 3.
        let _orig = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "foo.deb", CacheLayout::StructuredPool),
            None,
        );
        for _ in 0..3 {
            let _join = ad.lookup_or_insert(
                CacheEntryKeyRef::new(&mirror, "foo.deb", CacheLayout::StructuredPool),
                None,
            );
        }
        // Read back via the inner lock (test-only access is fine).
        // Use a short-lived scope so the read guard is released promptly.
        let key = CacheEntryKeyRef::new(&mirror, "foo.deb", CacheLayout::StructuredPool);
        let late_joiners = ad
            .inner
            .read()
            .entries
            .get(&key)
            .expect("entry exists")
            .late_joiners;
        assert_eq!(late_joiners, 3, "1 originator + 3 joiners -> peak 3");
    }

    #[test]
    fn lookup_or_insert_rejects_new_origination_at_cap() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let max = NonZero::new(1).expect("nonzero");
        let first = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "a.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        assert!(matches!(first, LookupResult::Originator(_)));
        let second = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "b.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        assert!(matches!(second, LookupResult::AtCapacity { max: m } if m == max));
        // The refused origination must not have registered anything.
        assert_eq!(ad.len(), 1, "rejected origination must not insert");
        assert_eq!(
            ad.upstream_slots(),
            1,
            "rejected origination must not mint a slot"
        );
    }

    #[test]
    fn lookup_or_insert_allows_late_join_at_cap() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let max = NonZero::new(1).expect("nonzero");
        let first = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "a.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        assert!(matches!(first, LookupResult::Originator(_)));
        // Same key at cap: joins the in-flight download, no new upstream
        // connection — exempt from the cap.
        let join = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "a.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        assert!(matches!(join, LookupResult::LateJoiner { .. }));
        assert_eq!(ad.upstream_slots(), 1, "a join mints no slot");
    }

    #[test]
    fn lookup_or_insert_originates_below_cap() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let max = NonZero::new(2).expect("nonzero");
        let first = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "a.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        assert!(matches!(first, LookupResult::Originator(_)));
        let second = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "b.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        assert!(matches!(second, LookupResult::Originator(_)));
        let third = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "c.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        assert!(matches!(third, LookupResult::AtCapacity { max: _ }));
    }

    /// The cap follows the slot, not the entry: an entry whose slot is gone
    /// (its upstream connection is back in the pool, the commit still
    /// running) admits a new origination, and an entry retired with its slot
    /// still held does not.
    #[test]
    fn cap_frees_when_the_slot_drops_not_when_the_entry_goes() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let max = NonZero::new(1).expect("nonzero");
        let LookupResult::Originator(Origination {
            init_tx: _,
            status: _,
            slot,
        }) = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "a.deb", CacheLayout::StructuredPool),
            Some(max),
        )
        else {
            unreachable!("an empty registry originates");
        };

        // Slot released, entry still mapped: the download is committing.
        drop(slot);
        assert_eq!(ad.len(), 1, "the entry outlives its slot");
        assert_eq!(ad.upstream_slots(), 0, "dropping the slot frees it");
        let second = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "b.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        let LookupResult::Originator(Origination {
            init_tx: _,
            status: _,
            slot: second_slot,
        }) = second
        else {
            unreachable!("a committing entry holds no slot, so the cap admits the origination");
        };

        // Entry retired, slot still held: nothing the cap counts changed.
        ad.remove(CacheEntryKeyRef::new(
            &mirror,
            "b.deb",
            CacheLayout::StructuredPool,
        ));
        assert_eq!(ad.upstream_slots(), 1, "remove() does not touch the slot");
        let third = ad.lookup_or_insert(
            CacheEntryKeyRef::new(&mirror, "c.deb", CacheLayout::StructuredPool),
            Some(max),
        );
        assert!(matches!(third, LookupResult::AtCapacity { max: _ }));
        drop(second_slot);
        assert_eq!(ad.upstream_slots(), 0);
    }

    #[test]
    fn lookup_or_insert_unlimited_without_cap() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        for name in ["a.deb", "b.deb", "c.deb", "d.deb"] {
            let result = ad.lookup_or_insert(
                CacheEntryKeyRef::new(&mirror, name, CacheLayout::StructuredPool),
                None,
            );
            assert!(matches!(result, LookupResult::Originator(_)));
        }
    }
}
