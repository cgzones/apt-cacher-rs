//! Coordinated state for in-flight downloads.
//!
//! [`ActiveDownloads`] is the single source of truth for "is a download for
//! this (mirror, debname) currently in flight?", shared between the hyper,
//! splice, and sendfile delivery backends. It also drives two pieces of
//! metric accounting so callers don't have to:
//!
//! - Late-joiner counts ([`metrics::LATE_JOINERS_TOTAL`] /
//!   [`metrics::LATE_JOINER_PEAK_PER_DOWNLOAD`]) — bumped atomically when
//!   [`ActiveDownloads::insert`] joins or [`ActiveDownloads::attach`] hits.
//! - Saturation transitions for `max_upstream_downloads`
//!   ([`metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS`]) — debounced via the
//!   module-private [`AT_CAP`] latch so each saturation episode counts once.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hashbrown::{Equivalent, HashMap, hash_map::Entry};

use crate::ContentLength;
use crate::deb_mirror::Mirror;
use crate::error::MirrorDownloadRate;
use crate::{global_config, metrics};

#[derive(Debug, Eq, Hash, PartialEq)]
struct ActiveDownloadKey {
    mirror: Mirror,
    debname: String,
}

#[derive(Hash)]
struct ActiveDownloadKeyRef<'a> {
    mirror: &'a Mirror,
    debname: &'a str,
}

impl Equivalent<ActiveDownloadKey> for ActiveDownloadKeyRef<'_> {
    fn equivalent(&self, key: &ActiveDownloadKey) -> bool {
        self.mirror == &key.mirror && self.debname == key.debname
    }
}

#[derive(Debug)]
pub(crate) enum AbortReason {
    MirrorDownloadRate(MirrorDownloadRate),
    AlreadyLoggedJustFail,
}

#[derive(Debug)]
pub(crate) enum ActiveDownloadStatus {
    Init(tokio::sync::watch::Receiver<()>),
    Download(PathBuf, ContentLength, tokio::sync::watch::Receiver<()>),
    Finished(PathBuf),
    Aborted(AbortReason),
}

#[derive(Clone, Debug)]
struct ActiveDownloadEntry {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    /// Number of late joiners that have attached to this download. Updated
    /// under `inner`'s write-lock on every late-join insert.
    late_joiners: usize,
}

#[derive(Clone)]
pub(crate) struct ActiveDownloads {
    inner: Arc<parking_lot::RwLock<HashMap<ActiveDownloadKey, ActiveDownloadEntry>>>,
}

impl std::fmt::Debug for ActiveDownloads {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveDownloads")
            .field("entries", &*self.inner.read())
            .finish()
    }
}

/// Outcome of [`ActiveDownloads::insert`]: either this caller originates the
/// download, or it attaches as a late joiner to one already in flight. The
/// late-joiner accounting (per-entry count + global metrics) is performed
/// inside `insert()` itself — callers do not need any follow-up helper.
pub(crate) enum InsertOutcome {
    Originator {
        init_tx: tokio::sync::watch::Sender<()>,
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    Joined {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
}

/// Outcome of [`ActiveDownloads::originate`]: either this caller originates
/// the download, or another download is already in flight for the same key.
/// `Concurrent` carries the existing download's status so the caller can hand
/// it straight to the sendfile late-joiner path without a separate `attach()`
/// — the `Arc<RwLock<…>>` outlives any subsequent `remove()` of the entry.
#[cfg(feature = "splice")]
pub(crate) enum OriginateOutcome {
    Originator {
        init_tx: tokio::sync::watch::Sender<()>,
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    Concurrent {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
}

/// Saturation-transition latch for `max_upstream_downloads`, used exclusively
/// by [`record_cap_saturation`] and [`record_cap_drain`].
static AT_CAP: AtomicBool = AtomicBool::new(false);

/// Insert/originate-side cap tracking: latch `AT_CAP` and bump the
/// transition counter the first time the active-download set hits
/// `max_upstream_downloads`. `max_upstream_downloads` is read per-call so
/// config reloads take effect. `AcqRel` pairs with `Release` in
/// [`record_cap_drain`] so two threads racing the saturation cannot
/// both observe `false` and double-increment the transition counter.
fn record_cap_saturation(current_len: usize) {
    let Some(max) = global_config().max_upstream_downloads else {
        return;
    };
    if current_len >= max.get() && !AT_CAP.swap(true, Ordering::AcqRel) {
        metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS.increment();
    }
}

/// Remove-side cap tracking: clear the latch when the active-download set
/// drains to zero so the next saturation episode can be counted. A remove
/// can only decrease `current_len`, so the latch-set branch is
/// unreachable from here and is omitted.
fn record_cap_drain(current_len: usize) {
    if current_len == 0 && global_config().max_upstream_downloads.is_some() {
        AT_CAP.store(false, Ordering::Release);
    }
}

impl ActiveDownloads {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.inner.read().len()
    }

    /// Originate a new download or attach as a late joiner if one is already
    /// in flight. Late-joiner accounting (`LATE_JOINERS_TOTAL`,
    /// `LATE_JOINER_PEAK_PER_DOWNLOAD`) is performed atomically when joining,
    /// so callers do not need to follow up with any metric helper.
    #[must_use]
    pub(crate) fn insert(&self, mirror: &Mirror, debname: &str) -> InsertOutcome {
        enum LookupResult {
            Occupied {
                status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
                peak: usize,
            },
            Vacant {
                sender: tokio::sync::watch::Sender<()>,
                status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
            },
        }

        // Assuming concurrent requests of resources in-download are rare,
        // pre-allocate the `ActiveDownloadKey` to avoid the likely
        // allocation while holding the write-lock.
        let key = ActiveDownloadKey {
            mirror: mirror.to_owned(),
            debname: debname.to_owned(),
        };

        // Create channel and status before acquiring write lock to minimize lock scope
        let (tx, rx) = tokio::sync::watch::channel(());
        let status = Arc::new(tokio::sync::RwLock::new(ActiveDownloadStatus::Init(rx)));

        let mut guard = self.inner.write();
        let lres = match guard.entry(key) {
            Entry::Occupied(mut oentry) => {
                let entry = oentry.get_mut();
                entry.late_joiners += 1;
                LookupResult::Occupied {
                    status: Arc::clone(&entry.status),
                    peak: entry.late_joiners,
                }
            }
            Entry::Vacant(ventry) => {
                ventry.insert(ActiveDownloadEntry {
                    status: Arc::clone(&status),
                    late_joiners: 0,
                });
                LookupResult::Vacant { sender: tx, status }
            }
        };
        let current_len = guard.len();
        record_cap_saturation(current_len);
        drop(guard);

        metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.update(current_len as u64);
        match lres {
            LookupResult::Occupied { status, peak } => {
                metrics::LATE_JOINERS_TOTAL.increment();
                metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.update(peak as u64);
                InsertOutcome::Joined { status }
            }
            LookupResult::Vacant { status, sender } => InsertOutcome::Originator {
                init_tx: sender,
                status,
            },
        }
    }

    /// Originate-only variant of [`Self::insert`]: returns `Concurrent`
    /// when a download for the same key is already in flight, while still
    /// bumping the existing entry's late-joiner accounting to mirror
    /// [`Self::attach`]. The splice path turns `Concurrent` into a fall-back
    /// signal; the caller may retry via [`Self::attach`] to serve from the
    /// partial file via the sendfile backend before falling back to hyper.
    #[cfg(feature = "splice")]
    #[must_use]
    pub(crate) fn originate(&self, mirror: &Mirror, debname: &str) -> OriginateOutcome {
        let key = ActiveDownloadKey {
            mirror: mirror.to_owned(),
            debname: debname.to_owned(),
        };

        let (tx, rx) = tokio::sync::watch::channel(());
        let status = Arc::new(tokio::sync::RwLock::new(ActiveDownloadStatus::Init(rx)));

        // On Occupied, mirror `attach()`: bump the late-joiner counters under
        // the same write lock so the status we hand back to the caller comes
        // with its accounting already settled. The caller may still encounter
        // a `NotApplicable` from `serve_unfinished_sendfile` and fall back to
        // hyper, where `insert()` would count a second time — same rare-and-
        // uncorrelated overcount trade as `attach()`.
        let mut guard = self.inner.write();
        let (outcome, late_joiner_peak) = match guard.entry(key) {
            Entry::Occupied(mut oentry) => {
                let entry = oentry.get_mut();
                entry.late_joiners += 1;
                let peak = entry.late_joiners;
                let existing_status = Arc::clone(&entry.status);
                (
                    OriginateOutcome::Concurrent {
                        status: existing_status,
                    },
                    Some(peak),
                )
            }
            Entry::Vacant(ventry) => {
                ventry.insert(ActiveDownloadEntry {
                    status: Arc::clone(&status),
                    late_joiners: 0,
                });
                (
                    OriginateOutcome::Originator {
                        init_tx: tx,
                        status,
                    },
                    None,
                )
            }
        };
        let current_len = guard.len();
        record_cap_saturation(current_len);
        drop(guard);

        metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.update(current_len as u64);
        if let Some(peak) = late_joiner_peak {
            metrics::LATE_JOINERS_TOTAL.increment();
            metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.update(peak as u64);
        }
        outcome
    }

    pub(crate) fn remove(&self, mirror: &Mirror, debname: &str) {
        let key = ActiveDownloadKeyRef { mirror, debname };
        let mut guard = self.inner.write();
        let was_present = guard.remove(&key);
        // Sample the post-remove length under the same write lock so the
        // cap-transition latch can clear when the active set drains to zero.
        // A remove can only decrease the length, so the saturation set-edge
        // is unreachable here; only the drain reset is meaningful.
        let current_len = guard.len();
        record_cap_drain(current_len);
        drop(guard);
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
    /// The sendfile path may still encounter a `NotApplicable` from
    /// `serve_unfinished_sendfile` and fall back to hyper, where `insert()`
    /// will count the late joiner a second time. That overcount is rare
    /// (only fires when upstream omits Content-Length) and uncorrelated with
    /// the silent undercount this design replaces — the trade was made
    /// deliberately on review.
    #[cfg(feature = "sendfile")]
    #[must_use]
    pub(crate) fn attach(
        &self,
        mirror: &Mirror,
        debname: &str,
    ) -> Option<Arc<tokio::sync::RwLock<ActiveDownloadStatus>>> {
        let key = ActiveDownloadKeyRef { mirror, debname };
        let mut guard = self.inner.write();
        let entry = guard.get_mut(&key)?;
        entry.late_joiners += 1;
        let peak = entry.late_joiners;
        let status = Arc::clone(&entry.status);
        drop(guard);

        metrics::LATE_JOINERS_TOTAL.increment();
        metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.update(peak as u64);
        Some(status)
    }

    #[must_use]
    pub(crate) fn download_size(&self) -> u64 {
        tokio::task::block_in_place(move || {
            let mut sum = 0;

            for entry in self.inner.read().values() {
                let d = entry.status.blocking_read();
                if let ActiveDownloadStatus::Download(_, size, _) = &*d {
                    sum += size.upper().get();
                }
            }

            sum
        })
    }

    #[must_use]
    pub(crate) fn download_count(&self) -> usize {
        tokio::task::block_in_place(move || {
            let mut count = 0;

            for entry in self.inner.read().values() {
                let d = entry.status.blocking_read();
                match &*d {
                    ActiveDownloadStatus::Init(_)
                    | ActiveDownloadStatus::Download(_, _, _)
                    | ActiveDownloadStatus::Aborted(_) => {
                        count += 1;
                    }
                    ActiveDownloadStatus::Finished(_) => (),
                }
            }

            count
        })
    }
}
