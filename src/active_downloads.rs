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

use std::num::NonZero;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use hashbrown::{Equivalent, HashMap, hash_map::Entry};

use crate::ContentLength;
use crate::cache_layout::CacheLayout;
use crate::cache_metadata::UpstreamMetadata;
use crate::deb_mirror::Mirror;
use crate::error::MirrorDownloadRate;
use crate::{global_config, metrics};

/// Layout-aware key for in-flight downloads.  Two discriminators are
/// part of the key:
///
/// - [`Mirror`]'s own `kind` field separates the structured and flat
///   mirror identities for the same `(host, port, path)` tuple — the
///   coarse "which subtree does this row live in" axis.
/// - `layout` carries the finer-grained on-disk shape within a subtree
///   (e.g. `StructuredPool` vs `Dists` vs `DistsByHash` all share the
///   same structured-`Mirror::kind`).  This is the value the cache
///   pipeline already threads through `ConnectionDetails`, so reusing
///   it here keeps the key uniform across the structured/flat split.
///
/// The two are redundant on the structured-vs-flat axis but not
/// overall, and dropping the `layout` field would lose the structured-
/// subtree distinctions.
///
/// Disambiguation between flat-pool `.deb`s living in different
/// sub-directories (`apt/amd64/foo.deb` vs `apt/arm64/foo.deb`) is
/// implicit in [`Mirror::path`], since the URL path becomes the mirror
/// path verbatim under the host-anchored flat layout.
#[derive(Debug, Eq, Hash, PartialEq)]
struct ActiveDownloadKey {
    mirror: Mirror,
    debname: String,
    layout: CacheLayout,
}

#[derive(Hash)]
struct ActiveDownloadKeyRef<'a> {
    mirror: &'a Mirror,
    debname: &'a str,
    layout: CacheLayout,
}

impl Equivalent<ActiveDownloadKey> for ActiveDownloadKeyRef<'_> {
    fn equivalent(&self, key: &ActiveDownloadKey) -> bool {
        let &Self {
            mirror,
            debname,
            layout,
        } = self;
        let ActiveDownloadKey {
            mirror: kmirror,
            debname: kdebname,
            layout: klayout,
        } = key;
        mirror == kmirror && debname == kdebname && layout == *klayout
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
    /// Rename-completed (or revalidation-confirmed) cached file.
    /// `meta` is `Some` when the values came from a fresh upstream
    /// response (`RenameBarrier::release`); `None` when the entry was
    /// produced by `InitBarrier::finished` (e.g. volatile-revalidation
    /// 304) — in that case readers fall through to the post-flight
    /// [`crate::cache_metadata`] cache, which lazy-loads from xattrs.
    Finished {
        path: PathBuf,
        meta: Option<Arc<UpstreamMetadata>>,
    },
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

/// Neutral result of [`ActiveDownloads::lookup_or_insert`], the shared
/// body of [`ActiveDownloads::insert`] and [`ActiveDownloads::originate`].
/// Each public method maps this onto its own outcome enum.
///
/// Late-joiner metrics (`LATE_JOINERS_TOTAL`, `LATE_JOINER_PEAK_PER_DOWNLOAD`)
/// have already been bumped inside `lookup_or_insert` when this returns
/// `LateJoiner`; the public adapters do not need to bump them.
enum LookupResult {
    Originator {
        init_tx: tokio::sync::watch::Sender<()>,
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    LateJoiner {
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
fn record_cap_saturation(current_len: usize, max: Option<NonZero<usize>>) {
    let Some(max) = max else {
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
fn record_cap_drain(current_len: usize, max: Option<NonZero<usize>>) {
    if current_len == 0 && max.is_some() {
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

    /// Common locked-region body shared by [`Self::insert`] and
    /// [`Self::originate`]: pre-allocate channel + status, perform the
    /// `entry()` Occupied / Vacant transition, do the cap-saturation +
    /// peak + late-joiner accounting, return the neutral [`LookupResult`].
    ///
    /// `max_upstream_downloads` is threaded in by the public callers
    /// (which read it from `global_config()`) so this helper can be
    /// driven from unit tests without standing up a full configuration.
    /// The helper is not side-effect-free: it still latches the
    /// module-private [`AT_CAP`] flag via [`record_cap_saturation`] and
    /// bumps the `ACTIVE_UPSTREAM_DOWNLOADS_PEAK`, `LATE_JOINERS_TOTAL`,
    /// and `LATE_JOINER_PEAK_PER_DOWNLOAD` global metrics.
    fn lookup_or_insert(
        &self,
        mirror: &Mirror,
        debname: &str,
        layout: CacheLayout,
        max_upstream_downloads: Option<NonZero<usize>>,
    ) -> LookupResult {
        let key = ActiveDownloadKey {
            mirror: mirror.to_owned(),
            debname: debname.to_owned(),
            layout,
        };

        // Pre-allocate channel + status outside the write lock so the
        // critical section stays as short as possible.
        let (tx, rx) = tokio::sync::watch::channel(());
        let status = Arc::new(tokio::sync::RwLock::new(ActiveDownloadStatus::Init(rx)));

        let mut guard = self.inner.write();
        let (outcome, late_joiner_peak) = match guard.entry(key) {
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
                ventry.insert(ActiveDownloadEntry {
                    status: Arc::clone(&status),
                    late_joiners: 0,
                });
                (
                    LookupResult::Originator {
                        init_tx: tx,
                        status,
                    },
                    None,
                )
            }
        };
        let current_len = guard.len();
        record_cap_saturation(current_len, max_upstream_downloads);
        drop(guard);

        metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.update(current_len as u64);
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
    #[must_use]
    pub(crate) fn insert(
        &self,
        mirror: &Mirror,
        debname: &str,
        layout: CacheLayout,
    ) -> InsertOutcome {
        let max = global_config().max_upstream_downloads;
        match self.lookup_or_insert(mirror, debname, layout, max) {
            LookupResult::Originator { init_tx, status } => {
                InsertOutcome::Originator { init_tx, status }
            }
            LookupResult::LateJoiner { status } => InsertOutcome::Joined { status },
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
    pub(crate) fn originate(
        &self,
        mirror: &Mirror,
        debname: &str,
        layout: CacheLayout,
    ) -> OriginateOutcome {
        let max = global_config().max_upstream_downloads;
        match self.lookup_or_insert(mirror, debname, layout, max) {
            LookupResult::Originator { init_tx, status } => {
                OriginateOutcome::Originator { init_tx, status }
            }
            LookupResult::LateJoiner { status } => OriginateOutcome::Concurrent { status },
        }
    }

    pub(crate) fn remove(&self, mirror: &Mirror, debname: &str, layout: CacheLayout) {
        let max = global_config().max_upstream_downloads;
        let key = ActiveDownloadKeyRef {
            mirror,
            debname,
            layout,
        };
        let mut guard = self.inner.write();
        let was_present = guard.remove(&key);
        // Sample the post-remove length AND clear the cap-transition latch
        // under the same write lock as the length transition. Releasing the
        // lock first would let a new originator reach `max_upstream_downloads`
        // and observe the stale `AT_CAP = true` (skipping its counter)
        // before this clear runs, then we would clear the latch while the
        // set is at cap. A remove can only decrease the length, so the
        // saturation set-edge is unreachable here; only the drain reset is
        // meaningful.
        let current_len = guard.len();
        record_cap_drain(current_len, max);
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
        layout: CacheLayout,
    ) -> Option<Arc<tokio::sync::RwLock<ActiveDownloadStatus>>> {
        let key = ActiveDownloadKeyRef {
            mirror,
            debname,
            layout,
        };
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
                if let ActiveDownloadStatus::Download {
                    path: _,
                    content_length,
                    rx: _,
                    meta: _,
                } = &*d
                {
                    sum += content_length.upper().get();
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
                    | ActiveDownloadStatus::Download { .. }
                    | ActiveDownloadStatus::Aborted(_) => {
                        count += 1;
                    }
                    ActiveDownloadStatus::Finished { .. } => (),
                }
            }

            count
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_layout::CacheLayout;
    use crate::config::ClientHost;
    use crate::deb_mirror::{Mirror, MirrorKind};

    fn test_mirror() -> Mirror {
        Mirror::new(
            ClientHost::new("deb.debian.org".to_string()).expect("valid host"),
            None,
            String::new(),
            MirrorKind::Structured,
        )
    }

    #[test]
    fn lookup_or_insert_originator_on_empty() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let result = ad.lookup_or_insert(&mirror, "foo.deb", CacheLayout::StructuredPool, None);
        assert!(matches!(result, LookupResult::Originator { .. }));
    }

    #[test]
    fn lookup_or_insert_late_joiner_on_existing() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        // First call: originator.
        let first = ad.lookup_or_insert(&mirror, "foo.deb", CacheLayout::StructuredPool, None);
        assert!(matches!(first, LookupResult::Originator { .. }));
        // Second call on the same key: late joiner.
        let second = ad.lookup_or_insert(&mirror, "foo.deb", CacheLayout::StructuredPool, None);
        assert!(matches!(second, LookupResult::LateJoiner { .. }));
    }

    #[test]
    fn lookup_or_insert_late_joiner_peak_counts_per_entry() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        // 1 originator + 3 late joiners. After 4 calls total, the
        // entry's late_joiners field should equal 3.
        let _orig = ad.lookup_or_insert(&mirror, "foo.deb", CacheLayout::StructuredPool, None);
        for _ in 0..3 {
            let _join = ad.lookup_or_insert(&mirror, "foo.deb", CacheLayout::StructuredPool, None);
        }
        // Read back via the inner lock (test-only access is fine).
        // Use a short-lived scope so the read guard is released promptly.
        let key = ActiveDownloadKeyRef {
            mirror: &mirror,
            debname: "foo.deb",
            layout: CacheLayout::StructuredPool,
        };
        let late_joiners = ad
            .inner
            .read()
            .get(&key)
            .expect("entry exists")
            .late_joiners;
        assert_eq!(late_joiners, 3, "1 originator + 3 joiners -> peak 3");
    }
}
