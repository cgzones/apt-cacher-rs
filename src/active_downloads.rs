//! Coordinated state for in-flight downloads.
//!
//! [`ActiveDownloads`] is the single source of truth for "is a download for
//! this (mirror, debname) currently in flight?", shared between the hyper,
//! splice, and sendfile delivery backends. It is also the single enforcement
//! site for `max_upstream_downloads`: a new origination at the cap returns
//! `AtCapacity` from [`ActiveDownloads::insert`] /
//! [`ActiveDownloads::originate`] (late joiners are exempt — they open no new
//! upstream connection), which every backend maps to the canonical 503. It
//! also drives the related metric accounting so callers don't have to:
//!
//! - Late-joiner counts ([`metrics::LATE_JOINERS_TOTAL`] /
//!   [`metrics::LATE_JOINER_PEAK_PER_DOWNLOAD`]) — bumped atomically when
//!   [`ActiveDownloads::insert`] joins, [`ActiveDownloads::attach`] hits, or
//!   [`ActiveDownloads::originate`] returns `Concurrent`.
//! - Saturation transitions for `max_upstream_downloads`
//!   ([`metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS`]) — debounced via the
//!   module-private [`AT_CAP`] latch so each saturation episode counts once.
//! - Cap rejections ([`metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP`]) — bumped
//!   for every refused origination.

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
        content_length: ContentLength,
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
    #[cfg_attr(
        not(feature = "hyper"),
        expect(unused, reason = "not read in splice backend")
    )]
    Aborted(AbortReason),
}

#[derive(Clone, Debug)]
struct ActiveDownloadEntry {
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    /// Number of late joiners that have attached to this download. Updated
    /// under `inner`'s write-lock on every late-join insert and on each
    /// `attach()` call.
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
#[cfg(feature = "hyper")]
pub(crate) enum InsertOutcome {
    Originator {
        init_tx: tokio::sync::watch::Sender<()>,
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    Joined {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    /// `max` originations were already in flight, so nothing was registered.
    /// The caller must answer with the canonical 503
    /// (`"Too many concurrent upstream downloads"`); the
    /// `UPSTREAM_DOWNLOAD_REJECTED_CAP` bump already happened inside
    /// [`ActiveDownloads::lookup_or_insert`].
    AtCapacity { max: NonZero<usize> },
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
    /// `max` originations were already in flight, so nothing was registered.
    /// The caller must answer with the canonical 503
    /// (`"Too many concurrent upstream downloads"`); the
    /// `UPSTREAM_DOWNLOAD_REJECTED_CAP` bump already happened inside
    /// [`ActiveDownloads::lookup_or_insert`].
    AtCapacity { max: NonZero<usize> },
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
    /// A new origination was refused because `max` downloads were already in
    /// flight; nothing was inserted. Carries the enforced cap so callers can
    /// log the actual value the decision was made against.
    AtCapacity { max: NonZero<usize> },
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
    /// This is also the single enforcement site for
    /// `max_upstream_downloads`: a new origination while the set is at the
    /// cap returns [`LookupResult::AtCapacity`] without inserting. Late
    /// joiners are exempt by construction (an occupied entry opens no new
    /// upstream connection), and the check happens under the same write
    /// lock as the insert, so the cap is exact — no check-then-insert race
    /// can overshoot it. Both backends inherit the cap through their public
    /// adapters and must map `AtCapacity` to the canonical 503.
    ///
    /// `max_upstream_downloads` is threaded in by the public callers
    /// (which read it from `global_config()`) so this helper can be
    /// driven from unit tests without standing up a full configuration.
    /// The helper is not side-effect-free: it still latches the
    /// module-private [`AT_CAP`] flag via [`record_cap_saturation`] and
    /// bumps the `ACTIVE_UPSTREAM_DOWNLOADS_PEAK`, `LATE_JOINERS_TOTAL`,
    /// `LATE_JOINER_PEAK_PER_DOWNLOAD`, and (on a refused origination)
    /// `UPSTREAM_DOWNLOAD_REJECTED_CAP` global metrics.
    fn lookup_or_insert(
        &self,
        mirror: &Mirror,
        debname: &str,
        layout: CacheLayout,
        max_upstream_downloads: Option<NonZero<usize>>,
    ) -> LookupResult {
        // First pass with the borrowed key: joining an in-flight download
        // allocates nothing (no owned key, no channel, no status Arc).
        {
            let keyref = ActiveDownloadKeyRef {
                mirror,
                debname,
                layout,
            };
            let mut guard = self.inner.write();
            if let Some(entry) = guard.get_mut(&keyref) {
                entry.late_joiners += 1;
                let peak = entry.late_joiners;
                let status = Arc::clone(&entry.status);
                let current_len = guard.len();
                record_cap_saturation(current_len, max_upstream_downloads);
                drop(guard);

                metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.update(current_len as u64);
                metrics::LATE_JOINERS_TOTAL.increment();
                metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.update(peak as u64);
                return LookupResult::LateJoiner { status };
            }
        }

        let key = ActiveDownloadKey {
            mirror: mirror.to_owned(),
            debname: debname.to_owned(),
            layout,
        };

        // Pre-allocate channel + status outside the write lock so the
        // critical section stays as short as possible.
        let (tx, rx) = tokio::sync::watch::channel(());
        let status = Arc::new(tokio::sync::RwLock::new(ActiveDownloadStatus::Init(rx)));

        // Re-checked via entry(): another task may have originated the same
        // download between the two lock acquisitions — then we join late
        // after all and the pre-allocations are discarded (rare race).
        let mut guard = self.inner.write();
        // Sampled before `entry()` (which borrows the map exclusively); only
        // the Vacant arm consults it — joins are exempt from the cap.
        let at_capacity = max_upstream_downloads.filter(|max| guard.len() >= max.get());
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
                        LookupResult::Originator {
                            init_tx: tx,
                            status,
                        },
                        None,
                    )
                }
            }
        };
        let current_len = guard.len();
        record_cap_saturation(current_len, max_upstream_downloads);
        drop(guard);

        metrics::ACTIVE_UPSTREAM_DOWNLOADS_PEAK.update(current_len as u64);
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
            LookupResult::AtCapacity { max } => InsertOutcome::AtCapacity { max },
        }
    }

    /// Originate-only variant of [`Self::insert`]: returns `Concurrent`
    /// when a download for the same key is already in flight, while still
    /// bumping the existing entry's late-joiner accounting to mirror
    /// [`Self::attach`]. `Concurrent` carries the existing entry's status,
    /// which the sendfile caller serves the partial file from directly — no
    /// separate `attach()`, no re-check race. `AtCapacity` means the
    /// `max_upstream_downloads` cap refused a new origination — the caller
    /// answers with the canonical 503.
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
            LookupResult::AtCapacity { max } => OriginateOutcome::AtCapacity { max },
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

        // Fast path under the shared lock: this runs on every cacheable
        // sendfile request and almost always misses (nothing in flight for
        // the key), so don't pay the exclusive lock for a pure lookup.
        if !self.inner.read().contains_key(&key) {
            return None;
        }

        // Re-check under the write lock — the entry may have been removed
        // between the two acquisitions.
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
                let content_length = {
                    let d = entry.status.blocking_read();
                    match &*d {
                        ActiveDownloadStatus::Download {
                            path: _,
                            content_length,
                            rx: _,
                            meta: _,
                        }
                        | ActiveDownloadStatus::Verifying {
                            path: _,
                            content_length,
                            meta: _,
                        } => Some(*content_length),
                        ActiveDownloadStatus::Init(_)
                        | ActiveDownloadStatus::Finished { .. }
                        | ActiveDownloadStatus::Aborted(_) => None,
                    }
                };
                if let Some(content_length) = content_length {
                    sum += content_length.upper().get();
                }
            }

            sum
        })
    }

    #[cfg(feature = "hyper")]
    #[must_use]
    pub(crate) fn download_count(&self) -> usize {
        // Every terminal status transition (Finished/Aborted) in guards.rs
        // is immediately followed by `remove()`, so mapped entries are in a
        // pre-terminal state apart from a transition-to-removal window a
        // few statements wide. The map length therefore matches the old
        // per-entry status scan (which took every entry's status lock
        // inside block_in_place) up to that transient — fine for the
        // parallel-hack probability and web display consumers.
        self.inner.read().len()
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

    #[test]
    fn lookup_or_insert_rejects_new_origination_at_cap() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let max = NonZero::new(1).expect("nonzero");
        let first = ad.lookup_or_insert(&mirror, "a.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(first, LookupResult::Originator { .. }));
        let second = ad.lookup_or_insert(&mirror, "b.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(second, LookupResult::AtCapacity { max: m } if m == max));
        // The refused origination must not have registered anything.
        assert_eq!(ad.len(), 1, "rejected origination must not insert");
    }

    #[test]
    fn lookup_or_insert_allows_late_join_at_cap() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let max = NonZero::new(1).expect("nonzero");
        let first = ad.lookup_or_insert(&mirror, "a.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(first, LookupResult::Originator { .. }));
        // Same key at cap: joins the in-flight download, no new upstream
        // connection — exempt from the cap.
        let join = ad.lookup_or_insert(&mirror, "a.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(join, LookupResult::LateJoiner { .. }));
    }

    #[test]
    fn lookup_or_insert_originates_below_cap() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let max = NonZero::new(2).expect("nonzero");
        let first = ad.lookup_or_insert(&mirror, "a.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(first, LookupResult::Originator { .. }));
        let second = ad.lookup_or_insert(&mirror, "b.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(second, LookupResult::Originator { .. }));
        let third = ad.lookup_or_insert(&mirror, "c.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(third, LookupResult::AtCapacity { max: _ }));
    }

    #[test]
    fn lookup_or_insert_cap_frees_after_removal() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        let max = NonZero::new(1).expect("nonzero");
        let first = ad.lookup_or_insert(&mirror, "a.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(first, LookupResult::Originator { .. }));
        // Remove via the inner map directly: `remove()` reads
        // `global_config()`, which is unavailable in unit tests.
        let key = ActiveDownloadKeyRef {
            mirror: &mirror,
            debname: "a.deb",
            layout: CacheLayout::StructuredPool,
        };
        assert!(ad.inner.write().remove(&key).is_some());
        let second = ad.lookup_or_insert(&mirror, "b.deb", CacheLayout::StructuredPool, Some(max));
        assert!(matches!(second, LookupResult::Originator { .. }));
    }

    #[test]
    fn lookup_or_insert_unlimited_without_cap() {
        let ad = ActiveDownloads::new();
        let mirror = test_mirror();
        for name in ["a.deb", "b.deb", "c.deb", "d.deb"] {
            let result = ad.lookup_or_insert(&mirror, name, CacheLayout::StructuredPool, None);
            assert!(matches!(result, LookupResult::Originator { .. }));
        }
    }
}
