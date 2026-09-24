//! Disk-quota accounting for the cache directory.
//!
//! Every size is counted as [`accounted_size`]: the length rounded up to
//! whole [`QUOTA_BLOCK_SIZE`] (4 KiB) blocks, 0 for an empty file. Counting
//! apparent lengths let millions of tiny index and by-hash files occupy far
//! more disk than the quota saw. The rounding applies to every input -- a
//! reservation's `Content-Length`, the replaced file, an adopted, kept or
//! removed partial, the finalised size -- and to every file the cache scan
//! and cleanup count, so the reconcile compares like with like; all figures
//! below are in these units.
//!
//! One mutex guards every number the quota decision depends on, so a check,
//! its reservation, a finalisation and the cleanup reconcile can never
//! interleave inconsistently:
//!
//! - `size`: the accounted cache size. Files below the mirror directories --
//!   the `.partial` files in their `tmp/` subdirectories included -- plus the
//!   reservation of every download in flight. Kept partials are disk usage a
//!   failing upstream can grow at will (a partial survives its download for a
//!   later resume), so they count like cached files: a reservation that
//!   resumes a partial *adopts* its bytes (they move from the kept partial
//!   into the reservation), a download that ends without a commit hands back
//!   what its partial then holds (only the unwritten remainder is reverted),
//!   and every removal of a partial releases its bytes exactly once --
//!   cleanup's `tmp/` reap through the reconcile's `removed`, every other
//!   unlink (a discarded resume, a checksum mismatch, a replaced leftover)
//!   through [`CacheQuota::release_removed_partial`]. A download claims its
//!   partial's path before touching it and holds the claim until both its
//!   partial guard and its [`ReservedPartial`] are gone; cleanup reaps only
//!   unclaimed partials (`partial_claim`), so a partial is released by the
//!   reap or by the reservation that adopted it, never by both. The random
//!   scratch files of volatile downloads live in the cache root's `tmp/`,
//!   are unlinked with their download and purged at startup, and are never
//!   counted.
//! - `inflight_reserved` / `inflight_replaced`: what the live reservations
//!   added to and subtracted from `size` (`replaced` includes the adopted
//!   partials). The reconcile adds their net to the scanned on-disk total
//!   instead of asking the active-downloads registry, so the comparison is
//!   taken under the same lock as `size`.
//! - `inflight_unwritten`: the bytes the live reservations writing a partial
//!   may still add to it (`reserved - adopted`). The scan counts such a
//!   partial at whatever size it had when walked, anywhere between adopted
//!   and complete, so the reconcile's lower bound is widened by this much.
//! - `committed_grown` / `committed_shrunk`: monotonic on-disk deltas the
//!   scan may have seen on either side of: finished commits (renames; a
//!   partial's rename out of `tmp/` can be counted in both places), partials
//!   kept by an unfinished download, and partial removals. A reconcile
//!   snapshots them before its scan and treats the changes that landed
//!   during the scan as unknown-to-the-scan: the accounted size is only
//!   "repaired" when it lies outside the interval those changes could
//!   explain. Without that, a download committed after the scan had walked
//!   its directory was repaired away, under-counting the cache until the
//!   next cleanup.
//!
//! A [`QuotaReservation`] is minted only by [`CacheQuota::try_acquire`] /
//! [`CacheQuota::acquire_for_cleanup`], is required to build a download
//! barrier (`guards.rs`), is finalised inside the rename step
//! (`integrity::verify_and_rename`, in the same blocking closure as the
//! `rename(2)`, so a cancelled commit future cannot land the file and revert
//! the reservation), and reverts itself on drop -- keeping the bytes its
//! [`ReservedPartial`] then holds.
//!
//! The same admission also keeps `min_disk_free` free on the cache
//! filesystem ([`DiskHeadroom`], with or without a `disk_quota`): the quota
//! bounds what this daemon accounts, but the filesystem is what runs out,
//! and it may be shared or already fuller than the cache. The decision reads
//! a `statvfs(3)` sample at most [`DISK_SAMPLE_TTL`] old, minus everything
//! admitted since it was taken -- the sample cannot see those yet, and a
//! burst of misses within one sample must not all pass on the same free
//! figure. Cleanup's index fetches are admitted past this floor for the
//! reason they are admitted past the quota.

use std::{
    cmp::Ordering,
    num::NonZero,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{self, AtomicBool},
    },
};

use tracing::{debug, error, info, trace};

use crate::{
    error::ErrorReport, healthcheck::filesystem_space, humanfmt::HumanFmt, metrics,
    partial_claim::PartialClaim, sticky, upstream_head::ContentLength, warn_once_or_info,
};

/// Represents a quota violation.
pub(crate) struct QuotaExceeded;

/// The allocation granularity the quota charges every file in: the block
/// size of the common Linux filesystems (ext4, XFS, btrfs).
pub(crate) const QUOTA_BLOCK_SIZE: u64 = 4096;

/// The size a file of `len` bytes is accounted as: `len` rounded up to whole
/// [`QUOTA_BLOCK_SIZE`] blocks, saturating. An empty file counts 0: it holds
/// no data block, and inodes are not what the quota measures.
///
/// Every length reaching the quota goes through this -- reservations,
/// finalisation, a replaced file, a kept or removed partial -- and so does
/// every file the cache scan and cleanup count, or the reconcile would
/// "repair" the difference between the two sums.
#[must_use]
pub(crate) const fn accounted_size(len: u64) -> u64 {
    len.div_ceil(QUOTA_BLOCK_SIZE)
        .saturating_mul(QUOTA_BLOCK_SIZE)
}

/// [`accounted_size`] of a non-zero length, which stays non-zero.
#[expect(
    clippy::non_zero_suggestions,
    reason = "misfires on the local `accounted_size`, which has no NonZero form to call"
)]
fn accounted_nonzero(len: NonZero<u64>) -> NonZero<u64> {
    NonZero::new(accounted_size(len.get())).unwrap_or(len)
}

/// The `.partial` file a permanent download writes into, handed to the quota
/// so the bytes a failed download leaves behind stay accounted.
#[derive(Debug)]
pub(crate) struct ReservedPartial {
    /// The download's claim on the partial's path (`partial_claim`), shared
    /// with its `TempPath` guard: held until the reservation has measured
    /// what the partial keeps, so cleanup cannot reap it in between.
    claim: PartialClaim,
    /// What the partial was accounted as when the download took it over (see
    /// [`accounted_size`]): the resume offset, 0 for a fresh download.
    /// Accounted as a kept partial until then, it moves into the reservation.
    adopted: u64,
}

impl ReservedPartial {
    /// `adopted` is the partial's length in bytes.
    #[must_use]
    pub(crate) const fn new(claim: PartialClaim, adopted: u64) -> Self {
        Self {
            claim,
            adopted: accounted_size(adopted),
        }
    }
}

/// The size of the regular file at `path`, 0 when there is none (or it is
/// not a regular file, which the scan does not count either).
///
/// A direct `lstat(2)` rather than `block_in_place`: it runs from
/// [`QuotaReservation`]'s `Drop`, which also fires on current-thread
/// runtimes and inside blocking closures, and it stats a file its own
/// download has just written, so the inode is cached. The reservation's claim
/// on the path is still held, so cleanup cannot have reaped it.
fn partial_len(path: &Path) -> u64 {
    match std::fs::symlink_metadata(path) {
        Ok(mdata) if mdata.file_type().is_file() => mdata.len(),
        Ok(_) => 0,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to stat partial file `{}`; not counting it towards the cache size until the next cleanup reconcile:  {}",
                path.display(),
                ErrorReport(&err)
            );
            0
        }
    }
}

#[derive(Debug, Default)]
struct Accounting {
    /// Accounted cache size: on-disk tracked files plus live reservations.
    size: u64,
    /// Sum of `reserved` over live reservations.
    inflight_reserved: u64,
    /// Sum of `prev_file_size` plus the adopted partial over live
    /// reservations.
    inflight_replaced: u64,
    /// Sum of `reserved - adopted` over live reservations writing a partial.
    inflight_unwritten: u64,
    /// Monotonic sum of the on-disk growth the scan may have missed: commits
    /// that grew the cache, partials kept past their adopted size.
    committed_grown: u64,
    /// Monotonic sum of the on-disk shrinkage (or double counting) the scan
    /// may have seen: commits that shrank the cache, partials renamed out of
    /// `tmp/`, removed partials.
    committed_shrunk: u64,
    /// Monotonic sum of the disk bytes every admitted reservation may still
    /// write ([`disk_needed`]); what a free-space sample taken earlier cannot
    /// reflect yet.
    admitted_total: u64,
    /// The latest free-space sample of the cache filesystem; `None` until
    /// the first one (or without a [`DiskHeadroom`]).
    disk: Option<DiskSample>,
}

/// One `statvfs(3)` reading for the `min_disk_free` admission check.
#[derive(Clone, Copy, Debug)]
struct DiskSample {
    taken: coarsetime::Instant,
    /// Bytes available; `None` when the probe failed, which admits.
    free: Option<u64>,
    /// `admitted_total` when the probe started.
    admitted_at: u64,
}

impl Accounting {
    /// The free space the admission check works with: the sample minus what
    /// was admitted since it was taken. `None` without a usable sample.
    fn disk_free_now(&self) -> Option<u64> {
        let sample = self.disk?;
        let free = sample.free?;
        Some(free.saturating_sub(self.admitted_total.wrapping_sub(sample.admitted_at)))
    }

    /// Net of the live reservations (`reserved - replaced`); what the
    /// reservations currently contribute to `size` on top of the on-disk
    /// files. Signed as `(add, sub)` because a shrinking overwrite
    /// contributes a negative net.
    const fn inflight_net(&self) -> (u64, u64) {
        if self.inflight_reserved >= self.inflight_replaced {
            (self.inflight_reserved - self.inflight_replaced, 0)
        } else {
            (0, self.inflight_replaced - self.inflight_reserved)
        }
    }

    fn add(&mut self, amount: u64, what: &str) {
        if let Some(val) = self.size.checked_add(amount) {
            self.size = val;
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache-size accounting overflowed on {what}: current={} added={amount}; clamping to u64::MAX, all further downloads are rejected as over quota until the next cleanup reconcile",
                self.size
            );
            self.size = u64::MAX;
        }
    }

    fn subtract(&mut self, amount: u64, what: &str) {
        if let Some(val) = self.size.checked_sub(amount) {
            self.size = val;
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache-size accounting underflowed on {what}: current={} removed={amount}; clamping to 0, the accounted cache size now understates the on-disk size until the next cleanup reconcile",
                self.size
            );
            self.size = 0;
        }
    }

    /// Remove a reservation's contribution from the in-flight tallies.
    fn retire(&mut self, reserved: u64, replaced: u64, unwritten: u64) {
        self.inflight_reserved = self.inflight_reserved.saturating_sub(reserved);
        self.inflight_replaced = self.inflight_replaced.saturating_sub(replaced);
        self.inflight_unwritten = self.inflight_unwritten.saturating_sub(unwritten);
    }

    /// Record an on-disk change from `before` to `after` bytes the scan may
    /// have seen either side of.
    const fn record_change(&mut self, before: u64, after: u64) {
        if after > before {
            self.committed_grown = self.committed_grown.wrapping_add(after - before);
        } else {
            self.committed_shrunk = self.committed_shrunk.wrapping_add(before - after);
        }
    }
}

/// One pointer wide: every [`QuotaReservation`] carries a handle, and it
/// rides inside the download barriers' failure type.
#[derive(Clone)]
pub(crate) struct CacheQuota {
    inner: Arc<QuotaInner>,
}

struct QuotaInner {
    accounting: parking_lot::Mutex<Accounting>,
    quota_config: Option<NonZero<u64>>,
    headroom: Option<DiskHeadroom>,
}

/// The `min_disk_free` floor downloads may not dig into, and where to
/// measure it.
pub(crate) struct DiskHeadroom {
    cache_dir: PathBuf,
    min_free: NonZero<u64>,
    /// Single flight for [`CacheQuota::refresh_disk_headroom`].
    refreshing: AtomicBool,
}

impl DiskHeadroom {
    #[must_use]
    pub(crate) const fn new(cache_dir: PathBuf, min_free: NonZero<u64>) -> Self {
        Self {
            cache_dir,
            min_free,
            refreshing: AtomicBool::new(false),
        }
    }
}

/// How long a free-space sample serves admissions before
/// [`CacheQuota::refresh_disk_headroom`] takes a new one.
const DISK_SAMPLE_TTL: coarsetime::Duration = coarsetime::Duration::from_secs(1);

/// Upper bound for one refresh's `statvfs(3)`: a hung filesystem keeps the
/// previous sample instead of stalling the request that asked.
const DISK_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Whether `needed` more bytes on a filesystem with `free` bytes available
/// still leave `min_free` of them free.
const fn headroom_allows(free: u64, needed: u64, min_free: u64) -> bool {
    free >= min_free.saturating_add(needed)
}

/// The disk space a reservation may still consume: all of it, except the
/// bytes its adopted partial already holds.
fn disk_needed(reserved: NonZero<u64>, partial: Option<&ReservedPartial>) -> u64 {
    reserved
        .get()
        .saturating_sub(partial.map_or(0, |p| p.adopted))
}

/// Snapshot of the commit counters taken before a reconcile's scan; see the
/// module doc.
#[derive(Clone, Copy)]
#[must_use]
pub(crate) struct ReconcileWindow {
    grown: u64,
    shrunk: u64,
}

/// What `subtract_and_reconcile` saw and did; every field is for the
/// caller's log line.
#[must_use]
pub(crate) struct Reconciled {
    /// Accounted size after subtracting the cleanup's removals, before any
    /// repair.
    pub(crate) stored: u64,
    /// Scanned on-disk size plus the net of the live reservations: the value
    /// the accounted size must have if no commit landed during the scan.
    pub(crate) expected: u64,
    /// On-disk bytes added / removed by commits, kept and removed partials
    /// during the scan window.
    pub(crate) grown_during_scan: u64,
    pub(crate) shrunk_during_scan: u64,
    /// Bytes the in-flight downloads may still write into their partials,
    /// which the scan counted at an unknown fill level.
    pub(crate) inflight_unwritten: u64,
    /// Accounted size after the reconcile.
    pub(crate) corrected: u64,
    /// `|corrected - stored|`; 0 when no repair was needed.
    pub(crate) difference: u64,
}

/// The accounted cache size that reserving `reserved` bytes in place of
/// `prev_file_size` existing bytes would produce:
/// `current - prev_file_size + reserved`, saturating.
///
/// Accounting for `prev_file_size` *before* adding `reserved` lets a
/// smaller-replacement download proceed while the cache is over quota -- the
/// net size decreases by `prev_file_size - reserved`, so rejecting it would
/// prevent self-heal via volatile re-fetches. Saturation on the add yields
/// `u64::MAX` only when the sum would overflow, which then rejects via
/// `> quota`.
///
/// This is the single definition of the formula: both admission checks and
/// [`CacheQuota::reserve_locked`] (which applies it to `size`) call it, so an
/// admitted check can never disagree with the reservation it admits.
const fn projected_size(current: u64, prev_file_size: u64, reserved: NonZero<u64>) -> u64 {
    current
        .saturating_sub(prev_file_size)
        .saturating_add(reserved.get())
}

/// What a reservation replaces: the previous cache file plus the partial it
/// adopts.
fn replaced_size(prev_file_size: u64, partial: Option<&ReservedPartial>) -> u64 {
    prev_file_size.saturating_add(partial.map_or(0, |p| p.adopted))
}

/// What a reservation may still write into its partial; 0 without one.
fn unwritten_size(reserved: NonZero<u64>, partial: Option<&ReservedPartial>) -> u64 {
    partial.map_or(0, |p| reserved.get().saturating_sub(p.adopted))
}

impl CacheQuota {
    /// A `CacheQuota` with the given initial size and quota configuration and
    /// no `min_disk_free` floor; the daemon builds its one quota with
    /// [`Self::with_disk_headroom`].
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new(initial: u64, quota_config: Option<NonZero<u64>>) -> Self {
        Self::with_disk_headroom(initial, quota_config, None)
    }

    /// A `CacheQuota` with the given initial size and quota configuration
    /// that also keeps `headroom`'s `min_disk_free` on the
    /// cache filesystem: [`Self::try_acquire`] refuses a download that would
    /// dig into it.
    #[must_use]
    pub(crate) fn with_disk_headroom(
        initial: u64,
        quota_config: Option<NonZero<u64>>,
        headroom: Option<DiskHeadroom>,
    ) -> Self {
        Self {
            inner: Arc::new(QuotaInner {
                accounting: parking_lot::Mutex::new(Accounting {
                    size: initial,
                    ..Accounting::default()
                }),
                quota_config,
                headroom,
            }),
        }
    }

    /// Store a free-space sample of the cache filesystem (`None`: the probe
    /// failed). The startup scan seeds one; [`Self::refresh_disk_headroom`]
    /// keeps it fresh.
    pub(crate) fn record_disk_free(&self, free: Option<u64>) {
        let mut mg = self.inner.accounting.lock();
        let admitted_at = mg.admitted_total;
        mg.disk = Some(DiskSample {
            taken: coarsetime::Instant::now(),
            free,
            admitted_at,
        });
    }

    /// Take a new free-space sample for the `min_disk_free` admission check
    /// when the current one is older than [`DISK_SAMPLE_TTL`]. The quota
    /// gates await it right before [`Self::try_acquire`], which is
    /// synchronous and only reads the sample.
    ///
    /// Single flight: a request arriving while another refreshes goes on
    /// with the current sample, which still charges everything admitted
    /// since it was taken. A probe that fails or times out keeps the
    /// previous sample (a failed one admits).
    pub(crate) async fn refresh_disk_headroom(&self) {
        /// Clears the single-flight flag even when the refresh is cancelled.
        struct Refreshing<'a>(&'a AtomicBool);
        impl Drop for Refreshing<'_> {
            fn drop(&mut self) {
                self.0.store(false, atomic::Ordering::Release);
            }
        }

        let Some(headroom) = &self.inner.headroom else {
            return;
        };
        let admitted_at = {
            let mg = self.inner.accounting.lock();
            if mg.disk.is_some_and(|s| {
                coarsetime::Instant::now().duration_since(s.taken) < DISK_SAMPLE_TTL
            }) {
                return;
            }
            mg.admitted_total
        };
        if headroom.refreshing.swap(true, atomic::Ordering::AcqRel) {
            return;
        }
        let _refreshing = Refreshing(&headroom.refreshing);
        let Ok(space) =
            tokio::time::timeout(DISK_PROBE_TIMEOUT, filesystem_space(&headroom.cache_dir)).await
        else {
            return;
        };
        let mut mg = self.inner.accounting.lock();
        mg.disk = Some(DiskSample {
            taken: coarsetime::Instant::now(),
            free: space.map(|s| s.free_bytes),
            admitted_at,
        });
    }

    /// Atomically check quota and reserve space for a download.
    ///
    /// `content_length.upper()` is the maximum size we might write.
    /// `prev_file_size` is the size of an existing file being replaced
    /// (subtracted from the delta). It must be the real on-disk size when a
    /// download overwrites an entry (e.g. a stale-volatile re-fetch): passing
    /// 0 silently over-counts the quota, which only surfaces later as a
    /// `Repaired cache size discrepancy` warn from cleanup.
    ///
    /// `partial` is the `.partial` a permanent download writes into (`None`
    /// for a volatile download's scratch file). Its adopted bytes count as
    /// replaced here, like `prev_file_size`: `content_length` covers the
    /// whole file, the resumed prefix included.
    ///
    /// With a [`DiskHeadroom`], the download is also refused when the bytes
    /// it may still write (all but the adopted prefix) would leave less than
    /// `min_disk_free` on the cache filesystem, judged from the latest
    /// sample minus everything admitted since ([`Self::refresh_disk_headroom`]).
    /// Both refusals are the same [`QuotaExceeded`]: the client sees one
    /// "Disk quota reached" 503 either way.
    pub(crate) fn try_acquire(
        &self,
        content_length: ContentLength,
        prev_file_size: u64,
        partial: Option<ReservedPartial>,
        debname: &str,
    ) -> Result<QuotaReservation, QuotaExceeded> {
        let reserved = accounted_nonzero(content_length.upper());
        let prev_file_size = accounted_size(prev_file_size);
        let replaced = replaced_size(prev_file_size, partial.as_ref());
        let mg = self.inner.accounting.lock();
        let curr = mg.size;

        if let Some(quota) = self.inner.quota_config
            && projected_size(curr, replaced, reserved) > quota.get()
        {
            drop(mg);
            // A cache sitting at its quota rejects on *every* cacheable
            // miss until cleanup runs, so only the first rejection is a
            // warning -- the rest stay visible at info.
            warn_once_or_info!(
                "Disk quota reached while reserving space for {debname} (cache size {}, reserving {}, quota {}); rejecting the download with 503",
                HumanFmt::Size(curr),
                HumanFmt::Size(reserved.get()),
                HumanFmt::Size(quota.get()),
            );
            metrics::DOWNLOAD_REJECTED_QUOTA.increment();
            return Err(QuotaExceeded);
        }

        if let Some(headroom) = &self.inner.headroom
            && let Some(free) = mg.disk_free_now()
        {
            let needed = disk_needed(reserved, partial.as_ref());
            if !headroom_allows(free, needed, headroom.min_free.get()) {
                drop(mg);
                // Like the quota: a nearly full disk rejects every cacheable
                // miss until space is freed.
                warn_once_or_info!(
                    "Low disk space while reserving space for {debname} ({} free on the cache filesystem, needing {}, min_disk_free {}); rejecting the download with 503",
                    HumanFmt::Size(free),
                    HumanFmt::Size(needed),
                    HumanFmt::Size(headroom.min_free.get()),
                );
                metrics::DOWNLOAD_REJECTED_QUOTA.increment();
                return Err(QuotaExceeded);
            }
        }

        Ok(self.reserve_locked(mg, reserved, prev_file_size, partial, debname))
    }

    /// Reserve space for one of cleanup's own index fetches without
    /// enforcing the limits (`disk_quota` and `min_disk_free`).
    ///
    /// Cleanup can only free space after reconciling against the current
    /// `Release`/`Packages` indexes, and it fetches them through the regular
    /// cache path. At quota, a grown index would be rejected, the mirror
    /// would bail conservatively, and nothing would ever be evicted -- the
    /// cache would stay full forever. Indexes are bounded by
    /// `max_object_size`, so the overshoot is small and the cleanup that
    /// caused it sweeps it back below the limit. Serving a stale cached index
    /// instead is not an option: reconciling against an outdated reference
    /// set would grace-sweep live debs.
    pub(crate) fn acquire_for_cleanup(
        &self,
        content_length: ContentLength,
        prev_file_size: u64,
        partial: Option<ReservedPartial>,
        debname: &str,
    ) -> QuotaReservation {
        let reserved = accounted_nonzero(content_length.upper());
        let prev_file_size = accounted_size(prev_file_size);
        let replaced = replaced_size(prev_file_size, partial.as_ref());
        let mg = self.inner.accounting.lock();
        let curr = mg.size;
        if let Some(quota) = self.inner.quota_config
            && projected_size(curr, replaced, reserved) > quota.get()
        {
            info!(
                "Disk quota reached while reserving space for cleanup index fetch {debname} (cache size {}, reserving {}, quota {}); admitting it over quota so cleanup can reconcile and free space",
                HumanFmt::Size(curr),
                HumanFmt::Size(reserved.get()),
                HumanFmt::Size(quota.get()),
            );
        }
        if let Some(headroom) = &self.inner.headroom
            && let Some(free) = mg.disk_free_now()
        {
            let needed = disk_needed(reserved, partial.as_ref());
            if !headroom_allows(free, needed, headroom.min_free.get()) {
                info!(
                    "Low disk space while reserving space for cleanup index fetch {debname} ({} free on the cache filesystem, needing {}, min_disk_free {}); admitting it so cleanup can reconcile and free space",
                    HumanFmt::Size(free),
                    HumanFmt::Size(needed),
                    HumanFmt::Size(headroom.min_free.get()),
                );
            }
        }
        self.reserve_locked(mg, reserved, prev_file_size, partial, debname)
    }

    /// Apply a reservation to the accounting and mint its token. Takes the
    /// held guard so the caller's check and this update are one critical
    /// section.
    fn reserve_locked(
        &self,
        mut mg: parking_lot::MutexGuard<'_, Accounting>,
        reserved: NonZero<u64>,
        prev_file_size: u64,
        partial: Option<ReservedPartial>,
        debname: &str,
    ) -> QuotaReservation {
        let replaced = replaced_size(prev_file_size, partial.as_ref());
        trace!(
            "Adjusting cache size for file {debname} to be downloaded by {reserved} minus previous file size {prev_file_size} and adopted partial size {}",
            replaced - prev_file_size
        );

        // Reconcile catches any residual drift from `replaced > curr`
        // caller bugs and emits `Repaired cache size discrepancy`.
        mg.size = projected_size(mg.size, replaced, reserved);
        mg.inflight_reserved = mg.inflight_reserved.saturating_add(reserved.get());
        mg.inflight_replaced = mg.inflight_replaced.saturating_add(replaced);
        mg.inflight_unwritten = mg
            .inflight_unwritten
            .saturating_add(unwritten_size(reserved, partial.as_ref()));
        mg.admitted_total = mg
            .admitted_total
            .wrapping_add(disk_needed(reserved, partial.as_ref()));
        let new_size = mg.size;
        drop(mg);

        self.sample_utilization_peak_with(new_size);

        QuotaReservation {
            quota: self.clone(),
            reserved,
            prev_file_size,
            partial: partial.map(Box::new),
            finalized: sticky::Bool::new(),
        }
    }

    /// Release the bytes of a `.partial` file that was just unlinked outside
    /// cleanup's `tmp/` reap (which reports its removals through the
    /// reconcile's `removed` instead): a discarded resume, a checksum
    /// mismatch, a leftover replaced by a fresh download. `len` is the size
    /// the file had when it was removed.
    pub(crate) fn release_removed_partial(&self, len: u64) {
        let len = accounted_size(len);
        if len == 0 {
            return;
        }
        let mut mg = self.inner.accounting.lock();
        mg.subtract(len, "partial removal");
        mg.record_change(len, 0);
    }

    /// Return the current cache size.
    #[must_use]
    pub(crate) fn current_size(&self) -> u64 {
        self.inner.accounting.lock().size
    }

    /// Configured quota limit, if any. `None` means unlimited.
    #[must_use]
    pub(crate) fn quota_limit(&self) -> Option<NonZero<u64>> {
        self.inner.quota_config
    }

    /// Update `CACHE_QUOTA_UTIL_PEAK_BPS` with the current utilization
    /// (in basis points: hundredths of a percent). No-op when no quota is
    /// configured, since utilization is not well defined.
    ///
    /// `current` is taken as a parameter so callers that already hold (or
    /// just released) the accounting lock do not have to re-acquire it.
    pub(crate) fn sample_utilization_peak_with(&self, current: u64) {
        let Some(quota) = self.inner.quota_config else {
            return;
        };
        // bps = current * 10000 / quota, computed in u128 to avoid overflow.
        // Clamp to 10_000 (= 100.00 %) so over-quota states do not produce a
        // misleading sentinel; `quota` is NonZero so no div-by-zero.
        let bps = u128::from(current).saturating_mul(10_000) / std::num::NonZeroU128::from(quota);
        let bps = u64::try_from(bps.min(10_000)).expect("10_000 fits in u64");
        metrics::CACHE_QUOTA_UTIL_PEAK_BPS.update(bps);
    }

    /// Seed the accounted size with the startup scan's total. Runs before
    /// the listener accepts, so no reservation can be live yet.
    pub(crate) fn record_startup_scan(&self, scanned: u64) {
        let mut mg = self.inner.accounting.lock();
        debug_assert_eq!(
            (mg.inflight_reserved, mg.inflight_replaced),
            (0, 0),
            "the startup scan must complete before any download is admitted"
        );
        mg.add(scanned, "startup scan");
        let new_size = mg.size;
        drop(mg);
        self.sample_utilization_peak_with(new_size);
    }

    /// Snapshot the commit counters. Take it *before* the reconcile's cache
    /// scan starts and hand it to [`Self::subtract_and_reconcile`].
    pub(crate) fn begin_reconcile_window(&self) -> ReconcileWindow {
        let mg = self.inner.accounting.lock();
        ReconcileWindow {
            grown: mg.committed_grown,
            shrunk: mg.committed_shrunk,
        }
    }

    /// Atomically subtract `removed` bytes (what this cleanup run deleted)
    /// and reconcile against `actual_cache_size`, the on-disk total the scan
    /// after those deletions produced.
    ///
    /// The scan takes time, and a commit that lands during it is visible to
    /// the scan only if its directory had not been walked yet. So the
    /// accounted size is compared against an interval, not a point: the
    /// scanned total plus the live reservations, widened by the on-disk
    /// deltas recorded since `window` was taken and, downwards, by what the
    /// live downloads may still write into the partials the scan counted.
    /// A value inside the interval is left alone; one outside is moved to
    /// the nearest bound.
    pub(crate) fn subtract_and_reconcile(
        &self,
        removed: u64,
        actual_cache_size: u64,
        window: ReconcileWindow,
    ) -> Reconciled {
        let mut mg = self.inner.accounting.lock();
        mg.size = mg.size.saturating_sub(removed);
        let stored = mg.size;

        let (inflight_add, inflight_sub) = mg.inflight_net();
        let expected = if let Some(val) = actual_cache_size.checked_add(inflight_add) {
            val.saturating_sub(inflight_sub)
        } else {
            metrics::CACHE_SIZE_CORRUPTION.increment();
            error!(
                "Cache-quota reconcile overflowed: actual_cache_size={actual_cache_size} inflight_reserved={} inflight_replaced={}; recording the cache as full, downloads are rejected as over quota until the next reconcile",
                mg.inflight_reserved, mg.inflight_replaced
            );
            u64::MAX
        };
        let grown_during_scan = mg.committed_grown.wrapping_sub(window.grown);
        let shrunk_during_scan = mg.committed_shrunk.wrapping_sub(window.shrunk);
        let inflight_unwritten = mg.inflight_unwritten;
        let lower = expected
            .saturating_sub(shrunk_during_scan)
            .saturating_sub(inflight_unwritten);
        let upper = expected.saturating_add(grown_during_scan);

        let corrected = stored.clamp(lower, upper);
        let difference = stored.abs_diff(corrected);
        if difference != 0 {
            mg.size = corrected;
            metrics::RECONCILE_EVENTS.increment();
            metrics::RECONCILE_BYTES_REPAIRED.increment_by(difference);
        }
        drop(mg);
        // An upward reconcile may push past the prior utilisation peak; downward
        // reconciles cannot, so skip the sample to avoid pointless work.
        if corrected > stored {
            self.sample_utilization_peak_with(corrected);
        }
        Reconciled {
            stored,
            expected,
            grown_during_scan,
            shrunk_during_scan,
            inflight_unwritten,
            corrected,
            difference,
        }
    }
}

impl std::fmt::Debug for CacheQuota {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheQuota")
            .field("accounting", &*self.inner.accounting.lock())
            .field("quota_config", &self.inner.quota_config)
            .finish()
    }
}

#[must_use]
pub(crate) struct QuotaReservation {
    quota: CacheQuota,
    reserved: NonZero<u64>,
    prev_file_size: u64,
    /// The partial the download writes into; `None` for a volatile scratch
    /// file. What it holds when the reservation ends unfinalised stays
    /// accounted; its claim on the path is released only after `Drop` has
    /// measured that.
    partial: Option<Box<ReservedPartial>>,
    finalized: sticky::Bool,
}

impl QuotaReservation {
    /// Finalize the reservation after the download landed in the cache.
    ///
    /// Adjusts the accounted size so the net change from acquire + finalize
    /// equals `bytes_received - prev_file_size`. For `ContentLength::Exact`
    /// with an honest upstream this is a no-op. For `ContentLength::Unknown`
    /// (or an upstream that under-delivered), the unused reservation is
    /// reclaimed. For an upstream that over-delivered (sent more bytes than
    /// announced via `Content-Length`), the extra is added so the accounted
    /// size tracks the actual on-disk size.
    ///
    /// Call it right after the `rename(2)` that made the file visible, in
    /// the same non-cancellable step: it also records the commit's on-disk
    /// delta for a concurrent reconcile (see the module doc).
    ///
    /// A download that wrote a partial renamed it out of `tmp/`, where the
    /// scan may have counted it too, so its full size is also recorded as a
    /// possible shrink.
    pub(crate) fn finalize(mut self, bytes_received: u64) {
        let bytes_received = accounted_size(bytes_received);
        let reserved = self.reserved.get();
        let prev = self.prev_file_size;
        let partial = self.partial.as_deref();
        let mut mg = self.quota.inner.accounting.lock();
        mg.retire(
            reserved,
            replaced_size(prev, partial),
            unwritten_size(self.reserved, partial),
        );
        match reserved.cmp(&bytes_received) {
            Ordering::Equal => {}
            Ordering::Greater => {
                let diff = reserved - bytes_received;
                trace!(
                    "Finalizing quota reservation: reserved={reserved} received={bytes_received} diff=-{diff}"
                );
                mg.subtract(diff, "finalize");
            }
            Ordering::Less => {
                let diff = bytes_received - reserved;
                trace!(
                    "Finalizing quota reservation: reserved={reserved} received={bytes_received} diff=+{diff}"
                );
                mg.add(diff, "finalize");
            }
        }
        mg.record_change(prev, bytes_received);
        if partial.is_some() {
            mg.record_change(bytes_received, 0);
        }
        let new_size = mg.size;
        drop(mg);
        self.finalized.set();
        if bytes_received > reserved {
            self.quota.sample_utilization_peak_with(new_size);
        }
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        if self.finalized.get() {
            return;
        }

        // Revert the reservation, but keep what the partial now holds: it
        // stays on disk for a later resume (a volatile scratch file is
        // unlinked with its download and keeps nothing).
        let reserved = self.reserved.get();
        let prev = self.prev_file_size;
        let partial = self.partial.as_deref();
        let adopted = partial.map_or(0, |p| p.adopted);
        let kept = partial.map_or(0, |p| accounted_size(partial_len(p.claim.path())));
        // `reserved` out, `prev_file_size` and the kept partial back in.
        let restored = prev.saturating_add(kept);
        // Both trace lines below start with "Reverting quota reservation",
        // which `kept_partial_counts_against_the_disk_quota` waits on to know
        // the reservation has ended: keep the wording stable.
        let mut mg = self.quota.inner.accounting.lock();
        mg.retire(
            reserved,
            replaced_size(prev, partial),
            unwritten_size(self.reserved, partial),
        );
        match reserved.cmp(&restored) {
            Ordering::Equal => {}
            Ordering::Less => {
                let revert = restored - reserved;
                trace!(
                    "Reverting quota reservation: reserved={reserved} prev_file_size={prev} kept_partial={kept} revert=+{revert}"
                );
                mg.add(revert, "revert");
            }
            Ordering::Greater => {
                let revert = reserved - restored;
                trace!(
                    "Reverting quota reservation: reserved={reserved} prev_file_size={prev} kept_partial={kept} revert=-{revert}"
                );
                mg.subtract(revert, "revert");
            }
        }
        if partial.is_some() {
            mg.record_change(adopted, kept);
        }
        drop(mg);
        if let Some(partial) = partial
            && kept > 0
        {
            debug!(
                "Keeping {} of partial `{}` accounted towards the cache size",
                HumanFmt::Size(kept),
                partial.claim.path().display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `n` whole quota blocks, in bytes. Every size the quota handles is
    /// rounded up to a block, so the tests count in blocks.
    const fn b(n: u64) -> u64 {
        n * QUOTA_BLOCK_SIZE
    }

    /// `v` blocks.
    fn nz(v: u64) -> NonZero<u64> {
        NonZero::new(b(v)).expect("non-zero test value")
    }

    /// A `Content-Length` of `v` blocks.
    fn exact(v: u64) -> ContentLength {
        ContentLength::Exact(nz(v))
    }

    #[test]
    fn sizes_are_accounted_in_whole_blocks() {
        assert_eq!(accounted_size(0), 0, "an empty file has no data block");
        assert_eq!(accounted_size(1), 4096);
        assert_eq!(accounted_size(4096), 4096);
        assert_eq!(accounted_size(4097), 8192);
        assert_eq!(accounted_size(u64::MAX), u64::MAX, "saturates");
    }

    /// Many tiny files take far more disk than their lengths add up to: each
    /// is charged a whole block, in the reservation, at finalisation, on
    /// replacement and when its partial is kept or removed alike.
    #[test]
    fn every_quota_input_is_rounded_to_whole_blocks() {
        let quota = CacheQuota::new(0, Some(nz(2)));
        let tiny = ContentLength::Exact(NonZero::new(10).expect("non-zero"));
        let first = quota
            .try_acquire(tiny, 0, None, "first")
            .ok()
            .expect("one block");
        assert_eq!(quota.current_size(), b(1));
        first.finalize(10);
        assert_eq!(quota.current_size(), b(1));
        let second = quota
            .try_acquire(tiny, 0, None, "second")
            .ok()
            .expect("the second block");
        assert!(
            quota.try_acquire(tiny, 0, None, "third").is_err(),
            "two 10-byte files fill a two-block quota"
        );
        drop(second);

        // Replacing a 10-byte file with a 20-byte one needs no new block.
        let overwrite = quota
            .try_acquire(
                ContentLength::Exact(NonZero::new(20).expect("non-zero")),
                10,
                None,
                "overwrite",
            )
            .ok()
            .expect("fits");
        assert_eq!(quota.current_size(), b(1));
        overwrite.finalize(20);
        assert_eq!(quota.current_size(), b(1));

        let (_dir, path) = partial_path();
        let reservation = quota
            .try_acquire(tiny, 0, Some(reserved(&path, 0)), "kept")
            .ok()
            .expect("fits");
        std::fs::write(&path, b"x").expect("write partial");
        drop(reservation);
        assert_eq!(quota.current_size(), b(2), "a 1-byte partial keeps a block");
        quota.release_removed_partial(1);
        assert_eq!(quota.current_size(), b(1));
    }

    #[test]
    fn fresh_download_under_quota_accepts() {
        let quota = CacheQuota::new(b(80), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(10), 0, None, "fresh-under")
            .ok()
            .expect("fresh download under quota should be accepted");
        assert_eq!(quota.current_size(), b(90));
        drop(reservation);
        // Drop reverts the reservation since `finalize` was not called.
        assert_eq!(quota.current_size(), b(80));
    }

    #[test]
    fn fresh_download_over_quota_rejects() {
        let quota = CacheQuota::new(b(100), Some(nz(100)));
        let res = quota.try_acquire(exact(10), 0, None, "fresh-over");
        assert!(
            res.is_err(),
            "fresh download that would exceed quota must be rejected"
        );
        assert_eq!(quota.current_size(), b(100));
    }

    #[test]
    fn fresh_download_exactly_at_quota_accepts() {
        // The projected size may equal the quota (`> quota` rejects, not
        // `>=`); one byte past it is refused.
        let quota = CacheQuota::new(b(90), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(10), 0, None, "fresh-at")
            .ok()
            .expect("projected size equal to the quota must be accepted");
        assert_eq!(quota.current_size(), b(100));
        drop(reservation);
        assert_eq!(quota.current_size(), b(90));

        let quota = CacheQuota::new(b(91), Some(nz(100)));
        assert!(
            quota.try_acquire(exact(10), 0, None, "fresh-past").is_err(),
            "projected size one byte over the quota must be rejected"
        );
        assert_eq!(quota.current_size(), b(91));
    }

    #[test]
    fn overwrite_same_size_under_quota_accepts() {
        let quota = CacheQuota::new(b(80), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(10), b(10), None, "overwrite-same")
            .ok()
            .expect("same-size overwrite under quota should be accepted");
        // Reserve adds 10, subtracts prev 10: net 0.
        assert_eq!(quota.current_size(), b(80));
        drop(reservation);
        assert_eq!(quota.current_size(), b(80));
    }

    #[test]
    fn overwrite_smaller_while_over_quota_accepts() {
        // Cache is currently over quota, and the replacement would actually
        // shrink it: `curr - prev + reserved = 110 - 20 + 5 = 95 <= 100`.
        let quota = CacheQuota::new(b(110), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(5), b(20), None, "shrink-while-over")
            .ok()
            .expect("smaller overwrite must be accepted to allow self-heal");
        assert_eq!(quota.current_size(), b(95));
        drop(reservation);
        assert_eq!(quota.current_size(), b(110));
    }

    #[test]
    fn overwrite_larger_that_would_push_over_rejects() {
        let quota = CacheQuota::new(b(80), Some(nz(100)));
        // 80 - 10 + 40 = 110 > 100 → reject.
        let res = quota.try_acquire(exact(40), b(10), None, "grow-over");
        assert!(
            res.is_err(),
            "overwrite that would push past quota must be rejected"
        );
        assert_eq!(quota.current_size(), b(80));
    }

    #[test]
    fn release_round_trip_finalize_exact() {
        let quota = CacheQuota::new(b(50), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(20), b(5), None, "round-trip")
            .ok()
            .expect("must accept");
        // 50 - 5 + 20 = 65 in flight.
        assert_eq!(quota.current_size(), b(65));
        // Finalize with the announced size: no further adjustment.
        reservation.finalize(b(20));
        assert_eq!(quota.current_size(), b(65));
    }

    #[test]
    fn release_round_trip_finalize_under_delivers() {
        let quota = CacheQuota::new(b(50), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(20), 0, None, "under-deliver")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), b(70));
        // Upstream sent only 12 bytes — the unused 8-byte reservation
        // must be reclaimed.
        reservation.finalize(b(12));
        assert_eq!(quota.current_size(), b(62));
    }

    #[test]
    fn release_round_trip_finalize_over_delivers() {
        let quota = CacheQuota::new(b(50), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(20), 0, None, "over-deliver")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), b(70));
        // Upstream sent 25 bytes despite announcing 20; the accounted size
        // must follow the bytes that actually landed on disk, not the
        // reservation, or the quota under-counts the cache forever.
        reservation.finalize(b(25));
        assert_eq!(quota.current_size(), b(75));
    }

    #[test]
    fn reconcile_window_ignores_an_abandoned_reservation() {
        // A download that never commits must widen no reconcile interval:
        // only `finalize` records an on-disk delta, so a scan taken after the
        // abort sees the truth and the accounted size needs no repair.
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let reservation = quota
            .try_acquire(exact(30), 0, None, "abandoned")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), b(80));
        drop(reservation);
        let r = quota.subtract_and_reconcile(b(0), b(50), window);
        assert_eq!(r.grown_during_scan, b(0), "an abort commits nothing");
        assert_eq!(r.shrunk_during_scan, b(0));
        assert_eq!(r.difference, b(0));
        assert_eq!(quota.current_size(), b(50));
    }

    #[test]
    fn release_round_trip_drop_without_finalize_reverts() {
        let quota = CacheQuota::new(b(50), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(20), b(5), None, "drop-revert")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), b(65));
        drop(reservation);
        // Drop without finalize reverts net change: back to original 50.
        assert_eq!(quota.current_size(), b(50));
    }

    #[test]
    fn no_quota_configured_always_accepts() {
        let quota = CacheQuota::new(u64::MAX / 2, None);
        let reservation = quota
            .try_acquire(exact(1_000), 0, None, "no-quota")
            .ok()
            .expect("must accept when quota is unconfigured");
        drop(reservation);
    }

    #[test]
    fn cleanup_index_fetch_is_admitted_over_quota() {
        let quota = CacheQuota::new(b(100), Some(nz(100)));
        let reservation = quota.acquire_for_cleanup(exact(10), b(4), None, "Packages.xz");
        // Accounted like any other reservation: 100 - 4 + 10.
        assert_eq!(quota.current_size(), b(106));
        reservation.finalize(b(10));
        assert_eq!(quota.current_size(), b(106));
    }

    #[test]
    fn reconcile_in_flight_overwrite_is_not_a_discrepancy() {
        // A stale volatile re-fetch in flight: on disk the 20-byte previous
        // file still exists, the reservation holds 30 for the replacement.
        let quota = CacheQuota::new(b(80), Some(nz(1000)));
        let reservation = quota
            .try_acquire(exact(30), b(20), None, "index")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), b(90));
        let window = quota.begin_reconcile_window();
        // The scan still sees the old 20-byte file among the 80 on disk.
        let r = quota.subtract_and_reconcile(b(0), b(80), window);
        assert_eq!(r.difference, b(0), "in-flight net must explain the gap");
        assert_eq!(quota.current_size(), b(90));
        reservation.finalize(b(30));
        assert_eq!(quota.current_size(), b(90));
    }

    #[test]
    fn reconcile_shrinking_in_flight_overwrite_is_not_a_discrepancy() {
        let quota = CacheQuota::new(b(80), Some(nz(1000)));
        let reservation = quota
            .try_acquire(exact(5), b(20), None, "index")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), b(65));
        let window = quota.begin_reconcile_window();
        let r = quota.subtract_and_reconcile(b(0), b(80), window);
        assert_eq!(r.difference, b(0));
        drop(reservation);
        assert_eq!(quota.current_size(), b(80));
    }

    #[test]
    fn reconcile_keeps_commit_the_scan_missed() {
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        // During the scan a 30-byte download commits after its directory was
        // walked: the scan reports 50, the accounted size is already 80.
        let reservation = quota
            .try_acquire(exact(30), 0, None, "late")
            .ok()
            .expect("must accept");
        reservation.finalize(b(30));
        assert_eq!(quota.current_size(), b(80));
        let r = quota.subtract_and_reconcile(b(0), b(50), window);
        assert_eq!(r.difference, b(0), "a commit during the scan is not drift");
        assert_eq!(r.grown_during_scan, b(30));
        assert_eq!(quota.current_size(), b(80));
    }

    #[test]
    fn reconcile_accepts_commit_the_scan_saw() {
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let reservation = quota
            .try_acquire(exact(30), 0, None, "early")
            .ok()
            .expect("must accept");
        reservation.finalize(b(30));
        // The scan walked the directory after the commit: it reports 80.
        let r = quota.subtract_and_reconcile(b(0), b(80), window);
        assert_eq!(r.difference, b(0));
        assert_eq!(quota.current_size(), b(80));
    }

    #[test]
    fn reconcile_repairs_real_drift_beyond_the_window() {
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let reservation = quota
            .try_acquire(exact(30), 0, None, "late")
            .ok()
            .expect("must accept");
        reservation.finalize(b(30));
        // Scan reports 40: even if the commit was missed, 80 exceeds
        // 40 + 30, so 10 bytes are genuine drift.
        let r = quota.subtract_and_reconcile(b(0), b(40), window);
        assert_eq!(r.difference, b(10));
        assert_eq!(r.corrected, b(70));
        assert_eq!(quota.current_size(), b(70));
    }

    #[test]
    fn reconcile_repairs_under_count_upwards() {
        let quota = CacheQuota::new(b(10), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let r = quota.subtract_and_reconcile(b(0), b(40), window);
        assert_eq!(r.difference, b(30));
        assert_eq!(quota.current_size(), b(40));
    }

    #[test]
    fn reconcile_subtracts_removed_first() {
        let quota = CacheQuota::new(b(100), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        // Cleanup deleted 40 bytes; the scan after the deletions reports 60.
        let r = quota.subtract_and_reconcile(b(40), b(60), window);
        assert_eq!(r.stored, b(60));
        assert_eq!(r.difference, b(0));
        assert_eq!(quota.current_size(), b(60));
    }

    #[test]
    fn startup_scan_seeds_the_size() {
        let quota = CacheQuota::new(b(0), Some(nz(1000)));
        quota.record_startup_scan(b(123));
        assert_eq!(quota.current_size(), b(123));
    }

    /// A partial path in a fresh temporary directory; nothing on disk yet.
    fn partial_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x_1.0_amd64.deb.partial");
        (dir, path)
    }

    /// Fill the partial at `path` with `blocks` whole blocks.
    fn write_len(path: &Path, blocks: u64) {
        let len = usize::try_from(b(blocks)).expect("small test file");
        std::fs::write(path, vec![0u8; len]).expect("write partial");
    }

    /// The partial at `path`, claimed as its download would, adopting
    /// `adopted` bytes.
    fn reserved(path: &Path, adopted: u64) -> ReservedPartial {
        let claim = PartialClaim::acquire(path.to_path_buf()).expect("unclaimed partial");
        ReservedPartial::new(claim, adopted)
    }

    /// Cleanup trying to reap a partial a resume has adopted leaves it to
    /// the reservation: the bytes are released once, when the reservation
    /// ends, and a reap after that counts nothing twice. Reaping it under the
    /// download released them from both sides.
    #[test]
    fn a_partial_adopted_by_a_resume_is_released_once() {
        use crate::partial_claim::{FileId, Reap, reap_unclaimed};

        let (_dir, path) = partial_path();
        write_len(&path, 40);
        let walked = FileId::of(&std::fs::symlink_metadata(&path).expect("stat"));
        // 50 blocks of cached files plus the kept 40-block partial.
        let quota = CacheQuota::new(b(90), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let reservation = quota
            .try_acquire(exact(100), 0, Some(reserved(&path, b(40))), "resume")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), b(150));

        // The walk found it stale, but the reservation's claim wins.
        assert!(matches!(
            reap_unclaimed(&path, walked, |_| true),
            Reap::Claimed
        ));
        write_len(&path, 45);
        drop(reservation);
        assert_eq!(
            quota.current_size(),
            b(95),
            "the reservation keeps what the partial holds"
        );

        // The next reap may take it, and counts it once.
        let walked = FileId::of(&std::fs::symlink_metadata(&path).expect("stat"));
        let reaped = match reap_unclaimed(&path, walked, |_| true) {
            Reap::Removed { len } => Ok(len),
            other @ (Reap::Claimed
            | Reap::Changed
            | Reap::StatFailed(_)
            | Reap::RemoveFailed(_)) => Err(other),
        };
        let tmp_bytes_removed = accounted_size(reaped.expect("an unclaimed partial is reaped"));
        let r = quota.subtract_and_reconcile(tmp_bytes_removed, b(50), window);
        assert_eq!(r.stored, b(50), "released once");
        assert_eq!(r.difference, b(0), "nothing to repair");
    }

    #[test]
    fn failed_download_keeps_what_its_partial_holds() {
        let (_dir, path) = partial_path();
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let reservation = quota
            .try_acquire(exact(100), 0, Some(reserved(&path, b(0))), "kept")
            .ok()
            .expect("must accept");
        assert_eq!(quota.current_size(), b(150));
        write_len(&path, 30);
        drop(reservation);
        assert_eq!(
            quota.current_size(),
            b(80),
            "only the 70 unwritten bytes are reverted"
        );
    }

    #[test]
    fn failed_download_without_a_partial_on_disk_keeps_nothing() {
        let (_dir, path) = partial_path();
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let reservation = quota
            .try_acquire(exact(100), 0, Some(reserved(&path, b(0))), "none")
            .ok()
            .expect("must accept");
        drop(reservation);
        assert_eq!(quota.current_size(), b(50));
    }

    #[test]
    fn resume_adopts_the_kept_partial() {
        // 50 bytes of cached files plus a kept 40-byte partial; resuming it to
        // a 50-byte file only adds 10 bytes, which fits the quota exactly.
        let (_dir, path) = partial_path();
        write_len(&path, 40);
        let quota = CacheQuota::new(b(90), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(50), 0, Some(reserved(&path, b(40))), "resume")
            .ok()
            .expect("a resume adding 10 bytes fits");
        assert_eq!(quota.current_size(), b(100));
        reservation.finalize(b(50));
        assert_eq!(
            quota.current_size(),
            b(100),
            "the partial became the cached file: counted once"
        );

        // The same resume failing after 5 more bytes keeps the 45-byte partial.
        let quota = CacheQuota::new(b(90), Some(nz(100)));
        let reservation = quota
            .try_acquire(exact(50), 0, Some(reserved(&path, b(40))), "resume")
            .ok()
            .expect("must accept");
        write_len(&path, 45);
        drop(reservation);
        assert_eq!(quota.current_size(), b(95));
    }

    #[test]
    fn a_resume_is_admitted_by_its_remainder_only() {
        let (_dir, path) = partial_path();
        write_len(&path, 40);
        let quota = CacheQuota::new(b(90), Some(nz(100)));
        assert!(
            quota
                .try_acquire(exact(50), 0, None, "not-adopted")
                .is_err(),
            "without adoption the partial would be counted twice"
        );
    }

    #[test]
    fn removed_partial_releases_its_bytes() {
        let quota = CacheQuota::new(b(80), Some(nz(1000)));
        quota.release_removed_partial(b(30));
        assert_eq!(quota.current_size(), b(50));
    }

    #[test]
    fn reconcile_counts_a_live_partial_at_any_fill_level() {
        let (_dir, path) = partial_path();
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let reservation = quota
            .try_acquire(exact(100), 0, Some(reserved(&path, b(0))), "live")
            .ok()
            .expect("must accept");
        let window = quota.begin_reconcile_window();
        // The scan walked the partial empty, 30 bytes in, or complete.
        for scanned in [b(50), b(80), b(150)] {
            let r = quota.subtract_and_reconcile(b(0), scanned, window);
            assert_eq!(r.difference, b(0), "scanned {scanned}");
            assert_eq!(r.inflight_unwritten, b(100));
        }
        assert_eq!(quota.current_size(), b(150));
        // Beyond what any fill level explains is drift.
        let r = quota.subtract_and_reconcile(b(0), b(40), window);
        assert_eq!(r.difference, b(10));
        drop(reservation);
    }

    #[test]
    fn reconcile_tolerates_a_partial_kept_during_the_scan() {
        let (_dir, path) = partial_path();
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let reservation = quota
            .try_acquire(exact(100), 0, Some(reserved(&path, b(0))), "kept")
            .ok()
            .expect("must accept");
        write_len(&path, 30);
        drop(reservation);
        assert_eq!(quota.current_size(), b(80));
        // The scan walked `tmp/` before the download wrote, or after it ended.
        for scanned in [b(50), b(80)] {
            let r = quota.subtract_and_reconcile(b(0), scanned, window);
            assert_eq!(r.difference, b(0), "scanned {scanned}");
        }
    }

    #[test]
    fn reconcile_tolerates_a_partial_commit_counted_twice() {
        let (_dir, path) = partial_path();
        let quota = CacheQuota::new(b(50), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        let reservation = quota
            .try_acquire(exact(30), 0, Some(reserved(&path, b(0))), "moved")
            .ok()
            .expect("must accept");
        reservation.finalize(b(30));
        assert_eq!(quota.current_size(), b(80));
        // Neither copy seen, one of them, or the complete partial in `tmp/`
        // before the rename and the final file after it.
        for scanned in [b(50), b(80), b(110)] {
            let r = quota.subtract_and_reconcile(b(0), scanned, window);
            assert_eq!(r.difference, b(0), "scanned {scanned}");
        }
    }

    #[test]
    fn reconcile_tolerates_a_partial_removed_during_the_scan() {
        // 30 of the 80 bytes are a kept partial a discarded resume unlinks.
        let quota = CacheQuota::new(b(80), Some(nz(1000)));
        let window = quota.begin_reconcile_window();
        quota.release_removed_partial(b(30));
        for scanned in [b(50), b(80)] {
            let r = quota.subtract_and_reconcile(b(0), scanned, window);
            assert_eq!(r.difference, b(0), "scanned {scanned}");
        }
        assert_eq!(quota.current_size(), b(50));
    }

    #[test]
    fn headroom_keeps_min_disk_free_after_the_reservation() {
        // 1000 bytes free, 600 must stay free: 400 may still be written.
        assert!(headroom_allows(1000, 400, 600));
        assert!(!headroom_allows(1000, 401, 600));
        assert!(!headroom_allows(500, 0, 600), "already below the floor");
        assert!(!headroom_allows(1000, u64::MAX, 600), "saturates");
    }

    /// No `disk_quota`, `min_disk_free` of `min_free`, a sample of `free`.
    fn headroom_quota(min_free: u64, free: Option<u64>) -> CacheQuota {
        let quota = CacheQuota::with_disk_headroom(
            0,
            None,
            Some(DiskHeadroom::new(
                PathBuf::from("/nonexistent"),
                nz(min_free),
            )),
        );
        quota.record_disk_free(free.map(b));
        quota
    }

    #[test]
    fn low_disk_space_rejects_a_download() {
        let quota = headroom_quota(600, Some(1000));
        assert!(quota.try_acquire(exact(401), 0, None, "big").is_err());
        assert_eq!(quota.current_size(), b(0), "a rejection reserves nothing");
        let first = quota
            .try_acquire(exact(300), 0, None, "first")
            .ok()
            .expect("300 of the 400 spare bytes");
        // The sample predates the first reservation and cannot reflect it.
        assert!(quota.try_acquire(exact(200), 0, None, "second").is_err());
        drop(first);
        // A fresh sample starts over.
        quota.record_disk_free(Some(b(1000)));
        assert!(quota.try_acquire(exact(400), 0, None, "fresh").is_ok());
    }

    #[test]
    fn low_disk_space_charges_a_resume_its_remainder_only() {
        let (_dir, path) = partial_path();
        write_len(&path, 300);
        let quota = headroom_quota(600, Some(1000));
        // 500 bytes in total, 300 already on disk.
        assert!(
            quota
                .try_acquire(exact(500), 0, Some(reserved(&path, b(300))), "resume")
                .is_ok()
        );
    }

    #[test]
    fn low_disk_space_admits_cleanup_index_fetches() {
        let quota = headroom_quota(600, Some(1000));
        let reservation = quota.acquire_for_cleanup(exact(900), 0, None, "Packages.xz");
        assert_eq!(quota.current_size(), b(900));
        drop(reservation);
    }

    #[test]
    fn unknown_free_space_admits() {
        let quota = headroom_quota(600, None);
        assert!(quota.try_acquire(exact(5000), 0, None, "unknown").is_ok());
        let quota = CacheQuota::with_disk_headroom(
            0,
            None,
            Some(DiskHeadroom::new(PathBuf::from("/nonexistent"), nz(600))),
        );
        assert!(
            quota.try_acquire(exact(5000), 0, None, "unsampled").is_ok(),
            "no sample yet"
        );
    }

    #[tokio::test]
    async fn refresh_samples_the_cache_filesystem() {
        let dir = tempfile::tempdir().expect("tempdir");
        // More free space than any filesystem has.
        let quota = CacheQuota::with_disk_headroom(
            0,
            None,
            Some(DiskHeadroom::new(
                dir.path().to_path_buf(),
                NonZero::new(u64::MAX / 2).expect("non-zero"),
            )),
        );
        quota.refresh_disk_headroom().await;
        assert!(quota.try_acquire(exact(1), 0, None, "tiny").is_err());
    }
}
