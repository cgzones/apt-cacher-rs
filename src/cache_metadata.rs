//! Process-local cache for cached-file metadata (`ETag`, Last-Modified).
//!
//! Motivated by a profiling finding (May 2026, local samply baseline):
//! every cache-hit conditional-request path
//! issues two `fgetxattr(2)` syscalls (one for the `ETag` xattr, one for
//! Last-Modified), and the rustix bounds-check inside the xattr crate
//! showed up at ~0.5 % of worker samples plus drove `block_in_place` and
//! `spawn_blocking_inner` mutex traffic. Caching the parsed values per
//! `(mirror, debname, layout)` lets repeat hits skip the syscalls entirely.
//!
//! # Source-of-truth split
//!
//! - **In-flight downloads** carry their etag/last-modified on
//!   [`crate::active_downloads::ActiveDownloadStatus::Download`] and on `Finished { meta:
//!   Some(_) }`; late-joiners read those directly. `Finished { meta:
//!   None }` (volatile-304 in `InitBarrier::finished`, error fallback
//!   in `RenameBarrier::commit`) falls through to
//!   [`CacheMetadataStore::resolve`].
//! - **Post-flight (rename complete, active-downloads entry removed)** is
//!   what this cache covers. The transition from in-flight to post-flight
//!   happens inside `RenameBarrier::commit`, which calls
//!   [`CacheMetadataStore::set`] (via `cache_metadata::store().set(...)`)
//!   *before* removing the active-downloads entry — so a worker that
//!   misses the entry always finds the cache populated.
//!
//! The xattrs on the cached file remain the persistent source of truth.
//! This cache is empty at boot; the first read for each file falls back
//! to the xattr helpers and inserts the result. xattr writes still happen
//! on the download path (every backend calls [`write_upstream_metadata`]
//! on the same [`UpstreamMetadata`] it later publishes) so the values
//! survive process restarts. A resumed download's metadata first inherits
//! each validator its `206` omitted from the partial
//! ([`UpstreamMetadata::inherit_resumed`]); on a resumed partial a
//! validator it still lacks is *removed* there, not left alone: the partial
//! still carries its first attempt's xattrs, and a stale one would
//! otherwise be what a restart reads back for a file whose download
//! published `None`. Every other download writes to a file it just created
//! ([`TargetFile::New`]), which has nothing to remove.
//! Volatile 304 revalidation also writes xattrs: [`revalidate`] merges the
//! supplied validators with the selected stored representation, persists
//! that snapshot, then publishes it through [`CacheMetadataStore::set`]
//! before the refreshed entry is released to waiting readers.
//!
//! # Publication invariant
//!
//! Every caller of [`CacheMetadataStore::set`] **must** persist matching
//! xattrs to the cached file *before* invoking `set`: the entry is what
//! clients are served until it is cleared or the daemon restarts, and the
//! xattrs are what they are served after, so the two have to agree or
//! conditional requests change their answer across a restart.
//!
//! `resolve`'s cold path releases the read lock before reading xattrs and
//! re-acquires the write lock to insert.  A concurrent `set` can publish
//! in between, and then wins: resolve's insert re-checks the entry under
//! the write lock and returns the published `Arc`, dropping what it read.
//! That read is stale by construction whenever it started before the
//! publish (a volatile revalidation rewrites the xattrs of the very file a
//! hit is resolving; a commit renames a new file over the one it opened),
//! and under the lock nothing tells such a read from a caller that skipped
//! its xattr write, so the mismatch is not asserted or logged.  The
//! invariant is what keeps the published value and the file in step, not
//! something resolve can check.
//!
//! # Negative caching and transient errors
//!
//! Successfully observing absent xattrs (no value, FS doesn't support
//! xattrs, or a malformed value was scrubbed) inserts a `(None, None)`
//! entry — subsequent hits skip the syscalls.  Transient I/O failures
//! (e.g. `EIO`) are deliberately NOT cached: a one-time syscall failure
//! would otherwise pin the negative entry until process restart and
//! silently disable conditional-request handling.  When *either* xattr
//! read errors, `resolve` returns a best-effort `Arc` for the current
//! request that contains whichever fields succeeded (so an `EIO` on the
//! `ETag` xattr while Last-Modified read cleanly yields
//! `(None, Some(...))`, and vice versa) but does not insert; the next
//! reader retries both syscalls.

use std::{path::Path, sync::Arc};

use hashbrown::{Equivalent, HashMap, HashSet};

use crate::{
    cache_layout::{CacheEntryKeyRef, CacheLayout},
    deb_mirror::Mirror,
    http_etag::{ETag, MAX_ETAG_LEN, is_valid_etag},
    http_last_modified::{LastModified, is_valid_http_date},
    http_range::HttpDate,
    mem_usage::{ARC_HEADER, Footprint},
    warn_once_or_info,
    xattr_helpers::{self, ExpectedSize, XattrValue as _},
};

/// Upstream-supplied metadata for a single cached file.  Used both as the
/// in-flight value carried on [`crate::active_downloads::ActiveDownloadStatus::Download`] and
/// as the post-flight cache entry.
///
/// `last_modified` stores both the raw header string (for `Last-Modified`
/// response headers) and its parsed [`HttpDate`] (for If-Modified-Since
/// comparison) so consumers don't re-parse on every hit.
///
/// The strings are `Arc<str>` so per-serve [`crate::cache_conditional::CacheInfo`]
/// construction is a refcount bump instead of a String clone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UpstreamMetadata {
    pub(crate) etag: Option<Arc<str>>,
    pub(crate) last_modified: Option<(Arc<str>, HttpDate)>,
}

impl UpstreamMetadata {
    /// Build from raw upstream header strings.  The Last-Modified pair is
    /// produced only if the value parses as a valid HTTP-date.
    #[must_use]
    pub(crate) fn from_upstream(etag: Option<&str>, last_modified: Option<&str>) -> Self {
        let last_modified =
            last_modified.and_then(|s| HttpDate::parse(s).map(|t| (Arc::from(s), t)));
        Self {
            etag: etag.filter(|value| is_valid_etag(value)).map(Arc::from),
            last_modified,
        }
    }

    /// Fill in, for a download that resumes a partial, each validator the
    /// upstream's `206` omitted from `resumed` -- the values the partial's
    /// first attempt stored ([`crate::partial_file::PartialDownload::resumed_validators`];
    /// `None` for any other download, which leaves `self` as it is).
    ///
    /// A resume is only ever requested with the stored strong `ETag` as
    /// `If-Range`, so a `206` is the upstream's statement that the
    /// representation is unchanged (RFC 9110 §13.1.5): the first attempt's
    /// validators still describe it, and RFC 9110 §15.3.7 does not require a
    /// `206` to repeat `Last-Modified`. Without this, a `206` lacking one
    /// would publish a synthesized `Last-Modified` in place of the real one,
    /// and one lacking the `ETag` would leave the file unresumable after a
    /// second interruption. A value the `206` does carry wins. The stored
    /// `Last-Modified` is not inherited next to a *different* `ETag` the
    /// `206` names: that response does not vouch for the stored
    /// representation, so the date would be paired with a tag it never
    /// belonged to. That branch is defense in depth, not a production path:
    /// `upstream_head::plan_download` already turns such a `206` into
    /// `ResumeAnomaly::ETagMismatch`, which discards the partial before any
    /// metadata is built.
    #[must_use]
    pub(crate) fn inherit_resumed(self, resumed: Option<&Self>) -> Self {
        let Some(Self {
            etag: stored_etag,
            last_modified: stored_last_modified,
        }) = resumed
        else {
            return self;
        };
        let Self {
            etag,
            last_modified,
        } = self;
        let same_representation = etag.is_none() || etag == *stored_etag;
        let last_modified = match last_modified {
            Some(own) => Some(own),
            None if same_representation => stored_last_modified.clone(),
            None => None,
        };
        Self {
            etag: etag.or_else(|| stored_etag.clone()),
            last_modified,
        }
    }
}

/// Persist a 304's validator updates before publishing the refreshed entry.
/// Absent fields retain the values of the selected stored representation.
pub(crate) fn revalidate(
    key: CacheEntryKeyRef<'_>,
    file: &tokio::fs::File,
    path: &Path,
    update: UpstreamMetadata,
) -> Arc<UpstreamMetadata> {
    let stored = store().resolve(&key, file, path);
    let updated = Arc::new(UpstreamMetadata {
        etag: update.etag.or_else(|| stored.etag.clone()),
        last_modified: update
            .last_modified
            .or_else(|| stored.last_modified.clone()),
    });
    write_upstream_metadata(file, path, &updated, None, TargetFile::Resumed);
    store().set(&key, Arc::clone(&updated));
    updated
}

/// Where [`write_upstream_metadata`] writes: what decides whether a
/// validator the metadata lacks can be left alone. From
/// `partial_file::PartialDownload::target_file`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetFile {
    /// Created for this download (`O_EXCL`: a `Fresh` partial or a volatile
    /// temp file), so it carries no xattrs yet.
    New,
    /// A resumed partial, still carrying its first attempt's xattrs.
    Resumed,
}

/// Persist a download's upstream metadata on its cache file: the `ETag` and
/// `Last-Modified` validators from `meta`, plus the expected total size when
/// the upstream announced one (so a resume can detect an upstream change).
/// Written early, on the partial/temp file, so the values survive an
/// interrupted download for resume; every backend calls this on the very
/// [`UpstreamMetadata`] it hands the download barrier, which is what keeps
/// the publication invariant (module docs) trivially true -- including for
/// a validator `meta` lacks on a [`TargetFile::Resumed`] partial, whose
/// attribute is removed in case the earlier attempt left one behind (an
/// absent one is success). A [`TargetFile::New`] file skips those removals:
/// they could only ever answer `ENODATA`.
///
/// `meta`'s strings were validated once per upstream response by
/// [`check_upstream_validators`], so the re-parse here cannot fail; the
/// skip arm is the defensive fallback for a caller that bypassed it.
pub(crate) fn write_upstream_metadata(
    file: &tokio::fs::File,
    display_path: &Path,
    meta: &UpstreamMetadata,
    expected_size: Option<u64>,
    target: TargetFile,
) {
    let UpstreamMetadata {
        etag,
        last_modified,
    } = meta;
    // One blocking section for all three attributes: writing them through
    // the `tokio::fs::File` target would demote the worker once per
    // attribute, and every fresh download writes up to three.
    tokio::task::block_in_place(|| {
        let file = &xattr_helpers::XattrFile(file);
        match etag {
            Some(etag) => {
                if let Some(etag) = ETag::parse(etag) {
                    xattr_helpers::write(file, display_path, &etag);
                } else {
                    warn_once_or_info!(
                        "Skipping write of malformed ETag to `{}`: `{}`",
                        display_path.display(),
                        etag.escape_debug()
                    );
                }
            }
            None => {
                if target == TargetFile::Resumed {
                    xattr_helpers::remove_stale::<ETag>(file, display_path);
                }
            }
        }
        match last_modified {
            Some((raw, _time)) => {
                if let Some(lm) = LastModified::parse(raw) {
                    xattr_helpers::write(file, display_path, &lm);
                } else {
                    warn_once_or_info!(
                        "Skipping write of malformed Last-Modified to `{}`: `{}`",
                        display_path.display(),
                        raw.escape_debug()
                    );
                }
            }
            None => {
                if target == TargetFile::Resumed {
                    xattr_helpers::remove_stale::<LastModified>(file, display_path);
                }
            }
        }
        if let Some(size) = expected_size {
            xattr_helpers::write(file, display_path, &ExpectedSize(size));
        }
    });
}

/// A malformed upstream validator discarded by [`check_upstream_validators`],
/// carrying the offending value for the caller's warn line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InvalidValidator<'a> {
    /// `ETag` not well-formed per RFC 9110 §8.8.3.
    ETag(&'a str),
    /// `Last-Modified` not an IMF-fixdate HTTP-date (RFC 9110 §5.6.7).
    LastModified(&'a str),
    /// A validator longer than [`MAX_VALIDATOR_LEN`]: reported by length,
    /// never by value, so a hostile upstream cannot put the value (up to the
    /// ~400 KiB a hyper response head may hold) into the log.
    Oversized { header: &'static str, len: usize },
}

/// Longest upstream validator value [`check_upstream_validators`] inspects:
/// [`MAX_ETAG_LEN`], which an IMF-fixdate `Last-Modified` (29 bytes) is far
/// below as well.
const MAX_VALIDATOR_LEN: usize = MAX_ETAG_LEN;

/// Validate the raw upstream `ETag`/`Last-Modified` header values once per
/// upstream response, before either reaches a client response header, an
/// `If-Range` comparison or an xattr.  Malformed values come back as `None`.
///
/// Both backends route through here so the accepted set is identical;
/// `on_invalid` receives each discarded value so the caller emits its
/// backend's warn line.
///
/// A value longer than [`MAX_VALIDATOR_LEN`] is discarded before it is
/// parsed: a kept validator is retained per cached file (metadata store,
/// xattr), which is sized for short values.
pub(crate) fn check_upstream_validators<S: AsRef<str>>(
    etag: Option<S>,
    last_modified: Option<S>,
    mut on_invalid: impl FnMut(InvalidValidator<'_>),
) -> (Option<S>, Option<S>) {
    let etag = etag.filter(|etag| {
        let etag = etag.as_ref();
        if etag.len() > MAX_VALIDATOR_LEN {
            on_invalid(InvalidValidator::Oversized {
                header: "ETag",
                len: etag.len(),
            });
            return false;
        }
        let valid = is_valid_etag(etag);
        if !valid {
            on_invalid(InvalidValidator::ETag(etag));
        }
        valid
    });
    let last_modified = last_modified.filter(|lm| {
        let lm = lm.as_ref();
        if lm.len() > MAX_VALIDATOR_LEN {
            on_invalid(InvalidValidator::Oversized {
                header: "Last-Modified",
                len: lm.len(),
            });
            return false;
        }
        let valid = is_valid_http_date(lm);
        if !valid {
            on_invalid(InvalidValidator::LastModified(lm));
        }
        valid
    });
    (etag, last_modified)
}

/// Process-local cache mapping `(mirror, debname, layout)` to the most
/// recently observed upstream metadata for the file.  Lookups return an
/// [`Arc`] so readers drop the map lock before inspecting fields.
pub(crate) struct CacheMetadataStore {
    inner: parking_lot::RwLock<Inner>,
}

/// The map and the mirrors its keys share.
struct Inner {
    map: HashMap<StoredKey, Arc<UpstreamMetadata>>,
    /// One copy of each mirror that at least one entry names, so a cache
    /// holding tens of thousands of files from a handful of mirrors stores
    /// each mirror's host and path once rather than per entry.  An entry's
    /// removal drops the copy its mirror no longer needs.
    mirrors: HashSet<Arc<Mirror>>,
}

/// The owned form of a key as the map stores it: the mirror shared through
/// [`Inner::mirrors`], the name boxed to its length.  A quarter the size of
/// `CacheEntryKey`, which matters because the table keeps every key inline
/// in a bucket, half of which are empty right after it doubles.
///
/// Hashes field by field like [`CacheEntryKeyRef`] (the `Arc` and the `Box`
/// hash as their contents), which is what lets the borrowed key look it up.
#[derive(Debug, Eq, Hash, PartialEq)]
struct StoredKey {
    mirror: Arc<Mirror>,
    debname: Box<str>,
    layout: CacheLayout,
}

impl Equivalent<StoredKey> for CacheEntryKeyRef<'_> {
    fn equivalent(&self, key: &StoredKey) -> bool {
        let &Self {
            mirror,
            debname,
            layout,
        } = self;
        let StoredKey {
            mirror: kmirror,
            debname: kdebname,
            layout: klayout,
        } = key;
        mirror == &**kmirror && debname == &**kdebname && layout == *klayout
    }
}

impl Inner {
    /// Clear the map once it is at its cap; call before inserting a key the
    /// map does not hold.
    fn make_room(&mut self) {
        if self.map.len() >= CACHE_METADATA_MAX_ENTRIES {
            log_metadata_cache_cleared();
            self.map.clear();
            self.mirrors.clear();
        }
    }

    /// Insert an entry for a key the map does not hold, sharing its mirror
    /// with the entries that already name it.
    fn insert(&mut self, key: &CacheEntryKeyRef<'_>, meta: Arc<UpstreamMetadata>) {
        let &CacheEntryKeyRef {
            mirror,
            debname,
            layout,
        } = key;
        let mirror = if let Some(shared) = self.mirrors.get(mirror) {
            Arc::clone(shared)
        } else {
            let shared = Arc::new(mirror.clone());
            self.mirrors.insert(Arc::clone(&shared));
            shared
        };
        let stored = StoredKey {
            mirror,
            debname: debname.into(),
            layout,
        };
        self.map.insert(stored, meta);
    }

    fn remove(&mut self, key: &CacheEntryKeyRef<'_>) {
        if let Some((stored, _meta)) = self.map.remove_entry(key) {
            // Two owners left, the set's and this key's: no other entry
            // names the mirror any more.
            if Arc::strong_count(&stored.mirror) == 2 {
                self.mirrors.remove(&*stored.mirror);
            }
        }
    }
}

/// Soft cap on cached entries, bounding memory for caches holding very
/// many distinct files (entries are a few hundred bytes each).  Values are
/// lazily re-loadable from the on-disk xattrs, so overflow simply clears
/// the map (no LRU) and subsequent serves re-populate it — same
/// best-effort approach as `verify_throttle` and `permitted_host_cache`.
///
/// Seven eighths of 2^16: the most a hashbrown table of 2^16 buckets
/// holds, so the table never doubles for a last eighth of entries and sits
/// half empty at the cap.
pub(crate) const CACHE_METADATA_MAX_ENTRIES: usize = 7 * (1 << 16) / 8;

/// The clear is silent otherwise: serves go back to two `fgetxattr(2)`
/// round-trips through `block_in_place` -- the cost this cache exists to
/// remove -- and on a cache larger than the cap that repeats indefinitely.
/// The dashboard only ever shows the post-clear count, which looks idle.
fn log_metadata_cache_cleared() {
    warn_once_or_info!(
        "Cache metadata store reached {CACHE_METADATA_MAX_ENTRIES} entries; clearing it (xattr reads resume until it refills)"
    );
}

impl std::fmt::Debug for CacheMetadataStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid dumping the entire map (could be large and mostly noise)
        // and avoid acquiring the lock so this is safe to call from any
        // context — e.g. `Result::expect(...)` at startup.
        f.debug_struct("CacheMetadataStore").finish_non_exhaustive()
    }
}

impl CacheMetadataStore {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            inner: parking_lot::RwLock::new(Inner {
                map: HashMap::new(),
                mirrors: HashSet::new(),
            }),
        }
    }

    /// Look up the cached metadata for a key; on miss, read xattrs from
    /// the supplied file and populate the entry.  The caller must already
    /// have an open `tokio::fs::File` for the cached path so the xattr
    /// lookups address the same inode the caller is serving from.
    ///
    /// The hot-path lookup is zero-clone — readers pass a
    /// [`CacheEntryKeyRef`] that borrows the caller's `Mirror` and
    /// `debname`, and we only materialise an owned [`StoredKey`] on the
    /// cold cache-miss insert.  The `block_in_place` round-trip happens
    /// only on miss; subsequent hits return an [`Arc`] clone with no
    /// syscalls.
    pub(crate) fn resolve(
        &self,
        key: &CacheEntryKeyRef<'_>,
        file: &tokio::fs::File,
        path: &Path,
    ) -> Arc<UpstreamMetadata> {
        if let Some(entry) = self.inner.read().map.get(key) {
            return Arc::clone(entry);
        }

        // Cold path: fetch from xattrs.  One blocking section for both
        // attributes — reading them through the `tokio::fs::File` target
        // would demote the worker once per attribute, the same reason
        // `write_upstream_metadata` batches its three writes.  Batching puts
        // the section *above* `try_read`'s own support check, so repeat that
        // check here: on a cache filesystem without xattrs the closure has
        // nothing to do, and entering it would cost a worker->blocking
        // transition (and a multi-thread runtime) per cold resolve.
        let (etag_res, last_modified_res) = if xattr_helpers::xattr_supported() {
            tokio::task::block_in_place(|| {
                let file = &xattr_helpers::XattrFile(file);
                (
                    xattr_helpers::try_read::<ETag>(file, path),
                    xattr_helpers::try_read::<LastModified>(file, path),
                )
            })
        } else {
            (Ok(None), Ok(None))
        };

        // If either read errors, surface a best-effort `Arc` containing
        // whichever fields succeeded for this request but do not insert —
        // see the "Negative caching and transient errors" module docs.
        let etag_res = etag_res.map(|o| o.map(|etag| Arc::from(etag.into_string())));
        let last_modified_res = last_modified_res.map(|o| {
            o.map(|lm| {
                let (raw, time) = lm.into_parts();
                (Arc::from(raw), time)
            })
        });
        let (etag, last_modified) = match (etag_res, last_modified_res) {
            (Ok(etag), Ok(last_modified)) => (etag, last_modified),
            (etag_res, last_modified_res) => {
                return Arc::new(UpstreamMetadata {
                    etag: etag_res.ok().flatten(),
                    last_modified: last_modified_res.ok().flatten(),
                });
            }
        };

        let meta = Arc::new(UpstreamMetadata {
            etag,
            last_modified,
        });

        // Re-check under the write lock: a concurrent `set` may have
        // published while we were reading xattrs, and what we read is then
        // older than it (see the module docs on why that is not a mismatch
        // worth reporting).
        let mut inner = self.inner.write();
        if let Some(published) = inner.map.get(key) {
            return Arc::clone(published);
        }
        inner.make_room();
        inner.insert(key, Arc::clone(&meta));
        meta
    }

    /// Replace the entry for `key` with `meta`.  Used by the rename
    /// barrier transition to publish post-flight metadata before clearing
    /// the active-downloads entry, and by volatile 304 [`revalidate`] to
    /// publish merged validators after writing them to the cached file's
    /// xattrs and before releasing the refreshed entry to waiting readers.
    ///
    /// **Publication invariant:** callers must have already persisted
    /// matching xattrs to the cached file before invoking this, so that
    /// a restart, which reads the file, serves what this published (see
    /// the module-level docs).
    pub(crate) fn set(&self, key: &CacheEntryKeyRef<'_>, meta: Arc<UpstreamMetadata>) {
        let mut inner = self.inner.write();
        if let Some(published) = inner.map.get_mut(key) {
            *published = meta;
        } else {
            inner.make_room();
            inner.insert(key, meta);
        }
    }

    /// Drop any cached entry for `key`.  Called from cleanup file
    /// removal and (in principle) from any other context where the on-
    /// disk file is going away.
    pub(crate) fn invalidate(&self, key: &CacheEntryKeyRef<'_>) {
        self.inner.write().remove(key);
    }

    /// Number of currently cached entries (the dashboard reads
    /// [`Self::footprint`]).
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.inner.read().map.len()
    }

    /// Entries and the heap they take: the table, each key's name, each
    /// value and its validator strings, and the shared mirrors. Walks the
    /// table under the read lock, which blocks no reader and holds writers
    /// (a commit, a cleanup unlink) for the few hundred microseconds a full
    /// table takes.
    pub(crate) fn footprint(&self) -> Footprint {
        let inner = self.inner.read();
        let entries: usize = inner
            .map
            .iter()
            .map(|(key, meta)| {
                let UpstreamMetadata {
                    etag,
                    last_modified,
                } = meta.as_ref();
                key.debname.len()
                    + ARC_HEADER
                    + size_of::<UpstreamMetadata>()
                    + etag.as_ref().map_or(0, |etag| ARC_HEADER + etag.len())
                    + last_modified
                        .as_ref()
                        .map_or(0, |(raw, _)| ARC_HEADER + raw.len())
            })
            .sum();
        let shared: usize = inner
            .mirrors
            .iter()
            .map(|mirror| ARC_HEADER + size_of::<Mirror>() + mirror.heap_bytes())
            .sum();
        Footprint {
            entries: inner.map.len(),
            bytes: inner.map.allocation_size() + inner.mirrors.allocation_size() + entries + shared,
        }
    }
}

mod store {
    //! Global handle to the singleton [`CacheMetadataStore`].  The pattern
    //! mirrors `database_task::DB_TASK_QUEUE_SENDER`: initialised once at
    //! startup, accessed via a typed getter that panics if uninitialised
    //! (which would be a logic bug — startup is required to call `init`).

    use std::sync::OnceLock;

    use super::CacheMetadataStore;

    static STORE: OnceLock<CacheMetadataStore> = OnceLock::new();

    /// Install the singleton store.  Returns `Err` (with the rejected
    /// new instance) if `init` was already called; mirrors
    /// `OnceLock::set` so callers can `.expect("...")` at startup like
    /// `database_task::DB_TASK_QUEUE_SENDER` does.
    pub(crate) fn init() -> Result<(), CacheMetadataStore> {
        STORE.set(CacheMetadataStore::new())
    }

    #[must_use]
    pub(crate) fn store() -> &'static CacheMetadataStore {
        STORE.get().expect(
            "cache_metadata::store called before init; main() must invoke cache_metadata::init",
        )
    }
}

pub(crate) use store::{init, store};

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tokio::fs::File;

    use super::*;
    use crate::cache_layout::CacheEntryKey;
    use crate::config::ClientHost;
    use crate::deb_mirror::MirrorKind;
    use crate::xattr_helpers::tests::supports_user_xattrs;

    fn write_etag(file: &File, path: &Path, etag: &str) {
        xattr_helpers::write(file, path, &ETag::parse(etag).expect("valid ETag"));
    }

    fn write_last_modified(file: &File, path: &Path, value: &str) {
        xattr_helpers::write(
            file,
            path,
            &LastModified::parse(value).expect("valid HTTP-date"),
        );
    }

    fn fixture_key() -> CacheEntryKey {
        CacheEntryKey {
            mirror: Mirror::new(
                ClientHost::new("example.test").unwrap(),
                std::num::NonZero::new(80),
                "/debian".into(),
                MirrorKind::Structured,
            ),
            debname: "test.deb".into(),
            layout: CacheLayout::StructuredPool,
        }
    }

    async fn fixture_file() -> (tempfile::TempDir, File, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("probe.deb");
        let file = File::create(&path).await.expect("create file");
        (dir, file, path)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn resolve_misses_then_caches() {
        let store = CacheMetadataStore::new();
        let (_dir, file, path) = fixture_file().await;
        if !supports_user_xattrs(&path) {
            return;
        }
        write_etag(&file, &path, "\"abc\"");
        write_last_modified(&file, &path, "Thu, 01 Jan 1970 00:00:00 GMT");

        let key = fixture_key();
        let first = store.resolve(&key.as_ref(), &file, &path);
        assert_eq!(first.etag.as_deref(), Some("\"abc\""));
        assert!(first.last_modified.is_some());
        assert_eq!(store.len(), 1);

        // Mutate the file's xattr to confirm the second resolve returns the
        // cached value, not a fresh disk read.
        write_etag(&file, &path, "\"xyz\"");
        let second = store.resolve(&key.as_ref(), &file, &path);
        assert_eq!(second.etag.as_deref(), Some("\"abc\""));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_upstream_metadata_persists_what_resolve_reads() {
        let store = CacheMetadataStore::new();
        let (_dir, file, path) = fixture_file().await;
        if !supports_user_xattrs(&path) {
            return;
        }
        let meta =
            UpstreamMetadata::from_upstream(Some("\"abc\""), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
        write_upstream_metadata(&file, &path, &meta, Some(4096), TargetFile::New);

        let resolved = store.resolve(&fixture_key().as_ref(), &file, &path);
        assert_eq!(
            resolved.as_ref(),
            &meta,
            "the published value is what was persisted"
        );
        assert_eq!(
            xattr_helpers::read::<ExpectedSize>(&file, &path),
            Some(ExpectedSize(4096))
        );
    }

    /// A resumed partial carries the xattrs of its first attempt; when the
    /// resuming response no longer sends a validator, the published metadata
    /// is `None` and the file must agree (publication invariant), or a
    /// restart resurrects the first attempt's value.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_upstream_metadata_removes_validators_the_download_lacks() {
        let (_dir, file, path) = fixture_file().await;
        if !supports_user_xattrs(&path) {
            return;
        }
        write_etag(&file, &path, "\"first\"");
        write_last_modified(&file, &path, "Thu, 01 Jan 1970 00:00:00 GMT");

        let meta = UpstreamMetadata::from_upstream(None, None);
        write_upstream_metadata(&file, &path, &meta, Some(4096), TargetFile::Resumed);

        assert!(
            xattr_helpers::read::<ETag>(&file, &path).is_none(),
            "the first attempt's ETag must not outlive a download without one"
        );
        assert!(
            xattr_helpers::read::<LastModified>(&file, &path).is_none(),
            "the first attempt's Last-Modified must not outlive a download without one"
        );
        assert_eq!(
            xattr_helpers::read::<ExpectedSize>(&file, &path),
            Some(ExpectedSize(4096))
        );
    }

    /// A file the download just created has no xattrs to remove, so the
    /// removals are skipped: a value planted anyway survives, which is how
    /// the skip shows.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_upstream_metadata_skips_removals_on_a_new_file() {
        let (_dir, file, path) = fixture_file().await;
        if !supports_user_xattrs(&path) {
            return;
        }
        write_etag(&file, &path, "\"planted\"");

        let meta = UpstreamMetadata::from_upstream(None, None);
        write_upstream_metadata(&file, &path, &meta, None, TargetFile::New);

        assert_eq!(
            xattr_helpers::read::<ETag>(&file, &path),
            ETag::parse("\"planted\""),
            "no removal is attempted on a new file"
        );
    }

    const STORED_ETAG: &str = "\"first\"";
    const STORED_LM: &str = "Thu, 01 Jan 2004 00:00:00 GMT";

    fn stored_validators() -> UpstreamMetadata {
        UpstreamMetadata::from_upstream(Some(STORED_ETAG), Some(STORED_LM))
    }

    /// A `206` answering the stored `ETag` as `If-Range` proves the first
    /// attempt's validators still hold: the ones it omits are inherited.
    #[test]
    fn inherit_resumed_fills_what_the_206_omits() {
        let stored = stored_validators();
        assert_eq!(
            UpstreamMetadata::from_upstream(None, None).inherit_resumed(Some(&stored)),
            stored,
            "a 206 without validators keeps both"
        );
        assert_eq!(
            UpstreamMetadata::from_upstream(Some(STORED_ETAG), None).inherit_resumed(Some(&stored)),
            stored,
            "a 206 echoing the ETag keeps the stored Last-Modified"
        );
        let own_lm = "Fri, 02 Jan 2004 00:00:00 GMT";
        assert_eq!(
            UpstreamMetadata::from_upstream(None, Some(own_lm)).inherit_resumed(Some(&stored)),
            UpstreamMetadata::from_upstream(Some(STORED_ETAG), Some(own_lm)),
            "a value the 206 carries wins; the ETag it omits is inherited"
        );
    }

    /// A `206` naming a different `ETag` does not vouch for the stored
    /// representation: its own tag stands and the stored date is not paired
    /// with it. Defense in depth: the planner already refuses such a `206`
    /// as `ResumeAnomaly::ETagMismatch`, so no production path gets here.
    #[test]
    fn inherit_resumed_keeps_the_stored_date_off_a_different_etag() {
        let stored = stored_validators();
        let other = UpstreamMetadata::from_upstream(Some("\"second\""), None);
        assert_eq!(other.clone().inherit_resumed(Some(&stored)), other);
    }

    /// Anything but a resumed download publishes the upstream's values as
    /// they are.
    #[test]
    fn inherit_resumed_without_a_resumed_partial_is_identity() {
        let upstream = UpstreamMetadata::from_upstream(None, Some(STORED_LM));
        assert_eq!(upstream.clone().inherit_resumed(None), upstream);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_upstream_metadata_without_size_leaves_no_expected_size() {
        let (_dir, file, path) = fixture_file().await;
        let meta = UpstreamMetadata::from_upstream(Some("\"abc\""), None);
        write_upstream_metadata(&file, &path, &meta, None, TargetFile::New);
        assert_eq!(xattr_helpers::read::<ExpectedSize>(&file, &path), None);
        assert!(xattr_helpers::read::<LastModified>(&file, &path).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn set_overwrites_existing_entry() {
        let store = CacheMetadataStore::new();
        let key = fixture_key();
        store.set(
            &key.as_ref(),
            Arc::new(UpstreamMetadata::from_upstream(Some("\"old\""), None)),
        );
        store.set(
            &key.as_ref(),
            Arc::new(UpstreamMetadata::from_upstream(Some("\"new\""), None)),
        );
        let (_dir, file, path) = fixture_file().await;
        let entry = store.resolve(&key.as_ref(), &file, &path);
        assert_eq!(entry.etag.as_deref(), Some("\"new\""));
    }

    /// `layout` is part of the key precisely so a flat-pool and a
    /// structured-pool file of the same name under the same mirror do not
    /// share one entry (see `CacheEntryKey`'s docs).
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn entries_of_the_same_debname_do_not_collide_across_layouts() {
        let store = CacheMetadataStore::new();
        let pool_key = fixture_key();
        let flat_key = CacheEntryKey {
            layout: CacheLayout::Flat,
            ..fixture_key()
        };
        store.set(
            &pool_key.as_ref(),
            Arc::new(UpstreamMetadata::from_upstream(Some("\"pool\""), None)),
        );
        store.set(
            &flat_key.as_ref(),
            Arc::new(UpstreamMetadata::from_upstream(Some("\"flat\""), None)),
        );
        assert_eq!(store.len(), 2, "the layout discriminates the two entries");

        let (_dir, file, path) = fixture_file().await;
        assert_eq!(
            store
                .resolve(&pool_key.as_ref(), &file, &path)
                .etag
                .as_deref(),
            Some("\"pool\"")
        );
        assert_eq!(
            store
                .resolve(&flat_key.as_ref(), &file, &path)
                .etag
                .as_deref(),
            Some("\"flat\"")
        );

        store.invalidate(&flat_key.as_ref());
        assert_eq!(
            store
                .resolve(&pool_key.as_ref(), &file, &path)
                .etag
                .as_deref(),
            Some("\"pool\""),
            "invalidating one layout leaves the other entry alone"
        );
    }

    /// The `Equivalent` bridge: a borrowed key must hash and compare to the
    /// stored key its own cold path materialised, or every hot-path lookup
    /// would miss and re-read the xattrs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_borrowed_key_finds_the_entry_it_populated() {
        let store = CacheMetadataStore::new();
        let (_dir, file, path) = fixture_file().await;
        let key = fixture_key();

        let cold = store.resolve(&key.as_ref(), &file, &path);
        assert_eq!(store.len(), 1, "the cold path materialises the stored key");

        let hot = Arc::clone(
            store
                .inner
                .read()
                .map
                .get(&key.as_ref())
                .expect("the borrowed key finds the entry"),
        );
        assert!(
            Arc::ptr_eq(&cold, &hot),
            "the lookup must hit the entry the cold path inserted"
        );
        assert_eq!(store.len(), 1);
    }

    /// Entries of one mirror share a single copy of it, which the last of
    /// them to go takes along; a cap clear drops every copy.
    #[test]
    fn entries_share_their_mirror_until_the_last_one_goes() {
        let store = CacheMetadataStore::new();
        let meta = Arc::new(UpstreamMetadata::default());
        let first = fixture_key();
        let second = CacheEntryKey {
            debname: "other.deb".into(),
            ..fixture_key()
        };
        let elsewhere = CacheEntryKey {
            mirror: Mirror::new(
                ClientHost::new("other.test").unwrap(),
                None,
                "/debian".into(),
                MirrorKind::Structured,
            ),
            ..fixture_key()
        };
        store.set(&first.as_ref(), Arc::clone(&meta));
        store.set(&second.as_ref(), Arc::clone(&meta));
        store.set(&elsewhere.as_ref(), Arc::clone(&meta));

        {
            let inner = store.inner.read();
            assert_eq!(inner.mirrors.len(), 2, "one copy per distinct mirror");
            let shared = inner
                .mirrors
                .get(&first.mirror)
                .expect("the mirror is interned");
            assert_eq!(
                Arc::strong_count(shared),
                3,
                "the set and the two entries own the copy"
            );
            for (stored, _) in &inner.map {
                if *stored.mirror == first.mirror {
                    assert!(Arc::ptr_eq(&stored.mirror, shared));
                }
            }
        }

        store.invalidate(&first.as_ref());
        assert_eq!(
            store.inner.read().mirrors.len(),
            2,
            "a mirror with an entry left stays"
        );
        store.invalidate(&second.as_ref());
        assert_eq!(
            store.inner.read().mirrors.len(),
            1,
            "a mirror's last entry takes the copy along"
        );

        for n in 0..CACHE_METADATA_MAX_ENTRIES {
            let key = CacheEntryKey {
                debname: format!("fill-{n}.deb"),
                ..fixture_key()
            };
            store.set(&key.as_ref(), Arc::clone(&meta));
        }
        assert_eq!(
            store.len(),
            1,
            "the insert past the cap clears the map and holds only itself"
        );
        assert_eq!(
            store.inner.read().mirrors.len(),
            1,
            "the clear drops the mirrors of the cleared entries"
        );
    }

    #[test]
    fn invalidate_drops_entry() {
        let store = CacheMetadataStore::new();
        let key = fixture_key();
        store.set(
            &key.as_ref(),
            Arc::new(UpstreamMetadata::from_upstream(Some("\"abc\""), None)),
        );
        assert_eq!(store.len(), 1);
        store.invalidate(&key.as_ref());
        assert_eq!(store.len(), 0);
    }

    /// Invalidation is the only way back to the file as source of truth: a
    /// published entry shadows the xattrs until it is dropped, which is what
    /// every site that replaces a cached file without calling
    /// [`CacheMetadataStore::set`] has to rely on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn invalidate_makes_resolve_re_read_the_xattrs() {
        let store = CacheMetadataStore::new();
        let (_dir, file, path) = fixture_file().await;
        if !supports_user_xattrs(&path) {
            return;
        }
        write_etag(&file, &path, "\"on-disk\"");
        let key = fixture_key();

        store.set(
            &key.as_ref(),
            Arc::new(UpstreamMetadata::from_upstream(Some("\"published\""), None)),
        );
        assert_eq!(
            store.resolve(&key.as_ref(), &file, &path).etag.as_deref(),
            Some("\"published\""),
            "a published entry shadows the file's own xattrs"
        );

        store.invalidate(&key.as_ref());
        let reread = store.resolve(&key.as_ref(), &file, &path);
        assert_eq!(
            reread.etag.as_deref(),
            Some("\"on-disk\""),
            "after invalidation the cold path re-reads the file"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn negative_caching_for_absent_xattrs() {
        let store = CacheMetadataStore::new();
        let (_dir, file, path) = fixture_file().await;
        let key = fixture_key();
        let entry = store.resolve(&key.as_ref(), &file, &path);
        assert!(entry.etag.is_none());
        assert!(entry.last_modified.is_none());
        // Second call still hits the cache.
        assert_eq!(store.len(), 1);
        let again = store.resolve(&key.as_ref(), &file, &path);
        assert!(Arc::ptr_eq(&entry, &again), "the negative entry is reused");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn from_upstream_parses_last_modified() {
        let m =
            UpstreamMetadata::from_upstream(Some("\"abc\""), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
        assert_eq!(m.etag.as_deref(), Some("\"abc\""));
        let (s, _date) = m.last_modified.expect("parsed");
        assert_eq!(&*s, "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn from_upstream_drops_malformed_etag() {
        let m = UpstreamMetadata::from_upstream(
            Some("not-an-etag"),
            Some("Thu, 01 Jan 1970 00:00:00 GMT"),
        );
        assert!(m.etag.is_none());
        let (s, _date) = m.last_modified.expect("valid Last-Modified is retained");
        assert_eq!(&*s, "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn from_upstream_drops_malformed_last_modified() {
        let m = UpstreamMetadata::from_upstream(None, Some("not a date"));
        assert!(m.last_modified.is_none());
    }

    #[test]
    fn check_upstream_validators_keeps_well_formed_values() {
        let mut calls = 0;
        let (etag, lm) = check_upstream_validators(
            Some("W/\"abc\""),
            Some("Thu, 01 Jan 1970 00:00:00 GMT"),
            |_invalid| calls += 1,
        );
        assert_eq!(etag.as_deref(), Some("W/\"abc\""));
        assert_eq!(lm.as_deref(), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
        assert_eq!(calls, 0);
    }

    #[test]
    fn check_upstream_validators_passes_absent_values_silently() {
        let mut calls = 0;
        let (etag, lm) = check_upstream_validators::<&str>(None, None, |_invalid| calls += 1);
        assert_eq!(etag, None);
        assert_eq!(lm, None);
        assert_eq!(calls, 0);
    }

    #[test]
    fn check_upstream_validators_discards_malformed_etag() {
        let mut expected = [InvalidValidator::ETag("not-an-etag")].into_iter();
        let (etag, lm) = check_upstream_validators(
            Some("not-an-etag"),
            Some("Thu, 01 Jan 1970 00:00:00 GMT"),
            |invalid| assert_eq!(Some(invalid), expected.next()),
        );
        assert_eq!(etag, None);
        assert_eq!(lm.as_deref(), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
        assert_eq!(expected.next(), None);
    }

    #[test]
    fn check_upstream_validators_discards_malformed_last_modified() {
        let mut expected = [InvalidValidator::LastModified("not a date")].into_iter();
        let (etag, lm) =
            check_upstream_validators(Some("\"abc\""), Some("not a date"), |invalid| {
                assert_eq!(Some(invalid), expected.next())
            });
        assert_eq!(etag.as_deref(), Some("\"abc\""));
        assert_eq!(lm, None);
        assert_eq!(expected.next(), None);
    }

    #[test]
    fn check_upstream_validators_discards_oversized_values_by_length() {
        // Well-formed apart from their length: an upstream head may carry
        // ~400 KiB through the hyper client, and a kept value is retained
        // per cached file.
        let etag = format!("\"{}\"", "a".repeat(MAX_VALIDATOR_LEN - 1));
        let lm = format!(
            "Thu, 01 Jan 1970 00:00:00 GMT{}",
            " ".repeat(MAX_VALIDATOR_LEN)
        );
        let mut expected = [
            InvalidValidator::Oversized {
                header: "ETag",
                len: etag.len(),
            },
            InvalidValidator::Oversized {
                header: "Last-Modified",
                len: lm.len(),
            },
        ]
        .into_iter();
        let (kept_etag, kept_lm) = check_upstream_validators(Some(etag), Some(lm), |invalid| {
            assert_eq!(Some(invalid), expected.next());
        });
        assert_eq!(kept_etag, None);
        assert_eq!(kept_lm, None);
        assert_eq!(expected.next(), None);

        let at_cap = format!("\"{}\"", "a".repeat(MAX_VALIDATOR_LEN - 2));
        let mut calls = 0;
        let (kept_etag, _) =
            check_upstream_validators(Some(at_cap.clone()), None, |_invalid| calls += 1);
        assert_eq!(kept_etag, Some(at_cap));
        assert_eq!(calls, 0);
    }

    #[test]
    fn check_upstream_validators_reports_both_malformed_values() {
        let mut expected = [
            InvalidValidator::ETag("bad"),
            InvalidValidator::LastModified("worse"),
        ]
        .into_iter();
        let (etag, lm) = check_upstream_validators(Some("bad"), Some("worse"), |invalid| {
            assert_eq!(Some(invalid), expected.next());
        });
        assert_eq!(etag, None);
        assert_eq!(lm, None);
        assert_eq!(expected.next(), None);
    }
}
