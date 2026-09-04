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
//! survive process restarts.
//!
//! # Publication invariant
//!
//! `resolve`'s cold path releases the read lock before reading xattrs and
//! re-acquires the write lock to insert.  A concurrent
//! [`CacheMetadataStore::set`] can win that race and publish a fresher
//! value before resolve's insert runs.  To keep resolve from clobbering
//! the published value, every caller of [`CacheMetadataStore::set`]
//! **must** persist matching xattrs to the cached file *before* invoking
//! `set`.  With that invariant, the value
//! the racing `resolve` reads from xattrs equals the value `set`
//! published, so the two writers race to insert equivalent `Arc`s.
//!
//! Resolve's insert re-checks the entry under the write lock: if `set`
//! got there first, it returns the published `Arc` and `debug_assert!`s
//! it matches what we just read from xattrs.  If the assertion ever
//! fires, a caller of `set` published metadata without first writing
//! matching xattrs — fix that caller, not the assertion.
//!
//! The assertion is skipped when the xattr read produced `(None, None)`:
//! `xattr_helpers::write` is best-effort and silently swallows
//! `ErrorKind::Unsupported`, so on filesystems without xattr support a
//! caller's xattr write is a no-op and the racing `resolve` legitimately
//! reads `(None, None)` while `set` publishes `Some(...)`.  The publisher's
//! value still wins; we just don't crash debug builds in that environment.
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

use std::{hash::Hash, path::Path, sync::Arc};

use hashbrown::{Equivalent, HashMap, hash_map::Entry};

use crate::{
    cache_layout::{CacheEntryKey, CacheEntryKeyRef},
    http_etag::{ETag, is_valid_etag},
    http_last_modified::{LastModified, is_valid_http_date},
    http_range::HttpDate,
    warn_once, warn_once_or_info,
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
    pub(crate) fn from_upstream(etag: Option<String>, last_modified: Option<String>) -> Self {
        let last_modified =
            last_modified.and_then(|s| HttpDate::parse(&s).map(|t| (Arc::from(s), t)));
        Self {
            etag: etag.map(Arc::from),
            last_modified,
        }
    }
}

/// Persist a download's upstream metadata on its cache file: the `ETag` and
/// `Last-Modified` validators from `meta`, plus the expected total size when
/// the upstream announced one (so a resume can detect an upstream change).
/// Written early, on the partial/temp file, so the values survive an
/// interrupted download for resume; every backend calls this on the very
/// [`UpstreamMetadata`] it hands the download barrier, which is what keeps
/// the publication invariant (module docs) trivially true.
///
/// `meta`'s strings were validated once per upstream response by
/// [`check_upstream_validators`], so the re-parse here cannot fail; the
/// skip arm is the defensive fallback for a caller that bypassed it.
pub(crate) fn write_upstream_metadata(
    file: &tokio::fs::File,
    display_path: &Path,
    meta: &UpstreamMetadata,
    expected_size: Option<u64>,
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
        if let Some(etag) = etag {
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
        if let Some((raw, _time)) = last_modified {
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
}

/// Validate the raw upstream `ETag`/`Last-Modified` header values once per
/// upstream response, before either reaches a client response header, an
/// `If-Range` comparison or an xattr.  Malformed values come back as `None`.
///
/// Both backends route through here so the accepted set is identical;
/// `on_invalid` receives each discarded value so the caller emits its
/// backend's warn line.
pub(crate) fn check_upstream_validators(
    etag: Option<String>,
    last_modified: Option<String>,
    mut on_invalid: impl FnMut(InvalidValidator<'_>),
) -> (Option<String>, Option<String>) {
    let etag = etag.filter(|etag| {
        let valid = is_valid_etag(etag);
        if !valid {
            on_invalid(InvalidValidator::ETag(etag));
        }
        valid
    });
    let last_modified = last_modified.filter(|lm| {
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
    map: parking_lot::RwLock<HashMap<CacheEntryKey, Arc<UpstreamMetadata>>>,
}

/// Soft cap on cached entries, bounding memory for caches holding very
/// many distinct files (entries are a few hundred bytes each).  Values are
/// lazily re-loadable from the on-disk xattrs, so overflow simply clears
/// the map (no LRU) and subsequent serves re-populate it — same
/// best-effort approach as `verify_throttle` and `permitted_host_cache`.
const CACHE_METADATA_MAX_ENTRIES: usize = 64 * 1024;

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
            map: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Look up the cached metadata for a key; on miss, read xattrs from
    /// the supplied file and populate the entry.  The caller must already
    /// have an open `tokio::fs::File` for the cached path so the xattr
    /// lookups address the same inode the caller is serving from.
    ///
    /// The hot-path lookup is zero-clone — readers pass a
    /// [`CacheEntryKeyRef`] that borrows the caller's `Mirror` and
    /// `debname`, and we only materialise an owned [`CacheEntryKey`]
    /// on the cold cache-miss insert.  The `block_in_place` round-trip
    /// happens only on miss; subsequent hits return an [`Arc`] clone with
    /// no syscalls.
    pub(crate) fn resolve<K>(
        &self,
        key: &K,
        file: &tokio::fs::File,
        path: &Path,
    ) -> Arc<UpstreamMetadata>
    where
        K: Hash + Equivalent<CacheEntryKey> + ?Sized,
        Self: ResolveOwn<K>,
    {
        if let Some(entry) = self.map.read().get(key) {
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
        // published a value while we were reading xattrs.  Per the
        // publication invariant (see module docs), that value must
        // equal what we just read; the debug_assert catches violations.
        // In release we trust the publisher's value.
        //
        // Exception: if our xattr read produced `(None, None)`, treat it
        // as "xattrs unavailable on this FS" (`xattr_helpers::write` is
        // best-effort and silently swallows `ErrorKind::Unsupported`), trust
        // the publisher, and skip the assert.  Asserting here would fire
        // spuriously on filesystems without xattr support.
        let owned = <Self as ResolveOwn<K>>::own(key);
        let mut map = self.map.write();
        if map.len() >= CACHE_METADATA_MAX_ENTRIES && !map.contains_key(&owned) {
            log_metadata_cache_cleared();
            map.clear();
        }
        match map.entry(owned) {
            Entry::Occupied(occ) => {
                let disagrees = !(meta.etag.is_none() && meta.last_modified.is_none())
                    && occ.get().as_ref() != meta.as_ref();
                debug_assert!(
                    !disagrees,
                    "publication invariant violated: a concurrent `set` published \
                     metadata that disagrees with the on-disk xattrs; every caller \
                     of `set` must persist matching xattrs first (published={:?}, \
                     read={:?})",
                    occ.get().as_ref(),
                    meta.as_ref(),
                );
                if disagrees {
                    // Release builds accept the published value, so clients
                    // can be served validators that permanently disagree with
                    // the file's xattrs -- conditional requests then behave
                    // differently before and after a restart.
                    warn_once!(
                        "Cache metadata publication invariant violated for `{}`: published {:?} disagrees with the on-disk xattrs {:?}; keeping the published value",
                        path.display(),
                        occ.get().as_ref(),
                        meta.as_ref()
                    );
                }
                Arc::clone(occ.get())
            }
            Entry::Vacant(vac) => {
                vac.insert(Arc::clone(&meta));
                meta
            }
        }
    }

    /// Replace the entry for `key` with `meta`.  Used by the rename
    /// barrier transition to publish post-flight metadata before clearing
    /// the active-downloads entry.  The volatile-revalidation 304 path
    /// does **not** call this — the cached file's xattrs are unchanged
    /// across the revalidation, so a subsequent [`Self::resolve`] lazy-
    /// loads the same values directly from xattr.
    ///
    /// **Publication invariant:** callers must have already persisted
    /// matching xattrs to the cached file before invoking this.  See
    /// the module-level docs for the rationale (a concurrent cold-path
    /// [`Self::resolve`] reads xattrs after releasing its read lock and
    /// would otherwise clobber the published value with the stale xattr
    /// read).
    pub(crate) fn set(&self, key: CacheEntryKey, meta: Arc<UpstreamMetadata>) {
        let mut map = self.map.write();
        if map.len() >= CACHE_METADATA_MAX_ENTRIES && !map.contains_key(&key) {
            log_metadata_cache_cleared();
            map.clear();
        }
        map.insert(key, meta);
    }

    /// Drop any cached entry for `key`.  Called from cleanup file
    /// removal and (in principle) from any other context where the on-
    /// disk file is going away.  Accepts borrowed keys via the same
    /// [`Equivalent`] mechanism as `resolve`, so callers don't need to
    /// clone `Mirror` and `debname` to invalidate.
    pub(crate) fn invalidate<K>(&self, key: &K)
    where
        K: Hash + Equivalent<CacheEntryKey> + ?Sized,
    {
        self.map.write().remove(key);
    }

    /// Number of currently cached entries.  Used by tests and by the web
    /// interface "Daemon Status" row that surfaces in-memory cache size.
    pub(crate) fn len(&self) -> usize {
        self.map.read().len()
    }
}

/// Helper trait used by [`CacheMetadataStore::resolve`] to materialise an
/// owned [`CacheEntryKey`] on the cold cache-miss insert.  Implemented
/// for both the borrowed [`CacheEntryKeyRef`] (hot-path callers) and
/// the owned [`CacheEntryKey`] (test/cold callers).
pub(crate) trait ResolveOwn<K: ?Sized> {
    fn own(key: &K) -> CacheEntryKey;
}

impl ResolveOwn<CacheEntryKey> for CacheMetadataStore {
    #[inline]
    fn own(key: &CacheEntryKey) -> CacheEntryKey {
        key.clone()
    }
}

impl ResolveOwn<CacheEntryKeyRef<'_>> for CacheMetadataStore {
    #[inline]
    fn own(key: &CacheEntryKeyRef<'_>) -> CacheEntryKey {
        (*key).to_owned()
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
    use crate::cache_layout::CacheLayout;
    use crate::deb_mirror::{Mirror, MirrorKind};

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
        use crate::config::ClientHost;
        CacheEntryKey {
            mirror: Mirror::new(
                ClientHost::new(String::from("example.test")).unwrap(),
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
        write_etag(&file, &path, "\"abc\"");
        write_last_modified(&file, &path, "Thu, 01 Jan 1970 00:00:00 GMT");

        let key = fixture_key();
        let first = store.resolve(&key, &file, &path);
        // Skip entirely on filesystems that reject xattr writes (the prior
        // `write_etag` would have silently been a no-op).
        if first.etag.is_none() && first.last_modified.is_none() {
            return;
        }
        assert_eq!(first.etag.as_deref(), Some("\"abc\""));
        assert!(first.last_modified.is_some());
        assert_eq!(store.len(), 1);

        // Mutate the file's xattr to confirm the second resolve returns the
        // cached value, not a fresh disk read.
        write_etag(&file, &path, "\"xyz\"");
        let second = store.resolve(&key, &file, &path);
        assert_eq!(second.etag.as_deref(), Some("\"abc\""));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_upstream_metadata_persists_what_resolve_reads() {
        let store = CacheMetadataStore::new();
        let (_dir, file, path) = fixture_file().await;
        let meta = UpstreamMetadata::from_upstream(
            Some("\"abc\"".into()),
            Some("Thu, 01 Jan 1970 00:00:00 GMT".into()),
        );
        write_upstream_metadata(&file, &path, &meta, Some(4096));

        let resolved = store.resolve(&fixture_key(), &file, &path);
        // Skip on filesystems that reject xattr writes.
        if resolved.etag.is_none() && resolved.last_modified.is_none() {
            return;
        }
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_upstream_metadata_without_size_leaves_no_expected_size() {
        let (_dir, file, path) = fixture_file().await;
        let meta = UpstreamMetadata::from_upstream(Some("\"abc\"".into()), None);
        write_upstream_metadata(&file, &path, &meta, None);
        assert_eq!(xattr_helpers::read::<ExpectedSize>(&file, &path), None);
        assert!(xattr_helpers::read::<LastModified>(&file, &path).is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn set_overwrites_existing_entry() {
        let store = CacheMetadataStore::new();
        let key = fixture_key();
        store.set(
            key.clone(),
            Arc::new(UpstreamMetadata::from_upstream(
                Some("\"old\"".into()),
                None,
            )),
        );
        store.set(
            key.clone(),
            Arc::new(UpstreamMetadata::from_upstream(
                Some("\"new\"".into()),
                None,
            )),
        );
        let (_dir, file, path) = fixture_file().await;
        let entry = store.resolve(&key, &file, &path);
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
            pool_key.clone(),
            Arc::new(UpstreamMetadata::from_upstream(
                Some("\"pool\"".into()),
                None,
            )),
        );
        store.set(
            flat_key.clone(),
            Arc::new(UpstreamMetadata::from_upstream(
                Some("\"flat\"".into()),
                None,
            )),
        );
        assert_eq!(store.len(), 2, "the layout discriminates the two entries");

        let (_dir, file, path) = fixture_file().await;
        assert_eq!(
            store.resolve(&pool_key, &file, &path).etag.as_deref(),
            Some("\"pool\"")
        );
        assert_eq!(
            store.resolve(&flat_key, &file, &path).etag.as_deref(),
            Some("\"flat\"")
        );

        store.invalidate(&flat_key);
        assert_eq!(
            store.resolve(&pool_key, &file, &path).etag.as_deref(),
            Some("\"pool\""),
            "invalidating one layout leaves the other entry alone"
        );
    }

    /// The `Equivalent` bridge: a borrowed key must hash and compare to the
    /// owned key its own cold path materialised, or every hot-path lookup
    /// would miss and re-read the xattrs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn a_borrowed_key_populates_the_entry_an_owned_key_finds() {
        let store = CacheMetadataStore::new();
        let (_dir, file, path) = fixture_file().await;
        let key = fixture_key();

        let via_ref = store.resolve(&key.as_ref(), &file, &path);
        assert_eq!(store.len(), 1, "the cold path materialises the owned key");

        let via_owned = store.resolve(&key, &file, &path);
        assert!(
            Arc::ptr_eq(&via_ref, &via_owned),
            "the owned key must hit the entry the borrowed key inserted"
        );
        assert_eq!(store.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn invalidate_drops_entry() {
        let store = CacheMetadataStore::new();
        let key = fixture_key();
        store.set(
            key.clone(),
            Arc::new(UpstreamMetadata::from_upstream(
                Some("\"abc\"".into()),
                None,
            )),
        );
        assert_eq!(store.len(), 1);
        store.invalidate(&key);
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
        write_etag(&file, &path, "\"on-disk\"");
        let key = fixture_key();

        store.set(
            key.clone(),
            Arc::new(UpstreamMetadata::from_upstream(
                Some("\"published\"".into()),
                None,
            )),
        );
        assert_eq!(
            store.resolve(&key, &file, &path).etag.as_deref(),
            Some("\"published\""),
            "a published entry shadows the file's own xattrs"
        );

        store.invalidate(&key);
        let reread = store.resolve(&key, &file, &path);
        // Skip on filesystems that reject xattr writes (`write_etag` was a
        // silent no-op there).
        if reread.etag.is_none() {
            return;
        }
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
        let entry = store.resolve(&key, &file, &path);
        assert!(entry.etag.is_none());
        assert!(entry.last_modified.is_none());
        // Second call still hits the cache.
        assert_eq!(store.len(), 1);
        let _again = store.resolve(&key, &file, &path);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn from_upstream_parses_last_modified() {
        let m = UpstreamMetadata::from_upstream(
            Some("\"abc\"".into()),
            Some("Thu, 01 Jan 1970 00:00:00 GMT".into()),
        );
        assert_eq!(m.etag.as_deref(), Some("\"abc\""));
        let (s, _date) = m.last_modified.expect("parsed");
        assert_eq!(&*s, "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn from_upstream_drops_malformed_last_modified() {
        let m = UpstreamMetadata::from_upstream(None, Some("not a date".into()));
        assert!(m.last_modified.is_none());
    }

    #[test]
    fn check_upstream_validators_keeps_well_formed_values() {
        let mut rejected = Vec::new();
        let (etag, lm) = check_upstream_validators(
            Some("W/\"abc\"".into()),
            Some("Thu, 01 Jan 1970 00:00:00 GMT".into()),
            |invalid| rejected.push(format!("{invalid:?}")),
        );
        assert_eq!(etag.as_deref(), Some("W/\"abc\""));
        assert_eq!(lm.as_deref(), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
        assert_eq!(rejected, Vec::<String>::new());
    }

    #[test]
    fn check_upstream_validators_passes_absent_values_silently() {
        let mut calls = 0;
        let (etag, lm) = check_upstream_validators(None, None, |_invalid| calls += 1);
        assert_eq!(etag, None);
        assert_eq!(lm, None);
        assert_eq!(calls, 0);
    }

    #[test]
    fn check_upstream_validators_discards_malformed_etag() {
        let mut rejected = Vec::new();
        let (etag, lm) = check_upstream_validators(
            Some("not-an-etag".into()),
            Some("Thu, 01 Jan 1970 00:00:00 GMT".into()),
            |invalid| rejected.push(format!("{invalid:?}")),
        );
        assert_eq!(etag, None);
        assert_eq!(lm.as_deref(), Some("Thu, 01 Jan 1970 00:00:00 GMT"));
        assert_eq!(rejected, vec!["ETag(\"not-an-etag\")".to_owned()]);
    }

    #[test]
    fn check_upstream_validators_discards_malformed_last_modified() {
        let mut rejected = Vec::new();
        let (etag, lm) = check_upstream_validators(
            Some("\"abc\"".into()),
            Some("not a date".into()),
            |invalid| rejected.push(format!("{invalid:?}")),
        );
        assert_eq!(etag.as_deref(), Some("\"abc\""));
        assert_eq!(lm, None);
        assert_eq!(rejected, vec!["LastModified(\"not a date\")".to_owned()]);
    }

    #[test]
    fn check_upstream_validators_reports_both_malformed_values() {
        let mut rejected = Vec::new();
        let (etag, lm) =
            check_upstream_validators(Some("bad".into()), Some("worse".into()), |invalid| {
                rejected.push(format!("{invalid:?}"));
            });
        assert_eq!(etag, None);
        assert_eq!(lm, None);
        assert_eq!(
            rejected,
            vec![
                "ETag(\"bad\")".to_owned(),
                "LastModified(\"worse\")".to_owned()
            ]
        );
    }
}
