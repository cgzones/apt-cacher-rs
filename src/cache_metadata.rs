//! Process-local cache for cached-file metadata (`ETag`, Last-Modified).
//!
//! See `dev/baselines/2026-05-08-e64d9328.summary.txt` for the profiling
//! finding that motivated this: every cache-hit conditional-request path
//! issues two `fgetxattr(2)` syscalls (one for the `ETag` xattr, one for
//! Last-Modified), and the rustix bounds-check inside the xattr crate
//! showed up at ~0.5 % of worker samples plus drove `block_in_place` and
//! `spawn_blocking_inner` mutex traffic. Caching the parsed values per
//! `(mirror, debname)` lets repeat hits skip the syscalls entirely.
//!
//! # Source-of-truth split
//!
//! - **In-flight downloads** carry their etag/last-modified on
//!   [`crate::ActiveDownloadStatus::Download`] and on `Finished { meta:
//!   Some(_) }`; late-joiners read those directly. `Finished { meta:
//!   None }` (volatile-304 in `InitBarrier::finished`, error fallback
//!   in `RenameBarrier::release`) falls through to
//!   [`CacheMetadataStore::resolve`].
//! - **Post-flight (rename complete, active-downloads entry removed)** is
//!   what this cache covers. The transition from in-flight to post-flight
//!   happens inside `RenameBarrier::release`, which calls
//!   [`CacheMetadataStore::set`] (via `cache_metadata::store().set(...)`)
//!   *before* removing the active-downloads entry — so a worker that
//!   misses the entry always finds the cache populated.
//!
//! The xattrs on the cached file remain the persistent source of truth.
//! This cache is empty at boot; the first read for each file falls back
//! to the xattr helpers and inserts the result. xattr writes still happen
//! on the download path (see `xattr_helpers::write_*`) so the values
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
//! `xattr_helpers::write_helper` is best-effort and silently swallows
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
    cache_layout::CacheLayout, deb_mirror::Mirror, http_etag::try_read_etag,
    http_last_modified::try_read_last_modified, http_range::HttpDate,
};

/// Upstream-supplied metadata for a single cached file.  Used both as the
/// in-flight value carried on [`crate::ActiveDownloadStatus::Download`] and
/// as the post-flight cache entry.
///
/// `last_modified` stores both the raw header string (for `Last-Modified`
/// response headers) and its parsed [`HttpDate`] (for If-Modified-Since
/// comparison) so consumers don't re-parse on every hit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UpstreamMetadata {
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<(String, HttpDate)>,
}

impl UpstreamMetadata {
    /// Build from raw upstream header strings.  The Last-Modified pair is
    /// produced only if the value parses as a valid HTTP-date.
    #[must_use]
    pub(crate) fn from_upstream(etag: Option<String>, last_modified: Option<String>) -> Self {
        let last_modified = last_modified.and_then(|s| HttpDate::parse(&s).map(|t| (s, t)));
        Self {
            etag,
            last_modified,
        }
    }
}

/// A wrapper around [`UpstreamMetadata`] that supports borrowed, owned, and
/// shared references.
pub(crate) enum UpstreamMetadataView<'a> {
    Borrowed(&'a UpstreamMetadata),
    Arc(Arc<UpstreamMetadata>),
}

impl std::ops::Deref for UpstreamMetadataView<'_> {
    type Target = UpstreamMetadata;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(meta) => meta,
            Self::Arc(meta) => meta,
        }
    }
}

/// Cache key.  Mirrors the keying used by `active_downloads.rs` so the
/// in-flight and post-flight stores look up the same logical resource;
/// see that module's `ActiveDownloadKey` doc for the rationale behind
/// keeping both [`Mirror::kind`] (coarse structured-vs-flat) and
/// `layout` (fine-grained subtree) in the key.  Disambiguation between
/// flat-pool `.deb`s nested under different sub-directories
/// (`apt/amd64/foo.deb` vs `apt/arm64/foo.deb`) is implicit in
/// [`Mirror::path`], since the URL path becomes the mirror path
/// verbatim under the host-anchored flat layout.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CacheMetadataKey {
    pub(crate) mirror: Mirror,
    pub(crate) debname: String,
    pub(crate) layout: CacheLayout,
}

impl CacheMetadataKey {
    #[must_use]
    pub(crate) fn new(mirror: Mirror, debname: String, layout: CacheLayout) -> Self {
        Self {
            mirror,
            debname,
            layout,
        }
    }
}

/// Borrow-only counterpart to [`CacheMetadataKey`].  Used as a lookup key
/// on the hot-path `resolve` to avoid cloning `Mirror` and `debname` on
/// every cache hit; mirrors the `ActiveDownloadKeyRef` pattern in
/// `active_downloads.rs`.
#[derive(Hash)]
pub(crate) struct CacheMetadataKeyRef<'a> {
    pub(crate) mirror: &'a Mirror,
    pub(crate) debname: &'a str,
    pub(crate) layout: CacheLayout,
}

impl<'a> CacheMetadataKeyRef<'a> {
    #[must_use]
    pub(crate) fn new(mirror: &'a Mirror, debname: &'a str, layout: CacheLayout) -> Self {
        Self {
            mirror,
            debname,
            layout,
        }
    }

    /// Materialise an owned [`CacheMetadataKey`] (used on the cold-path
    /// insert when a resolve misses).
    #[must_use]
    fn to_owned(&self) -> CacheMetadataKey {
        CacheMetadataKey {
            mirror: self.mirror.clone(),
            debname: self.debname.to_owned(),
            layout: self.layout,
        }
    }
}

impl Equivalent<CacheMetadataKey> for CacheMetadataKeyRef<'_> {
    fn equivalent(&self, key: &CacheMetadataKey) -> bool {
        let &Self {
            mirror,
            debname,
            layout,
        } = self;
        let CacheMetadataKey {
            mirror: kmirror,
            debname: kdebname,
            layout: klayout,
        } = key;
        mirror == kmirror && debname == kdebname && layout == *klayout
    }
}

/// Process-local cache mapping `(mirror, debname)` to the most recently
/// observed upstream metadata for the file.  Lookups return an [`Arc`] so
/// readers drop the map lock before inspecting fields.
pub(crate) struct CacheMetadataStore {
    map: parking_lot::RwLock<HashMap<CacheMetadataKey, Arc<UpstreamMetadata>>>,
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
    /// [`CacheMetadataKeyRef`] that borrows the caller's `Mirror` and
    /// `debname`, and we only materialise an owned [`CacheMetadataKey`]
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
        K: Hash + Equivalent<CacheMetadataKey> + ?Sized,
        Self: ResolveOwn<K>,
    {
        if let Some(entry) = self.map.read().get(key) {
            return Arc::clone(entry);
        }

        // Cold path: fetch from xattrs.  If either read errors, surface
        // a best-effort `Arc` containing whichever fields succeeded for
        // this request but do not insert — see the "Negative caching
        // and transient errors" section in the module docs.
        let etag_res = try_read_etag(file, path);
        let last_modified_res = try_read_last_modified(file, path);
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
        // as "xattrs unavailable on this FS" (the `write_helper` is best-
        // effort and silently swallows `ErrorKind::Unsupported`), trust
        // the publisher, and skip the assert.  Asserting here would fire
        // spuriously on filesystems without xattr support.
        let owned = <Self as ResolveOwn<K>>::own(key);
        let mut map = self.map.write();
        match map.entry(owned) {
            Entry::Occupied(occ) => {
                debug_assert!(
                    (meta.etag.is_none() && meta.last_modified.is_none())
                        || occ.get().as_ref() == meta.as_ref(),
                    "publication invariant violated: a concurrent `set` published \
                     metadata that disagrees with the on-disk xattrs; every caller \
                     of `set` must persist matching xattrs first (published={:?}, \
                     read={:?})",
                    occ.get().as_ref(),
                    meta.as_ref(),
                );
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
    pub(crate) fn set(&self, key: CacheMetadataKey, meta: Arc<UpstreamMetadata>) {
        self.map.write().insert(key, meta);
    }

    /// Drop any cached entry for `key`.  Called from cleanup file
    /// removal and (in principle) from any other context where the on-
    /// disk file is going away.  Accepts borrowed keys via the same
    /// [`Equivalent`] mechanism as `resolve`, so callers don't need to
    /// clone `Mirror` and `debname` to invalidate.
    pub(crate) fn invalidate<K>(&self, key: &K)
    where
        K: Hash + Equivalent<CacheMetadataKey> + ?Sized,
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
/// owned [`CacheMetadataKey`] on the cold cache-miss insert.  Implemented
/// for both the borrowed [`CacheMetadataKeyRef`] (hot-path callers) and
/// the owned [`CacheMetadataKey`] (test/cold callers).
pub(crate) trait ResolveOwn<K: ?Sized> {
    fn own(key: &K) -> CacheMetadataKey;
}

impl ResolveOwn<CacheMetadataKey> for CacheMetadataStore {
    #[inline]
    fn own(key: &CacheMetadataKey) -> CacheMetadataKey {
        key.clone()
    }
}

impl ResolveOwn<CacheMetadataKeyRef<'_>> for CacheMetadataStore {
    #[inline]
    fn own(key: &CacheMetadataKeyRef<'_>) -> CacheMetadataKey {
        key.to_owned()
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
    use crate::deb_mirror::{Mirror, MirrorKind};
    use crate::http_etag::write_etag;
    use crate::http_last_modified::write_last_modified;

    fn fixture_key() -> CacheMetadataKey {
        use crate::config::ClientHost;
        CacheMetadataKey::new(
            Mirror::new(
                ClientHost::new(String::from("example.test")).unwrap(),
                std::num::NonZero::new(80),
                "/debian".into(),
                MirrorKind::Structured,
            ),
            "test.deb".into(),
            CacheLayout::StructuredPool,
        )
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
        assert_eq!(first.etag.as_deref(), Some("\"abc\""));
        assert!(first.last_modified.is_some());
        assert_eq!(store.len(), 1);

        // Mutate the file's xattr to confirm the second resolve returns the
        // cached value, not a fresh disk read.  We also skip the assertion
        // entirely on filesystems that reject xattr writes (the prior
        // `write_etag` would have silently been a no-op).
        if first.etag.is_none() && first.last_modified.is_none() {
            return;
        }
        write_etag(&file, &path, "\"xyz\"");
        let second = store.resolve(&key, &file, &path);
        assert_eq!(second.etag.as_deref(), Some("\"abc\""));
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
        assert_eq!(s, "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn from_upstream_drops_malformed_last_modified() {
        let m = UpstreamMetadata::from_upstream(None, Some("not a date".into()));
        assert!(m.last_modified.is_none());
    }
}
