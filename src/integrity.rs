//! Download-commit integrity verification.
//!
//! Before a finished download is renamed into the cache, verify its content
//! against the repository's own metadata: by-hash files self-verify (digest
//! in the URL); `.deb` (Pool) and `Packages` files are checked against an
//! in-memory registry populated from streamed `Release` / `Packages` ingest.
//! Coupled into `guards::RenameBarrier::commit` so no download backend can
//! skip it.
//!
//! Defence in depth only -- APT's client-side GPG check remains the
//! cryptographic root of trust.
//!
//! Scope: verification gates *caching*, not in-flight *delivery*. A client
//! served concurrently from the same download (a late joiner streaming the
//! growing partial file, or one attaching during the post-download
//! `Verifying` hash window) receives its bytes before the digest is known. A
//! mismatch then blocks the `rename` but cannot unsend what was already
//! streamed. That is by design: the concurrent client's own APT GPG check is
//! the backstop.
//!
//! The registry learns an index's digests when the index is committed, and
//! again whenever a request for it is answered without a commit (a cache
//! hit, a client or upstream 304) while its digests are missing: after a
//! restart, an eviction from its scope, or a skipped or transiently failed
//! ingest. Every backend calls [`note_cached_index_touch`] where it answers
//! an index from cache; `ingest_ledger` keeps that cheap for a warm index.

use std::borrow::Cow;
use std::collections::{BinaryHeap, VecDeque};
use std::fmt;
use std::fs::Metadata;
use std::hash::BuildHasher as _;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};

use hashbrown::{
    DefaultHashBuilder, Equivalent, HashMap, HashTable, hash_map::EntryRef, hash_table::AbsentEntry,
};
use parking_lot::Mutex;
use tokio::sync::{Semaphore, SemaphorePermit, TryAcquireError};
use tracing::{debug, error, warn};

use crate::error::ErrorReport;
use crate::fs_open::{count_cache_failure, hint_sequential_read, nofollow_nonblock_options};
use crate::ingest_ledger::{Claim, IngestLedger, Outcome};
use crate::limits::{self, PackagesCompression};
use crate::mem_usage::{ARC_HEADER, Footprint, buffer_bytes};
use crate::{
    cache_layout::{ByHashContent, CacheEntryKey, ConnectionDetails, ResourceKind},
    cache_quota::QuotaReservation,
    deb_mirror::{Mirror, normalize_uri_path},
    guards::DownloadWriteLease,
    index_parser::{self, Digest, HashAlgo, ReleaseHeader, StanzaStream, StreamedDigest},
    metrics,
    mirror_indexes::{self, SuiteIndex},
    partial_file::TempPath,
    verified_marker::{self, FileIdentity},
};
use crate::{
    global_checksum_registry, global_config, info_once, warn_once_or_debug,
    warn_once_or_debug_gated, warn_once_or_info,
};

/// Why a download could not be committed to the cache. Every variant retires
/// the active-downloads entry and skips the DB records;
/// [`Self::ChecksumMismatch`] additionally arms the verify throttle and
/// unlinks the temp file (`guards::RenameBarrier::commit`), while the two
/// transient variants keep it for a later resume.
///
/// `Display` carries the message only; the `io::Error` hangs off `source()`,
/// so report it through [`ErrorReport`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum CommitError {
    #[error("checksum mismatch")]
    ChecksumMismatch,
    /// Reading the temp file back for verification, or the `fstat` that ties
    /// the rename to the verified file, failed. Fail-closed. Counted
    /// (`CACHE_IO_FAILURE`) and logged where it arises.
    #[error("verification I/O error")]
    VerifyIo(#[source] std::io::Error),
    /// The `rename(2)` (or the `create_dir_all` it falls back to) failed, the
    /// path no longer named the verified file, or the job died while
    /// renaming. Counted and logged once, in [`verify_and_rename`]'s tail.
    #[error("rename failed")]
    Rename(#[source] std::io::Error),
}

/// Input for [`verify_temp_file`]: plain values/borrows, so the decision is
/// free of process-global state and unit-testable.
struct VerifyInput<'a> {
    /// [`VerifyKind::Unverifiable`] when verification is disabled
    /// ([`digest_source`] yields no digest then).
    kind: VerifyKind,
    /// The finished temp file, open for reading. Read through its own cursor
    /// (rewound first), which is safe because every other holder of this open
    /// file description -- the splice cache writer's `pwrite` and a demoted
    /// client's `sendfile` -- uses explicit offsets
    /// (`splice/body.rs::prepare_file_serve`).
    file: &'a std::fs::File,
    /// `file`'s `fstat`, taken by the commit job before verifying. Nothing
    /// moves the file's size or mtime after it (the writer has finished,
    /// hashing only reads and the marker's xattr write leaves the mtime
    /// alone), so it also serves as the marker's identity.
    meta: &'a Metadata,
    /// `file`'s path, for log context and the verified marker only; never
    /// reopened.
    temp_path: &'a Path,
    /// The digest the body loop computed as it wrote the file, when it could
    /// (splice only, no resume onto a pre-existing prefix, bytes passed
    /// through userspace). Used only if its algorithm is the one the expected
    /// digest needs *and* it covered as many bytes as the finished file
    /// holds; otherwise the file is re-read and hashed.
    streamed: Option<StreamedDigest>,
}

/// What the downloaded temp file is verified against.
enum VerifyKind {
    /// For a by-hash resource the algorithm is the one from the `<algo>` URL
    /// path segment, never inferred from the digest length; for a
    /// registry-backed one it is always SHA256.
    Expected(Digest),
    /// The resource *could* have been verified but no expected digest is
    /// known - a registry miss, or a by-hash URL whose algorithm segment and
    /// digest did not agree. Cached unverified and counted as a coverage gap
    /// (`CHECKSUM_UNVERIFIED`).
    Unknown,
    /// Not verifiable by this module today (other metadata, flat-pool .debs
    /// with Layer-B path-alignment deferred): cached unverified *without*
    /// counting a coverage gap.
    Unverifiable,
}

/// `algo` is the one the parser took from the URL's `<algo>` segment (never
/// re-read from the raw path, where an earlier decoy `by-hash` segment could
/// name another). A digest length that disagrees with it degrades to
/// [`VerifyKind::Unknown`] instead of hashing with a guessed algorithm.
fn byhash_verify_kind(algo: HashAlgo, filename: &str) -> VerifyKind {
    let Some(digest) = index_parser::byhash_digest_for_algo(algo, filename) else {
        // The URL parser already rejects this, so reaching here means the
        // parser and the digest decoder diverged.
        warn_once_or_info!(
            "By-hash digest did not decode for its URL algorithm; caching `{}` unverified",
            filename.escape_debug()
        );
        return VerifyKind::Unknown;
    };
    VerifyKind::Expected(digest)
}

/// Performs file I/O (reads and hashes `file`) only for
/// [`VerifyKind::Expected`]; callers on an async worker must wrap that case
/// in `spawn_blocking`.
///
/// `Ok` when verification passed or was skipped (disabled / non-verifiable /
/// unknown digest).
fn verify_temp_file(input: &VerifyInput<'_>) -> Result<(), CommitError> {
    let VerifyKind::Expected(expected) = &input.kind else {
        // Only count the kinds that *could* have been verified, so the metric
        // reflects a real coverage gap.
        if matches!(input.kind, VerifyKind::Unknown) {
            metrics::CHECKSUM_UNVERIFIED.increment();
        }
        return Ok(());
    };
    let algo = expected.algo();

    let reused = reuse_streamed_digest(
        input.streamed.as_ref(),
        algo,
        input.meta.len(),
        input.temp_path,
    );
    let fallback;
    let computed = match reused {
        Some(reused) => reused,
        None => match hash_file(input.file, input.meta.len(), input.temp_path, algo) {
            Ok(c) => {
                fallback = c;
                fallback.as_slice()
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to read `{}` for {} verification; discarding the download, not caching:  {}",
                    input.temp_path.display(),
                    algo.as_str(),
                    ErrorReport(&err),
                );
                return Err(CommitError::VerifyIo(err));
            }
        },
    };

    if computed == expected.as_slice() {
        metrics::CHECKSUM_VERIFIED.increment();
        // Stamp the cleanup-verification marker, so the first cleanup cycle
        // after this download does not re-read and re-hash the file cold from
        // disk. Before the rename: `rename(2)` keeps the inode and the mtime,
        // and the size is final, so the marker is valid for the destination
        // path cleanup will read it from. Unlike `cleanup/verify.rs`, no
        // post-hash identity recheck is needed -- the temp file is
        // exclusively owned by this download, so the identity is the commit
        // job's `fstat` (`meta`). Best-effort: an xattr failure only means
        // the next cleanup cycle hashes the file.
        verified_marker::stamp(
            input.file,
            input.temp_path,
            FileIdentity::of(input.meta),
            expected,
        );
        Ok(())
    } else {
        metrics::CHECKSUM_MISMATCH.increment();
        // Logged by the async wrapper, with host and path in scope. WARN (not
        // ERROR): can also be a third-party repo that replaced a file in
        // place. Not rate-limited: each event is potentially
        // security-relevant.
        Err(CommitError::ChecksumMismatch)
    }
}

/// The body loop's incremental digest, when it can be trusted for `algo`.
///
/// An algorithm mismatch is an ordinary outcome and falls back silently. The
/// byte count the hasher consumed must equal the size of the file about to
/// be renamed in: otherwise a file diverging from the stream would be
/// committed as verified *and* have that digest stamped into the cleanup
/// marker, which makes cleanup trust it forever. A divergence is a bug, so
/// it is logged loudly, but the fallback is the re-read rather than a
/// reject: hashing what is on disk answers the question correctly either
/// way.
fn reuse_streamed_digest<'a>(
    streamed: Option<&'a StreamedDigest>,
    algo: HashAlgo,
    on_disk: u64,
    path: &Path,
) -> Option<&'a [u8]> {
    let streamed = streamed?;
    if streamed.digest.algo() != algo {
        return None;
    }
    if on_disk != streamed.bytes {
        error!(
            "Streamed {} digest of `{}` covered {} bytes but the file holds {}; re-reading the file instead of trusting the digest",
            algo.as_str(),
            path.display(),
            streamed.bytes,
            on_disk,
        );
        return None;
    }
    Some(streamed.digest.as_slice())
}

/// Hashes through the download's own descriptor (`path` is for log context
/// only). The writer's cursor sits wherever its last write left it, hence
/// the rewind.
fn hash_file(
    file: &std::fs::File,
    size: u64,
    path: &Path,
    algo: HashAlgo,
) -> std::io::Result<Digest> {
    use std::io::Seek as _;

    let mut reader = file;
    reader.rewind()?;
    hint_sequential_read(file, size, path);
    index_parser::hash_open_file(algo, &mut reader, size)
}

/// Rename paths and resource identity for `verify_and_rename`.
pub(crate) struct RenamePlan {
    pub(crate) dest_path: PathBuf,
    pub(crate) resource_kind: ResourceKind,
    /// The download's cache entry, shared with its write lease.
    ///
    /// `debname` is the on-disk leaf name. For a by-hash resource this is the
    /// hex digest; for `Pool` it is the basename used directly as the
    /// registry-lookup key; for other kinds it is kept only for log context.
    ///
    /// `mirror` is the canonical mirror. Its authority (host and port) and
    /// repo-prefix path are the registry key, so two distinct mirrors served
    /// from the same host (e.g. `host/m1/pool/...` vs `host/m2/pool/...`, or
    /// one repository per port) cannot poison each other's expected digests
    /// via same-named packages.
    pub(crate) key: Arc<CacheEntryKey>,
    /// The raw request URI path (pre-normalisation). Used for `Release`
    /// relative-path resolution and as the relative-key component of the
    /// `Packages` registry lookup (see `verify_and_rename`).
    pub(crate) raw_uri_path: String,
}

/// Registry scope: the mirror's `host[:port]` and repo-prefix path. The
/// per-scope lookup key (`relpath`) is NOT uniformly "repo-relative": for a
/// pool `.deb` (layer B) it is the bare basename, for an index file (layer
/// C) the full host-relative URI path (e.g.
/// `debian/dists/sid/main/binary-amd64/Packages.xz`). The port is part of
/// the scope because `allowed_mirrors` permits a host on every port: without
/// it, a client fetching an index from `host:8080` would replace the digests
/// the default port's downloads are checked against.
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct RegistryScope {
    authority: String,
    mirror_path: String,
}

/// Borrowed form of `RegistryScope`, so `lookup` does not allocate.
#[derive(Hash)]
struct RegistryScopeRef<'a> {
    authority: &'a str,
    mirror_path: &'a str,
}

// Both maps key on `Arc<RegistryScope>` (the registry shares the allocation
// with the eviction epochs), and `lookup` stays allocation-free through the
// borrowed `RegistryScopeRef`. `Arc<T>: Hash` delegates to `T: Hash` in std,
// and both derives hash `authority` then `mirror_path`, so the hashes agree.
impl Equivalent<Arc<RegistryScope>> for RegistryScopeRef<'_> {
    fn equivalent(&self, key: &Arc<RegistryScope>) -> bool {
        let &Self {
            authority,
            mirror_path,
        } = self;
        let RegistryScope {
            authority: kauthority,
            mirror_path: kmpath,
        } = &**key;
        authority == kauthority && mirror_path == kmpath
    }
}

/// Bounded in-memory map from `(authority, mirror_path)` scope and per-scope
/// lookup key to an expected SHA256 digest, populated from `Packages` /
/// `Release` index files. Lost on restart. FIFO bulk eviction at the
/// configured cap, checked once per insert batch (so the count may pass the
/// cap by up to one batch).
///
/// An entry holds no key text: a 128-bit fingerprint of its relpath (the
/// first half of its SHA-256), the digest and its family, in an
/// insertion-ordered slot log ([`Slot`]); ~70 bytes per entry against ~200
/// when keyed on the relpath text. Nothing reads a key back, and an upstream
/// that could craft a colliding name controls the index, and with it the
/// digest, already. What that upstream must not be able to steer is where a
/// slot lands in the index: it is filed under a hash of the fingerprint from
/// a per-scope randomly seeded hasher, never under the fingerprint's own
/// (public) bits, or a crafted `Packages` could make every insert walk one
/// probe sequence under the lock each digest lookup takes.
///
/// `insert` and `lookup` are module-private on purpose, so nothing outside
/// this module can seed or consult expected digests.
#[derive(Debug)]
pub(crate) struct ChecksumRegistry {
    inner: Mutex<RegistryInner>,
    /// Behind a lock of its own: every index cache-hit touch reads an epoch
    /// ([`Self::scope_epoch`]), and must not wait out an eviction pass,
    /// which runs under `inner`. Lock order: `inner`, then `epochs` (only
    /// `evict` takes both).
    epochs: Mutex<EvictionEpochs>,
    cap: usize,
}

/// The first half of the key's SHA-256, stored in place of the key text.
type Fingerprint = [u8; 16];

fn fingerprint(key: &str) -> Fingerprint {
    fingerprint_joined([key])
}

/// The [`fingerprint`] of `parts` concatenated, without building the
/// concatenation: a `Release` entry's key is `<release_dir>/<rel>`.
fn fingerprint_joined<'a>(parts: impl IntoIterator<Item = &'a str>) -> Fingerprint {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
    }
    let digest: [u8; 32] = hasher.finalize().into();
    *digest
        .first_chunk::<16>()
        .expect("a SHA-256 holds 16 bytes")
}

/// Seeded per scope rather than the fingerprint's own bits; see the
/// [`ChecksumRegistry`] doc.
fn fingerprint_hash(hasher: &DefaultHashBuilder, key: &Fingerprint) -> u64 {
    hasher.hash_one(key)
}

/// One registered digest. The family is stored so an eviction knows which
/// count it lowers without the key text. Built by the ingest, outside the
/// registry lock, so the fingerprint's SHA-256 does not run under it.
#[derive(Clone, Copy, Debug)]
struct Slot {
    key: Fingerprint,
    digest: [u8; 32],
    kind: KeyKind,
}

#[cfg(test)]
impl Slot {
    fn for_key(key: &str, digest: [u8; 32]) -> Self {
        Self {
            key: fingerprint(key),
            digest,
            kind: KeyKind::of(key),
        }
    }
}

#[derive(Debug, Default)]
struct ScopeState {
    /// Every insert appends a slot; the slot at position `i` has sequence
    /// `base + i`. A slot is live while `index` maps its key to its
    /// sequence. A re-inserted key gets a new slot at the back (the FIFO
    /// refresh) and leaves its old one stale; eviction skips stale slots and
    /// `compact_slots` drops them.
    slots: VecDeque<Slot>,
    /// Sequence of the front slot; moves with every pop and compaction, so
    /// no sequence is ever handed out twice.
    base: u64,
    /// The sequence of each live key's slot, filed under `fingerprint_hash`
    /// of its key.
    index: HashTable<u64>,
    hasher: DefaultHashBuilder,
    /// Per `Release` directory, the `Date:` (unix seconds; `None` when the
    /// file had none) of the newest `Release`/`InRelease` whose entries were
    /// registered. The two files of one directory write the same keys, so
    /// an older one ingested later must not overwrite the newer digests.
    /// Dropped with the scope when eviction drains it.
    release_dates: HashMap<Box<str>, Option<i64>>,
    /// How many live slots are [`KeyKind::Package`] keys; the rest are
    /// [`KeyKind::Index`] ones. Read only to explain a miss
    /// ([`RegistryMiss`]).
    packages: usize,
}

/// Free-standing (not a `ScopeState` method) so a closure over the slots
/// can run while the scope's `index` is borrowed mutably.
fn slot_in(slots: &VecDeque<Slot>, base: u64, seq: u64) -> Option<&Slot> {
    let position = usize::try_from(seq.checked_sub(base)?).ok()?;
    slots.get(position)
}

/// Which of the two digest families a registry key belongs to. The key
/// alone tells them apart: a package's key is its bare basename, an index's
/// the host-relative path `<release_dir>/<rel>`, which always holds a `/`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyKind {
    /// A `.deb`, registered by a `Packages` index.
    Package,
    /// A `Packages` index, registered by a `Release`/`InRelease`.
    Index,
}

impl KeyKind {
    fn of(key: &str) -> Self {
        if key.contains('/') {
            Self::Index
        } else {
            Self::Package
        }
    }
}

/// Why a lookup came up empty: a cold registry and a populated one that
/// does not list the key call for different reactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegistryMiss {
    kind: KeyKind,
    /// Digests of `kind` the scope holds.
    held: usize,
    /// Whether an eviction took entries from the scope, so `held` is not
    /// everything its indexes registered.
    evicted: bool,
}

impl fmt::Display for RegistryMiss {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            kind,
            held,
            evicted,
        } = *self;
        let source = match kind {
            KeyKind::Package => "Packages indexes",
            KeyKind::Index => "Release files",
        };
        if held == 0 {
            write!(f, "none held from this mirror's {source}")?;
        } else {
            write!(f, "not among the {held} held from this mirror's {source}")?;
        }
        if evicted {
            f.write_str(", after evictions")?;
        }
        Ok(())
    }
}

impl ScopeState {
    fn live(&self, key: &Fingerprint) -> Option<&Slot> {
        self.index
            .find(fingerprint_hash(&self.hasher, key), |&seq| {
                slot_in(&self.slots, self.base, seq).is_some_and(|slot| slot.key == *key)
            })
            .and_then(|&seq| slot_in(&self.slots, self.base, seq))
    }

    fn next_seq(&self) -> u64 {
        self.base + self.slots.len() as u64
    }

    fn len(&self) -> usize {
        self.index.len()
    }
}

#[derive(Debug)]
struct RegistryInner {
    /// The scope `Arc` is shared with the eviction epochs.
    map: HashMap<Arc<RegistryScope>, ScopeState>,
    /// Live entries across all scopes.
    len: usize,
}

/// Scopes [`EvictionEpochs`] remembers before it forgets them all at once.
/// `mirror_path` is free-form under an allowed host, so without a bound
/// every scope ever evicted from would stay mapped for the process lifetime.
const MAX_EPOCH_SCOPES: usize = 4096;

/// Per-scope eviction epochs: a scope's epoch changes with every `evict`
/// pass that removes at least one live entry of it, and an ingest ledger
/// mark taken under another epoch reads as stale. Kept apart from the
/// scope's entries, so a scope drained empty and removed keeps its epoch.
///
/// Epochs come from one counter, so a value is never handed out twice. At
/// [`MAX_EPOCH_SCOPES`] the map is cleared and `floor` (every unmapped
/// scope's epoch) is raised above every value handed out so far: every
/// existing mark then reads stale once -- its index re-ingests on its next
/// touch -- and none can match by accident.
#[derive(Debug)]
struct EvictionEpochs {
    by_scope: HashMap<Arc<RegistryScope>, u64>,
    /// The epoch of every scope not in `by_scope`.
    floor: u64,
    /// The last epoch handed out.
    last: u64,
    cap: usize,
}

impl EvictionEpochs {
    fn new(cap: usize) -> Self {
        Self {
            by_scope: HashMap::new(),
            floor: 0,
            last: 0,
            cap,
        }
    }

    fn get(&self, authority: &str, mirror_path: &str) -> u64 {
        self.by_scope
            .get(&RegistryScopeRef {
                authority,
                mirror_path,
            })
            .copied()
            .unwrap_or(self.floor)
    }

    /// Whether an eviction took entries from the scope since the map was
    /// last cleared (a cleared map under-reports, it never invents one).
    fn evicted(&self, authority: &str, mirror_path: &str) -> bool {
        self.by_scope.contains_key(&RegistryScopeRef {
            authority,
            mirror_path,
        })
    }

    fn bump(&mut self, scope: &Arc<RegistryScope>) {
        if self.by_scope.len() >= self.cap && !self.by_scope.contains_key(scope) {
            self.by_scope.clear();
            self.floor = self.last + 1;
            self.last = self.floor;
        }
        self.last += 1;
        self.by_scope.insert(Arc::clone(scope), self.last);
    }
}

impl ChecksumRegistry {
    pub(crate) fn new(cap: NonZero<usize>) -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                map: HashMap::new(),
                len: 0,
            }),
            epochs: Mutex::new(EvictionEpochs::new(MAX_EPOCH_SCOPES)),
            cap: cap.get(),
        }
    }

    #[cfg(test)]
    fn insert(&self, authority: &str, mirror_path: &str, relpath: &str, digest: [u8; 32]) {
        self.insert_many(authority, mirror_path, &[Slot::for_key(relpath, digest)]);
    }

    /// Re-inserting an existing key refreshes its eviction-order position to
    /// most-recent.
    fn insert_many(&self, authority: &str, mirror_path: &str, slots: &[Slot]) {
        let mut inner = self.inner.lock();
        let _scope = inner.insert(authority, mirror_path, slots);
        self.evict_over_cap(&mut inner);
        drop(inner);
    }

    /// Register a `Release`/`InRelease`'s `Packages` entries unless a newer
    /// source for the same directory already did; `false` when superseded.
    /// Decided and written under one lock, so a concurrently ingested
    /// sibling cannot interleave its inserts. A dated source beats an
    /// undated one; between dated ones the later `Date:` wins; two undated
    /// ones keep last-writer-wins. An archive whose `Date:` legitimately
    /// goes backwards (restored from backup) is therefore pinned to the
    /// newer date already recorded until this process restarts or the scope
    /// drains from eviction. `date` is already clamped
    /// ([`clamp_future_release_date`]).
    fn insert_release(
        &self,
        authority: &str,
        mirror_path: &str,
        release_dir: &str,
        date: Option<i64>,
        slots: &[Slot],
    ) -> bool {
        let mut inner = self.inner.lock();
        let recorded = inner
            .scope(authority, mirror_path)
            .and_then(|state| state.release_dates.get(release_dir).copied());
        let supersedes = match (recorded, date) {
            (None | Some(None), _) => true,
            (Some(Some(_)), None) => false,
            (Some(Some(recorded)), Some(date)) => date >= recorded,
        };
        if !supersedes {
            return false;
        }
        // Only on a scope that exists: a `Release` listing no `Packages`
        // creates none. Recorded before the eviction, which drops the dates
        // with the scope if it drains it (a drained scope rebuilds its dates
        // on re-ingest).
        if let Some(state) = inner.insert(authority, mirror_path, slots) {
            state.release_dates.insert(release_dir.into(), date);
        }
        self.evict_over_cap(&mut inner);
        drop(inner);
        true
    }

    fn lookup(&self, authority: &str, mirror_path: &str, relpath: &str) -> Option<[u8; 32]> {
        let key = fingerprint(relpath);
        let inner = self.inner.lock();
        inner
            .scope(authority, mirror_path)
            .and_then(|state| state.live(&key))
            .map(|slot| slot.digest)
    }

    /// A second lock round trip, taken on the miss path only; an ingest
    /// landing in between makes the figure newer than the miss, never wrong
    /// about the scope.
    fn explain_miss(&self, authority: &str, mirror_path: &str, relpath: &str) -> RegistryMiss {
        let kind = KeyKind::of(relpath);
        let held = self
            .inner
            .lock()
            .scope(authority, mirror_path)
            .map_or(0, |state| match kind {
                KeyKind::Package => state.packages,
                KeyKind::Index => state.len() - state.packages,
            });
        let evicted = self.epochs.lock().evicted(authority, mirror_path);
        RegistryMiss {
            kind,
            held,
            evicted,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len
    }

    /// Includes the eviction epochs, whose table keeps a scope's name alive
    /// after its last entry went. Reads only capacities, so a 500k-entry
    /// scope costs nothing to account for.
    pub(crate) fn footprint(&self) -> Footprint {
        let inner = self.inner.lock();
        let scopes: usize = inner
            .map
            .iter()
            .map(|(scope, state)| {
                let ScopeState {
                    slots,
                    base: _,
                    index,
                    hasher: _,
                    release_dates,
                    packages: _,
                } = state;
                ARC_HEADER
                    + scope_bytes(scope)
                    + buffer_bytes(slots.capacity(), size_of::<Slot>())
                    + index.allocation_size()
                    + release_dates.allocation_size()
                    + release_dates.keys().map(|dir| dir.len()).sum::<usize>()
            })
            .sum();
        // Taken after `inner`, the order `evict` takes them in. A scope only
        // the epochs still name (its entries all evicted) is theirs to
        // account for; one the map holds too was counted above.
        let epochs = self.epochs.lock();
        let forgotten: usize = epochs
            .by_scope
            .keys()
            .filter(|scope| Arc::strong_count(scope) == 1)
            .map(|scope| ARC_HEADER + scope_bytes(scope))
            .sum();
        Footprint {
            entries: inner.len,
            bytes: inner.map.allocation_size()
                + scopes
                + epochs.by_scope.allocation_size()
                + forgotten,
        }
    }

    /// `(live entries, index capacity, slot count, slot capacity)` of one
    /// scope.
    #[cfg(test)]
    fn scope_footprint(&self, authority: &str, mirror_path: &str) -> (usize, usize, usize, usize) {
        self.inner
            .lock()
            .scope(authority, mirror_path)
            .map(|state| {
                (
                    state.len(),
                    state.index.capacity(),
                    state.slots.len(),
                    state.slots.capacity(),
                )
            })
            .expect("scope present")
    }

    #[cfg(test)]
    fn slot_len(&self) -> usize {
        self.inner.lock().map.values().map(|s| s.slots.len()).sum()
    }

    fn scope_epoch(&self, authority: &str, mirror_path: &str) -> u64 {
        self.epochs.lock().get(authority, mirror_path)
    }

    fn evict_over_cap(&self, inner: &mut RegistryInner) {
        let cap = self.cap;
        if inner.len > cap {
            // The dashboard only ever shows the post-eviction count, so a
            // registry permanently sized below its working set looks idle
            // while verification coverage quietly drops.
            info_once!(
                "Checksum registry reached its {} entry cap; evicting the oldest entries of the largest mirror scope (verification coverage drops for evicted keys)",
                cap
            );
            evict(inner, cap, &self.epochs);
        }
    }
}

impl RegistryInner {
    fn scope(&self, authority: &str, mirror_path: &str) -> Option<&ScopeState> {
        self.map.get(&RegistryScopeRef {
            authority,
            mirror_path,
        })
    }

    /// Insert (or refresh) one scope's slots, resolving the scope once for
    /// the batch, and return it. An empty batch creates no scope and returns
    /// `None`. Never evicts: the caller does, once the whole batch is in
    /// ([`ChecksumRegistry::evict_over_cap`]).
    fn insert(
        &mut self,
        authority: &str,
        mirror_path: &str,
        slots: &[Slot],
    ) -> Option<&mut ScopeState> {
        if slots.is_empty() {
            return None;
        }
        let state = match self.map.entry_ref(&RegistryScopeRef {
            authority,
            mirror_path,
        }) {
            EntryRef::Occupied(entry) => entry.into_mut(),
            EntryRef::Vacant(entry) => entry.insert_with_key(
                Arc::new(RegistryScope {
                    authority: authority.to_owned(),
                    mirror_path: mirror_path.to_owned(),
                }),
                ScopeState::default(),
            ),
        };
        for &slot in slots {
            if state.insert(slot) {
                self.len += 1;
            }
        }
        Some(state)
    }
}

impl ScopeState {
    /// Whether the slot's key is new to the scope.
    fn insert(&mut self, slot: Slot) -> bool {
        let Slot {
            key,
            digest: _,
            kind,
        } = slot;
        let seq = self.next_seq();
        if self.slots.len() == self.slots.capacity() {
            // Grow in eighths, not by doubling: at 49 bytes a slot, a log
            // of half a million entries would otherwise reserve 25 MB it
            // never fills.
            self.slots.reserve_exact(self.slots.len() / 8 + 16);
        }
        self.slots.push_back(slot);
        let Self {
            slots,
            base,
            index,
            hasher,
            ..
        } = &mut *self;
        let (slots, base, hasher) = (&*slots, *base, &*hasher);
        let hash = fingerprint_hash(hasher, &key);
        // A live key moves to the new slot; its old one goes stale.
        let inserted = if let Some(live) = index.find_mut(hash, |&live| {
            slot_in(slots, base, live).is_some_and(|slot| slot.key == key)
        }) {
            *live = seq;
            false
        } else {
            index.insert_unique(hash, seq, |&live| index_hash(hasher, slots, base, live));
            true
        };
        if self.slots.len() > self.len() + stale_allowance(self.len()) {
            compact_slots(self);
        }
        if inserted && kind == KeyKind::Package {
            self.packages += 1;
        }
        inserted
    }
}

/// For the index's own rehashes. Every index entry points at a present
/// slot: a slot leaves `slots` only after its index entry is removed
/// (`evict`) or the index is rebuilt (`compact_slots`).
fn index_hash(hasher: &DefaultHashBuilder, slots: &VecDeque<Slot>, base: u64, seq: u64) -> u64 {
    let slot = slot_in(slots, base, seq).expect("every index entry points at a present slot");
    fingerprint_hash(hasher, &slot.key)
}

/// Free `cap / 4` live entries, plus however far past `cap + 1` a batch
/// took the registry, oldest first and always from the scope currently
/// holding the most entries, so one oversized (or hostile) index cannot
/// drain the digests of every other mirror. A scope that drains empty is
/// removed and the next-largest scope pays the remainder. Stale slots
/// (re-inserted keys, whose live slot is newer) are skipped and do not count
/// against the quota.
fn evict(inner: &mut RegistryInner, cap: usize, epochs: &Mutex<EvictionEpochs>) {
    let quota = (cap / 4).max(1) + inner.len.saturating_sub(cap + 1);
    // A selected scope is drained or finishes the pass, so the remaining
    // scopes' sizes never change. Heapify once instead of rescanning the
    // map after every drained scope (quadratic for many small scopes).
    let mut scopes: BinaryHeap<_> = inner
        .map
        .iter()
        .map(|(scope, state)| (state.len(), Arc::clone(scope)))
        .collect();
    let mut live = 0usize;
    while live < quota {
        let Some((_, scope)) = scopes.pop() else {
            break;
        };
        let Some(state) = inner.map.get_mut(&scope) else {
            break;
        };
        let before = live;
        while live < quota {
            let Some(front) = state.slots.front().copied() else {
                break;
            };
            let seq = state.base;
            // Live iff the index still points at this slot; a stale slot's
            // key was re-inserted later. The index entry goes before the
            // slot, so no index entry ever points past the front.
            let was_live = match state
                .index
                .find_entry(fingerprint_hash(&state.hasher, &front.key), |&live| {
                    live == seq
                }) {
                Ok(entry) => {
                    entry.remove();
                    true
                }
                Err(_absent @ AbsentEntry { .. }) => false,
            };
            state.slots.pop_front();
            state.base += 1;
            if was_live {
                if front.kind == KeyKind::Package {
                    state.packages -= 1;
                }
                inner.len -= 1;
                live += 1;
            }
        }
        if live > before {
            epochs.lock().bump(&scope);
        }
        if state.len() == 0 {
            inner.map.remove(&scope);
            continue;
        }
        shrink_scope(state);
        // The inner loop stops short of the quota only once the slots are
        // drained, which empties the scope and is handled above; so this is
        // unreachable while every live entry has a slot, and otherwise keeps
        // the outer loop from picking the same scope forever.
        debug_assert!(live >= quota, "a scope with entries but no slots");
        if live < quota {
            break;
        }
    }
}

/// Stale slots a scope with `live` entries may carry before the log is
/// compacted, and spare capacity it may keep after an eviction: a quarter,
/// so the log costs at most ~1.25 slots per live entry while a compaction
/// still only runs once per quarter of the scope re-inserted (every arch's
/// `Packages` lists the `all` packages again, so re-inserts are the norm).
fn stale_allowance(live: usize) -> usize {
    live / 4 + 16
}

/// Neither the index nor the slot log shrinks on its own, so a scope that
/// once held most of the cap (a hostile index, which is what eviction hits
/// first) would keep its peak footprint. The thresholds keep the rehash and
/// copy costs amortised over the evictions that caused them.
fn shrink_scope(state: &mut ScopeState) {
    let ScopeState {
        slots,
        base,
        index,
        hasher,
        ..
    } = state;
    if index.capacity() > 2 * index.len() + 16 {
        index.shrink_to_fit(|&live| index_hash(hasher, slots, *base, live));
    }
    if slots.capacity() > slots.len() + stale_allowance(slots.len()) {
        slots.shrink_to_fit();
    }
}

/// The heap a scope's name takes beyond its `Arc`.
fn scope_bytes(scope: &RegistryScope) -> usize {
    let RegistryScope {
        authority,
        mirror_path,
    } = scope;
    size_of::<RegistryScope>() + authority.capacity() + mirror_path.capacity()
}

/// Rebuild a scope's slot log keeping only the live slots, in their order,
/// re-sequenced past every sequence handed out so far.
fn compact_slots(state: &mut ScopeState) {
    // Room for the next growth step too, or the insert that triggered the
    // compaction reallocates the fresh log at once.
    let mut live: VecDeque<Slot> = VecDeque::with_capacity(state.len() + state.len() / 8 + 16);
    live.extend(
        state
            .slots
            .iter()
            .enumerate()
            .filter(|&(position, slot)| {
                let seq = state.base + position as u64;
                state
                    .index
                    .find(fingerprint_hash(&state.hasher, &slot.key), |&s| s == seq)
                    .is_some()
            })
            .map(|(_, &slot)| slot),
    );
    state.base = state.next_seq();
    state.slots = live;
    state.index.clear();
    let ScopeState {
        slots,
        base,
        index,
        hasher,
        ..
    } = state;
    let (slots, base, hasher) = (&*slots, *base, &*hasher);
    for (position, slot) in slots.iter().enumerate() {
        index.insert_unique(
            fingerprint_hash(hasher, &slot.key),
            base + position as u64,
            |&live| index_hash(hasher, slots, base, live),
        );
    }
}

/// A miss is expected while the registry is still cold (the first
/// `apt install` after startup), but a *persistent* one means the key
/// derived here disagrees with the key ingest inserted. Each case has its
/// own once-gate: the cold miss nearly every start produces must not spend
/// the one WARN of the miss worth looking into.
fn log_registry_miss(plan: &RenamePlan, key: &str, miss: RegistryMiss) {
    static COLD: AtomicBool = AtomicBool::new(false);
    static UNLISTED: AtomicBool = AtomicBool::new(false);

    warn_once_or_debug_gated!(
        if miss.held == 0 { &COLD } else { &UNLISTED },
        "No expected digest in the checksum registry for host {} mirror {} key `{}` ({miss}); caching {} unverified",
        plan.key.mirror.host(),
        plan.key.mirror.path(),
        key.escape_debug(),
        plan.key.debname
    );
}

fn registry_verify_kind(plan: &RenamePlan, key: &str) -> VerifyKind {
    let registry = global_checksum_registry();
    let mirror = &plan.key.mirror;
    let (authority, mirror_path) = (mirror.format_authority(), mirror.path());
    registry.lookup(authority, mirror_path, key).map_or_else(
        || {
            let miss = registry.explain_miss(authority, mirror_path, key);
            log_registry_miss(plan, key, miss);
            VerifyKind::Unknown
        },
        |digest| VerifyKind::Expected(Digest::Sha256(Box::new(digest))),
    )
}

/// `rename(2)` the finished temp file into the cache, creating the
/// destination directory only when it turns out to be missing, so the
/// steady state costs no `mkdir`.
///
/// `rename(2)` reports `ENOENT` for a missing *source* too, so a lost temp
/// file costs one wasted `mkdir` before failing with the same errno. A
/// `create_dir_all` failure surfaces through `CommitError::Rename`.
fn rename_into_cache(temp_path: &Path, dest_path: &Path) -> std::io::Result<()> {
    match std::fs::rename(temp_path, dest_path) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        result => return result,
    }

    if let Some(parent) = dest_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::rename(temp_path, dest_path)
}

/// Whether `path` still names the file `verified` was taken from (same device
/// and inode, `lstat`, so a symlink planted in its place fails too).
///
/// The commit verifies the open descriptor but renames by path, so a
/// process of the same user that replaced the temp file between the two
/// would otherwise have its file renamed into the cache unverified. The
/// check narrows that window from the whole verification (a full hash of
/// a large download) to the gap between the `lstat` and the `rename(2)`;
/// closing it outright needs a rename by descriptor, which
/// Linux does not offer without privileges (`linkat` of `/proc/self/fd`
/// needs `CAP_DAC_READ_SEARCH`).
fn check_path_names_file(path: &Path, verified: &Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let at_path = std::fs::symlink_metadata(path)?;
    if at_path.dev() == verified.dev() && at_path.ino() == verified.ino() {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "the temp file's path no longer names the verified file (replaced after verification)",
        ))
    }
}

/// A step the commit job runs on the open temp file before anything else:
/// splice's `fsync` (`splice/commit.rs::sync_cache_file`). It reports its own
/// failure; the commit goes on either way.
pub(crate) type PrepareStep = fn(&std::fs::File, &Path);

/// A file whose writer has completed and flushed all pending I/O, handed to
/// the commit job whole. Commit consumes this proof rather than accepting an
/// arbitrary writable file.
pub(crate) struct FinishedCacheFile {
    /// The open descriptor: the job's `fstat`, and the read the verification
    /// may need.
    file: tokio::fs::File,
    /// The digest the download computed incrementally over the bytes it
    /// wrote, when it could; spares `verify_temp_file` the re-read. `None`
    /// from every path that cannot produce one -- the zero-copy splice loop
    /// (the plaintext never reaches userspace), a resumed
    /// download whose temp file already held a prefix, `volatile.rs`, and the
    /// hyper backend (it writes through a `BufWriter` whose bytes are not
    /// funnelled through a single hashable site).
    digest: Option<StreamedDigest>,
    /// `None` from the hyper backend, which has never `fsync`ed a download.
    prepare: Option<PrepareStep>,
}

impl FinishedCacheFile {
    #[cfg(feature = "hyper")]
    pub(crate) async fn flush(
        mut file: tokio::fs::File,
        path: &Path,
    ) -> Result<Self, crate::transfer_error::CacheError> {
        use tokio::io::AsyncWriteExt as _;
        file.flush().await.map_err(|err| {
            crate::transfer_error::CacheError::counted_io("flush cache file for commit", path, err)
        })?;
        Ok(Self {
            file,
            digest: None,
            prepare: None,
        })
    }

    #[cfg(feature = "splice")]
    pub(crate) fn from_writer(
        writer: crate::splice::DrainedCacheWriter,
        prepare: PrepareStep,
    ) -> Self {
        let (file, digest) = writer.into_parts();
        Self {
            file,
            digest,
            prepare: Some(prepare),
        }
    }
}

/// Why [`verify_and_rename`] did not land the file, plus the temp file's guard
/// for the caller to act on (a checksum mismatch unlinks it). The guard is
/// `None` only when the commit job itself failed and took it down with it.
#[derive(Debug)]
pub(crate) struct CommitFailure {
    pub(crate) error: CommitError,
    pub(crate) guard: Option<TempPath>,
}

/// Verify the finished temp file and rename it into the cache.
///
/// Everything that touches the disk runs as **one** blocking job owning the
/// descriptor, the write lease and the reservation, in order: the
/// [`PrepareStep`], an `fstat`, the verification (on the open descriptor,
/// never a reopen of the path), [`check_path_names_file`], then the
/// `rename(2)`.
///
/// `reservation` is finalised inside that job, right after the `rename(2)`
/// succeeds: a `spawn_blocking` closure runs to completion even when the
/// awaiting future is dropped, so a cancelled commit can never leave the
/// file in the cache with its reservation reverted, nor a verified download
/// behind as a `.partial`. A cancellation skips only the async tail: the
/// checksum-mismatch warn, the rename-failure report and the post-commit
/// ingest scheduling.
///
/// The job owns the registry lease: cancelling the commit cannot permit a
/// retry to modify the file while it is read, or to replace the partial
/// before the queued rename runs.
pub(crate) async fn verify_and_rename(
    plan: &RenamePlan,
    finished: FinishedCacheFile,
    // Owned by the job, not the awaiting future, so a cancelled commit cannot
    // race the job's `rename(2)` with a scratch guard's unlink. The job
    // defuses it after the rename and hands it back on every other exit.
    guard: TempPath,
    reservation: QuotaReservation,
    lease: Arc<DownloadWriteLease>,
) -> Result<(), CommitFailure> {
    let verify_enabled = global_config().verify_checksums;
    let CacheEntryKey {
        mirror,
        debname,
        layout: _,
    } = &*plan.key;

    // Registry lookups happen here, before `spawn_blocking`, so the decision
    // stays global-free.
    let kind = match digest_source(
        plan.resource_kind,
        debname,
        &plan.raw_uri_path,
        verify_enabled,
    ) {
        DigestSource::InUrl(algo) => byhash_verify_kind(algo, debname),
        DigestSource::Registry(key) => registry_verify_kind(plan, &key),
        DigestSource::Absent => VerifyKind::Unverifiable,
    };

    let FinishedCacheFile {
        file,
        digest: streamed,
        prepare,
    } = finished;
    // No blocking hop: the file is idle, so this only waits out an in-flight
    // operation that cannot exist.
    let file = file.into_std().await;
    // For the rename-failure line of a job that died with the guard.
    let temp_path = guard.to_path_buf();

    // Set just before the rename, so a job that dies is attributed to the
    // step it died in: the two keep their distinct messages and variants.
    let renaming = Arc::new(AtomicBool::new(false));
    let job = {
        let dest_path = plan.dest_path.clone();
        let renaming = Arc::clone(&renaming);
        move |lease: &DownloadWriteLease| -> Result<(), (CommitError, TempPath)> {
            if let Some(prepare) = prepare {
                prepare(&file, &guard);
            }
            // Without it the rename could not be tied to the verified file,
            // so a failed `fstat` fails the commit closed, like a failed read.
            let verified_meta = match file.metadata() {
                Ok(meta) => meta,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to stat temp file `{}` before rename; discarding the download, not caching:  {}",
                        guard.display(),
                        ErrorReport(&err)
                    );
                    return Err((CommitError::VerifyIo(err), guard));
                }
            };
            let bytes_received = verified_meta.len();
            if let Err(err) = verify_temp_file(&VerifyInput {
                kind,
                file: &file,
                meta: &verified_meta,
                temp_path: &guard,
                streamed,
            }) {
                return Err((err, guard));
            }
            drop(file);
            renaming.store(true, Ordering::Relaxed);
            if let Err(err) = check_path_names_file(&guard, &verified_meta) {
                return Err((CommitError::Rename(err), guard));
            }
            match rename_into_cache(&guard, &dest_path) {
                Ok(()) => {
                    // The file no longer exists under its old name, so the
                    // guard must not try to remove it.
                    TempPath::defuse(guard);
                    reservation.finalize(bytes_received);
                    lease.invalidate_metadata();
                    // Here, not after the await: a commit future cancelled
                    // between the rename and the scheduling below would
                    // otherwise leave the replaced file's mark on the new one.
                    if verify_enabled {
                        INGEST_LEDGER.invalidate(&dest_path);
                    }
                    Ok(())
                }
                Err(err) => Err((CommitError::Rename(err), guard)),
            }
        }
    };

    let (error, guard) = match lease.spawn_blocking(job).await {
        Ok(Ok(())) => {
            // Post-commit, best-effort: ingest index files into the registry
            // so future downloads are verifiable. Detached so the client
            // connection is never delayed by decompression/parsing.
            let _queued = schedule_ingest(&IndexFile::from(plan));
            return Ok(());
        }
        Ok(Err((error, guard))) => (error, Some(guard)),
        Err(join_err) if renaming.load(Ordering::Relaxed) => {
            (CommitError::Rename(std::io::Error::other(join_err)), None)
        }
        Err(join_err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to run the verification task for {} from host {}; discarding the download, not caching:  {}",
                debname,
                mirror.host(),
                ErrorReport(&join_err),
            );
            (CommitError::VerifyIo(std::io::Error::other(join_err)), None)
        }
    };
    match &error {
        CommitError::ChecksumMismatch => warn!(
            "Checksum mismatch for {} from host {} mirror {}; discarding the download, not caching",
            debname,
            mirror.host(),
            mirror.path(),
        ),
        CommitError::Rename(io_err) => {
            // A directory planted at the destination fails the rename with
            // `EISDIR`: a non-regular entry, not a failed syscall. The
            // inode-mismatch and dead-job errors carry no errno and stay
            // `CACHE_IO_FAILURE`.
            count_cache_failure(io_err);
            error!(
                "Failed to rename temp file `{}` to `{}`; leaving the download uncached:  {}",
                temp_path.display(),
                plan.dest_path.display(),
                ErrorReport(io_err)
            );
        }
        // Counted and logged where it arose.
        CommitError::VerifyIo(_) => {}
    }
    Err(CommitFailure { error, guard })
}

/// How many `Packages` ingests decode at once. An upstream serving many
/// hostile indexes would otherwise hold one blocking-pool thread each for a
/// full decode up to the size caps (seconds each) and starve every other
/// `spawn_blocking` user (`tokio::fs`, verification). Two keep an
/// `apt update` over several components flowing while bounding that.
/// `Release` ingest reads a capped, uncompressed file and takes no decode
/// permit.
const PACKAGES_INGEST_CONCURRENCY: usize = 2;

static PACKAGES_INGEST_PERMITS: Semaphore = Semaphore::const_new(PACKAGES_INGEST_CONCURRENCY);

/// `Packages` ingests that may wait for a decode permit at once. The permits
/// bound the CPU, not the line in front of them: without a bound, a mirror
/// serving cap-sized indexes would queue one task per committed or touched
/// index. Sixty-four holds the burst the first `apt update` after a restart
/// touches (tens of indexes for a multi-suite, multi-arch Debian mirror).
const INGEST_QUEUE: usize = 64;

/// One slot per scheduled `Packages` ingest, from before its spawn to its
/// end. Taken synchronously in [`admit`], so together with
/// [`RELEASE_INGEST_SLOTS`] it bounds the paths `Running` in the ingest
/// ledger (whose cap never drops `Running` entries).
static INGEST_SLOTS: Semaphore = Semaphore::const_new(PACKAGES_INGEST_CONCURRENCY + INGEST_QUEUE);

/// How many `Release`/`InRelease` ingests may be admitted at once, in a pool
/// separate from [`INGEST_SLOTS`]: a hostile permitted mirror committing
/// cap-sized `.xz` `Packages` indexes can hold every slot of that line, and
/// every other mirror's `Release` ingest would then be refused too.
const RELEASE_INGEST_QUEUE: usize = 16;

static RELEASE_INGEST_SLOTS: Semaphore = Semaphore::const_new(RELEASE_INGEST_QUEUE);

enum Admission<'l, 's> {
    /// Ingested under the current epoch, failed for good, or already running.
    Nothing,
    /// No slot free; the path stays unmarked for its next touch.
    Refused,
    /// Run it: the ledger claim and the slot, both held by the job.
    Admitted(Claim<'l>, SemaphorePermit<'s>),
}

/// Claim `path` in `ledger`, then take a slot. A refused claim is dropped,
/// which leaves the path unmarked.
fn admit<'l, 's>(
    ledger: &'l IngestLedger,
    slots: &'s Semaphore,
    path: &Path,
    epoch: u64,
) -> Admission<'l, 's> {
    let Some(claim) = ledger.claim(path, epoch) else {
        return Admission::Nothing;
    };
    match slots.try_acquire() {
        Ok(slot) => Admission::Admitted(claim, slot),
        Err(_err @ (TryAcquireError::NoPermits | TryAcquireError::Closed)) => {
            drop(claim);
            Admission::Refused
        }
    }
}

async fn with_decode_permit<F: Future>(permits: &Semaphore, ingest: F) -> F::Output {
    let _permit = permits
        .acquire()
        .await
        .expect("the ingest semaphore is never closed");
    ingest.await
}

/// Paths the ledger tracks at most; see [`IngestLedger::claim`].
#[expect(
    clippy::decimal_literal_representation,
    reason = "16384 reads as a round entry-count cap, not a bit-width constant"
)]
const INGEST_LEDGER_CAP: usize = 16_384;

static INGEST_LEDGER: LazyLock<IngestLedger> =
    LazyLock::new(|| IngestLedger::new(INGEST_LEDGER_CAP));

#[must_use]
pub(crate) fn ingest_ledger_footprint() -> (Footprint, usize) {
    (INGEST_LEDGER.footprint(), INGEST_LEDGER_CAP)
}

/// Queue the ingest of `file` unless the ledger says its digests are
/// already registered, it failed for good, or an ingest of it is running;
/// whether one was queued.
///
/// Nothing is queued when verification is disabled: the registry an ingest
/// populates is read only by `verify_temp_file`, so parsing (and
/// decompressing) every index file would be pure waste.
fn schedule_ingest(file: &IndexFile<'_>) -> bool {
    if !global_config().verify_checksums {
        return false;
    }
    let Some(kind) = ingest_kind(file) else {
        return false;
    };
    let registry = global_checksum_registry();
    let (authority, mirror_path) = (file.mirror.format_authority(), file.mirror.path());
    let epoch = registry.scope_epoch(authority, mirror_path);
    let slots = match &kind {
        IngestKind::Release { release_dir: _ } => &RELEASE_INGEST_SLOTS,
        IngestKind::Packages { compression: _ } => &INGEST_SLOTS,
    };
    let (claim, slot) = match admit(&INGEST_LEDGER, slots, file.path, epoch) {
        Admission::Nothing => return false,
        Admission::Refused => {
            metrics::INGEST_SKIPPED_QUEUE_FULL.increment();
            warn_once_or_debug!(
                "Skipping registry ingest of index `{}` for host {authority} mirror {mirror_path} (ingest queue full); retrying on its next request",
                file.path.display(),
            );
            return false;
        }
        Admission::Admitted(claim, slot) => (claim, slot),
    };
    let mirror = file.mirror.clone();
    let buffer_size = global_config().buffer_size;
    tokio::spawn(run_ingest_job(claim, slot, kind, mirror, buffer_size));
    true
}

/// Answer a request for a cached index without a commit (a cache hit, a
/// client or upstream 304): re-ingest it if the registry lacks its digests.
pub(crate) fn note_cached_index_touch(
    conn_details: &ConnectionDetails,
    raw_uri_path: &str,
    cache_path: &Path,
) {
    if schedule_ingest(&IndexFile {
        resource_kind: conn_details.resource_kind,
        debname: &conn_details.debname,
        raw_uri_path,
        mirror: &conn_details.mirror,
        path: cache_path,
    }) {
        metrics::INGEST_TOUCH_TRIGGERED.increment();
    }
}

/// The upstream answered a revalidation of a cached `Release`/`InRelease`
/// with a 304: the mirror still serves it, so its suite counts as confirmed
/// now (`mirror_indexes`). A suite no ingest recorded yet -- the touch
/// ingest `note_cached_index_touch` just scheduled may still be running --
/// takes the confirmation once it is recorded.
pub(crate) fn note_release_revalidated(conn_details: &ConnectionDetails, raw_uri_path: &str) {
    if conn_details.resource_kind != ResourceKind::Release || !global_config().verify_checksums {
        return;
    }
    let Some(release_dir) = release_dir_from_uri_path(raw_uri_path) else {
        return;
    };
    mirror_indexes::confirm(
        &conn_details.mirror,
        &release_dir,
        coarsetime::Clock::now_since_epoch().as_secs(),
    );
}

/// One claimed path's ingest, run again while commits keep replacing the
/// file under it.
async fn run_ingest_job(
    mut claim: Claim<'static>,
    // Held for the whole job, reruns included; see `INGEST_SLOTS`.
    _slot: SemaphorePermit<'static>,
    kind: IngestKind,
    mirror: Mirror,
    buffer_size: usize,
) {
    let registry = global_checksum_registry();
    let (authority, mirror_path) = (mirror.format_authority(), mirror.path());
    loop {
        let result = ingest_once(registry, &kind, &mirror, claim.path(), buffer_size).await;
        let outcome = ingest_outcome(&result);
        log_ingest_result(&result, outcome, authority, mirror_path, claim.path());
        if !claim.finish(outcome, registry.scope_epoch(authority, mirror_path)) {
            return;
        }
    }
}

async fn ingest_once(
    registry: &ChecksumRegistry,
    kind: &IngestKind,
    mirror: &Mirror,
    dest: &Path,
    buffer_size: usize,
) -> std::io::Result<()> {
    let (authority, mirror_path) = (mirror.format_authority(), mirror.path());
    match kind {
        IngestKind::Packages { compression } => {
            with_decode_permit(
                &PACKAGES_INGEST_PERMITS,
                ingest_packages_file(
                    registry,
                    authority,
                    mirror_path,
                    dest,
                    *compression,
                    buffer_size,
                ),
            )
            .await
        }
        IngestKind::Release { release_dir } => {
            ingest_release_file(registry, authority, mirror_path, dest, release_dir)
                .await
                .map(|seen| {
                    // Whether or not the registry took its entries: an older
                    // `Release` than the registered one is still what the
                    // mirror served last.
                    mirror_indexes::record(mirror, release_dir, seen);
                })
        }
    }
}

fn log_ingest_result(
    result: &std::io::Result<()>,
    outcome: Outcome,
    authority: &str,
    mirror_path: &str,
    dest: &Path,
) {
    match (result, outcome) {
        (Err(err), Outcome::Failed) => {
            metrics::INGEST_FAILED_MARKED.increment();
            warn_once_or_debug!(
                "Failed to ingest index `{}` for host {authority} mirror {mirror_path}; not retried until the file changes:  {}",
                dest.display(),
                ErrorReport(err),
            );
        }
        (Err(err), Outcome::Ingested | Outcome::Retry) => warn_once_or_debug!(
            "Failed to ingest index `{}` for host {authority} mirror {mirror_path}; retrying on its next request:  {}",
            dest.display(),
            ErrorReport(err),
        ),
        // Sync point for `wait_for_log("Index ingestion completed")`; keep the wording stable.
        (Ok(()), _) => debug!("Index ingestion completed for `{}`", dest.display()),
    }
}

enum IngestKind {
    Packages {
        /// `None`: unknown, so the ingest sniffs magic bytes. APT with
        /// `Acquire::By-Hash: yes` fetches `Packages.xz` via
        /// `/by-hash/SHA256/<hex>` URLs that carry no extension.
        compression: Option<PackagesCompression>,
    },
    Release {
        release_dir: String,
    },
}

/// The facts that decide whether and how a cached file is ingested, taken
/// from a commit's `RenamePlan` or from a request answered from cache.
struct IndexFile<'a> {
    resource_kind: ResourceKind,
    /// On-disk leaf name (`_`-joined for structured `Packages`).
    debname: &'a str,
    /// The raw request URI path (`Release`'s directory comes from it).
    raw_uri_path: &'a str,
    /// The canonical mirror; its host and path are the registry scope.
    mirror: &'a Mirror,
    /// The cache file the ingest reads; the ledger key.
    path: &'a Path,
}

impl<'a> From<&'a RenamePlan> for IndexFile<'a> {
    fn from(plan: &'a RenamePlan) -> Self {
        let RenamePlan {
            dest_path,
            resource_kind,
            key,
            raw_uri_path,
        } = plan;
        Self {
            resource_kind: *resource_kind,
            debname: &key.debname,
            raw_uri_path,
            mirror: &key.mirror,
            path: dest_path,
        }
    }
}

/// `None` for a resource that feeds no registry entries.
fn ingest_kind(file: &IndexFile<'_>) -> Option<IngestKind> {
    #[expect(clippy::match_same_arms, reason = "prefer clarity")]
    let kind = match file.resource_kind {
        // `file.debname` is `_`-joined; the leaf after the last `_` is the
        // filename, which the router only classifies as `Packages` when
        // `from_filename` knows it (`deb_mirror::is_packages_filename`).
        ResourceKind::Packages => {
            let leaf = file
                .debname
                .rsplit_once('_')
                .map_or(file.debname, |(_, leaf)| leaf);
            PackagesCompression::from_filename(leaf).map(|compression| IngestKind::Packages {
                compression: Some(compression),
            })
        }
        // A flat repository's indexes feed nothing: its pool downloads are
        // `VerifyKind::Unverifiable` and its `Packages` files are not
        // verified against a flat `Release` either, so their digests would
        // only take decode permits and ingest slots from the structured
        // mirrors (and share their registry scope on the same host and path).
        ResourceKind::FlatMetadata => None,
        ResourceKind::Release => release_dir_from_uri_path(file.raw_uri_path)
            .map(|d| IngestKind::Release { release_dir: d }),
        // A per-component Release (`binary-<arch>/Release`) carries no SHA256:
        // section listing Packages files.
        ResourceKind::ComponentRelease => None,
        // A by-hash file may be a Packages file. The directory its
        // validated `by-hash/` hangs in, judged once by the classifier,
        // distinguishes a binary Packages index from Contents/dep11/i18n
        // by-hash content.
        ResourceKind::ByHash(_, ByHashContent::MaybePackages) => {
            Some(IngestKind::Packages { compression: None })
        }
        // Like `FlatMetadata`: nothing reads a flat repository's digests.
        ResourceKind::FlatByHash(_, ByHashContent::MaybePackages | ByHashContent::Other)
        | ResourceKind::ByHash(_, ByHashContent::Other) => None,
        // A pdiff patch is an ed script, not an index to ingest.
        ResourceKind::Pool
        | ResourceKind::Sources
        | ResourceKind::Translation
        | ResourceKind::Icon
        | ResourceKind::FlatPool
        | ResourceKind::Pdiff => None,
    };
    kind
}

/// A filesystem anomaly that may be corrected before the next request,
/// unlike decode failures that repeat on the same index bytes.
#[derive(Debug, thiserror::Error)]
#[error("cached index is not a regular file")]
struct NonRegularIndex;

fn require_regular_index(metadata: &Metadata) -> std::io::Result<()> {
    if metadata.is_file() {
        Ok(())
    } else {
        metrics::CACHE_NON_REGULAR.increment();
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            NonRegularIndex,
        ))
    }
}

/// The ledger outcome of one admitted ingest run. An OS error or a
/// nonregular cache entry may pass after the filesystem is corrected. Every
/// other error was built by the decode pipeline itself -- a size or bomb cap,
/// a corrupt stream, an over-cap or non-UTF-8 `Release` -- and repeats on the
/// same bytes.
fn ingest_outcome(result: &std::io::Result<()>) -> Outcome {
    match result {
        Ok(()) => Outcome::Ingested,
        Err(err)
            if err.raw_os_error().is_some()
                || err
                    .get_ref()
                    .is_some_and(<dyn std::error::Error + Send + Sync>::is::<NonRegularIndex>) =>
        {
            Outcome::Retry
        }
        Err(_) => Outcome::Failed,
    }
}

/// Registry identity of an already-classified URI path. Routing validates
/// fields before this boundary; decode the path once, after collapsing
/// redundant separators and dot segments. Release metadata paths are literal
/// filesystem names and must never pass through this URI-only helper.
fn registry_path_from_uri(raw_uri_path: &str) -> Cow<'_, str> {
    let normalized = normalize_uri_path(raw_uri_path);
    if normalized.contains('%') {
        Cow::Owned(
            percent_encoding::percent_decode_str(normalized.trim_start_matches('/'))
                .decode_utf8()
                .expect("classified URI path is valid UTF-8")
                .into_owned(),
        )
    } else {
        match normalized {
            Cow::Borrowed(path) => Cow::Borrowed(path.trim_start_matches('/')),
            Cow::Owned(path) => Cow::Owned(path.trim_start_matches('/').to_owned()),
        }
    }
}

/// The host-relative directory a `dists/.../Release` file lives in,
/// normalized like the cache path (`//` runs and `.` segments collapse), so
/// every spelling of one `Release` registers the keys [`digest_source`]
/// looks up.
///
/// `Release.gpg` is a detached signature with no SHA256 section, so it is
/// excluded.
fn release_dir_from_uri_path(raw_uri_path: &str) -> Option<String> {
    let normalized = registry_path_from_uri(raw_uri_path);
    let (dir, leaf) = normalized.rsplit_once('/')?;
    if !matches!(leaf, "Release" | "InRelease") {
        return None;
    }
    Some(dir.to_owned())
}

/// Where the digest a download is verified against comes from.
#[derive(Debug, PartialEq, Eq)]
enum DigestSource<'a> {
    /// Self-verifying by-hash URL: the digest is the URL leaf, hashed with
    /// the algorithm its `<algo>` segment named.
    InUrl(HashAlgo),
    /// The checksum registry, under this key, always SHA-256 (layer B: a
    /// pool `.deb`'s bare basename; layer C: a `Packages` index's
    /// host-relative path).
    Registry(Cow<'a, str>),
    /// No digest: verification is disabled, or the kind has none today
    /// ([`VerifyKind::Unverifiable`]).
    Absent,
}

/// Shared by [`verify_and_rename`]'s commit-time decision and the
/// splice-only `stream_hash_algo_for_download`'s pre-download one, which
/// must agree about which digest decides a download.
fn digest_source<'a>(
    resource_kind: ResourceKind,
    debname: &'a str,
    raw_uri_path: &'a str,
    verify_enabled: bool,
) -> DigestSource<'a> {
    if !verify_enabled {
        return DigestSource::Absent;
    }
    match resource_kind {
        ResourceKind::ByHash(algo, _) | ResourceKind::FlatByHash(algo, _) => {
            DigestSource::InUrl(algo)
        }
        // Layer B: a pool .deb's key is its bare basename, the form
        // `PendingDigests::push_stanza` registers. Flat-pool downloads are
        // not verified this way, so no flat variant is needed.
        ResourceKind::Pool => DigestSource::Registry(Cow::Borrowed(debname)),
        // Layer C: the full host-relative URI path, normalized like the
        // `release_dir` `ingest_release_file` inserted it under
        // ("<release_dir>/<rel>").
        ResourceKind::Packages => DigestSource::Registry(registry_path_from_uri(raw_uri_path)),
        // A pdiff patch: APT checks it against `SHA256-Download` in its
        // `Packages.diff/Index`; ingesting that `Index` to verify here too is
        // a possible follow-up.
        ResourceKind::Release
        | ResourceKind::ComponentRelease
        | ResourceKind::Sources
        | ResourceKind::Translation
        | ResourceKind::Icon
        | ResourceKind::FlatMetadata
        | ResourceKind::FlatPool
        | ResourceKind::Pdiff => DigestSource::Absent,
    }
}

/// Which digest, if any, a download will be verified against, decided from
/// the request alone so a body loop can hash incrementally and spare
/// [`verify_temp_file`] its re-read of the finished file.
///
/// A [`DigestSource::Registry`] kind is not simply `Some(Sha256)`: when the
/// lookup misses (the ordinary state on a cold cache) `verify_temp_file`
/// hashes nothing, so a several-hundred-megabyte `.deb` would be hashed
/// inline on the worker for a digest nothing ever compares. A disagreement
/// with the commit-time decision (the registry gained or lost the digest in
/// between) is safe: a registry that gains the digest falls back to the
/// re-read, and one that loses it discards a digest.
#[cfg(feature = "splice")]
#[must_use]
pub(crate) fn stream_hash_algo_for_download(
    resource_kind: ResourceKind,
    raw_uri_path: &str,
    debname: &str,
    authority: &str,
    mirror_path: &str,
) -> Option<HashAlgo> {
    match digest_source(
        resource_kind,
        debname,
        raw_uri_path,
        global_config().verify_checksums,
    ) {
        DigestSource::InUrl(algo) => Some(algo),
        DigestSource::Registry(key) => global_checksum_registry()
            .lookup(authority, mirror_path, &key)
            .map(|_digest| HashAlgo::Sha256),
        DigestSource::Absent => None,
    }
}

/// Detect Packages compression from magic bytes, for by-hash content whose
/// URL leaf carries no extension. Falls back to `Raw`: a corrupt or
/// unexpected payload then yields zero stanzas.
///
/// Reads `file` from its start and rewinds it after, so the caller parses
/// the same descriptor.
async fn sniff_packages_compression(
    file: &mut tokio::fs::File,
) -> std::io::Result<PackagesCompression> {
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    // Tolerate short reads and early EOF (a tiny raw `Packages` file is
    // valid and classifies as `Raw`, not an error).
    let mut buf = [0u8; 6];
    let mut n = 0;
    while n < buf.len() {
        match file.read(&mut buf[n..]).await? {
            0 => break,
            read => n += read,
        }
    }
    file.rewind().await?;
    // gzip: 1F 8B; xz: FD 37 7A 58 5A 00.
    if n >= 2 && buf[0] == 0x1F && buf[1] == 0x8B {
        Ok(PackagesCompression::Gz)
    } else if n >= 6 && &buf[..6] == b"\xfd7zXZ\x00" {
        Ok(PackagesCompression::Xz)
    } else {
        Ok(PackagesCompression::Raw)
    }
}

/// Stream a (possibly compressed) `Packages` file and insert every
/// `(Filename, SHA256)` pair into `registry`. A `None` `compression` is
/// sniffed from the file's magic bytes.
///
/// Guards against decompression bombs: [`crate::limits::decompressed_limit`]
/// caps total decompressed output, and line length is capped at
/// [`crate::limits::MAX_METADATA_LINE_LEN`]. What was read before a cap (or
/// any other error) stays registered.
async fn ingest_packages_file(
    registry: &ChecksumRegistry,
    authority: &str,
    mirror_path: &str,
    path: &Path,
    compression: Option<PackagesCompression>,
    buffer_size: usize,
) -> std::io::Result<()> {
    let mut file = nofollow_nonblock_options()
        .read(true)
        .open_async(path)
        .await?;
    let metadata = file.metadata().await?;
    // Before sniffing or decoding: a FIFO would block the read.
    require_regular_index(&metadata)?;
    let compression = match compression {
        Some(compression) => compression,
        None => sniff_packages_compression(&mut file).await?,
    };
    let compressed_size = metadata.len();
    limits::check_packages_file_size(compression, compressed_size)?;
    let reader = limits::packages_reader(
        limits::PackagesInput::File(file),
        compression,
        limits::decompressed_limit(NonZero::new(compressed_size)),
        buffer_size,
    )
    .await;

    let mut stanzas = StanzaStream::new(
        reader,
        index_parser::Stanza::new_sha256_only().with_source(format!(
            "{authority}/{mirror_path} index `{}`",
            path.display(),
        )),
    );
    let mut pending = PendingDigests::default();
    loop {
        match stanzas.next().await {
            Ok(Some(stanza)) => {
                if pending.push_stanza(stanza, authority, mirror_path) {
                    pending.flush(registry, authority, mirror_path);
                }
            }
            Ok(None) => {
                pending.flush(registry, authority, mirror_path);
                return Ok(());
            }
            Err(err) => {
                pending.flush(registry, authority, mirror_path);
                warn_once_or_debug!(
                    "Failed to read `{}` during Packages ingestion (may exceed size/line limits); aborting the ingest of this index:  {}",
                    path.display(),
                    ErrorReport(&err),
                );
                return Err(err);
            }
        }
    }
}

/// Read a cached `Release` / `InRelease` file with the cache's standard
/// hardening: a nonblocking, symlink-refusing open, a regular-file check,
/// and a read capped at `MAX_RELEASE_SIZE`, so a hostile or buggy mirror
/// serving a multi-GB `Release` (which passes the `max_object_size`
/// admission check) cannot balloon memory. An over-cap file fails with
/// `io::ErrorKind::InvalidData` rather than truncating silently.
pub(crate) async fn read_release_to_string(path: &Path) -> std::io::Result<String> {
    read_release(path).await.map(|(content, _mtime)| content)
}

/// [`read_release_to_string`], with the modification time of the file read
/// (its `fstat`, so the pair describes one inode).
///
/// One blocking-pool hop for the whole read; through `tokio::fs` the open,
/// the `fstat` and every read are a hop each, about fifteen for the
/// 50-200 KiB `InRelease` a commit ingests after every index download.
async fn read_release(path: &Path) -> std::io::Result<(String, std::time::SystemTime)> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || read_release_sync(&path))
        .await
        .unwrap_or_else(|err| Err(std::io::Error::other(err)))
}

fn read_release_sync(path: &Path) -> std::io::Result<(String, std::time::SystemTime)> {
    use std::io::Read as _;

    let file = nofollow_nonblock_options().read(true).open(path)?;
    let metadata = file.metadata()?;
    require_regular_index(&metadata)?;
    let mtime = metadata
        .modified()
        .expect("Platform should support modification timestamps via setup check");
    let limit = limits::MAX_RELEASE_SIZE.get();
    // Sized from the fstat so the buffer never regrows; a file grown since is
    // still bounded by the `take` below. The read is three calls, not two:
    // `Take` passes no size hint, so std starts with an 8 KiB read before it
    // fills the rest and probes for EOF.
    let capacity = usize::try_from(metadata.len().min(limit)).unwrap_or(0);
    let mut buf = String::with_capacity(capacity);
    // One byte past the cap tells an over-cap file from one exactly at it.
    let read = (&file).take(limit + 1).read_to_string(&mut buf)?;
    if read as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Release file exceeds the size limit",
        ));
    }
    Ok((buf, mtime))
}

/// How far ahead of the wall clock a parsed `Date:` may be before
/// [`clamp_future_release_date`] treats it as absent. One day tolerates
/// ordinary clock skew between this host and the mirror while still
/// rejecting a repository clock error or a one-time MITM that pushed the
/// date forward on plaintext HTTP: without a clamp such a date would never
/// be superseded (an undated source never overwrites a dated one), so the
/// corrected `Release` a mirror serves later would keep being refused and
/// its named `Packages` downloads kept unverified and throttled.
const FUTURE_RELEASE_DATE_TOLERANCE_SECS: i64 = 24 * 60 * 60;

/// Treat a parsed `Date:` more than [`FUTURE_RELEASE_DATE_TOLERANCE_SECS`]
/// ahead of now as if the field were absent: the implausible date still
/// registers its entries (so a cold cache verifies against them) but can
/// never pin the directory against a later, honestly-dated `Release`.
fn clamp_future_release_date(date: Option<i64>) -> Option<i64> {
    let date = date?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if date > now.saturating_add(FUTURE_RELEASE_DATE_TOLERANCE_SECS) {
        None
    } else {
        Some(date)
    }
}

/// Parse a `Release` / `InRelease` file and insert its `Packages*` entries
/// (the only `Release`-listed resources the proxy verifies, layer C) into
/// the registry. `release_dir` is the host-relative directory the file
/// lives in; its entry paths are relative to it.
///
/// An older `Date:` than the directory's registered one registers nothing
/// and still returns `Ok`.
///
/// Returns what the file said about its age for `mirror_indexes`, with the
/// file's mtime as the time the mirror last served or confirmed it (a
/// commit writes the file, an upstream 304 touches it).
async fn ingest_release_file(
    registry: &ChecksumRegistry,
    authority: &str,
    mirror_path: &str,
    path: &Path,
    release_dir: &str,
) -> std::io::Result<SuiteIndex> {
    let (content, mtime) = read_release(path).await?;
    let header = index_parser::parse_release_header(&content);
    let date = clamp_future_release_date(header.date);
    let dir = release_dir.trim_end_matches('/');
    let slots: Vec<Slot> = index_parser::parse_release_checksums(&content, |rel| {
        let leaf = rel.rsplit_once('/').map_or(rel, |(_, leaf)| leaf);
        PackagesCompression::from_filename(leaf).is_some()
    })
    .map(|(rel, digest)| Slot {
        // The host-relative key (matches the Packages lookup key):
        // <release_dir>/<rel>.
        key: fingerprint_joined([dir, "/", rel]),
        digest,
        kind: KeyKind::Index,
    })
    .collect();
    if !registry.insert_release(authority, mirror_path, release_dir, date, &slots) {
        debug!(
            "Not registering index `{}` for host {authority} mirror {mirror_path}; a newer Release/InRelease of `{release_dir}` is already registered",
            path.display(),
        );
    }
    Ok(SuiteIndex {
        header: ReleaseHeader {
            date,
            valid_until: header.valid_until,
        },
        confirmed_at: time::OffsetDateTime::from(mtime).unix_timestamp(),
    })
}

/// The digests of one `Packages` ingest not yet registered. Batched so the
/// registry lock (which every cache miss's digest lookup also takes) is
/// taken once per [`Self::BATCH`] rather than once per stanza (~65k for
/// Debian), with the fingerprints computed outside it.
#[derive(Default)]
struct PendingDigests {
    slots: Vec<Slot>,
}

impl PendingDigests {
    /// Entries per lock: short enough that a concurrent lookup waits
    /// microseconds, not the ingest.
    const BATCH: usize = 256;

    /// Whether the batch is full. A stanza without a usable SHA256 (a
    /// SHA512-only mirror leaves every stanza that way) was already warned
    /// about by [`StanzaStream`] and registers nothing.
    fn push_stanza(
        &mut self,
        stanza: &index_parser::Stanza,
        authority: &str,
        mirror_path: &str,
    ) -> bool {
        let (Some(filename), Some(sha256)) = (stanza.filename(), stanza.sha256) else {
            return false;
        };
        let Some(key) = stanza.registry_key() else {
            // `Stanza` already rejected (and logged) unsafe values, so this
            // is the length gate: a name no cache file can have.
            warn_once_or_debug!(
                "Not registering the digest of a {} byte Filename value from host {authority} mirror {mirror_path}; no cache file can have that name",
                filename.len(),
            );
            return false;
        };
        self.slots.push(Slot {
            key: fingerprint(key),
            digest: sha256,
            kind: KeyKind::Package,
        });
        self.slots.len() >= Self::BATCH
    }

    fn flush(&mut self, registry: &ChecksumRegistry, authority: &str, mirror_path: &str) {
        if self.slots.is_empty() {
            return;
        }
        registry.insert_many(authority, mirror_path, &self.slots);
        self.slots.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs_open::nofollow_options;
    use crate::test_support::{gzip, structured_mirror};
    use std::io::Write as _;

    fn temp_file_with(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(content).expect("write temp file");
        f.flush().expect("flush");
        f
    }

    // sha256("hello world")
    const HELLO_SHA256: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    #[tokio::test]
    async fn packages_ingests_run_at_most_two_at_a_time() {
        use std::cell::Cell;

        let running = Cell::new(0);
        // Other tests may ingest through the process-global decode semaphore.
        let permits = Semaphore::new(PACKAGES_INGEST_CONCURRENCY);
        let release = Semaphore::new(0);
        let mut tasks: Vec<_> = std::iter::repeat_with(|| {
            Box::pin(with_decode_permit(&permits, async {
                running.set(running.get() + 1);
                release
                    .acquire()
                    .await
                    .expect("release gate stays open")
                    .forget();
                running.set(running.get() - 1);
            }))
        })
        .take(6)
        .collect();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for task in &mut tasks {
            assert!(task.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(running.get(), PACKAGES_INGEST_CONCURRENCY);
        release.add_permits(tasks.len());
        futures_util::future::join_all(tasks).await;
        assert_eq!(running.get(), 0);
        assert_eq!(permits.available_permits(), PACKAGES_INGEST_CONCURRENCY);
    }

    #[test]
    fn verify_temp_file_table() {
        let expected = || byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256);
        let hello = || {
            index_parser::byhash_digest_for_algo(HashAlgo::Sha256, HELLO_SHA256)
                .expect("HELLO_SHA256 is valid hex")
        };
        let zero256 = || Digest::Sha256(Box::new([0u8; 32]));
        let zero512 = || Digest::Sha512(Box::new([0u8; 64]));
        let streamed = |digest, bytes| Some(StreamedDigest { digest, bytes });
        for (label, content, kind, streamed, matches) in [
            ("by-hash match", "hello world", expected(), None, true),
            ("by-hash mismatch", "tampered", expected(), None, false),
            // The on-disk body is wrong, so passing proves it was not re-read.
            (
                "streamed digest used instead of a re-read",
                "not hello at all",
                expected(),
                streamed(hello(), 16),
                true,
            ),
            (
                "streamed digest mismatch",
                "hello world",
                expected(),
                streamed(zero256(), 11),
                false,
            ),
            (
                "streamed digest of another algorithm: re-read",
                "hello world",
                expected(),
                streamed(zero512(), 11),
                true,
            ),
            (
                "streamed digest over more bytes than the file holds: re-read",
                "hello world",
                expected(),
                streamed(zero256(), 999),
                true,
            ),
            (
                "unverifiable kind",
                "anything",
                VerifyKind::Unverifiable,
                None,
                true,
            ),
            (
                "unknown digest",
                "some deb",
                VerifyKind::Unknown,
                None,
                true,
            ),
        ] {
            let f = temp_file_with(content.as_bytes());
            let result = verify_temp_file(&VerifyInput {
                kind,
                file: f.as_file(),
                meta: &f.as_file().metadata().unwrap(),
                temp_path: f.path(),
                streamed,
            });
            if matches {
                assert!(matches!(result, Ok(())), "{label}: {result:?}");
            } else {
                assert!(
                    matches!(result, Err(CommitError::ChecksumMismatch)),
                    "{label}: {result:?}"
                );
            }
        }
    }

    #[test]
    fn digest_source_table() {
        const POOL: &str = "/debian/pool/main/h/hello/hello_1.0_amd64.deb";

        assert_eq!(
            digest_source(
                ResourceKind::ByHash(HashAlgo::Sha512, ByHashContent::Other),
                "x",
                POOL,
                true
            ),
            DigestSource::InUrl(HashAlgo::Sha512)
        );
        assert_eq!(
            digest_source(
                ResourceKind::FlatByHash(HashAlgo::Sha256, ByHashContent::Other),
                "x",
                POOL,
                true
            ),
            DigestSource::InUrl(HashAlgo::Sha256)
        );
        assert_eq!(
            digest_source(ResourceKind::Pool, "hello_1.0_amd64.deb", POOL, true),
            DigestSource::Registry("hello_1.0_amd64.deb".into())
        );
        assert_eq!(
            digest_source(
                ResourceKind::Packages,
                "Packages.xz",
                "/dists/sid/main/binary-amd64/Packages.xz",
                true
            ),
            DigestSource::Registry("dists/sid/main/binary-amd64/Packages.xz".into())
        );
        // Every spelling of one URL looks up the key a normalized
        // `release_dir` registered.
        assert_eq!(
            digest_source(
                ResourceKind::Packages,
                "Packages.xz",
                "/debian//dists/./sid/main/binary-amd64/Packages.xz",
                true
            ),
            DigestSource::Registry("debian/dists/sid/main/binary-amd64/Packages.xz".into())
        );
        for kind in [
            ResourceKind::Release,
            ResourceKind::ComponentRelease,
            ResourceKind::Sources,
            ResourceKind::Translation,
            ResourceKind::Icon,
            ResourceKind::FlatMetadata,
            ResourceKind::FlatPool,
            ResourceKind::Pdiff,
        ] {
            assert_eq!(
                digest_source(kind, "hello_1.0_amd64.deb", POOL, true),
                DigestSource::Absent,
                "{kind:?}"
            );
        }
    }

    #[test]
    fn disabled_yields_no_digest_source() {
        const BYHASH: ResourceKind = ResourceKind::ByHash(HashAlgo::Sha256, ByHashContent::Other);
        assert_eq!(
            digest_source(BYHASH, HELLO_SHA256, "/x", false),
            DigestSource::Absent
        );
        assert_eq!(
            digest_source(ResourceKind::Pool, "hello_1.0_amd64.deb", "/x", false),
            DigestSource::Absent
        );
    }

    #[test]
    fn unreadable_temp_file_returns_reject_verifyio() {
        let f = temp_file_with(b"hello world");
        let write_only = nofollow_options()
            .write(true)
            .open(f.path())
            .expect("open write-only");
        let plan = VerifyInput {
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            file: &write_only,
            meta: &write_only.metadata().unwrap(),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(
            verify_temp_file(&plan),
            Err(CommitError::VerifyIo(_))
        ));
    }

    #[test]
    fn registry_insert_and_lookup() {
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        reg.insert(
            "deb.debian.org",
            "debian",
            "pool/main/f/foo/foo_1_amd64.deb",
            [1u8; 32],
        );
        assert_eq!(
            reg.lookup(
                "deb.debian.org",
                "debian",
                "pool/main/f/foo/foo_1_amd64.deb"
            ),
            Some([1u8; 32])
        );
        assert_eq!(
            reg.lookup("deb.debian.org", "debian", "pool/main/f/foo/other.deb"),
            None
        );
        assert_eq!(
            reg.lookup("other.host", "debian", "pool/main/f/foo/foo_1_amd64.deb"),
            None
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_discriminates_mirrors_on_same_host() {
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        reg.insert("host", "m1", "foo_1_amd64.deb", [1u8; 32]);
        reg.insert("host", "m2", "foo_1_amd64.deb", [2u8; 32]);
        assert_eq!(reg.lookup("host", "m1", "foo_1_amd64.deb"), Some([1u8; 32]));
        assert_eq!(reg.lookup("host", "m2", "foo_1_amd64.deb"), Some([2u8; 32]));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn registry_explains_a_miss_by_what_the_scope_holds() {
        const INDEX: &str = "dists/sid/main/binary-arm64/Packages.xz";
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        let miss = |kind, held| RegistryMiss {
            kind,
            held,
            evicted: false,
        };

        // Nothing ingested for the mirror at all.
        assert_eq!(
            reg.explain_miss("h", "debian", "a_1_arm64.deb"),
            miss(KeyKind::Package, 0)
        );

        // Only its `Release` so far (a restart, then an `InRelease` touch):
        // the scope exists, but a deb lookup is as cold as before.
        assert!(reg.insert_release(
            "h",
            "debian",
            "dists/sid",
            None,
            &[Slot::for_key(INDEX, [0; 32])]
        ));
        assert_eq!(
            reg.explain_miss("h", "debian", "a_1_arm64.deb"),
            miss(KeyKind::Package, 0)
        );
        assert_eq!(
            reg.explain_miss("h", "debian", "dists/sid/main/binary-amd64/Packages.xz"),
            miss(KeyKind::Index, 1)
        );

        // A `Packages` ingest; a refreshed key is not counted twice.
        reg.insert("h", "debian", "b_1_arm64.deb", [1; 32]);
        reg.insert("h", "debian", "c_1_arm64.deb", [2; 32]);
        reg.insert("h", "debian", "c_1_arm64.deb", [3; 32]);
        assert_eq!(
            reg.explain_miss("h", "debian", "a_1_arm64.deb"),
            miss(KeyKind::Package, 2)
        );
        // Another mirror of the same host stays cold.
        assert_eq!(
            reg.explain_miss("h", "debian-security", "a_1_arm64.deb"),
            miss(KeyKind::Package, 0)
        );
    }

    #[test]
    fn registry_miss_counts_survive_eviction() {
        let reg = ChecksumRegistry::new(NonZero::new(8).unwrap());
        assert!(reg.insert_release(
            "h",
            "m",
            "dists/sid",
            None,
            &[Slot::for_key(
                "dists/sid/main/binary-arm64/Packages.xz",
                [0; 32]
            )]
        ));
        for i in 0..8u8 {
            reg.insert("h", "m", &format!("p{i}_1_arm64.deb"), [i; 32]);
        }
        // Nine entries at a cap of eight: the two oldest went, the index
        // digest and the first package.
        assert_eq!(reg.len(), 7);
        assert_eq!(
            reg.explain_miss("h", "m", "p0_1_arm64.deb"),
            RegistryMiss {
                kind: KeyKind::Package,
                held: 7,
                evicted: true,
            }
        );
        assert_eq!(
            reg.explain_miss("h", "m", "dists/sid/main/binary-arm64/Packages.xz"),
            RegistryMiss {
                kind: KeyKind::Index,
                held: 0,
                evicted: true,
            }
        );
    }

    #[test]
    fn registry_miss_display() {
        let miss = |kind, held, evicted| {
            RegistryMiss {
                kind,
                held,
                evicted,
            }
            .to_string()
        };
        assert_eq!(
            miss(KeyKind::Package, 0, false),
            "none held from this mirror's Packages indexes"
        );
        assert_eq!(
            miss(KeyKind::Package, 68_412, false),
            "not among the 68412 held from this mirror's Packages indexes"
        );
        assert_eq!(
            miss(KeyKind::Package, 68_412, true),
            "not among the 68412 held from this mirror's Packages indexes, after evictions"
        );
        assert_eq!(
            miss(KeyKind::Index, 0, true),
            "none held from this mirror's Release files, after evictions"
        );
    }

    #[test]
    fn registry_evicts_oldest_at_cap() {
        let reg = ChecksumRegistry::new(NonZero::new(4).unwrap());
        for i in 0..4u8 {
            reg.insert("h", "m", &format!("p{i}"), [i; 32]);
        }
        assert_eq!(reg.len(), 4);
        reg.insert("h", "m", "p4", [4u8; 32]);
        assert!(reg.len() <= 4, "registry stayed within cap");
        assert_eq!(
            reg.lookup("h", "m", "p4"),
            Some([4u8; 32]),
            "newest entry present"
        );
        assert_eq!(reg.lookup("h", "m", "p0"), None, "oldest entry evicted");
    }

    #[test]
    fn registry_evicts_from_the_largest_scope_first() {
        // One hostile index (scope B) must not evict another mirror's
        // digests (scope A): at the cap, the largest scope pays.
        let reg = ChecksumRegistry::new(NonZero::new(8).unwrap());
        for i in 0..4u8 {
            reg.insert("a", "m", &format!("a{i}"), [i; 32]);
        }
        for i in 0..8u8 {
            reg.insert("b", "m", &format!("b{i}"), [i; 32]);
        }
        assert!(reg.len() <= 8, "registry stayed within cap");
        for i in 0..4u8 {
            assert!(
                reg.lookup("a", "m", &format!("a{i}")).is_some(),
                "a{i} must survive eviction driven by scope b"
            );
        }
        assert!(reg.lookup("b", "m", "b0").is_none(), "b's oldest evicted");
        assert!(reg.lookup("b", "m", "b7").is_some(), "b's newest present");
    }

    #[test]
    fn registry_evicts_once_per_batch_including_the_overshoot() {
        let reg = ChecksumRegistry::new(NonZero::new(8).unwrap());
        for i in 0..4u8 {
            reg.insert("a", "m", &format!("a{i}"), [i; 32]);
        }
        let batch: Vec<Slot> = (0..12u8)
            .map(|i| Slot::for_key(&format!("b{i}"), [i; 32]))
            .collect();
        reg.insert_many("b", "m", &batch);

        // 16 entries at a cap of 8: the pass frees 2 (a quarter of the cap)
        // plus the 7 past the ninth, all from the largest scope, oldest first.
        assert_eq!(reg.len(), 7);
        for i in 0..4u8 {
            assert!(reg.lookup("a", "m", &format!("a{i}")).is_some(), "a{i}");
        }
        for i in 0..12u8 {
            assert_eq!(
                reg.lookup("b", "m", &format!("b{i}")).is_some(),
                i >= 9,
                "b{i}"
            );
        }
        assert_eq!(reg.scope_epoch("b", "m"), 1, "one pass");
        assert_eq!(reg.scope_epoch("a", "m"), 0);
    }

    #[test]
    fn eviction_drains_scopes_in_size_order_and_stops_at_the_quota() {
        let reg = ChecksumRegistry::new(NonZero::new(2).unwrap());
        {
            let mut inner = reg.inner.lock();
            for (host, count) in [("largest", 4), ("medium", 3), ("small", 2), ("tiny", 1)] {
                let slots: Vec<_> = (0..count)
                    .map(|i| Slot::for_key(&format!("p{i}"), [0; 32]))
                    .collect();
                let _scope = inner.insert(host, "m", &slots);
            }
            // Ten live entries at cap two: remove eight, draining the
            // largest two scopes and only the oldest of the third.
            evict(&mut inner, 2, &reg.epochs);
            assert_eq!(inner.len, 2);
            assert_eq!(inner.map.len(), 2);
        }
        assert_eq!(reg.lookup("small", "m", "p0"), None);
        assert_eq!(reg.lookup("small", "m", "p1"), Some([0; 32]));
        assert_eq!(reg.lookup("tiny", "m", "p0"), Some([0; 32]));
        assert_eq!(reg.scope_epoch("largest", "m"), 1);
        assert_eq!(reg.scope_epoch("medium", "m"), 2);
        assert_eq!(reg.scope_epoch("small", "m"), 3);
        assert_eq!(reg.scope_epoch("tiny", "m"), 0);
    }

    #[test]
    fn eviction_shrinks_the_scope_it_drains() {
        // One scope fills the cap, then another mirror's inserts make it pay
        // for the evictions.
        let reg = ChecksumRegistry::new(NonZero::new(1000).unwrap());
        for i in 0..1000u32 {
            reg.insert("big", "m", &format!("b{i}"), [0; 32]);
        }
        let (_, peak_capacity, _, _) = reg.scope_footprint("big", "m");
        for i in 0..600u32 {
            reg.insert("small", "m", &format!("s{i}"), [0; 32]);
        }
        let (len, capacity, slot_len, slot_capacity) = reg.scope_footprint("big", "m");
        assert!(len <= 500, "big paid for the evictions, {len} left");
        assert!(
            capacity <= 2 * len + 16 && capacity < peak_capacity,
            "entry capacity {capacity} for {len} entries (peak {peak_capacity})"
        );
        assert!(
            slot_capacity <= 2 * slot_len + 16,
            "slot capacity {slot_capacity} for {slot_len} slots"
        );
    }

    #[test]
    fn a_full_epoch_map_forgets_every_scope_and_stales_every_mark() {
        let scope = |host: &str| {
            Arc::new(RegistryScope {
                authority: host.to_owned(),
                mirror_path: "m".to_owned(),
            })
        };
        let mut epochs = EvictionEpochs::new(2);
        let untouched_mark = epochs.get("d", "m");
        epochs.bump(&scope("a"));
        epochs.bump(&scope("b"));
        let (mark_a, mark_b) = (epochs.get("a", "m"), epochs.get("b", "m"));
        assert_ne!(mark_a, untouched_mark);
        assert_ne!(mark_a, mark_b);
        epochs.bump(&scope("a"));
        assert_ne!(epochs.get("a", "m"), mark_a, "a re-bump changes the epoch");
        assert_eq!(
            epochs.by_scope.len(),
            2,
            "a mapped scope is not a new entry"
        );
        let mark_a = epochs.get("a", "m");

        epochs.bump(&scope("c"));
        assert_eq!(epochs.by_scope.len(), 1, "the full map was cleared");
        for (host, mark) in [("a", mark_a), ("b", mark_b), ("d", untouched_mark)] {
            assert_ne!(
                epochs.get(host, "m"),
                mark,
                "{host}'s old mark must read stale"
            );
        }
        assert_ne!(epochs.get("c", "m"), epochs.get("a", "m"));
    }

    #[test]
    fn eviction_bumps_the_epoch_of_each_drained_scope() {
        let reg = ChecksumRegistry::new(NonZero::new(8).unwrap());
        for i in 0..8u32 {
            reg.insert("big", "m", &format!("b{i}"), [0; 32]);
        }
        reg.insert("small", "m", "s0", [0; 32]);
        assert_eq!(reg.scope_epoch("small", "m"), 0);
        assert_eq!(reg.scope_epoch("never", "m"), 0);
        // The ninth insert crossed the cap: `big` (the largest scope) paid.
        assert_eq!(reg.scope_epoch("big", "m"), 1);

        // Fully drain `big` (6 live entries left: b2..b7). Each retrigger
        // cycle needs `quota` (2) new entries; parking them in brand-new,
        // never-grown, one-entry scopes keeps every one of them below
        // `big`'s shrinking count (6, then 4, then 2), so `big` stays the
        // largest scope -- and so eviction's target -- through all three
        // passes, until it empties and is dropped from `map`.
        for i in 0..6u32 {
            reg.insert(&format!("p{i}"), "m", "x", [0; 32]);
        }
        for i in 0..8u32 {
            assert_eq!(
                reg.lookup("big", "m", &format!("b{i}")),
                None,
                "big must be fully drained, b{i} still present"
            );
        }
        // A scope drained empty and removed from `map` keeps its epoch.
        assert!(reg.scope_epoch("big", "m") > 0);
    }

    #[test]
    fn registry_reinsert_refreshes_value() {
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        reg.insert("h", "m", "p", [1u8; 32]);
        reg.insert("h", "m", "p", [2u8; 32]);
        assert_eq!(reg.lookup("h", "m", "p"), Some([2u8; 32]));
        assert_eq!(reg.len(), 1);
    }

    /// A decoy `by-hash/` run in front of the validated (last) one must not
    /// flip the answer either way.
    #[test]
    fn byhash_ingest_is_decided_by_the_parsed_directory() {
        use crate::{
            cache_layout::classify_request, deb_mirror::parse_request_path,
            test_support::local_client,
        };

        for (path, expected) in [
            ("debian/dists/sid/main/binary-amd64", true),
            ("debian/dists/sid/main/source", true),
            // Deeper than the origin scope, still a `Packages` directory.
            ("debian/dists/sid/main/debian-installer/binary-amd64", true),
            ("debian/dists/sid/main/dep11", false),
            ("debian/dists/sid/main", false),
            ("debian/dists", false),
            ("debian/dists/sid/main/binary-amd64/Packages.diff", false),
            // Decoys: the directory before the first `by-hash` said otherwise.
            ("debian/dists/sid/main/binary-amd64/by-hash/MD5Sum", false),
            ("debian/dists/sid/main/i18n/by-hash/X/binary-amd64", true),
            // A flat repository feeds no registry.
            ("apt/binary-amd64", false),
            ("apt", false),
        ] {
            let path = format!("{path}/by-hash/SHA256/{HELLO_SHA256}");
            let resource = parse_request_path(&path).expect("parses as a by-hash object");
            let class = classify_request(&resource, &local_client()).expect("classifies");
            let raw_uri_path = format!("/{path}");
            let kind = ingest_kind(&IndexFile {
                resource_kind: class.resource_kind,
                debname: &class.debname,
                raw_uri_path: &raw_uri_path,
                mirror: &structured_mirror("h", &class.mirror_path),
                path: Path::new("/cache/x"),
            });
            let sniffed = matches!(kind, Some(IngestKind::Packages { compression: None }));
            assert!(sniffed || kind.is_none(), "{path}: unexpected ingest kind");
            assert_eq!(sniffed, expected, "{path}");
        }
    }

    /// Verification bypass: a decoy `by-hash/X/` in front of the validated
    /// (last) one must not hide the algorithm and get the object cached
    /// unverified.
    #[test]
    fn byhash_decoy_segment_does_not_disable_verification() {
        use crate::{
            cache_layout::classify_request, deb_mirror::parse_request_path,
            test_support::local_client,
        };

        for path in [
            format!("debian/dists/by-hash/X/by-hash/SHA256/{HELLO_SHA256}"),
            format!(
                "debian/dists/sid/main/binary-amd64/by-hash/MD5Sum/by-hash/SHA256/{HELLO_SHA256}"
            ),
        ] {
            let resource = parse_request_path(&path).expect("parses as a by-hash object");
            let class = classify_request(&resource, &local_client()).expect("classifies");
            let algo = if let ResourceKind::ByHash(algo, _) = class.resource_kind {
                Some(algo)
            } else {
                None
            };
            assert_eq!(algo, Some(HashAlgo::Sha256), "{path}");
            let algo = algo.expect("asserted above");

            let f = temp_file_with(b"not hello world");
            let plan = VerifyInput {
                kind: byhash_verify_kind(algo, &class.debname),
                file: f.as_file(),
                meta: &f.as_file().metadata().unwrap(),
                temp_path: f.path(),
                streamed: None,
            };
            assert!(
                matches!(verify_temp_file(&plan), Err(CommitError::ChecksumMismatch)),
                "{path}"
            );
        }
    }

    #[test]
    fn byhash_length_algo_mismatch_caches_unverified() {
        // A SHA512 URL segment carrying a 64-hex digest must NOT be hashed as
        // SHA256: cached unverified, never a spurious mismatch.
        let kind = byhash_verify_kind(HashAlgo::Sha512, HELLO_SHA256);
        assert!(
            matches!(kind, VerifyKind::Unknown),
            "a digest whose length contradicts its URL algorithm must not become an expectation"
        );
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            kind,
            file: f.as_file(),
            meta: &f.as_file().metadata().unwrap(),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), Ok(())));
    }

    #[test]
    fn byhash_well_formed_pair_becomes_an_expectation() {
        let resolved = match byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256) {
            VerifyKind::Expected(digest) => Some((digest.algo(), digest)),
            VerifyKind::Unknown | VerifyKind::Unverifiable => None,
        };
        let (algo, digest) = resolved.expect("a matching algorithm/digest pair must be verifiable");
        assert_eq!(algo, HashAlgo::Sha256);
        assert_eq!(index_parser::hex_encode(&digest), HELLO_SHA256);
    }

    #[test]
    fn registry_uri_identity_decodes_validated_segments_exactly_once() {
        for path in [
            "/debian/dists/sid/main/binary-amd64/Packages",
            "/%64ebian//dists/./%73id/%6dain/binary-%61md64/Packages",
        ] {
            assert_eq!(
                digest_source(ResourceKind::Packages, "Packages", path, true),
                DigestSource::Registry("debian/dists/sid/main/binary-amd64/Packages".into())
            );
        }
        assert_eq!(
            registry_path_from_uri("/debian/dists/%2573id/Release"),
            "debian/dists/%73id/Release"
        );
    }

    #[test]
    fn release_dir_extraction() {
        // Normalized and decoded like the Packages lookup key.
        for path in [
            "/debian/dists/sid/Release",
            "/debian/dists/sid/InRelease",
            "/debian//dists/./sid/InRelease",
            "/%64ebian/dists/%73id/Release",
        ] {
            assert_eq!(
                release_dir_from_uri_path(path).as_deref(),
                Some("debian/dists/sid"),
                "{path}"
            );
        }
        assert_eq!(release_dir_from_uri_path("/debian/pool/x/foo.deb"), None);
        // Release.gpg has no SHA256 section.
        assert_eq!(
            release_dir_from_uri_path("/debian/dists/sid/Release.gpg"),
            None
        );
    }

    #[tokio::test]
    async fn ingest_release_populates_packages_digests() {
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        let pkg_sha = [0x77u8; 32];
        let release = format!(
            "Origin: Test\nSHA256:\n 0000000000000000000000000000000000000000000000000000000000000000 1 main/binary-amd64/Release\n {} 4242 main/binary-amd64/Packages.xz\n",
            index_parser::hex_encode(&pkg_sha),
        );
        let f = temp_file_with(release.as_bytes());

        // The Release file lives at dists/sid/Release; its entries are relative
        // to dists/sid/.
        ingest_release_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            "debian/dists/sid",
        )
        .await
        .expect("ingest ok");

        assert_eq!(
            reg.lookup(
                "deb.debian.org",
                "debian",
                "debian/dists/sid/main/binary-amd64/Packages.xz"
            ),
            Some(pkg_sha),
        );
    }

    fn release_file(
        dir: &tempfile::TempDir,
        name: &str,
        date: Option<&str>,
        digest_hex: &str,
    ) -> PathBuf {
        let date_line = date.map_or(String::new(), |d| format!("Date: {d}\n"));
        let body = format!(
            "Origin: Test\n{date_line}SHA256:\n {digest_hex} 10 main/binary-amd64/Packages.xz\n"
        );
        let path = dir.path().join(name);
        std::fs::write(&path, body).expect("write release");
        path
    }

    #[tokio::test]
    async fn a_newer_release_date_wins_whatever_the_ingest_order() {
        let newer = "Sun, 20 Sep 2026 08:53:33 UTC";
        let older = "Sat, 19 Sep 2026 08:53:33 UTC";
        let new_hex = "11".repeat(32);
        let old_hex = "22".repeat(32);
        let key = "debian/dists/sid/main/binary-amd64/Packages.xz";
        let dir = tempfile::tempdir().expect("tempdir");
        let inrelease = release_file(&dir, "InRelease", Some(newer), &new_hex);
        let release = release_file(&dir, "Release", Some(older), &old_hex);
        for newer_first in [true, false] {
            let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
            let ingest_order = if newer_first {
                [&inrelease, &release]
            } else {
                [&release, &inrelease]
            };
            for path in ingest_order {
                ingest_release_file(&reg, "h", "debian", path, "debian/dists/sid")
                    .await
                    .expect("a superseded source is still a success");
            }
            assert_eq!(
                reg.lookup("h", "debian", key),
                Some([0x11; 32]),
                "newer_first={newer_first}"
            );
        }
    }

    #[tokio::test]
    async fn an_undated_release_never_overwrites_a_dated_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dated = release_file(
            &dir,
            "InRelease",
            Some("Sun, 20 Sep 2026 08:53:33 UTC"),
            &"11".repeat(32),
        );
        let undated = release_file(&dir, "Release", None, &"22".repeat(32));
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        ingest_release_file(&reg, "h", "debian", &dated, "debian/dists/sid")
            .await
            .expect("ingest");
        ingest_release_file(&reg, "h", "debian", &undated, "debian/dists/sid")
            .await
            .expect("ingest");
        assert_eq!(
            reg.lookup(
                "h",
                "debian",
                "debian/dists/sid/main/binary-amd64/Packages.xz"
            ),
            Some([0x11; 32])
        );
    }

    #[tokio::test]
    async fn a_release_ingest_reports_its_dates_and_mtime() {
        let reg = ChecksumRegistry::new(NonZero::new(64).expect("non-zero"));
        let release = temp_file_with(
            b"Date: Sun, 20 Sep 2026 08:53:33 UTC\nValid-Until: Sun, 27 Sep 2026 08:53:33 UTC\nSHA256:\n",
        );
        std::fs::set_times(
            release.path(),
            std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_789_900_000),
            ),
        )
        .expect("set mtime");
        let seen = ingest_release_file(&reg, "h", "debian", release.path(), "debian/dists/sid")
            .await
            .expect("ingest");
        assert_eq!(
            seen,
            SuiteIndex {
                header: ReleaseHeader {
                    date: Some(1_789_894_413),
                    valid_until: Some(1_789_894_413 + 7 * 86_400),
                },
                confirmed_at: 1_789_900_000,
            }
        );
    }

    /// One byte over fails as `InvalidData` without an OS error (cleanup's
    /// by-hash reconcile counts no cache I/O failure for it).
    #[tokio::test]
    async fn read_release_refuses_a_file_over_the_cap() {
        let cap = limits::MAX_RELEASE_SIZE.get();
        let file = tempfile::NamedTempFile::new().expect("temp file");
        file.as_file().set_len(cap).expect("size file at cap");
        let read = read_release_to_string(file.path())
            .await
            .expect("a file at the cap reads");
        assert_eq!(read.len(), usize::try_from(cap).expect("cap fits usize"));
        drop(read);

        file.as_file().set_len(cap + 1).expect("size file over cap");
        let err = read_release_to_string(file.path())
            .await
            .expect_err("a file over the cap fails");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.raw_os_error(), None);
    }

    #[tokio::test]
    async fn a_future_dated_release_is_treated_as_undated() {
        use time::format_description::well_known::Rfc2822;

        let now = time::OffsetDateTime::now_utc();
        let far_future = (now + time::Duration::days(400))
            .format(&Rfc2822)
            .expect("format far-future date");
        let later_dated = (now - time::Duration::days(1))
            .format(&Rfc2822)
            .expect("format dated");
        let future_hex = "11".repeat(32);
        let dated_hex = "22".repeat(32);
        let key = "debian/dists/sid/main/binary-amd64/Packages.xz";

        let dir = tempfile::tempdir().expect("tempdir");
        let future_release = release_file(&dir, "Release", Some(&far_future), &future_hex);
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());

        ingest_release_file(&reg, "h", "debian", &future_release, "debian/dists/sid")
            .await
            .expect("a clamped date is still a successful ingest");
        // The far-future date registers its entries (a cold cache still
        // verifies against them) but as undated, per `clamp_future_release_date`.
        assert_eq!(
            reg.lookup("h", "debian", key),
            Some([0x11; 32]),
            "the future-dated source still registers its digests"
        );

        // A later, honestly-dated Release must still overwrite it: an
        // undated source never blocks a dated one from superseding it.
        let dated_release = release_file(&dir, "InRelease", Some(&later_dated), &dated_hex);
        ingest_release_file(&reg, "h", "debian", &dated_release, "debian/dists/sid")
            .await
            .expect("ingest ok");
        assert_eq!(
            reg.lookup("h", "debian", key),
            Some([0x22; 32]),
            "a correctly-dated Release must overwrite the clamped future one"
        );
    }

    #[test]
    fn index_ingests_reject_fifos_and_retry_after_correction() {
        for kind in [
            IngestKind::Packages {
                compression: Some(PackagesCompression::Raw),
            },
            IngestKind::Packages { compression: None },
            IngestKind::Release {
                release_dir: "debian/dists/sid".to_owned(),
            },
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("index");
            nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");
            let reg = ChecksumRegistry::new(crate::nonzero!(16));
            let ledger = IngestLedger::new(16);
            let slots = Semaphore::new(1);
            let mirror = structured_mirror("fifo.test", "debian");
            let before = metrics::CACHE_NON_REGULAR.get();
            let before_io = metrics::CACHE_IO_FAILURE.get();
            let before_failed = metrics::INGEST_FAILED_MARKED.get();
            crate::test_support::fifo_read_timeout(&path, async {
                let Admission::Admitted(mut claim, slot) = admit(&ledger, &slots, &path, 0) else {
                    unreachable!("first ingest must be admitted");
                };
                let result = ingest_once(&reg, &kind, &mirror, &path, 64 * 1024).await;
                assert!(
                    result.is_err(),
                    "a FIFO must fail before sniffing or parsing"
                );
                let outcome = ingest_outcome(&result);
                assert_eq!(outcome, Outcome::Retry);
                log_ingest_result(&result, outcome, "fifo.test", "debian", &path);
                assert!(!claim.finish(outcome, 0));
                drop((claim, slot));
                assert_eq!(slots.available_permits(), 1, "admission slot released");
                assert_eq!(
                    PACKAGES_INGEST_PERMITS.available_permits(),
                    PACKAGES_INGEST_CONCURRENCY,
                    "decoder permits released"
                );
                assert_eq!(metrics::CACHE_NON_REGULAR.get(), before + 1);
                assert_eq!(metrics::CACHE_IO_FAILURE.get(), before_io);
                assert_eq!(metrics::INGEST_FAILED_MARKED.get(), before_failed);

                // Correct the path without a commit invalidating the ledger:
                // the very next touch must be able to ingest it.
                std::fs::remove_file(&path).expect("remove FIFO");
                let (content, key) = match &kind {
                    IngestKind::Packages { .. } => (
                        format!(
                            "Package: a\nFilename: pool/main/a/a/a_1_amd64.deb\nSHA256: {HELLO_SHA256}\n"
                        ),
                        "a_1_amd64.deb",
                    ),
                    IngestKind::Release { .. } => (
                        format!("SHA256:\n {HELLO_SHA256} 1 main/binary-amd64/Packages.xz\n"),
                        "debian/dists/sid/main/binary-amd64/Packages.xz",
                    ),
                };
                std::fs::write(&path, content).expect("write regular index");
                let Admission::Admitted(mut claim, slot) = admit(&ledger, &slots, &path, 0) else {
                    unreachable!("a corrected path must remain retryable");
                };
                let result = ingest_once(&reg, &kind, &mirror, &path, 64 * 1024).await;
                result.as_ref().expect("corrected index ingests");
                assert!(!claim.finish(ingest_outcome(&result), 0));
                drop((claim, slot));
                assert_eq!(
                    reg.lookup("fifo.test", "debian", key),
                    Some(index_parser::hex_decode_exact::<32>(HELLO_SHA256).unwrap())
                );
                assert_eq!(slots.available_permits(), 1);
                assert!(matches!(
                    admit(&ledger, &slots, &path, 0),
                    Admission::Nothing
                ));
            });
        }
    }

    #[tokio::test]
    async fn ingest_packages_populates_registry() {
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        let sha_a = [0xaau8; 32];
        let sha_b = [0xbbu8; 32];
        let packages = format!(
            "Package: a\nFilename: pool/main/a/a/a_1_amd64.deb\nSHA256: {}\n\n\
             Package: b\nFilename: pool/main/b/b/b_2_amd64.deb\nSHA256: {}\n",
            index_parser::hex_encode(&sha_a),
            index_parser::hex_encode(&sha_b),
        );
        let f = temp_file_with(packages.as_bytes());

        ingest_packages_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            Some(PackagesCompression::Raw),
            64 * 1024,
        )
        .await
        .expect("ingest ok");

        assert_eq!(
            reg.lookup("deb.debian.org", "debian", "a_1_amd64.deb"),
            Some(sha_a)
        );
        assert_eq!(
            reg.lookup("deb.debian.org", "debian", "b_2_amd64.deb"),
            Some(sha_b)
        );
    }

    #[tokio::test]
    async fn ingest_packages_reads_only_tracked_fields_as_utf8() {
        let sha = [0xaau8; 32];
        let stanza = format!(
            "Filename: pool/main/a/a/a_1_amd64.deb\nSHA256: {}\n\n",
            index_parser::hex_encode(&sha),
        );
        let ingest = async |packages: &[u8]| {
            let reg = ChecksumRegistry::new(NonZero::new(100).expect("non-zero"));
            let f = temp_file_with(packages);
            let result = ingest_packages_file(
                &reg,
                "deb.debian.org",
                "debian",
                f.path(),
                Some(PackagesCompression::Raw),
                64 * 1024,
            )
            .await;
            let registered = reg.lookup("deb.debian.org", "debian", "a_1_amd64.deb");
            (result, registered)
        };

        let latin1 = [
            b"Package: a\nDescription: \xe9t\xe9 cr\xe8me\n na\xefve\n".as_slice(),
            stanza.as_bytes(),
        ]
        .concat();
        let (result, registered) = ingest(&latin1).await;
        result.expect("a Latin-1 Description is never decoded");
        assert_eq!(registered, Some(sha));

        let bad_filename = [
            stanza.as_bytes(),
            b"Package: b\nFilename: pool/main/b/b/\xe9_1_amd64.deb\n".as_slice(),
        ]
        .concat();
        let (result, registered) = ingest(&bad_filename).await;
        let err = result.expect_err("a Filename that is not UTF-8 fails the ingest");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(registered, Some(sha), "what was read before it registers");
    }

    #[tokio::test]
    async fn ingest_registers_every_stanza_across_batches() {
        let count = 2 * PendingDigests::BATCH + 7;
        let reg = ChecksumRegistry::new(NonZero::new(4 * count).expect("non-zero"));
        let digest = |i: usize| {
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&(i as u64).to_be_bytes());
            digest
        };
        let mut packages = String::new();
        for i in 0..count {
            crate::swrite!(
                packages,
                "Package: p{i}\nFilename: pool/main/p/p{i}/p{i}_1_amd64.deb\nSHA256: {}\n\n",
                index_parser::hex_encode(&digest(i)),
            );
        }
        let f = temp_file_with(packages.as_bytes());

        ingest_packages_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            Some(PackagesCompression::Raw),
            64 * 1024,
        )
        .await
        .expect("ingest ok");

        assert_eq!(reg.len(), count);
        for i in [
            0,
            PendingDigests::BATCH - 1,
            PendingDigests::BATCH,
            count - 1,
        ] {
            assert_eq!(
                reg.lookup("deb.debian.org", "debian", &format!("p{i}_1_amd64.deb")),
                Some(digest(i)),
                "stanza {i}"
            );
        }
    }

    #[tokio::test]
    async fn ingest_scopes_digests_by_port() {
        use crate::{
            config::ClientHost,
            deb_mirror::{Mirror, MirrorKind},
        };

        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        let sha = [0xaau8; 32];
        let packages = format!(
            "Package: a\nFilename: pool/main/a/a/a_1_amd64.deb\nSHA256: {}\n",
            index_parser::hex_encode(&sha),
        );
        let f = temp_file_with(packages.as_bytes());
        let mirror = Mirror::new(
            ClientHost::new("deb.debian.org").expect("valid host"),
            NonZero::new(8080),
            "debian".into(),
            MirrorKind::Structured,
        );
        let kind = IngestKind::Packages {
            compression: Some(PackagesCompression::Raw),
        };

        let result = ingest_once(&reg, &kind, &mirror, f.path(), 64 * 1024).await;
        result.expect("ingest ok");
        assert_eq!(
            reg.lookup("deb.debian.org:8080", "debian", "a_1_amd64.deb"),
            Some(sha)
        );
        assert_eq!(
            reg.lookup("deb.debian.org", "debian", "a_1_amd64.deb"),
            None,
            "the default port's downloads are not checked against another port's index"
        );
    }

    #[tokio::test]
    async fn ingest_packages_skips_filenames_no_cache_file_can_have() {
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        let digest = index_parser::hex_encode(&[0xaau8; 32]);
        // A basename up to the 8 KiB line cap.
        let long = "a".repeat(8000);
        let packages = format!(
            "Package: a\nFilename: pool/main/a/a/a_1_amd64.deb\nSHA256: {digest}\n\n\
             Package: long\nFilename: pool/main/l/l/{long}.deb\nSHA256: {digest}\n"
        );
        let f = temp_file_with(packages.as_bytes());

        ingest_packages_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            Some(PackagesCompression::Raw),
            64 * 1024,
        )
        .await
        .expect("ingest ok");

        assert_eq!(reg.len(), 1, "only the cacheable name is registered");
        assert!(
            reg.lookup("deb.debian.org", "debian", "a_1_amd64.deb")
                .is_some()
        );
    }

    #[tokio::test]
    async fn ingest_packages_refuses_an_oversized_compressed_index_unread() {
        // A sparse file one byte past the compressed cap: refused on its
        // size, so nothing (not even the xz header) is decoded.
        let f = tempfile::NamedTempFile::new().expect("temp file");
        f.as_file()
            .set_len(limits::MAX_COMPRESSED_PACKAGES_SIZE.get() + 1)
            .expect("extend sparse");
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        let err = ingest_packages_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            Some(PackagesCompression::Xz),
            64 * 1024,
        )
        .await
        .expect_err("an index past the compressed cap must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains("exceeds the"), "{err}");
    }

    #[tokio::test]
    async fn ingest_packages_rejects_decompression_bomb() {
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());

        // Highly-compressible payload: ~4 MiB of zero bytes gzips to a few KiB,
        // far past the 100x ratio cap.
        let compressed = gzip(&vec![0u8; 4 * 1024 * 1024]).await;

        let f = temp_file_with(&compressed);

        let err = ingest_packages_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            Some(PackagesCompression::Gz),
            64 * 1024,
        )
        .await
        .expect_err("a decompression bomb must abort Packages ingestion");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        // Pin it to the ratio guard rather than any incidental InvalidData
        // (a malformed gzip stream would also surface as InvalidData).
        assert!(
            err.to_string().contains("decompressed size exceeds limit"),
            "unexpected error: {err}"
        );
    }

    /// The magic bytes read for the sniff must not be lost to the decoder.
    #[tokio::test]
    async fn ingest_packages_sniffs_the_compression_it_parses() {
        let reg = ChecksumRegistry::new(NonZero::new(100).expect("non-zero"));
        let sha = [0x5au8; 32];
        let packages = format!(
            "Package: a\nFilename: pool/main/a/a/a_1_amd64.deb\nSHA256: {}\n",
            index_parser::hex_encode(&sha),
        );
        let f = temp_file_with(&gzip(packages.as_bytes()).await);

        ingest_packages_file(&reg, "deb.debian.org", "debian", f.path(), None, 64 * 1024)
            .await
            .expect("ingest ok");
        assert_eq!(
            reg.lookup("deb.debian.org", "debian", "a_1_amd64.deb"),
            Some(sha)
        );
    }

    #[test]
    fn registry_reinsert_does_not_evict_live_under_stale_pressure() {
        let reg = ChecksumRegistry::new(NonZero::new(4).unwrap());
        let d = [0u8; 32];
        reg.insert("h", "m", "a", d);
        reg.insert("h", "m", "b", d);
        reg.insert("h", "m", "c", d);
        reg.insert("h", "m", "d", d);
        // Refresh A 100 times. Each re-insert leaves a stale slot (until the
        // stale ones exceed a quarter of the live entries plus 16 and the
        // log is compacted) but moves A to the logical back of FIFO.
        for _ in 0..100 {
            reg.insert("h", "m", "a", d);
        }
        // After all refreshes, A is the most-recently-inserted live entry.
        // B is the FIFO oldest.
        reg.insert("h", "m", "e", d);
        assert!(
            reg.lookup("h", "m", "a").is_some(),
            "A: most-recently refreshed must survive"
        );
        assert!(
            reg.lookup("h", "m", "b").is_none(),
            "B: true FIFO oldest at eviction time"
        );
        assert!(reg.lookup("h", "m", "c").is_some());
        assert!(reg.lookup("h", "m", "d").is_some());
        assert!(reg.lookup("h", "m", "e").is_some());
    }

    #[test]
    fn verify_temp_file_stamps_the_cleanup_marker_on_a_registry_match() {
        use crate::verified_marker::has_valid_marker;

        let dir = tempfile::tempdir().expect("tempdir");
        let temp_path = dir.path().join("pkg.deb.part");
        let payload = b"a small deb body";
        // Read + write, like a download's temp file; the cursor is left at
        // the end, so verification has to rewind before hashing.
        let mut temp_file = nofollow_options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .expect("create");
        temp_file.write_all(payload).expect("write");
        let digest: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(payload).into()
        };

        let outcome = verify_temp_file(&VerifyInput {
            kind: VerifyKind::Expected(Digest::Sha256(Box::new(digest))),
            file: &temp_file,
            meta: &temp_file.metadata().unwrap(),
            temp_path: &temp_path,
            streamed: None,
        });
        assert!(matches!(outcome, Ok(())));

        let file = std::fs::File::open(&temp_path).expect("reopen");
        let meta = file.metadata().expect("metadata");
        assert!(
            has_valid_marker(
                &file,
                &temp_path,
                FileIdentity::of(&meta),
                &Digest::from_bytes(HashAlgo::Sha256, &digest).expect("matching digest length")
            ),
            "commit must leave a marker cleanup accepts, or the first cleanup pass re-hashes every fresh download"
        );
    }

    #[test]
    fn registry_slot_compaction_bounds_memory() {
        let reg = ChecksumRegistry::new(NonZero::new(4).unwrap());
        let d = [0u8; 32];
        reg.insert("h", "m", "a", d);
        // Every re-insert of a live key appends a stale slot. The compaction
        // trigger is `slots.len() > live + stale_allowance(live)` -- 17 for
        // this one-entry scope -- so 20 further inserts must cross it and
        // rebuild the log down to the single live slot.
        for _ in 0..20 {
            reg.insert("h", "m", "a", d);
        }
        assert!(
            reg.slot_len() <= reg.len() + stale_allowance(reg.len()),
            "slot_len={} must stay within the compaction trigger",
            reg.slot_len()
        );
        assert_eq!(reg.len(), 1, "map still holds exactly one live entry");
        assert!(reg.lookup("h", "m", "a").is_some());
    }

    #[test]
    fn check_path_names_file_accepts_only_the_verified_file() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("pkg.deb.partial");
        std::fs::write(&path, b"verified").expect("write temp");
        let verified = std::fs::symlink_metadata(&path).expect("stat temp");
        check_path_names_file(&path, &verified).expect("the path still names the file");

        // Replaced by rename: same path, different inode.
        let other = dir.path().join("other");
        std::fs::write(&other, b"swapped").expect("write replacement");
        std::fs::rename(&other, &path).expect("swap the temp file");
        assert!(check_path_names_file(&path, &verified).is_err());

        // Replaced by a symlink to a file with the right content elsewhere.
        std::fs::remove_file(&path).expect("remove replacement");
        let target = dir.path().join("target");
        std::fs::write(&target, b"verified").expect("write target");
        std::os::unix::fs::symlink(&target, &path).expect("plant symlink");
        assert!(check_path_names_file(&path, &verified).is_err());

        // Gone.
        std::fs::remove_file(&path).expect("remove symlink");
        assert!(check_path_names_file(&path, &verified).is_err());
    }

    #[test]
    fn rename_into_cache_creates_the_directory_only_when_missing() {
        // Two missing levels: `entry_dir` can be several segments below the
        // mirror anchor (`dists/<suite>/<component>/by-hash/SHA256`).
        for dest in ["dest.deb", "dists/suite/by-hash/dest.deb"] {
            let dir = tempfile::tempdir().expect("create tempdir");
            let src = dir.path().join("src.partial");
            std::fs::write(&src, b"payload").expect("write source");
            let dest = dir.path().join(dest);

            rename_into_cache(&src, &dest).expect("rename");

            assert!(!src.exists(), "{dest:?}: the source must be gone");
            assert_eq!(std::fs::read(&dest).expect("read destination"), b"payload");
        }
    }

    #[test]
    fn ingest_filesystem_errors_retry_but_decode_errors_remain_failed() {
        let os = std::io::Error::from_raw_os_error(nix::libc::EIO);
        let gone = std::io::Error::from_raw_os_error(nix::libc::ENOENT);
        let cap = limits::check_packages_file_size(PackagesCompression::Xz, u64::MAX)
            .expect_err("over the cap");
        let corrupt = std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt xz");
        let nonregular = std::io::Error::new(std::io::ErrorKind::InvalidInput, NonRegularIndex);
        let unsupported = std::io::Error::new(std::io::ErrorKind::Unsupported, "compression");
        let invalid = std::io::Error::new(std::io::ErrorKind::InvalidInput, "decoder input");
        assert_eq!(ingest_outcome(&Err(nonregular)), Outcome::Retry);
        assert_eq!(ingest_outcome(&Err(unsupported)), Outcome::Failed);
        assert_eq!(ingest_outcome(&Err(invalid)), Outcome::Failed);
        assert_eq!(ingest_outcome(&Err(os)), Outcome::Retry);
        assert_eq!(ingest_outcome(&Err(gone)), Outcome::Retry);
        assert_eq!(ingest_outcome(&Err(cap)), Outcome::Failed);
        assert_eq!(ingest_outcome(&Err(corrupt)), Outcome::Failed);
        assert_eq!(ingest_outcome(&Ok(())), Outcome::Ingested);
    }

    #[test]
    fn admission_is_bounded_by_the_slots_and_refusal_is_retryable() {
        let ledger = IngestLedger::new(1024);
        let slots = Semaphore::new(2);
        let path = |i: usize| PathBuf::from(format!("/cache/idx{i}"));
        let admitted: Vec<_> = (0..100)
            .filter_map(|i| match admit(&ledger, &slots, &path(i), 0) {
                Admission::Admitted(claim, slot) => Some((claim, slot)),
                Admission::Refused | Admission::Nothing => None,
            })
            .collect();
        assert_eq!(admitted.len(), 2, "no more jobs than slots");
        assert!(matches!(
            admit(&ledger, &slots, &path(50), 0),
            Admission::Refused
        ));
        let mut done = admitted;
        let (mut claim, slot) = done.pop().expect("two admitted");
        assert!(!claim.finish(Outcome::Ingested, 0));
        drop((claim, slot));
        let again = admit(&ledger, &slots, &path(50), 0);
        assert!(
            matches!(again, Admission::Admitted(..)),
            "a refused path is admitted once a slot frees"
        );
        assert!(
            matches!(admit(&ledger, &slots, &path(99), 0), Admission::Refused),
            "slots are full again"
        );
        drop(again);
    }

    #[test]
    fn index_kinds_are_classified_once_for_commit_and_touch() {
        let mirror = structured_mirror("h", "debian");
        let file = |resource_kind, debname, raw_uri_path| IndexFile {
            resource_kind,
            debname,
            raw_uri_path,
            mirror: &mirror,
            path: Path::new("/cache/x"),
        };
        assert!(matches!(
            ingest_kind(&file(
                ResourceKind::Packages,
                "sid_main_binary-amd64_Packages.xz",
                "/debian/dists/sid/main/binary-amd64/Packages.xz"
            )),
            Some(IngestKind::Packages {
                compression: Some(PackagesCompression::Xz),
            })
        ));
        assert!(matches!(
            ingest_kind(&file(
                ResourceKind::ByHash(HashAlgo::Sha256, ByHashContent::MaybePackages),
                "abcd",
                "/debian/dists/sid/main/binary-amd64/by-hash/SHA256/abcd"
            )),
            Some(IngestKind::Packages { compression: None })
        ));
        // A flat repository's indexes feed no registry.
        assert!(
            ingest_kind(&file(
                ResourceKind::FlatMetadata,
                "Packages.xz",
                "/apt/Packages.xz"
            ))
            .is_none()
        );
        assert!(
            ingest_kind(&file(
                ResourceKind::FlatByHash(HashAlgo::Sha256, ByHashContent::MaybePackages),
                "abcd",
                "/apt/binary-amd64/by-hash/SHA256/abcd"
            ))
            .is_none()
        );
        assert!(
            ingest_kind(&file(
                ResourceKind::ByHash(HashAlgo::Sha256, ByHashContent::Other),
                "abcd",
                "/debian/dists/sid/main/i18n/by-hash/SHA256/abcd"
            ))
            .is_none()
        );
        assert!(matches!(
            ingest_kind(&file(
                ResourceKind::Release,
                "sid_InRelease",
                "/debian/dists/sid/InRelease"
            )),
            Some(IngestKind::Release { .. })
        ));
        assert!(
            ingest_kind(&file(
                ResourceKind::Pool,
                "foo_1.0_amd64.deb",
                "/debian/pool/main/f/foo/foo_1.0_amd64.deb"
            ))
            .is_none()
        );
    }

    #[test]
    fn rename_into_cache_reports_a_missing_source() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let src = dir.path().join("absent.partial");
        let dest = dir.path().join("sub/dest.deb");

        let err = rename_into_cache(&src, &dest).expect_err("a missing source cannot be renamed");

        // `rename(2)` reports ENOENT for a missing source as well as a
        // missing destination directory, so the fallback runs and fails
        // again with the same errno rather than masking it.
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::NotFound,
            "a missing source must surface as NotFound, not as a directory error"
        );
    }
}
