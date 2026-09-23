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
//! served concurrently from the same download -- a late joiner streaming the
//! growing partial file, or one attaching during the post-download `Verifying`
//! hash window (`ActiveDownloadStatus::Verifying`) -- receives its bytes before
//! the digest is known. A mismatch then blocks the `rename` (nothing enters the
//! cache) but cannot unsend what was already streamed; such readers hold an open
//! FD and finish serving even after the temp file is unlinked. That is
//! acceptable precisely because this is defence in depth: the concurrent
//! client's own APT GPG check is the backstop. So a reader path serving an
//! unverified `Verifying`/`Download` file is by design, not a bug to "fix".
//!
//! The registry learns an index's digests when the index is committed, and
//! again whenever a request for it is answered without a commit (a cache
//! hit, a client or upstream 304) while its digests are missing: after a
//! restart, an eviction from its scope, or a skipped or transiently failed
//! ingest. `ingest_ledger` records which cache files are ingested (or failed
//! for good), so a warm index costs `schedule_ingest` classifying the file
//! and reading its registry scope's eviction epoch under the registry mutex,
//! then one `ingest_ledger` map lookup that finds it already marked and
//! returns; every backend calls [`note_cached_index_touch`] where it answers
//! an index from cache.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use hashbrown::{Equivalent, HashMap};
use parking_lot::Mutex;
use tokio::sync::{Semaphore, SemaphorePermit, TryAcquireError};
use tracing::{debug, error, warn};

use crate::error::ErrorReport;
use crate::fs_open::{hint_sequential_read, nofollow_options, tokio_nofollow_options};
use crate::ingest_ledger::{Claim, IngestLedger, Outcome};
use crate::limits::{self, LimitedReader, PackagesCompression};
use crate::{
    cache_layout::{ByHashContent, ConnectionDetails, ResourceKind},
    cache_quota::QuotaReservation,
    deb_mirror::normalize_uri_path,
    guards::DownloadWriteLease,
    index_parser::{self, HashAlgo, IndexFormat, StanzaStream, StreamedDigest},
    metrics, verified_marker,
};
use crate::{
    global_checksum_registry, global_config, info_once, warn_once_or_debug, warn_once_or_info,
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
    /// The downloaded content did not match its expected digest.
    #[error("checksum mismatch")]
    ChecksumMismatch,
    /// Reading the temp file back for verification failed. Fail-closed: a file
    /// that cannot be verified does not enter the cache.
    #[error("verification I/O error")]
    VerifyIo(#[source] std::io::Error),
    /// [`rename_into_cache`] of the verified temp file failed — either the
    /// `rename(2)` itself, or the `create_dir_all` it falls back to when the
    /// destination directory turns out to be missing.
    #[error("rename failed")]
    Rename(#[source] std::io::Error),
}

/// Input for [`verify_temp_file`]. Holds everything the decision needs as
/// plain values/borrows so the decision logic is global-free (no `global_config()`, no
/// process-wide registry) and therefore unit-testable. Note: `verify_temp_file`
/// performs file I/O (it reads and hashes `temp_path`) - it is not a pure
/// function, but it is free of process-global state.
struct VerifyInput<'a> {
    /// `config.verify_checksums`.
    verify_enabled: bool,
    kind: VerifyKind,
    temp_path: &'a Path,
    /// The digest the body loop computed as it wrote the file, when it could
    /// (the splice-only `stream_hash_algo` picked an algorithm, the download
    /// did not resume onto a pre-existing prefix, and the bytes passed through
    /// userspace).
    /// Used only if its algorithm is the one the expected digest needs *and*
    /// it covered as many bytes as the finished file holds; otherwise, and
    /// when `None`, the file is re-read and hashed.
    pub(crate) streamed: Option<StreamedDigest>,
}

/// What the downloaded temp file is verified against. The resource-kind ->
/// expected-digest mapping is resolved at construction (in
/// `verify_and_rename`), so the pure decision never re-derives it and no
/// half-resolved combination - a by-hash algorithm whose digest did not
/// decode, a registry-backed kind carrying no digest - is representable.
enum VerifyKind {
    /// The expected digest is known: hash `temp_path` with `algo` and
    /// compare. For a by-hash resource `algo` is the authoritative algorithm
    /// the parser validated for the `<algo>` URL path segment
    /// (`SHA256`/`SHA512`) and carried on the `ResourceKind`, never inferred
    /// from the digest length; for a registry-backed one it is always SHA256.
    Expected { algo: HashAlgo, digest: Vec<u8> },
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

/// Resolve a by-hash URL's `(algo, leaf)` pair into a [`VerifyKind`].
///
/// `algo` is the authoritative algorithm the parser took from the URL's
/// `<algo>` segment (the one directly before the digest, never re-read from
/// the raw path, where an earlier decoy `by-hash` segment could name another)
/// and the digest length is cross-checked against it inside
/// [`index_parser::byhash_digest_for_algo`], so a pair that disagrees
/// degrades to [`VerifyKind::Unknown`] instead of hashing with a guessed
/// algorithm.
fn byhash_verify_kind(algo: HashAlgo, filename: &str) -> VerifyKind {
    let Some(digest) = index_parser::byhash_digest_for_algo(algo, filename) else {
        // Defence in depth: the URL parser already rejects anything other
        // than `SHA256/<64-hex>` or `SHA512/<128-hex>` with the algorithm
        // segment cross-checked against the digest length, so reaching this
        // branch indicates a future divergence between the parser and the
        // digest decoder. Keep the warning visible.
        warn_once_or_info!(
            "By-hash digest did not decode for its URL algorithm; caching `{}` unverified",
            filename.escape_debug()
        );
        return VerifyKind::Unknown;
    };
    VerifyKind::Expected { algo, digest }
}

/// Result of the pure verification decision.
#[derive(Debug)]
enum VerifyOutcome {
    /// Verification passed, or was skipped (disabled / non-verifiable / unknown
    /// digest). The caller proceeds with the `rename`.
    Proceed,
    /// Verification failed. The caller must not `rename`.
    Reject(CommitError),
}

/// Verification decision. Covers by-hash self-verification plus
/// registry-backed lookups for `Pool` (.deb) and `Packages` resources.
///
/// Global-free (no `global_config()`, no registry): all inputs arrive via
/// [`VerifyInput`], making this unit-testable. It does perform file I/O
/// (reads and hashes `temp_path`); callers on an async worker must wrap this
/// in `spawn_blocking` (see `verify_and_rename`).
fn verify_temp_file(input: &VerifyInput<'_>) -> VerifyOutcome {
    if !input.verify_enabled {
        return VerifyOutcome::Proceed;
    }

    let VerifyKind::Expected {
        algo,
        digest: expected,
    } = &input.kind
    else {
        // Best-effort: no known digest -> cache unverified. Only count the
        // kinds that *could* have been verified, so the metric reflects a real
        // coverage gap rather than every metadata / flat-pool file.
        if matches!(input.kind, VerifyKind::Unknown) {
            metrics::CHECKSUM_UNVERIFIED.increment();
        }
        return VerifyOutcome::Proceed;
    };
    let algo = *algo;

    let (computed, hashed_file) = match reuse_streamed_digest(
        input.streamed.as_ref(),
        algo,
        input.temp_path,
    ) {
        Some(reused) => reused,
        None => match hash_file(input.temp_path, algo) {
            Ok(c) => c,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to read `{}` for {} verification; discarding the download, not caching:  {}",
                    input.temp_path.display(),
                    algo.as_str(),
                    ErrorReport(&err),
                );
                return VerifyOutcome::Reject(CommitError::VerifyIo(err));
            }
        },
    };

    if computed == *expected {
        metrics::CHECKSUM_VERIFIED.increment();
        stamp_verified(&hashed_file, input.temp_path, algo, expected);
        VerifyOutcome::Proceed
    } else {
        metrics::CHECKSUM_MISMATCH.increment();
        // WARN (not ERROR): can also be a third-party repo that replaced a
        // file in place. The async wrapper logs once per mismatch with host
        // and path in scope; each event is potentially security-relevant so
        // they are not rate-limited.
        VerifyOutcome::Reject(CommitError::ChecksumMismatch)
    }
}

/// The body loop's incremental digest, plus an fd for [`stamp_verified`]'s
/// xattr, when that digest can be trusted for `algo` — the stream-verified
/// counterpart of [`hash_file`]: same fd, none of the reading, and no
/// `hint_sequential_read` because nothing is read.
///
/// Two things have to hold, and neither is checked anywhere else. The
/// algorithm must be the one the expected digest uses; a mismatch (the stream
/// guessed SHA-256 for a registry hit that turned out to be by-hash SHA-512,
/// say) is an ordinary outcome and falls back silently. And the byte count the
/// hasher consumed must equal the size of the file about to be renamed in:
/// without that, a file diverging from the stream — a future write site that
/// bypasses the two hashing ones, a mis-accounted short write — would be
/// committed as verified *and* have that digest stamped into the cleanup
/// marker, which makes cleanup trust it forever. A divergence is a bug rather
/// than a condition to tolerate, so it is logged loudly, but the fallback is
/// the re-read: hashing what is actually on disk answers the verification
/// question correctly either way, and rejecting outright would discard a
/// download that may well be intact.
///
/// A failed open returns `None` unlogged on purpose: [`hash_file`] reopens the
/// same path a moment later and reports the failure with its full context, so
/// the error surfaces exactly once. A failed `fstat` on an open fd has no such
/// second reporter and is logged here.
fn reuse_streamed_digest(
    streamed: Option<&StreamedDigest>,
    algo: HashAlgo,
    path: &Path,
) -> Option<(Vec<u8>, std::fs::File)> {
    let streamed = streamed?;
    if streamed.algo != algo {
        return None;
    }
    let file = nofollow_options().read(true).open(path).ok()?;
    let on_disk = match file.metadata() {
        Ok(meta) => meta.len(),
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to stat `{}` while checking the streamed {} digest against it; re-reading the file instead of trusting the digest:  {}",
                path.display(),
                algo.as_str(),
                ErrorReport(&err),
            );
            return None;
        }
    };
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
    Some((streamed.digest.clone(), file))
}

/// Open `path` with `O_NOFOLLOW`, hint sequential read, and hash it.
/// Returns the digest together with the still-open file so the caller can
/// stamp the verified marker on the same fd, without a second open.
fn hash_file(path: &Path, algo: HashAlgo) -> std::io::Result<(Vec<u8>, std::fs::File)> {
    let mut file = nofollow_options().read(true).open(path)?;
    // `u64::MAX`: hashing reads the whole file, and no cheap size is on hand
    // without an extra fstat, so always advise.
    hint_sequential_read(&file, u64::MAX, path);
    let digest = match algo {
        HashAlgo::Sha256 => index_parser::hash_open_file::<sha2::Sha256>(&mut file)?,
        HashAlgo::Sha512 => index_parser::hash_open_file::<sha2::Sha512>(&mut file)?,
    };
    Ok((digest, file))
}

/// Stamp the cleanup-verification marker on a temp file whose digest just
/// matched, so the first cleanup cycle after this download does not re-read
/// and re-hash it cold from disk.
///
/// Stamped before the rename: `rename(2)` keeps the inode and the size is
/// final, so the marker is valid for the destination path cleanup will read
/// it from. Unlike `cleanup/verify.rs`, no post-hash inode/size recheck is
/// needed — the temp file is exclusively owned by this download and no other
/// writer can reach it. Best-effort: a stat or xattr failure only means the
/// next cleanup cycle hashes the file, so it is not worth failing a commit.
fn stamp_verified(file: &std::fs::File, path: &Path, algo: HashAlgo, expected: &[u8]) {
    use std::os::unix::fs::MetadataExt as _;

    match file.metadata() {
        Ok(meta) => verified_marker::stamp(file, path, meta.ino(), meta.len(), algo, expected),
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to stat `{}` after hashing; skipping the cleanup verification marker, so the next cleanup cycle re-hashes it:  {}",
                path.display(),
                ErrorReport(&err)
            );
        }
    }
}

/// Everything `verify_and_rename` needs. Built in exactly one place,
/// `RenameBarrier::commit` (`guards.rs`), from the identity the barrier chain
/// carries since `InitBarrier::new` - no download backend assembles one.
pub(crate) struct RenamePlan {
    /// The finished `.partial` / temp file to verify and rename.
    pub(crate) temp_path: PathBuf,
    /// The final cache path to rename into.
    pub(crate) dest_path: PathBuf,
    /// Actual bytes on disk after download; `verify_and_rename` finalises
    /// the quota reservation with it right after the rename. For resumed
    /// downloads this includes the pre-existing prefix.
    pub(crate) bytes_received: u64,
    /// The digest the download computed incrementally over the bytes it
    /// wrote, when it could; spares `verify_temp_file` the re-read. `None`
    /// from every path that cannot produce one -- the zero-copy splice loop
    /// (the plaintext never reaches userspace), a resumed
    /// download whose temp file already held a prefix, `volatile.rs`, and the
    /// hyper backend.
    pub(crate) streamed_digest: Option<StreamedDigest>,
    /// Precise resource kind, from `ConnectionDetails::resource_kind`.
    pub(crate) resource_kind: ResourceKind,
    /// On-disk leaf name. For a by-hash resource this is the hex digest, used
    /// by `verify_temp_file` to decode the expected hash; for `Pool` it is
    /// the basename used directly as the registry-lookup key; for other
    /// kinds it is kept only for log context.
    pub(crate) debname: String,
    /// Upstream host. Part of the registry key, alongside `mirror_path`.
    pub(crate) host: String,
    /// Mirror's repo-prefix path (`Mirror::path()`). Part of the registry
    /// key so two distinct mirrors served from the same host (e.g.
    /// `host/m1/pool/...` vs `host/m2/pool/...`) cannot poison each other's
    /// expected digests via same-named packages.
    pub(crate) mirror_path: String,
    /// The raw request URI path (pre-normalisation). Used for `Release`
    /// relative-path resolution and as the relative-key component of the
    /// `Packages` registry lookup (see `verify_and_rename`).
    pub(crate) raw_uri_path: String,
}

/// Owned `(host, mirror_path, relpath)` registry key. `relpath` is the
/// resource's agreed lookup key, NOT uniformly "repo-relative": for a pool
/// `.deb` (layer B) it is the bare basename, for an index file (layer C) it is
/// the full host-relative URI path (e.g.
/// `debian/dists/sid/main/binary-amd64/Packages.xz`). `mirror_path`
/// discriminates same-`relpath` entries that two mirrors on the same host can
/// otherwise overwrite — see `RenamePlan::mirror_path`. (For layer-C keys
/// `mirror_path` is a redundant prefix of `relpath`; for layer-B basenames it
/// is the sole discriminator.)
#[derive(Debug, Eq, Hash, PartialEq)]
struct RegistryScope {
    host: String,
    mirror_path: String,
}

/// Borrowed lookup key paired with `RegistryScope` via
/// `hashbrown::Equivalent`, so `lookup` does not allocate per call. Mirrors
/// the pattern of `cache_layout::CacheEntryKeyRef`.
#[derive(Hash)]
struct RegistryScopeRef<'a> {
    host: &'a str,
    mirror_path: &'a str,
}

impl Equivalent<RegistryScope> for RegistryScopeRef<'_> {
    fn equivalent(&self, key: &RegistryScope) -> bool {
        let &Self { host, mirror_path } = self;
        let RegistryScope {
            host: khost,
            mirror_path: kmpath,
        } = key;
        host == khost && mirror_path == kmpath
    }
}

// The outer map keys on `Arc<RegistryScope>` so the eviction-order deque
// can share the same allocation. Forwarding `Equivalent` here lets `lookup`
// keep using the borrowed `RegistryScopeRef` (no allocation on the hot
// path). `Arc<T>: Hash` delegates to `T: Hash` in std, so the hash byte
// sequence matches `RegistryScope`'s derived hash and `RegistryScopeRef`'s
// manual impl.
impl Equivalent<Arc<RegistryScope>> for RegistryScopeRef<'_> {
    fn equivalent(&self, key: &Arc<RegistryScope>) -> bool {
        <Self as Equivalent<RegistryScope>>::equivalent(self, key.as_ref())
    }
}

/// Bounded in-memory map from `(host, mirror_path)` scope and per-scope
/// resource lookup key to an expected SHA256 digest, populated by parsing
/// `Packages` / `Release` index files as they flow through. In-memory only
/// (lost on restart; an index answered from cache is re-ingested when its
/// digests are missing, see the module doc). FIFO bulk eviction at the
/// configured cap.
///
/// Two-level layout: essentially all entries of one mirror share the same
/// `(host, mirror_path)` pair, so a flat per-entry key would store those
/// strings ~100k times per Debian-main `Packages` ingest (tens of MB at the
/// default 500k cap). The scope is allocated once per mirror; entries only
/// own their relpath.
///
/// `insert` and `lookup` are module-private on purpose: the only writers are
/// the ingests `schedule_ingest` runs (on commit or on a cache-hit touch)
/// and the only reader is `verify_and_rename`, so nothing outside this
/// module can seed or consult expected digests.
/// `new` (from `main`) and `len` (the dashboard gauge) are the whole
/// crate-visible surface.
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

/// Per-scope relpath map: digest plus insert generation (see
/// `RegistryInner::next_gen`).
type ScopeEntries = HashMap<Arc<str>, ([u8; 32], u64)>;

/// One `(host, mirror_path)` scope: its entries and their insertion order.
#[derive(Debug, Default)]
struct ScopeState {
    entries: ScopeEntries,
    /// Insertion-order log for FIFO eviction within the scope. Each entry
    /// pairs the relpath with the generation it was inserted at. Entries
    /// whose generation no longer matches the live entry are stale (the key
    /// was re-inserted later); the eviction loop skips them and
    /// `compact_order` periodically removes them.
    order: VecDeque<(Arc<str>, u64)>,
    /// Per `Release` directory, the `Date:` (unix seconds; `None` when the
    /// file had none) of the newest `Release`/`InRelease` whose entries were
    /// registered. The two files of one directory write the same keys, so
    /// an older one ingested later must not overwrite the newer digests.
    /// Dropped with the scope when eviction drains it.
    release_dates: HashMap<Box<str>, Option<i64>>,
}

impl ScopeState {
    /// Live generation of `relpath`, if present.
    fn live_generation(&self, relpath: &Arc<str>) -> Option<u64> {
        self.entries.get(relpath).map(|&(_, generation)| generation)
    }
}

#[derive(Debug)]
struct RegistryInner {
    /// `(host, mirror_path)` scope to its entries and eviction order. The
    /// scope `Arc` and relpath `Arc<str>` are shared between the map and the
    /// order log, so `insert` allocates each string once.
    map: HashMap<Arc<RegistryScope>, ScopeState>,
    /// Total relpath entry count across all scopes (the outer map's `len`
    /// counts scopes, not entries).
    len: usize,
    /// Monotonic counter, incremented on every `insert`. Overflow at 2^64
    /// is unreachable in practice (millennia at any realistic insert rate).
    next_gen: u64,
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

    fn get(&self, host: &str, mirror_path: &str) -> u64 {
        self.by_scope
            .get(&RegistryScopeRef { host, mirror_path })
            .copied()
            .unwrap_or(self.floor)
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
                next_gen: 0,
            }),
            epochs: Mutex::new(EvictionEpochs::new(MAX_EPOCH_SCOPES)),
            cap: cap.get(),
        }
    }

    /// Insert (or refresh) an expected digest. At the cap, evicts the oldest
    /// ~25% of entries in one pass, taken from the *largest* scope first so
    /// one oversized (or hostile) index cannot drain the digests of every
    /// other mirror. Re-inserting an existing key refreshes its
    /// eviction-order position to most-recent.
    fn insert(&self, host: &str, mirror_path: &str, relpath: &str, digest: [u8; 32]) {
        let mut inner = self.inner.lock();
        self.insert_locked(&mut inner, host, mirror_path, relpath, digest);
    }

    /// Register a `Release`/`InRelease`'s `Packages` entries unless a newer
    /// source for the same directory already did; `false` when superseded.
    /// Decided and written under one lock, so a concurrently ingested
    /// sibling cannot interleave its inserts. Ordering: a dated source
    /// beats an undated one; between dated ones the later `Date:` wins
    /// (equal dates overwrite, harmlessly); two undated ones keep
    /// last-writer-wins. An archive whose `Date:` legitimately goes
    /// backwards (restored from backup) is therefore pinned to the newer
    /// date already recorded until this process restarts or the scope
    /// drains from eviction -- `date` here has already been clamped by
    /// [`clamp_future_release_date`], so this rule only ever sees a date
    /// that was not implausibly far in the future when ingested.
    fn insert_release(
        &self,
        host: &str,
        mirror_path: &str,
        release_dir: &str,
        date: Option<i64>,
        entries: &[(String, [u8; 32])],
    ) -> bool {
        let mut inner = self.inner.lock();
        let recorded = inner
            .map
            .get(&RegistryScopeRef { host, mirror_path })
            .and_then(|state| state.release_dates.get(release_dir).copied());
        let supersedes = match (recorded, date) {
            (None | Some(None), _) => true,
            (Some(Some(_)), None) => false,
            (Some(Some(recorded)), Some(date)) => date >= recorded,
        };
        if !supersedes {
            return false;
        }
        for (key, digest) in entries {
            self.insert_locked(&mut inner, host, mirror_path, key, *digest);
        }
        // Eviction may have drained this scope; record the date only if it
        // still exists (a drained scope rebuilds its dates on re-ingest).
        if let Some(state) = inner.map.get_mut(&RegistryScopeRef { host, mirror_path }) {
            state.release_dates.insert(release_dir.into(), date);
        }
        drop(inner);
        true
    }

    /// Look up an expected digest by `(host, mirror_path, relpath)`.
    /// Allocation-free via `hashbrown::Equivalent` and `Arc<str>:
    /// Borrow<str>`.
    fn lookup(&self, host: &str, mirror_path: &str, relpath: &str) -> Option<[u8; 32]> {
        let inner = self.inner.lock();
        inner
            .map
            .get(&RegistryScopeRef { host, mirror_path })
            .and_then(|state| state.entries.get(relpath))
            .map(|&(digest, _)| digest)
    }

    /// Current entry count (for the web dashboard).
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len
    }

    /// `(entries, entry capacity, order length, order capacity)` of one
    /// scope.
    #[cfg(test)]
    fn scope_footprint(&self, host: &str, mirror_path: &str) -> (usize, usize, usize, usize) {
        self.inner
            .lock()
            .map
            .get(&RegistryScopeRef { host, mirror_path })
            .map(|state| {
                (
                    state.entries.len(),
                    state.entries.capacity(),
                    state.order.len(),
                    state.order.capacity(),
                )
            })
            .expect("scope present")
    }

    #[cfg(test)]
    fn order_len(&self) -> usize {
        self.inner.lock().map.values().map(|s| s.order.len()).sum()
    }

    /// The eviction epoch of `(host, mirror_path)`: bumped by every
    /// eviction that takes entries from the scope, so an ingest ledger mark
    /// taken under an older epoch knows its digests may be gone.
    fn scope_epoch(&self, host: &str, mirror_path: &str) -> u64 {
        self.epochs.lock().get(host, mirror_path)
    }

    /// Insert (or refresh) one expected digest under an already-locked
    /// `RegistryInner`, evicting when the insert pushes the registry over its
    /// cap. Shared by `ChecksumRegistry::insert` (one entry) and
    /// `ChecksumRegistry::insert_release` (a whole `Release`/`InRelease` batch
    /// under one lock).
    fn insert_locked(
        &self,
        inner: &mut RegistryInner,
        host: &str,
        mirror_path: &str,
        relpath: &str,
        digest: [u8; 32],
    ) {
        let cap = self.cap;
        let generation = inner.next_gen;
        inner.next_gen += 1;

        let scope_ref = RegistryScopeRef { host, mirror_path };
        let scope = if let Some((scope, _)) = inner.map.get_key_value(&scope_ref) {
            Arc::clone(scope)
        } else {
            let scope = Arc::new(RegistryScope {
                host: host.to_owned(),
                mirror_path: mirror_path.to_owned(),
            });
            inner.map.insert(Arc::clone(&scope), ScopeState::default());
            scope
        };

        let state = inner
            .map
            .get_mut(&scope)
            .expect("scope was just looked up or inserted");
        // Reuse the existing relpath allocation on refresh; `Arc<str>:
        // Borrow<str>` makes the borrowed lookup allocation-free.
        let rel = match state.entries.get_key_value(relpath) {
            Some((rel, _)) => Arc::clone(rel),
            None => Arc::from(relpath),
        };
        let inserted = state
            .entries
            .insert(Arc::clone(&rel), (digest, generation))
            .is_none();
        state.order.push_back((rel, generation));
        if state.order.len() > 2 * state.entries.len() + 16 {
            compact_order(state);
        }
        if inserted {
            inner.len += 1;
        }

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

/// Eviction: free `cap / 4` live entries, always from the scope currently
/// holding the most entries, oldest first. A scope that drains empty is
/// removed and the next-largest scope pays the remainder. Within a scope,
/// entries pop from the front of its `order`; stale ones (re-inserted keys
/// whose live generation is newer) are skipped and do not count against the
/// quota.
fn evict(inner: &mut RegistryInner, cap: usize, epochs: &Mutex<EvictionEpochs>) {
    let quota = (cap / 4).max(1);
    let mut live = 0usize;
    while live < quota {
        let Some(scope) = largest_scope(inner) else {
            break;
        };
        let Some(state) = inner.map.get_mut(&scope) else {
            break;
        };
        let before = live;
        while live < quota {
            let Some((rel, generation)) = state.order.pop_front() else {
                break;
            };
            match state.entries.get(&rel) {
                Some(&(_, current_gen)) if current_gen == generation => {
                    state.entries.remove(&rel);
                    inner.len -= 1;
                    live += 1;
                }
                _ => {
                    // Stale entry: the key was re-inserted later (newer gen)
                    // or already evicted. Drop it; no eviction quota consumed.
                }
            }
        }
        if live > before {
            epochs.lock().bump(&scope);
        }
        if state.entries.is_empty() {
            inner.map.remove(&scope);
            continue;
        }
        shrink_scope(state);
        if live < quota {
            // Its order log drained without meeting the quota: only stale
            // entries were left, which the pops above already discarded.
            break;
        }
    }
}

/// Give back the memory an eviction freed. Neither the entry map nor the
/// order log shrinks on its own, so a scope that once held most of the cap
/// (a hostile index, which is what eviction hits first) would keep its peak
/// footprint after losing most of its entries. Shrinking only past twice the
/// live size keeps the rehash cost amortised over the evictions that
/// caused it.
fn shrink_scope(state: &mut ScopeState) {
    if state.entries.capacity() > 2 * state.entries.len() + 16 {
        state.entries.shrink_to_fit();
    }
    if state.order.capacity() > 2 * state.order.len() + 16 {
        state.order.shrink_to_fit();
    }
}

/// The scope holding the most live entries, if any.
fn largest_scope(inner: &RegistryInner) -> Option<Arc<RegistryScope>> {
    // A maximum is order-independent; ties pick an arbitrary scope.
    inner
        .map
        .iter()
        .max_by_key(|(_, state)| state.entries.len())
        .map(|(scope, _)| Arc::clone(scope))
}

/// Rebuild a scope's `order` keeping only entries whose generation matches
/// the current live entry. Preserves FIFO order of live entries. Triggered
/// from `insert_locked` when the log outgrows twice the live count, so
/// amortized O(1) per insert.
fn compact_order(state: &mut ScopeState) {
    let mut compacted = VecDeque::with_capacity(state.entries.len());
    while let Some(entry) = state.order.pop_front() {
        let (ref rel, generation) = entry;
        if state.live_generation(rel) == Some(generation) {
            compacted.push_back(entry);
        }
    }
    state.order = compacted;
}

/// Report a registry lookup that came up empty: this download is cached
/// unverified. Expected while the registry is still cold (the first
/// `apt install` after startup), but a *persistent* miss means the key
/// derived here disagrees with the key ingest inserted, and the only symptom
/// otherwise is `CHECKSUM_UNVERIFIED` climbing with no identity attached.
fn log_registry_miss(plan: &RenamePlan, key: &str) {
    warn_once_or_debug!(
        "No expected digest in the checksum registry for host {} mirror {} key `{}`; caching {} unverified",
        plan.host,
        plan.mirror_path,
        key.escape_debug(),
        plan.debname
    );
}

/// Look the resource's expected SHA-256 up in the checksum registry,
/// degrading to [`VerifyKind::Unknown`] (and logging the miss) when it holds
/// no digest for `key`.
fn registry_verify_kind(plan: &RenamePlan, key: &str) -> VerifyKind {
    global_checksum_registry()
        .lookup(&plan.host, &plan.mirror_path, key)
        .map_or_else(
            || {
                log_registry_miss(plan, key);
                VerifyKind::Unknown
            },
            |digest| VerifyKind::Expected {
                algo: HashAlgo::Sha256,
                digest: digest.to_vec(),
            },
        )
}

/// A `Packages` index cached in a compression the ingest ladder does not
/// know (`.zst`, `.bz2`, `.lz4` on third-party repos): the file is served
/// from cache, but its digests never reach the registry, so every deb it
/// lists is cached unverified. The early return is otherwise shared with the
/// deliberate no-op kinds, which is why nothing marks this case today.
fn log_unsupported_packages_compression(leaf: &str, host: &str) {
    // `Packages` and the two supported suffixes always classify; anything
    // else with the `Packages.` prefix is an unsupported compression. Other
    // metadata leaves (Release, InRelease) legitimately have none.
    if !leaf.starts_with("Packages.") {
        return;
    }
    warn_once_or_debug!(
        "Unsupported Packages compression `{}` from host {host}; skipping registry ingest, its debs stay unverified",
        leaf.escape_debug()
    );
}

/// `rename(2)` the finished temp file into the cache, creating the
/// destination directory only when it turns out to be missing.
///
/// Same shape as `partial_file::create_partial_file`'s parent handling, and
/// for the same reason: the eager `create_dir_all` both download backends
/// used to run per download was a blocking-pool round trip whose `mkdir` +
/// `stat` answered `EEXIST` for every download after the first into a given
/// directory. The steady state now costs no `mkdir` at all.
///
/// `rename(2)` reports `ENOENT` for a missing *source* too, so a lost temp
/// file costs one wasted `mkdir` before failing with the same errno it would
/// have failed with anyway. A `create_dir_all` failure is returned as-is and
/// surfaces through `CommitError::Rename` — the caller's "Failed to rename
/// temp file `…` to `…`" ERROR (`guards.rs`) carries its errno, which names
/// the real cause; no separate error variant.
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

/// Verify the finished temp file and rename it into the cache.
///
/// `reservation` is finalised inside the same blocking closure as the
/// `rename(2)`, right after it succeeds: a `spawn_blocking` closure runs to
/// completion even when the awaiting future is dropped, so a cancelled
/// commit can never leave the file in the cache with its reservation
/// reverted. On every failure path the reservation is dropped, which
/// reverts it.
/// Both blocking jobs own the registry lease: cancelling verification cannot
/// permit a retry to modify the file while it is read, and cancelling rename
/// cannot let a retry replace the partial before the queued rename runs.
pub(crate) async fn verify_and_rename(
    plan: &RenamePlan,
    reservation: QuotaReservation,
    lease: Arc<DownloadWriteLease>,
) -> Result<(), CommitError> {
    let verify_enabled = global_config().verify_checksums;

    // Build the verification kind. Layer-B/C registry lookups happen here -
    // synchronously, before spawn_blocking - so the pure decision stays
    // global-free. Skipped entirely when verification is disabled.
    let kind = if verify_enabled {
        match plan.resource_kind {
            ResourceKind::ByHash(algo, _) | ResourceKind::FlatByHash(algo, _) => {
                byhash_verify_kind(algo, &plan.debname)
            }
            kind @ (ResourceKind::Pool | ResourceKind::Packages) => {
                let key = registry_lookup_key(kind, &plan.debname, &plan.raw_uri_path)
                    .expect("Pool and Packages are the registry-backed kinds");
                registry_verify_kind(plan, &key)
            }
            ResourceKind::Release
            | ResourceKind::ComponentRelease
            | ResourceKind::Sources
            | ResourceKind::Translation
            | ResourceKind::Icon
            | ResourceKind::FlatMetadata
            | ResourceKind::FlatPool => VerifyKind::Unverifiable,
        }
    } else {
        VerifyKind::Unverifiable
    };

    let temp_path = plan.temp_path.clone();
    let streamed = plan.streamed_digest.clone();
    let outcome = match Arc::clone(&lease)
        .spawn_blocking(move |_lease| {
            verify_temp_file(&VerifyInput {
                verify_enabled,
                kind,
                temp_path: &temp_path,
                streamed,
            })
        })
        .await
    {
        Ok(outcome) => outcome,
        Err(join_err) => {
            error!(
                "Failed to run the verification task for {} from host {}; discarding the download, not caching:  {}",
                plan.debname,
                plan.host,
                ErrorReport(&join_err),
            );
            metrics::CACHE_IO_FAILURE.increment();
            return Err(CommitError::VerifyIo(std::io::Error::other(join_err)));
        }
    };

    if let VerifyOutcome::Reject(err) = outcome {
        if matches!(err, CommitError::ChecksumMismatch) {
            warn!(
                "Checksum mismatch for {} from host {} mirror {}; discarding the download, not caching",
                plan.debname, plan.host, plan.mirror_path,
            );
        }
        return Err(err);
    }

    let temp_path = plan.temp_path.clone();
    let dest_path = plan.dest_path.clone();
    let bytes_received = plan.bytes_received;
    match lease
        .spawn_blocking(move |lease| {
            rename_into_cache(&temp_path, &dest_path).map(|()| {
                reservation.finalize(bytes_received);
                lease.invalidate_metadata();
                // Here, not after the await: a commit future cancelled
                // between the rename and the scheduling below would
                // otherwise leave the replaced file's mark on the new one.
                if verify_enabled {
                    INGEST_LEDGER.invalidate(&dest_path);
                }
            })
        })
        .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => return Err(CommitError::Rename(err)),
        Err(join_err) => {
            error!(
                "Failed to run the rename task for {} from host {}; discarding the download, not caching:  {}",
                plan.debname,
                plan.host,
                ErrorReport(&join_err),
            );
            metrics::CACHE_IO_FAILURE.increment();
            return Err(CommitError::Rename(std::io::Error::other(join_err)));
        }
    }

    // Post-commit, best-effort: ingest index files into the registry so future
    // downloads are verifiable. Detached so the client connection is never
    // delayed by decompression/parsing. Skipped when verification is disabled:
    // the registry it populates is read only by `verify_temp_file`, so parsing
    // (and decompressing) every index file would be pure waste.
    if verify_enabled {
        schedule_ingest(&IndexFile::from(plan), IngestTrigger::Commit);
    }

    Ok(())
}

/// How many `Packages` ingests decode at once. A commit or a touch schedules
/// one, and by-hash indexes are distinct resources, so an upstream serving
/// many small hostile `.xz` files would otherwise hold one blocking-pool
/// thread each for up to [`limits::MAX_XZ_DECODE_CPU`] and starve every
/// other `spawn_blocking` user (`tokio::fs`, verification). Two keep an
/// `apt update` over several components flowing while bounding that.
/// `Release` ingest reads a capped, uncompressed file and takes no decode
/// permit; it is admitted from the separate [`RELEASE_INGEST_SLOTS`] line
/// instead of [`INGEST_SLOTS`].
const PACKAGES_INGEST_CONCURRENCY: usize = 2;

static PACKAGES_INGEST_PERMITS: Semaphore = Semaphore::const_new(PACKAGES_INGEST_CONCURRENCY);

/// `Packages`/`PackagesSniff` ingests that may wait for a decode permit at
/// once. The permits bound the CPU, not the line in front of them: without a
/// bound, a mirror serving budget-burning indexes would queue one task per
/// committed or touched index and push every later ingest back by one
/// [`limits::MAX_XZ_DECODE_CPU`] turn each. Sixty-four holds the burst the
/// first `apt update` after a restart touches (every live index at once:
/// tens for a multi-suite, multi-arch Debian mirror).
const INGEST_QUEUE: usize = 64;

/// One slot per scheduled `Packages`/`PackagesSniff` ingest, from before its
/// spawn to its end: the decode permits plus the line. Taken synchronously
/// in [`admit`], so a burst of touches can never hold more `Packages`-kind
/// paths `Running` in the ingest ledger than this (the ledger cap never
/// drops `Running` entries). `Release` jobs draw from their own pool,
/// [`RELEASE_INGEST_SLOTS`], so the two pools together bound `Running`
/// ledger entries at `INGEST_SLOTS` + `RELEASE_INGEST_SLOTS` (66 + 16 = 82).
static INGEST_SLOTS: Semaphore = Semaphore::const_new(PACKAGES_INGEST_CONCURRENCY + INGEST_QUEUE);

/// How many `Release`/`InRelease` ingests may be admitted at once, in a pool
/// separate from [`INGEST_SLOTS`]: a hostile permitted mirror committing
/// budget-burning `.xz` `Packages` indexes can hold every slot of that
/// shared line, and without a pool of its own every other mirror's
/// `Release` ingest would then be refused too. `Release` jobs take no
/// decode permit (a capped, uncompressed read), so this pool only bounds
/// the line, not CPU; sixteen comfortably covers every live suite's
/// `Release`/`InRelease` across a multi-suite, multi-arch mirror set.
const RELEASE_INGEST_QUEUE: usize = 16;

static RELEASE_INGEST_SLOTS: Semaphore = Semaphore::const_new(RELEASE_INGEST_QUEUE);

/// The admission pool a job of `kind` draws its slot from: `Release` jobs
/// get their own pool ([`RELEASE_INGEST_SLOTS`]); `Packages`/`PackagesSniff`
/// share [`INGEST_SLOTS`] (see both statics' docs for why they are split).
fn ingest_pool(kind: &IngestKind) -> &'static Semaphore {
    match kind {
        IngestKind::Release { release_dir: _ } => &RELEASE_INGEST_SLOTS,
        IngestKind::Packages { .. } | IngestKind::PackagesSniff { .. } => &INGEST_SLOTS,
    }
}

/// What [`admit`] decided for one path.
enum Admission<'l, 's> {
    /// Ingested under the current epoch, failed for good, or already running.
    Nothing,
    /// No slot free; the path stays unmarked for its next touch.
    Refused,
    /// Run it: the ledger claim and the slot, both held by the job.
    Admitted(Claim<'l>, SemaphorePermit<'s>),
}

/// Claim `path` in `ledger`, then take a slot. A refused claim is dropped,
/// which leaves the path unmarked (the `Claim` drop guard). Pure over its
/// arguments; [`schedule_ingest`] passes the globals.
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

/// Run `ingest` under one of the [`PACKAGES_INGEST_PERMITS`].
async fn with_decode_permit<F: Future>(ingest: F) -> F::Output {
    let _permit = PACKAGES_INGEST_PERMITS
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

/// Why an ingest is scheduled (only the counters differ).
#[derive(Clone, Copy, PartialEq, Eq)]
enum IngestTrigger {
    Commit,
    Touch,
}

/// Queue the ingest of `file` unless the ledger says its digests are
/// already registered, it failed for good, or an ingest of it is running.
fn schedule_ingest(file: &IndexFile<'_>, trigger: IngestTrigger) {
    let Some(kind) = ingest_kind(file) else {
        return;
    };
    let registry = global_checksum_registry();
    let epoch = registry.scope_epoch(file.host, file.mirror_path);
    let (claim, slot) = match admit(&INGEST_LEDGER, ingest_pool(&kind), file.path, epoch) {
        Admission::Nothing => return,
        Admission::Refused => {
            metrics::INGEST_SKIPPED_QUEUE_FULL.increment();
            warn_once_or_debug!(
                "Skipping registry ingest of index `{}` for host {} mirror {} (ingest queue full); retrying on its next request",
                file.path.display(),
                file.host,
                file.mirror_path,
            );
            return;
        }
        Admission::Admitted(claim, slot) => (claim, slot),
    };
    if trigger == IngestTrigger::Touch {
        metrics::INGEST_TOUCH_TRIGGERED.increment();
    }
    let host = file.host.to_owned();
    let mirror_path = file.mirror_path.to_owned();
    let dest = file.path.to_path_buf();
    let buffer_size = global_config().buffer_size;
    tokio::spawn(run_ingest_job(
        claim,
        slot,
        kind,
        host,
        mirror_path,
        dest,
        buffer_size,
    ));
}

/// Answer a request for a cached index without a commit (a cache hit, a
/// client or upstream 304): re-ingest it if the registry lacks its digests.
/// `raw_uri_path` is the request path as received; `cache_path` the file
/// served.
pub(crate) fn note_cached_index_touch(
    conn_details: &ConnectionDetails,
    raw_uri_path: &str,
    cache_path: &Path,
) {
    if !global_config().verify_checksums {
        return;
    }
    schedule_ingest(
        &IndexFile {
            resource_kind: conn_details.resource_kind,
            debname: &conn_details.debname,
            raw_uri_path,
            host: conn_details.mirror.host().as_str(),
            mirror_path: conn_details.mirror.path(),
            path: cache_path,
        },
        IngestTrigger::Touch,
    );
}

/// One claimed path's ingest, run again while commits keep replacing the
/// file under it.
async fn run_ingest_job(
    mut claim: Claim<'static>,
    // Held for the whole job, reruns included; see `INGEST_SLOTS`.
    _slot: SemaphorePermit<'static>,
    kind: IngestKind,
    host: String,
    mirror_path: String,
    dest: PathBuf,
    buffer_size: usize,
) {
    let registry = global_checksum_registry();
    loop {
        let result = ingest_once(registry, &kind, &host, &mirror_path, &dest, buffer_size).await;
        let outcome = result.outcome();
        log_ingest_result(&result, outcome, &host, &mirror_path, &dest);
        if !claim.finish(outcome, registry.scope_epoch(&host, &mirror_path)) {
            return;
        }
    }
}

/// One ingest of `dest`: dispatches on `kind` to the matching parse
/// (`Packages`, sniffed-compression `Packages`, or `Release`), under a
/// decode permit for the two `Packages` variants.
async fn ingest_once(
    registry: &ChecksumRegistry,
    kind: &IngestKind,
    host: &str,
    mirror_path: &str,
    dest: &Path,
    buffer_size: usize,
) -> IngestResult {
    let result = match kind {
        IngestKind::Packages {
            compression,
            format,
        } => {
            with_decode_permit(ingest_packages_file(
                registry,
                host,
                mirror_path,
                dest,
                *compression,
                *format,
                buffer_size,
            ))
            .await
        }
        IngestKind::PackagesSniff { format } => {
            with_decode_permit(async {
                let compression = sniff_packages_compression(dest).await?;
                ingest_packages_file(
                    registry,
                    host,
                    mirror_path,
                    dest,
                    compression,
                    *format,
                    buffer_size,
                )
                .await
            })
            .await
        }
        IngestKind::Release { release_dir } => {
            ingest_release_file(registry, host, mirror_path, dest, release_dir).await
        }
    };
    match result {
        Ok(()) => IngestResult::Done,
        Err(err) => IngestResult::Failed(err),
    }
}

fn log_ingest_result(
    result: &IngestResult,
    outcome: Outcome,
    host: &str,
    mirror_path: &str,
    dest: &Path,
) {
    match (result, outcome) {
        (IngestResult::Failed(err), Outcome::Failed) => {
            metrics::INGEST_FAILED_MARKED.increment();
            warn_once_or_debug!(
                "Failed to ingest index `{}` for host {host} mirror {mirror_path}; not retried until the file changes:  {}",
                dest.display(),
                ErrorReport(err),
            );
        }
        (IngestResult::Failed(err), Outcome::Ingested | Outcome::Retry) => warn_once_or_debug!(
            "Failed to ingest index `{}` for host {host} mirror {mirror_path}; retrying on its next request:  {}",
            dest.display(),
            ErrorReport(err),
        ),
        // Sync point for `wait_for_log("Index ingestion completed")`; keep the wording stable.
        (IngestResult::Done, _) => debug!("Index ingestion completed for `{}`", dest.display()),
    }
}

/// How a cached file is ingested into the registry, or no-op for a resource
/// that feeds no registry entries.
enum IngestKind {
    Packages {
        compression: PackagesCompression,
        format: IndexFormat,
    },
    /// Compression unknown (by-hash URL leaf is a hex digest); the spawned
    /// task sniffs magic bytes before parsing. Required because modern APT
    /// with `Acquire::By-Hash: yes` fetches `Packages.xz` (typically) via
    /// `/by-hash/SHA256/<hex>` URLs that carry no extension, so the
    /// filename-based detection used elsewhere fails.
    PackagesSniff {
        format: IndexFormat,
    },
    Release {
        release_dir: String,
    },
}

/// The facts that decide whether and how a cached file is ingested, taken
/// from a commit's `RenamePlan` or from a request answered from cache.
pub(crate) struct IndexFile<'a> {
    pub(crate) resource_kind: ResourceKind,
    /// On-disk leaf name (`_`-joined for structured `Packages`).
    pub(crate) debname: &'a str,
    /// The raw request URI path (`Release`'s directory comes from it).
    pub(crate) raw_uri_path: &'a str,
    pub(crate) host: &'a str,
    pub(crate) mirror_path: &'a str,
    /// The cache file the ingest reads; the ledger key.
    pub(crate) path: &'a Path,
}

impl<'a> From<&'a RenamePlan> for IndexFile<'a> {
    fn from(plan: &'a RenamePlan) -> Self {
        let RenamePlan {
            temp_path: _,
            dest_path,
            bytes_received: _,
            streamed_digest: _,
            resource_kind,
            debname,
            host,
            mirror_path,
            raw_uri_path,
        } = plan;
        Self {
            resource_kind: *resource_kind,
            debname,
            raw_uri_path,
            host,
            mirror_path,
            path: dest_path,
        }
    }
}

/// How `file` is ingested, or `None` for a resource that feeds no registry
/// entries. One table for the commit and the touch path.
fn ingest_kind(file: &IndexFile<'_>) -> Option<IngestKind> {
    // For Packages/FlatMetadata, `file.debname` is `_`-joined for structured
    // resources; extract the leaf filename (the part after the last `_`).
    let leaf = file
        .debname
        .rsplit('_')
        .next()
        .expect("rsplit yields at least one element");

    // The structured and flat `Packages` arms are the same ingest, differing
    // only in how a `Filename:` field maps onto a registry key.
    let packages_kind = |format: IndexFormat| {
        let compression = PackagesCompression::from_filename(leaf);
        if compression.is_none() {
            log_unsupported_packages_compression(leaf, file.host);
        }
        compression.map(|compression| IngestKind::Packages {
            compression,
            format,
        })
    };

    #[expect(clippy::match_same_arms, reason = "prefer clarity")]
    let kind = match file.resource_kind {
        ResourceKind::Packages => packages_kind(IndexFormat::Structured),
        // Flat Packages files are ingested into the registry (layer-B deb
        // verification).  Flat-layer-C (verifying a flat Packages file against
        // a flat Release) is not implemented - consistent with flat-pool layer-B
        // also being deferred.
        ResourceKind::FlatMetadata => packages_kind(IndexFormat::Flat),
        ResourceKind::Release => release_dir_from_uri_path(file.raw_uri_path)
            .map(|d| IngestKind::Release { release_dir: d }),
        // A per-component Release (`binary-<arch>/Release`) carries no SHA256:
        // section listing Packages files, so parsing it yields nothing useful.
        // Route it to the no-op group rather than wasting a file-open + parse.
        ResourceKind::ComponentRelease => None,
        // A by-hash file may be a Packages file. The directory its
        // validated `by-hash/` hangs in, judged once by the classifier,
        // distinguishes a binary Packages index from Contents/dep11/i18n
        // by-hash content.
        ResourceKind::ByHash(_, ByHashContent::MaybePackages) => Some(IngestKind::PackagesSniff {
            format: IndexFormat::Structured,
        }),
        // Only a flat repository whose base directory is itself named
        // `binary-*` or `source` gets here.  Flat layer-C ingestion is
        // deferred (see `verify_and_rename`).
        ResourceKind::FlatByHash(_, ByHashContent::MaybePackages) => {
            Some(IngestKind::PackagesSniff {
                format: IndexFormat::Flat,
            })
        }
        ResourceKind::ByHash(_, ByHashContent::Other)
        | ResourceKind::FlatByHash(_, ByHashContent::Other) => None,
        ResourceKind::Pool
        | ResourceKind::Sources
        | ResourceKind::Translation
        | ResourceKind::Icon
        | ResourceKind::FlatPool => None,
    };
    kind
}

/// How one ingest run ended (a run is only started once admitted, so
/// "no slot" is not a result; see [`admit`]).
enum IngestResult {
    Done,
    Failed(std::io::Error),
}

impl IngestResult {
    /// The ledger outcome. An error carrying an OS errno is the file system
    /// failing (or cleanup removing the file) and may pass; every other
    /// error was built by the decode pipeline itself -- a size or bomb cap,
    /// a corrupt stream, the xz CPU budget, an over-cap or non-UTF-8
    /// `Release` -- and repeats on the same bytes.
    fn outcome(&self) -> Outcome {
        match self {
            Self::Done => Outcome::Ingested,
            Self::Failed(err) if err.raw_os_error().is_some() => Outcome::Retry,
            Self::Failed(_) => Outcome::Failed,
        }
    }
}

/// The host-relative directory a `dists/.../Release` file lives in, derived
/// from the raw URI path (the parent directory of the `Release` leaf),
/// normalized like the cache path (`//` runs and `.` segments collapse), so
/// every spelling of one `Release` registers the keys
/// [`registry_lookup_key`] looks up.
///
/// `Release.gpg` is a detached binary PGP signature with no SHA256 section to
/// ingest, so it's excluded — routing it here would just waste a file open
/// and a `read_to_string` of opaque bytes.
fn release_dir_from_uri_path(raw_uri_path: &str) -> Option<String> {
    let normalized = normalize_uri_path(raw_uri_path);
    let trimmed = normalized.trim_start_matches('/');
    let (dir, leaf) = trimmed.rsplit_once('/')?;
    if !matches!(leaf, "Release" | "InRelease") {
        return None;
    }
    Some(dir.to_owned())
}

/// The checksum-registry key a download of `resource_kind` is verified
/// against, or `None` for the kinds that carry their digest in the URL
/// (a by-hash URL) or have none at all ([`VerifyKind::Unverifiable`]).
///
/// One derivation, shared by [`verify_and_rename`]'s commit-time lookup and
/// the splice-only `stream_hash_algo_for_download`'s pre-download one, so the
/// two can never disagree about which registry entry decides a download's
/// digest.
fn registry_lookup_key<'a>(
    resource_kind: ResourceKind,
    debname: &'a str,
    raw_uri_path: &'a str,
) -> Option<Cow<'a, str>> {
    match resource_kind {
        // Layer B: a pool .deb's key is its bare basename, the form
        // `ingest_stanza_into_registry` inserted. Flat-pool downloads are
        // not verified this way, so no flat variant is needed.
        ResourceKind::Pool => Some(Cow::Borrowed(debname)),
        // Layer C: the full host-relative URI path, normalized like the
        // `release_dir` `ingest_release_file` inserted it under
        // ("<release_dir>/<rel>").
        ResourceKind::Packages => Some(match normalize_uri_path(raw_uri_path) {
            Cow::Borrowed(path) => Cow::Borrowed(path.trim_start_matches('/')),
            Cow::Owned(path) => Cow::Owned(path.trim_start_matches('/').to_owned()),
        }),
        ResourceKind::ByHash(..)
        | ResourceKind::FlatByHash(..)
        | ResourceKind::Release
        | ResourceKind::ComponentRelease
        | ResourceKind::Sources
        | ResourceKind::Translation
        | ResourceKind::Icon
        | ResourceKind::FlatMetadata
        | ResourceKind::FlatPool => None,
    }
}

/// Which digest, if any, a download of `resource_kind` will be verified
/// against — decided from the request alone, before the first byte arrives, so
/// a body loop can hash incrementally and spare
/// [`verify_temp_file`] its full re-read of the finished file.
///
/// Deliberately mirrors `verify_and_rename`'s `kind` table arm for arm, and is
/// exhaustive over `ResourceKind` so a new variant is a compile error in both
/// places. A disagreement is safe but wasteful: a digest computed with the
/// wrong algorithm is ignored ([`verify_temp_file`] compares the algorithm
/// carried alongside it before trusting it) and falls back to the re-read.
///
/// `registry_hit` is why the `Pool`/`Packages` arm is not simply
/// `Some(Sha256)`. Those kinds are verified against the in-memory registry,
/// and when the lookup misses — no `Packages` index ingested for that mirror
/// yet, the ordinary state on a cold cache — `verify_temp_file` returns before
/// it hashes anything. Hashing them anyway would not "waste the CPU the
/// re-read would have spent": there is no re-read to spend it on, so a
/// several-hundred-megabyte `.deb` would be hashed inline on the worker for a
/// digest nothing ever compares. The window between this call and the commit
/// is not a correctness concern in either direction — a registry that gains
/// the digest meanwhile falls back to the re-read, and one that loses it
/// discards a digest.
///
/// Pure: `verify_enabled` is `global_config().verify_checksums` and
/// `registry_hit` the registry probe, both passed in so this stays
/// unit-testable. [`stream_hash_algo_for_download`] is the wrapper that reads
/// them.
#[cfg(feature = "splice")]
#[must_use]
pub(crate) fn stream_hash_algo(
    resource_kind: ResourceKind,
    registry_hit: bool,
    verify_enabled: bool,
) -> Option<HashAlgo> {
    if !verify_enabled {
        return None;
    }
    match resource_kind {
        // Self-verifying: the algorithm is named in the URL.
        ResourceKind::ByHash(algo, _) | ResourceKind::FlatByHash(algo, _) => Some(algo),
        // Registry-backed, always SHA-256 (`VerifyKind::Registry`) -- but only
        // worth computing when the registry already holds the digest.
        ResourceKind::Pool | ResourceKind::Packages => registry_hit.then_some(HashAlgo::Sha256),
        // `VerifyKind::Unverifiable`: no digest exists for these today.
        ResourceKind::Release
        | ResourceKind::ComponentRelease
        | ResourceKind::Sources
        | ResourceKind::Translation
        | ResourceKind::Icon
        | ResourceKind::FlatMetadata
        | ResourceKind::FlatPool => None,
    }
}

/// [`stream_hash_algo`] with the two process-global reads it deliberately does
/// not do itself: `verify_checksums` and the checksum-registry probe.
///
/// Splice-only, like its one caller `splice::splice_proxy_drive`.
#[cfg(feature = "splice")]
#[must_use]
pub(crate) fn stream_hash_algo_for_download(
    resource_kind: ResourceKind,
    raw_uri_path: &str,
    debname: &str,
    host: &str,
    mirror_path: &str,
) -> Option<HashAlgo> {
    let registry_hit =
        registry_lookup_key(resource_kind, debname, raw_uri_path).is_some_and(|key| {
            global_checksum_registry()
                .lookup(host, mirror_path, &key)
                .is_some()
        });
    stream_hash_algo(
        resource_kind,
        registry_hit,
        global_config().verify_checksums,
    )
}

/// Detect Packages compression by reading magic bytes from the file. Used for
/// by-hash content whose URL leaf is a hex digest and so carries no extension.
/// Falls back to `Raw` if no recognised magic is found (best-effort: a
/// genuinely raw Packages file with no magic is parsed normally; a corrupt or
/// unexpected payload yields zero stanzas, which is the same outcome as the
/// pre-sniff behaviour for any non-`.xz`/non-`.gz` content).
async fn sniff_packages_compression(path: &Path) -> std::io::Result<PackagesCompression> {
    use tokio::io::AsyncReadExt as _;
    let mut file = tokio_nofollow_options().read(true).open(path).await?;
    // Fill up to 6 magic bytes, tolerating short reads (a single `read` may
    // return fewer bytes than requested) and early EOF (a genuinely tiny raw
    // `Packages` file is valid and classifies as `Raw`, not an error).
    let mut buf = [0u8; 6];
    let mut n = 0;
    while n < buf.len() {
        match file.read(&mut buf[n..]).await? {
            0 => break,
            read => n += read,
        }
    }
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
/// `(Filename, SHA256)` pair into `registry`. Best-effort: a malformed file
/// just yields fewer entries; errors are logged and returned.
///
/// Guards against decompression bombs: total decompressed output is capped at
/// the smaller of [`crate::limits::MAX_DECOMPRESSED_PACKAGES_SIZE`] and the
/// compressed file size multiplied by
/// [`crate::limits::MAX_DECOMPRESSION_RATIO`] (mirroring `cleanup/packages.rs`).
/// Per-line length is capped at [`crate::limits::MAX_METADATA_LINE_LEN`].
/// Hitting either cap stops ingestion gracefully (the registry is just
/// less-populated).
async fn ingest_packages_file(
    registry: &ChecksumRegistry,
    host: &str,
    mirror_path: &str,
    path: &Path,
    compression: PackagesCompression,
    format: IndexFormat,
    buffer_size: usize,
) -> std::io::Result<()> {
    let file = tokio_nofollow_options().read(true).open(path).await?;

    // Compute the decompressed-output ceiling from the compressed file size.
    // Fall back to the absolute cap if stat fails (non-fatal).
    let compressed_size = match file.metadata().await {
        Ok(m) => {
            limits::check_packages_file_size(compression, m.len())?;
            m.len()
        }
        Err(err) => {
            warn!(
                "Failed to stat `{}` for the decompression-ratio guard during Packages ingestion; ingesting with the guard disabled:  {}",
                path.display(),
                ErrorReport(&err),
            );
            u64::MAX
        }
    };
    let reader = limits::packages_reader(
        file,
        compression,
        limits::decompressed_limit(NonZero::new(compressed_size)),
        buffer_size,
    );

    let mut stanzas = StanzaStream::new(
        reader,
        index_parser::Stanza::new_sha256_only()
            .with_source(format!("{host}/{mirror_path} index `{}`", path.display())),
    );
    loop {
        match stanzas.next().await {
            Ok(Some(stanza)) => {
                ingest_stanza_into_registry(stanza, registry, host, mirror_path, format);
            }
            Ok(None) => return Ok(()),
            Err(err) => {
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

/// Read a cached `Release` / `InRelease` file to a string with the cache's
/// standard hardening: `O_NOFOLLOW` (reject a symlinked final component) and a
/// `LimitedReader` capped at `MAX_RELEASE_SIZE`, so a hostile or buggy mirror
/// serving a multi-GB `Release` (which passes the `max_object_size` admission
/// check) cannot balloon memory unbounded. An over-cap file fails with
/// `io::ErrorKind::InvalidData` rather than truncating silently.
///
/// Shared by registry ingest ([`ingest_release_file`]) and the by-hash cleanup
/// reference-set builder.
pub(crate) async fn read_release_to_string(path: &Path) -> std::io::Result<String> {
    let file = tokio_nofollow_options().read(true).open(path).await?;
    let mut limited = LimitedReader::new(file, limits::MAX_RELEASE_SIZE);
    let mut buf = String::new();
    tokio::io::AsyncReadExt::read_to_string(&mut limited, &mut buf).await?;
    Ok(buf)
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
/// ahead of now as if the field were absent. APT itself rejects a
/// future-dated `Release`; here the effect is milder -- an undated source
/// never overwrites a dated one and is itself overwritten by the next dated
/// one, which is the recovery this guards: the implausible date registers
/// its entries (so a cold cache still verifies against them) but can never
/// pin the directory against a later, honestly-dated `Release`.
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
/// into the registry. `release_dir` is the host-relative directory the
/// `Release` file lives in (`Release`'s entry paths are relative to it).
///
/// Only entries whose leaf matches a `Packages` file are inserted - those are
/// the only `Release`-listed resources the proxy verifies (layer C). Other
/// entries (`Contents-*`, `Translation-*`, ...) are skipped.
///
/// An older `Date:` than the directory's registered one registers nothing
/// (see `ChecksumRegistry::insert_release`) and still returns `Ok`. A
/// far-future `Date:` is clamped to absent first (see
/// [`clamp_future_release_date`]).
async fn ingest_release_file(
    registry: &ChecksumRegistry,
    host: &str,
    mirror_path: &str,
    path: &Path,
    release_dir: &str,
) -> std::io::Result<()> {
    let content = read_release_to_string(path).await?;
    let date = clamp_future_release_date(index_parser::parse_release_date(&content));
    let entries: Vec<(String, [u8; 32])> = index_parser::parse_release_checksums(&content)
        .filter_map(|(rel, digest)| {
            // Only Packages files are verified at layer C.
            let leaf = rel
                .rsplit('/')
                .next()
                .expect("rsplit yields at least one element");
            PackagesCompression::from_filename(leaf)?;
            // Resolve to the host-relative key (matches the Packages
            // lookup key): <release_dir>/<rel>.
            Some((
                format!("{}/{}", release_dir.trim_end_matches('/'), rel),
                digest,
            ))
        })
        .collect();
    if !registry.insert_release(host, mirror_path, release_dir, date, &entries) {
        debug!(
            "Not registering index `{}` for host {host} mirror {mirror_path}; a newer Release/InRelease of `{release_dir}` is already registered",
            path.display()
        );
    }
    Ok(())
}

/// Register one stanza's `(Filename, SHA256)` pair. A stanza without a
/// usable SHA256 (a SHA512-only mirror leaves every stanza that way, so deb
/// verification stays off for the whole archive) was already warned about
/// by [`StanzaStream`] and registers nothing.
fn ingest_stanza_into_registry(
    stanza: &index_parser::Stanza,
    registry: &ChecksumRegistry,
    host: &str,
    mirror_path: &str,
    format: IndexFormat,
) {
    let (Some(filename), Some(sha256)) = (stanza.filename.as_deref(), stanza.sha256) else {
        return;
    };
    let Some(key) = index_parser::registry_key_from_filename_field(filename, format) else {
        // `Stanza` already rejected (and logged) unsafe values, so this is
        // the length gate: a name no cache file can have.
        warn_once_or_debug!(
            "Not registering the digest of a {} byte Filename value from host {host} mirror {mirror_path}; no cache file can have that name",
            filename.len()
        );
        return;
    };
    registry.insert(host, mirror_path, &key, sha256);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn temp_file_with(content: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("create temp file");
        f.write_all(content).expect("write temp file");
        f.flush().expect("flush");
        f
    }

    // sha256("hello world") =
    // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    const HELLO_SHA256: &str = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

    /// A registry-style expectation: SHA256 over the 64-hex `digest`.
    fn expect_sha256(digest: &str) -> VerifyKind {
        VerifyKind::Expected {
            algo: HashAlgo::Sha256,
            digest: index_parser::hex_decode_exact::<32>(digest)
                .expect("test digest must be 64 hex chars")
                .to_vec(),
        }
    }

    /// An expectation nothing can match: 32 zero bytes.
    fn expect_zero_sha256() -> VerifyKind {
        VerifyKind::Expected {
            algo: HashAlgo::Sha256,
            digest: vec![0u8; 32],
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn packages_ingests_run_at_most_two_at_a_time() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static RUNNING: AtomicUsize = AtomicUsize::new(0);
        static PEAK: AtomicUsize = AtomicUsize::new(0);
        let tasks: Vec<_> = std::iter::repeat_with(|| {
            tokio::spawn(with_decode_permit(async {
                let now = RUNNING.fetch_add(1, Ordering::SeqCst) + 1;
                PEAK.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                RUNNING.fetch_sub(1, Ordering::SeqCst);
            }))
        })
        .take(6)
        .collect();
        for task in tasks {
            task.await.expect("ingest task");
        }
        assert_eq!(PEAK.load(Ordering::SeqCst), PACKAGES_INGEST_CONCURRENCY);
    }

    #[test]
    fn byhash_match_returns_proceed() {
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    /// The table must agree with `verify_and_rename`'s: exactly the kinds that
    /// can produce an expected digest opt in, and the by-hash ones take the
    /// algorithm their URL named rather than assuming SHA-256.
    #[cfg(feature = "splice")]
    #[test]
    fn stream_hash_algo_matches_the_verify_table() {
        // By-hash resources carry their digest in the URL, so the registry is
        // not consulted for them at all.
        assert_eq!(
            stream_hash_algo(
                ResourceKind::ByHash(HashAlgo::Sha512, ByHashContent::Other),
                false,
                true
            ),
            Some(HashAlgo::Sha512)
        );
        assert_eq!(
            stream_hash_algo(
                ResourceKind::FlatByHash(HashAlgo::Sha256, ByHashContent::Other),
                false,
                true
            ),
            Some(HashAlgo::Sha256)
        );
        assert_eq!(
            stream_hash_algo(ResourceKind::Pool, true, true),
            Some(HashAlgo::Sha256)
        );
        assert_eq!(
            stream_hash_algo(ResourceKind::Packages, true, true),
            Some(HashAlgo::Sha256)
        );

        // Registry-backed kinds with no digest on file: `verify_temp_file`
        // would return before hashing anything, so hashing the body as it
        // arrives would buy nothing.
        assert_eq!(stream_hash_algo(ResourceKind::Pool, false, true), None);
        assert_eq!(stream_hash_algo(ResourceKind::Packages, false, true), None);

        for kind in [
            ResourceKind::Release,
            ResourceKind::ComponentRelease,
            ResourceKind::Sources,
            ResourceKind::Translation,
            ResourceKind::Icon,
            ResourceKind::FlatMetadata,
            ResourceKind::FlatPool,
        ] {
            assert_eq!(stream_hash_algo(kind, true, true), None, "{kind:?}");
        }

        // Verification off: nothing is ever hashed.
        assert_eq!(stream_hash_algo(ResourceKind::Pool, true, false), None);
        assert_eq!(
            stream_hash_algo(
                ResourceKind::ByHash(HashAlgo::Sha512, ByHashContent::Other),
                true,
                false
            ),
            None
        );
    }

    /// The key each registry-backed kind is looked up under, so a change to
    /// the commit-time lookup and the pre-download one cannot drift apart.
    #[test]
    fn registry_lookup_key_covers_the_registry_backed_kinds() {
        const POOL: &str = "/debian/pool/main/h/hello/hello_1.0_amd64.deb";

        assert_eq!(
            registry_lookup_key(ResourceKind::Pool, "hello_1.0_amd64.deb", POOL).as_deref(),
            Some("hello_1.0_amd64.deb")
        );
        assert_eq!(
            registry_lookup_key(
                ResourceKind::Packages,
                "Packages.xz",
                "/dists/sid/main/binary-amd64/Packages.xz"
            )
            .as_deref(),
            Some("dists/sid/main/binary-amd64/Packages.xz")
        );
        // Every spelling of one URL looks up the key a normalized
        // `release_dir` registered.
        assert_eq!(
            registry_lookup_key(
                ResourceKind::Packages,
                "Packages.xz",
                "/debian//dists/./sid/main/binary-amd64/Packages.xz"
            )
            .as_deref(),
            Some("debian/dists/sid/main/binary-amd64/Packages.xz")
        );
        for kind in [
            ResourceKind::ByHash(HashAlgo::Sha256, ByHashContent::Other),
            ResourceKind::FlatByHash(HashAlgo::Sha256, ByHashContent::Other),
            ResourceKind::Release,
            ResourceKind::ComponentRelease,
            ResourceKind::Sources,
            ResourceKind::Translation,
            ResourceKind::Icon,
            ResourceKind::FlatMetadata,
            ResourceKind::FlatPool,
        ] {
            assert!(
                registry_lookup_key(kind, "hello_1.0_amd64.deb", POOL).is_none(),
                "{kind:?}"
            );
        }
    }

    /// A streamed digest of the right algorithm is trusted: the file's own
    /// bytes are never read, so a deliberately wrong on-disk body still
    /// passes. That is the whole point (the download already hashed what it
    /// wrote) and is also what proves the re-read was skipped.
    #[test]
    fn streamed_digest_is_used_instead_of_rereading() {
        let f = temp_file_with(b"not hello at all");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            temp_path: f.path(),
            streamed: Some(StreamedDigest {
                algo: HashAlgo::Sha256,
                digest: index_parser::byhash_digest_for_algo(HashAlgo::Sha256, HELLO_SHA256)
                    .expect("HELLO_SHA256 is valid hex"),
                bytes: b"not hello at all".len() as u64,
            }),
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn streamed_digest_mismatch_returns_reject() {
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            temp_path: f.path(),
            streamed: Some(StreamedDigest {
                algo: HashAlgo::Sha256,
                digest: vec![0u8; 32],
                bytes: b"hello world".len() as u64,
            }),
        };
        assert!(matches!(
            verify_temp_file(&plan),
            VerifyOutcome::Reject(CommitError::ChecksumMismatch)
        ));
    }

    /// A digest computed with a different algorithm than the one the expected
    /// digest needs is ignored, and the file is re-read and hashed instead --
    /// so the correct on-disk bytes still verify.
    #[test]
    fn streamed_digest_of_wrong_algo_falls_back_to_reread() {
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            temp_path: f.path(),
            // Right length for SHA-512, wrong algorithm for this resource.
            streamed: Some(StreamedDigest {
                algo: HashAlgo::Sha512,
                digest: vec![0u8; 64],
                bytes: b"hello world".len() as u64,
            }),
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    /// A digest that covered a different number of bytes than the file holds
    /// cannot describe that file, whatever the algorithm says. It is dropped
    /// and the file re-read, so the correct on-disk bytes still verify -- and
    /// the bogus digest never reaches the cleanup verification marker.
    #[test]
    fn streamed_digest_of_wrong_length_falls_back_to_reread() {
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            temp_path: f.path(),
            // Right algorithm, but it saw more bytes than the file holds.
            streamed: Some(StreamedDigest {
                algo: HashAlgo::Sha256,
                digest: vec![0u8; 32],
                bytes: 999,
            }),
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn byhash_mismatch_returns_reject() {
        let f = temp_file_with(b"tampered");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(
            verify_temp_file(&plan),
            VerifyOutcome::Reject(CommitError::ChecksumMismatch)
        ));
    }

    #[test]
    fn disabled_returns_proceed_without_hashing() {
        let f = temp_file_with(b"tampered");
        let plan = VerifyInput {
            verify_enabled: false,
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn non_verifiable_kind_returns_proceed() {
        let f = temp_file_with(b"anything");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::Unverifiable,
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn unreadable_temp_file_returns_reject_verifyio() {
        let plan = VerifyInput {
            verify_enabled: true,
            kind: byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256),
            temp_path: Path::new("/nonexistent/apt-cacher-rs/x"),
            streamed: None,
        };
        assert!(matches!(
            verify_temp_file(&plan),
            VerifyOutcome::Reject(CommitError::VerifyIo(_))
        ));
    }

    #[test]
    fn pool_with_known_matching_digest_proceeds() {
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: expect_sha256(HELLO_SHA256),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn pool_with_known_mismatching_digest_rejects() {
        let f = temp_file_with(b"tampered deb");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: expect_zero_sha256(),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(
            verify_temp_file(&plan),
            VerifyOutcome::Reject(CommitError::ChecksumMismatch)
        ));
    }

    #[test]
    fn packages_with_known_matching_digest_proceeds() {
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: expect_sha256(HELLO_SHA256),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn packages_with_mismatching_digest_rejects() {
        let f = temp_file_with(b"tampered packages");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: expect_zero_sha256(),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(
            verify_temp_file(&plan),
            VerifyOutcome::Reject(CommitError::ChecksumMismatch)
        ));
    }

    #[test]
    fn pool_with_unknown_digest_proceeds_best_effort() {
        let f = temp_file_with(b"some deb");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::Unknown,
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn registry_insert_and_lookup() {
        use std::num::NonZero;
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
        use std::num::NonZero;
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        // Same host, same basename, different mirror_path -> distinct entries.
        reg.insert("host", "m1", "foo_1_amd64.deb", [1u8; 32]);
        reg.insert("host", "m2", "foo_1_amd64.deb", [2u8; 32]);
        assert_eq!(reg.lookup("host", "m1", "foo_1_amd64.deb"), Some([1u8; 32]));
        assert_eq!(reg.lookup("host", "m2", "foo_1_amd64.deb"), Some([2u8; 32]));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn registry_evicts_oldest_at_cap() {
        use std::num::NonZero;
        let reg = ChecksumRegistry::new(NonZero::new(4).unwrap());
        for i in 0..4u8 {
            reg.insert("h", "m", &format!("p{i}"), [i; 32]);
        }
        assert_eq!(reg.len(), 4);
        // Inserting past the cap evicts the oldest batch.
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
        use std::num::NonZero;
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
    fn eviction_shrinks_the_scope_it_drains() {
        use std::num::NonZero;
        // One scope fills the cap, then another mirror's inserts make it pay
        // for the evictions: its map and order log must give the memory back
        // instead of keeping the footprint of 1000 entries.
        let reg = ChecksumRegistry::new(NonZero::new(1000).unwrap());
        for i in 0..1000u32 {
            reg.insert("big", "m", &format!("b{i}"), [0; 32]);
        }
        let (_, peak_capacity, _, _) = reg.scope_footprint("big", "m");
        for i in 0..600u32 {
            reg.insert("small", "m", &format!("s{i}"), [0; 32]);
        }
        let (len, capacity, order_len, order_capacity) = reg.scope_footprint("big", "m");
        assert!(len <= 500, "big paid for the evictions, {len} left");
        assert!(
            capacity <= 2 * len + 16 && capacity < peak_capacity,
            "entry capacity {capacity} for {len} entries (peak {peak_capacity})"
        );
        assert!(
            order_capacity <= 2 * order_len + 16,
            "order capacity {order_capacity} for {order_len} records"
        );
    }

    #[test]
    fn a_full_epoch_map_forgets_every_scope_and_stales_every_mark() {
        let scope = |host: &str| {
            Arc::new(RegistryScope {
                host: host.to_owned(),
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
        use std::num::NonZero;
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
        use std::num::NonZero;
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        reg.insert("h", "m", "p", [1u8; 32]);
        reg.insert("h", "m", "p", [2u8; 32]);
        assert_eq!(reg.lookup("h", "m", "p"), Some([2u8; 32]));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_reinsert_refreshes_eviction_position() {
        use std::num::NonZero;
        let reg = ChecksumRegistry::new(NonZero::new(4).unwrap());
        let d = [0u8; 32];
        reg.insert("h", "m", "a", d);
        reg.insert("h", "m", "b", d);
        reg.insert("h", "m", "c", d);
        reg.insert("h", "m", "d", d);
        // Refresh A -- order should now logically be B, C, D, A.
        reg.insert("h", "m", "a", d);
        // E pushes over cap (4) -> eviction drops oldest live entry, which is B.
        reg.insert("h", "m", "e", d);
        assert!(
            reg.lookup("h", "m", "a").is_some(),
            "A should survive re-insert refresh"
        );
        assert!(
            reg.lookup("h", "m", "b").is_none(),
            "B should be evicted first"
        );
        assert!(reg.lookup("h", "m", "c").is_some());
        assert!(reg.lookup("h", "m", "d").is_some());
        assert!(reg.lookup("h", "m", "e").is_some());
    }

    /// Regression: whether a by-hash object is also ingested as a `Packages`
    /// index used to be re-read from the directory before the raw path's
    /// *first* `by-hash` segment, while the parser validated the *last*. A
    /// decoy `by-hash/` run in front flipped the answer either way. The
    /// directory the parsed object hangs in decides now.
    #[test]
    fn byhash_ingest_is_decided_by_the_parsed_directory() {
        use crate::{
            cache_layout::classify_request, deb_mirror::parse_request_path,
            test_support::local_client,
        };

        for (path, expected) in [
            (
                "debian/dists/sid/main/binary-amd64",
                Some(IndexFormat::Structured),
            ),
            (
                "debian/dists/sid/main/source",
                Some(IndexFormat::Structured),
            ),
            // Deeper than the origin scope, still a `Packages` directory.
            (
                "debian/dists/sid/main/debian-installer/binary-amd64",
                Some(IndexFormat::Structured),
            ),
            ("debian/dists/sid/main/dep11", None),
            ("debian/dists/sid/main", None),
            ("debian/dists", None),
            ("debian/dists/sid/main/binary-amd64/Packages.diff", None),
            // Decoys: the directory before the first `by-hash` said otherwise.
            ("debian/dists/sid/main/binary-amd64/by-hash/MD5Sum", None),
            (
                "debian/dists/sid/main/i18n/by-hash/X/binary-amd64",
                Some(IndexFormat::Structured),
            ),
            ("apt/binary-amd64", Some(IndexFormat::Flat)),
            ("apt", None),
        ] {
            let path = format!("{path}/by-hash/SHA256/{HELLO_SHA256}");
            let resource = parse_request_path(&path).expect("parses as a by-hash object");
            let class = classify_request(&resource, &local_client()).expect("classifies");
            let raw_uri_path = format!("/{path}");
            let kind = ingest_kind(&IndexFile {
                resource_kind: class.resource_kind,
                debname: &class.debname,
                raw_uri_path: &raw_uri_path,
                host: "h",
                mirror_path: &class.mirror_path,
                path: Path::new("/cache/x"),
            });
            let format = if let Some(IngestKind::PackagesSniff { format }) = kind {
                Some(format)
            } else {
                assert!(kind.is_none(), "{path}: unexpected ingest kind");
                None
            };
            assert_eq!(format, expected, "{path}");
        }
    }

    /// Regression (verification bypass): the algorithm used to be re-read
    /// from the raw path after its *first* `by-hash` segment, while the
    /// parser validated the last one. A decoy `by-hash/X/` in front made
    /// that read come back empty, and the object was cached unverified. The
    /// algorithm now travels from the parser, so a body that does not hash
    /// to the digest in the URL is refused.
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
                verify_enabled: true,
                kind: byhash_verify_kind(algo, &class.debname),
                temp_path: f.path(),
                streamed: None,
            };
            assert!(
                matches!(
                    verify_temp_file(&plan),
                    VerifyOutcome::Reject(CommitError::ChecksumMismatch)
                ),
                "{path}"
            );
        }
    }

    #[test]
    fn byhash_length_algo_mismatch_caches_unverified() {
        // A SHA512 URL segment carrying a 64-hex (SHA256-length) digest is a
        // length/algo mismatch: it must NOT be hashed as SHA256. It resolves
        // to `Unknown` -> Proceed (cached unverified), never a spurious
        // mismatch.
        let kind = byhash_verify_kind(HashAlgo::Sha512, HELLO_SHA256);
        assert!(
            matches!(kind, VerifyKind::Unknown),
            "a digest whose length contradicts its URL algorithm must not become an expectation"
        );
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind,
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn byhash_well_formed_pair_becomes_an_expectation() {
        let resolved = match byhash_verify_kind(HashAlgo::Sha256, HELLO_SHA256) {
            VerifyKind::Expected { algo, digest } => Some((algo, digest)),
            VerifyKind::Unknown | VerifyKind::Unverifiable => None,
        };
        let (algo, digest) = resolved.expect("a matching algorithm/digest pair must be verifiable");
        assert_eq!(algo, HashAlgo::Sha256);
        assert_eq!(index_parser::hex_encode(&digest), HELLO_SHA256);
    }

    #[test]
    fn release_dir_extraction() {
        assert_eq!(
            release_dir_from_uri_path("/debian/dists/sid/Release"),
            Some("debian/dists/sid".to_string())
        );
        assert_eq!(
            release_dir_from_uri_path("/debian/dists/sid/InRelease"),
            Some("debian/dists/sid".to_string())
        );
        assert_eq!(
            release_dir_from_uri_path("/debian//dists/./sid/InRelease"),
            Some("debian/dists/sid".to_string()),
            "normalized like the Packages lookup key"
        );
        assert_eq!(release_dir_from_uri_path("/debian/pool/x/foo.deb"), None);
        // Release.gpg is a detached binary PGP signature with no SHA256
        // section, so the ingest dispatcher must not route it here.
        assert_eq!(
            release_dir_from_uri_path("/debian/dists/sid/Release.gpg"),
            None
        );
    }

    #[tokio::test]
    async fn ingest_release_populates_packages_digests() {
        use std::io::Write as _;
        use std::num::NonZero;

        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        let pkg_sha = [0x77u8; 32];
        let release = format!(
            "Origin: Test\nSHA256:\n 0000000000000000000000000000000000000000000000000000000000000000 1 main/binary-amd64/Release\n {} 4242 main/binary-amd64/Packages.xz\n",
            index_parser::hex_encode(&pkg_sha),
        );
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(release.as_bytes()).expect("write");
        f.flush().expect("flush");

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
        use std::num::NonZero;
        let newer = "Sun, 20 Sep 2026 08:53:33 UTC";
        let older = "Sat, 19 Sep 2026 08:53:33 UTC";
        let new_hex = "11".repeat(32);
        let old_hex = "22".repeat(32);
        let key = "debian/dists/sid/main/binary-amd64/Packages.xz";
        for newer_first in [true, false] {
            let dir = tempfile::tempdir().expect("tempdir");
            let inrelease = release_file(&dir, "InRelease", Some(newer), &new_hex);
            let release = release_file(&dir, "Release", Some(older), &old_hex);
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
        use std::num::NonZero;
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
    async fn a_future_dated_release_is_treated_as_undated() {
        use std::num::NonZero;
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

    #[tokio::test]
    async fn ingest_packages_populates_registry() {
        use std::io::Write as _;
        use std::num::NonZero;

        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        // Two minimal Packages stanzas (raw, uncompressed).
        let sha_a = [0xaau8; 32];
        let sha_b = [0xbbu8; 32];
        let packages = format!(
            "Package: a\nFilename: pool/main/a/a/a_1_amd64.deb\nSHA256: {}\n\n\
             Package: b\nFilename: pool/main/b/b/b_2_amd64.deb\nSHA256: {}\n",
            index_parser::hex_encode(&sha_a),
            index_parser::hex_encode(&sha_b),
        );
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(packages.as_bytes()).expect("write");
        f.flush().expect("flush");

        ingest_packages_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            PackagesCompression::Raw,
            IndexFormat::Structured,
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
    async fn ingest_packages_skips_filenames_no_cache_file_can_have() {
        use std::io::Write as _;
        use std::num::NonZero;

        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());
        let digest = index_parser::hex_encode(&[0xaau8; 32]);
        // A basename up to the 8 KiB line cap: before the length gate it was
        // retained verbatim, per entry.
        let long = "a".repeat(8000);
        let packages = format!(
            "Package: a\nFilename: pool/main/a/a/a_1_amd64.deb\nSHA256: {digest}\n\n\
             Package: long\nFilename: pool/main/l/l/{long}.deb\nSHA256: {digest}\n"
        );
        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(packages.as_bytes()).expect("write");
        f.flush().expect("flush");

        ingest_packages_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            PackagesCompression::Raw,
            IndexFormat::Structured,
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
        use std::num::NonZero;

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
            PackagesCompression::Xz,
            IndexFormat::Structured,
            64 * 1024,
        )
        .await
        .expect_err("an index past the compressed cap must be refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        assert!(err.to_string().contains("exceeds the"), "{err}");
    }

    #[tokio::test]
    async fn ingest_packages_rejects_decompression_bomb() {
        use std::num::NonZero;
        use tokio::io::AsyncWriteExt as _;
        // Registry ingest shares `limits::packages_reader` with cleanup's
        // reduce, so the ratio cap must bound it too: a gzip stream whose
        // decompressed size exceeds `compressed * MAX_DECOMPRESSION_RATIO` has
        // to fail rather than populate the registry from a bomb.
        let reg = ChecksumRegistry::new(NonZero::new(100).unwrap());

        // Highly-compressible payload: ~4 MiB of zero bytes gzips to a few KiB,
        // far past the 100x ratio cap.
        let mut encoder =
            async_compression::tokio::write::GzipEncoder::new(Vec::<u8>::with_capacity(4096));
        encoder
            .write_all(&vec![0u8; 4 * 1024 * 1024])
            .await
            .expect("write");
        encoder.shutdown().await.expect("shutdown");
        let compressed = encoder.into_inner();

        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        f.write_all(&compressed).expect("write");
        f.flush().expect("flush");

        let err = ingest_packages_file(
            &reg,
            "deb.debian.org",
            "debian",
            f.path(),
            PackagesCompression::Gz,
            IndexFormat::Structured,
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

    #[test]
    fn registry_reinsert_does_not_evict_live_under_stale_pressure() {
        use std::num::NonZero;
        let reg = ChecksumRegistry::new(NonZero::new(4).unwrap());
        let d = [0u8; 32];
        reg.insert("h", "m", "a", d);
        reg.insert("h", "m", "b", d);
        reg.insert("h", "m", "c", d);
        reg.insert("h", "m", "d", d);
        // Refresh A 100 times. Each re-insert leaves a stale order entry
        // (until compaction fires at order.len() > 2 * entries.len() + 16)
        // but moves A to the logical back of FIFO.
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
        use std::io::Write as _;
        use std::os::unix::fs::MetadataExt as _;

        use crate::verified_marker::has_valid_marker;

        let dir = tempfile::tempdir().expect("tempdir");
        let temp_path = dir.path().join("pkg.deb.part");
        let payload = b"a small deb body";
        {
            let mut f = std::fs::File::create(&temp_path).expect("create");
            f.write_all(payload).expect("write");
        }
        let digest: [u8; 32] = {
            use sha2::Digest as _;
            sha2::Sha256::digest(payload).into()
        };

        let outcome = verify_temp_file(&VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::Expected {
                algo: HashAlgo::Sha256,
                digest: digest.to_vec(),
            },
            temp_path: &temp_path,
            streamed: None,
        });
        assert!(matches!(outcome, VerifyOutcome::Proceed));

        let file = std::fs::File::open(&temp_path).expect("reopen");
        let meta = file.metadata().expect("metadata");
        assert!(
            has_valid_marker(
                &file,
                &temp_path,
                meta.ino(),
                meta.len(),
                HashAlgo::Sha256,
                &digest,
            ),
            "commit must leave a marker cleanup accepts, or the first cleanup pass re-hashes every fresh download"
        );
    }

    #[test]
    fn registry_order_compaction_bounds_memory() {
        use std::num::NonZero;
        let reg = ChecksumRegistry::new(NonZero::new(4).unwrap());
        let d = [0u8; 32];
        reg.insert("h", "m", "a", d);
        // Every re-insert of a live key appends a stale order record. The
        // compaction trigger is `order.len() > 2 * entries.len() + 16` -- 18
        // for this one-entry scope -- so 20 further inserts must cross it and
        // rebuild the log down to the single live entry. Without compaction
        // the log would hold all 21 records and this assert would fail.
        for _ in 0..20 {
            reg.insert("h", "m", "a", d);
        }
        assert!(
            reg.order_len() <= 2 * reg.len() + 16,
            "order_len={} must stay within the compaction trigger",
            reg.order_len()
        );
        assert_eq!(reg.len(), 1, "map still holds exactly one live entry");
        assert!(reg.lookup("h", "m", "a").is_some());
    }

    #[test]
    fn rename_into_cache_uses_an_existing_directory() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let src = dir.path().join("src.partial");
        std::fs::write(&src, b"payload").expect("write source");
        let dest = dir.path().join("dest.deb");

        rename_into_cache(&src, &dest).expect("rename into an existing directory");

        assert!(!src.exists(), "the source must be gone after the rename");
        assert_eq!(
            std::fs::read(&dest).expect("read destination"),
            b"payload",
            "the destination must hold the source's bytes"
        );
    }

    #[test]
    fn rename_into_cache_creates_a_missing_directory() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let src = dir.path().join("src.partial");
        std::fs::write(&src, b"payload").expect("write source");
        // Two missing levels: `entry_dir` can be several segments below the
        // mirror anchor (`dists/<suite>/<component>/by-hash/SHA256`).
        let dest = dir.path().join("dists/suite/by-hash/dest.deb");

        rename_into_cache(&src, &dest).expect("rename into a missing directory");

        assert!(!src.exists(), "the source must be gone after the rename");
        assert_eq!(
            std::fs::read(&dest).expect("read destination"),
            b"payload",
            "the destination must hold the source's bytes"
        );
    }

    #[test]
    fn ingest_errors_with_an_errno_are_retried_and_synthetic_ones_are_not() {
        use crate::ingest_ledger::Outcome;
        let os = std::io::Error::from_raw_os_error(nix::libc::EIO);
        let gone = std::io::Error::from_raw_os_error(nix::libc::ENOENT);
        let cap = limits::check_packages_file_size(PackagesCompression::Xz, u64::MAX)
            .expect_err("over the cap");
        let budget = std::io::Error::new(std::io::ErrorKind::TimedOut, "xz budget");
        assert_eq!(IngestResult::Failed(os).outcome(), Outcome::Retry);
        assert_eq!(IngestResult::Failed(gone).outcome(), Outcome::Retry);
        assert_eq!(IngestResult::Failed(cap).outcome(), Outcome::Failed);
        assert_eq!(IngestResult::Failed(budget).outcome(), Outcome::Failed);
        assert_eq!(IngestResult::Done.outcome(), Outcome::Ingested);
    }

    /// Admission happens before the spawn: with every slot taken a claim is
    /// refused and the path stays claimable; a burst of distinct paths never
    /// holds more `Running` entries than there are slots.
    #[test]
    fn admission_is_bounded_by_the_slots_and_refusal_is_retryable() {
        use crate::ingest_ledger::{IngestLedger, Outcome};
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

    /// A hostile mirror saturating the shared `Packages` line must not be
    /// able to refuse every other mirror's `Release` admission too.
    #[test]
    fn release_ingests_use_their_own_admission_pool() {
        let release = IngestKind::Release {
            release_dir: "debian/dists/sid".to_owned(),
        };
        let packages = IngestKind::Packages {
            compression: PackagesCompression::Xz,
            format: IndexFormat::Structured,
        };
        let sniff = IngestKind::PackagesSniff {
            format: IndexFormat::Structured,
        };
        assert!(std::ptr::eq(
            ingest_pool(&release),
            &raw const RELEASE_INGEST_SLOTS
        ));
        assert!(std::ptr::eq(
            ingest_pool(&packages),
            &raw const INGEST_SLOTS
        ));
        assert!(std::ptr::eq(ingest_pool(&sniff), &raw const INGEST_SLOTS));
    }

    #[test]
    fn index_kinds_are_classified_once_for_commit_and_touch() {
        let file = |resource_kind, debname, raw_uri_path| IndexFile {
            resource_kind,
            debname,
            raw_uri_path,
            host: "h",
            mirror_path: "debian",
            path: Path::new("/cache/x"),
        };
        assert!(matches!(
            ingest_kind(&file(
                ResourceKind::Packages,
                "sid_main_binary-amd64_Packages.xz",
                "/debian/dists/sid/main/binary-amd64/Packages.xz"
            )),
            Some(IngestKind::Packages {
                compression: PackagesCompression::Xz,
                ..
            })
        ));
        assert!(matches!(
            ingest_kind(&file(
                ResourceKind::ByHash(HashAlgo::Sha256, ByHashContent::MaybePackages),
                "abcd",
                "/debian/dists/sid/main/binary-amd64/by-hash/SHA256/abcd"
            )),
            Some(IngestKind::PackagesSniff { .. })
        ));
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
