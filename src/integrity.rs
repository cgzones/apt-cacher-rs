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

use std::collections::VecDeque;
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use hashbrown::{Equivalent, HashMap};
use parking_lot::Mutex;
use tracing::{debug, error, warn};

use crate::error::ErrorReport;
use crate::fs_open::{hint_sequential_read, nofollow_options, tokio_nofollow_options};
use crate::limits::{self, LimitedReader, PackagesCompression};
use crate::{
    cache_layout::ResourceKind,
    cache_quota::QuotaReservation,
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
    /// from the `<algo>` URL path segment (`SHA256`/`SHA512`), never inferred
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
/// `algo` is the authoritative algorithm from the URL's `<algo>` segment and
/// the digest length is cross-checked against it inside
/// [`index_parser::byhash_digest_for_algo`], so a pair that disagrees
/// degrades to [`VerifyKind::Unknown`] instead of hashing with a guessed
/// algorithm.
fn byhash_verify_kind(algo: Option<HashAlgo>, filename: &str) -> VerifyKind {
    let Some((algo, digest)) =
        algo.and_then(|a| index_parser::byhash_digest_for_algo(a, filename).map(|d| (a, d)))
    else {
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
    /// The raw request URI path (pre-normalisation). Used for the by-hash
    /// ingestion heuristic (segment before `by-hash`), for `Release`
    /// relative-path resolution, and as the relative-key component of the
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
/// (lost on restart, re-populated by the next `apt update`). FIFO bulk
/// eviction at the configured cap.
///
/// Two-level layout: essentially all entries of one mirror share the same
/// `(host, mirror_path)` pair, so a flat per-entry key would store those
/// strings ~100k times per Debian-main `Packages` ingest (tens of MB at the
/// default 500k cap). The scope is allocated once per mirror; entries only
/// own their relpath.
///
/// `insert` and `lookup` are module-private on purpose: the only writer is
/// the post-commit ingest below and the only reader is `verify_and_rename`,
/// so nothing outside this module can seed or consult expected digests.
/// `new` (from `main`) and `len` (the dashboard gauge) are the whole
/// crate-visible surface.
#[derive(Debug)]
pub(crate) struct ChecksumRegistry {
    inner: Mutex<RegistryInner>,
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

impl ChecksumRegistry {
    pub(crate) fn new(cap: NonZero<usize>) -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                map: HashMap::new(),
                len: 0,
                next_gen: 0,
            }),
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

        if inner.len > self.cap {
            // The dashboard only ever shows the post-eviction count, so a
            // registry permanently sized below its working set looks idle
            // while verification coverage quietly drops.
            info_once!(
                "Checksum registry reached its {} entry cap; evicting the oldest entries of the largest mirror scope (verification coverage drops for evicted keys)",
                self.cap
            );
            evict(&mut inner, self.cap);
        }
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

    #[cfg(test)]
    fn order_len(&self) -> usize {
        self.inner.lock().map.values().map(|s| s.order.len()).sum()
    }
}

/// Eviction: free `cap / 4` live entries, always from the scope currently
/// holding the most entries, oldest first. A scope that drains empty is
/// removed and the next-largest scope pays the remainder. Within a scope,
/// entries pop from the front of its `order`; stale ones (re-inserted keys
/// whose live generation is newer) are skipped and do not count against the
/// quota.
fn evict(inner: &mut RegistryInner, cap: usize) {
    let quota = (cap / 4).max(1);
    let mut live = 0usize;
    while live < quota {
        let Some(scope) = largest_scope(inner) else {
            break;
        };
        let Some(state) = inner.map.get_mut(&scope) else {
            break;
        };
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
        if state.entries.is_empty() {
            inner.map.remove(&scope);
        } else if live < quota {
            // Its order log drained without meeting the quota: only stale
            // entries were left, which the pops above already discarded.
            break;
        }
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
/// from `insert` when the log outgrows twice the live count, so amortized
/// O(1) per insert.
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
pub(crate) async fn verify_and_rename(
    plan: &RenamePlan,
    reservation: QuotaReservation,
) -> Result<(), CommitError> {
    let verify_enabled = global_config().verify_checksums;

    // Build the verification kind. Layer-B/C registry lookups happen here -
    // synchronously, before spawn_blocking - so the pure decision stays
    // global-free. Skipped entirely when verification is disabled.
    let kind = if verify_enabled {
        match plan.resource_kind {
            ResourceKind::ByHash | ResourceKind::FlatByHash => {
                byhash_verify_kind(byhash_algo_from_uri_path(&plan.raw_uri_path), &plan.debname)
            }
            kind @ (ResourceKind::Pool | ResourceKind::Packages) => {
                let key = registry_lookup_key(kind, &plan.debname, &plan.raw_uri_path)
                    .expect("Pool and Packages are the registry-backed kinds");
                registry_verify_kind(plan, key)
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
    let outcome = match tokio::task::spawn_blocking(move || {
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
    match tokio::task::spawn_blocking(move || {
        rename_into_cache(&temp_path, &dest_path).map(|()| reservation.finalize(bytes_received))
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
        spawn_ingest(plan);
    }

    Ok(())
}

/// Spawn a detached best-effort task to parse a just-committed index file into
/// the registry. No-op for non-index resources.
fn spawn_ingest(plan: &RenamePlan) {
    enum IngestKind {
        Packages {
            compression: PackagesCompression,
            format: IndexFormat,
        },
        /// Compression unknown (by-hash URL leaf is a hex digest); the
        /// spawned task sniffs magic bytes before parsing. Required because
        /// modern APT with `Acquire::By-Hash: yes` fetches `Packages.xz`
        /// (typically) via `/by-hash/SHA256/<hex>` URLs that carry no
        /// extension, so the filename-based detection used elsewhere fails.
        PackagesSniff {
            format: IndexFormat,
        },
        Release {
            release_dir: String,
        },
    }

    // For Packages/FlatMetadata, `plan.debname` is `_`-joined for structured
    // resources; extract the leaf filename (the part after the last `_`).
    let leaf = plan
        .debname
        .rsplit('_')
        .next()
        .expect("rsplit yields at least one element");

    // The structured and flat `Packages` arms are the same ingest, differing
    // only in how a `Filename:` field maps onto a registry key.
    let packages_kind = |format: IndexFormat| {
        let compression = PackagesCompression::from_filename(leaf);
        if compression.is_none() {
            log_unsupported_packages_compression(leaf, &plan.host);
        }
        compression.map(|compression| IngestKind::Packages {
            compression,
            format,
        })
    };

    #[expect(clippy::match_same_arms, reason = "prefer clarity")]
    let kind = match plan.resource_kind {
        ResourceKind::Packages => packages_kind(IndexFormat::Structured),
        // Flat Packages files are ingested into the registry (layer-B deb
        // verification).  Flat-layer-C (verifying a flat Packages file against
        // a flat Release) is not implemented - consistent with flat-pool layer-B
        // also being deferred.
        ResourceKind::FlatMetadata => packages_kind(IndexFormat::Flat),
        ResourceKind::Release => release_dir_from_uri_path(&plan.raw_uri_path)
            .map(|d| IngestKind::Release { release_dir: d }),
        // A per-component Release (`binary-<arch>/Release`) carries no SHA256:
        // section listing Packages files, so parsing it yields nothing useful.
        // Route it to the no-op group rather than wasting a file-open + parse.
        ResourceKind::ComponentRelease => None,
        // A by-hash file may be a Packages file. The raw URI path's
        // segment immediately before `by-hash` distinguishes a binary
        // Packages index from Contents/dep11/i18n by-hash content.
        ResourceKind::ByHash => {
            if byhash_path_looks_like_packages(&plan.raw_uri_path) {
                Some(IngestKind::PackagesSniff {
                    format: IndexFormat::Structured,
                })
            } else {
                None
            }
        }
        ResourceKind::FlatByHash => {
            // `byhash_path_looks_like_packages` matches a `binary-*` or
            // `source` segment before `by-hash`, which is a structured-layout
            // signature.  Flat by-hash URLs anchor at the flat repo's base
            // directory and never contain those tokens, so this arm is
            // effectively dead today.  Flat layer-C ingestion is deferred
            // (see `verify_and_rename`); leave the call in place to keep
            // the kind exhaustive.
            if byhash_path_looks_like_packages(&plan.raw_uri_path) {
                Some(IngestKind::PackagesSniff {
                    format: IndexFormat::Flat,
                })
            } else {
                None
            }
        }
        ResourceKind::Pool
        | ResourceKind::Sources
        | ResourceKind::Translation
        | ResourceKind::Icon
        | ResourceKind::FlatPool => None,
    };
    let Some(kind) = kind else { return };

    let host = plan.host.clone();
    let mirror_path = plan.mirror_path.clone();
    let dest = plan.dest_path.clone();
    let buffer_size = global_config().buffer_size;
    tokio::spawn(async move {
        let registry = global_checksum_registry();
        let result = match kind {
            IngestKind::Packages {
                compression,
                format,
            } => {
                ingest_packages_file(
                    registry,
                    &host,
                    &mirror_path,
                    &dest,
                    compression,
                    format,
                    buffer_size,
                )
                .await
            }
            IngestKind::PackagesSniff { format } => match sniff_packages_compression(&dest).await {
                Ok(compression) => {
                    ingest_packages_file(
                        registry,
                        &host,
                        &mirror_path,
                        &dest,
                        compression,
                        format,
                        buffer_size,
                    )
                    .await
                }
                Err(err) => Err(err),
            },
            IngestKind::Release { release_dir } => {
                ingest_release_file(registry, &host, &mirror_path, &dest, &release_dir).await
            }
        };
        if let Err(err) = result {
            // A persistent ingest failure leaves the registry empty, so every
            // deb from this mirror is committed unverified -- so far visible
            // only as a climbing CHECKSUM_UNVERIFIED.
            warn_once_or_debug!(
                "Failed to ingest index `{}` for host {host} mirror {mirror_path}; debs from this mirror stay unverified until an ingest succeeds:  {}",
                dest.display(),
                ErrorReport(&err),
            );
        } else {
            // Sync point for `wait_for_log("Index ingestion completed")`; keep the wording stable.
            debug!("Index ingestion completed for `{}`", dest.display());
        }
    });
}

/// The host-relative directory a `dists/.../Release` file lives in, derived
/// from the raw URI path (the parent directory of the `Release` leaf).
///
/// `Release.gpg` is a detached binary PGP signature with no SHA256 section to
/// ingest, so it's excluded — routing it here would just waste a file open
/// and a `read_to_string` of opaque bytes.
fn release_dir_from_uri_path(raw_uri_path: &str) -> Option<String> {
    let trimmed = raw_uri_path.trim_start_matches('/');
    let (dir, leaf) = trimmed.rsplit_once('/')?;
    if !matches!(leaf, "Release" | "InRelease") {
        return None;
    }
    Some(dir.to_owned())
}

/// `true` iff the raw by-hash URI path's segment immediately before `by-hash`
/// is a `binary-<arch>` or `source` directory - the only by-hash content that
/// is a `Packages`/`Sources` index. (`Sources` is parsed identically; its
/// stanzas carry no `Filename:` line so the parser yields nothing - harmless.)
fn byhash_path_looks_like_packages(raw_uri_path: &str) -> bool {
    let mut prev: Option<&str> = None;
    for seg in raw_uri_path.split('/') {
        if seg == "by-hash" {
            return matches!(prev, Some(p) if p.starts_with("binary-") || p == "source");
        }
        if !seg.is_empty() {
            prev = Some(seg);
        }
    }
    false
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
) -> Option<&'a str> {
    match resource_kind {
        // Layer B: a pool .deb's key is its bare basename, the form
        // `ingest_stanza_into_registry` inserted. Flat-pool downloads are
        // not verified this way, so no flat variant is needed.
        ResourceKind::Pool => Some(debname),
        // Layer C: the full host-relative URI path, as `ingest_release_file`
        // inserted it ("<release_dir>/<rel>").
        ResourceKind::Packages => Some(raw_uri_path.trim_start_matches('/')),
        ResourceKind::ByHash
        | ResourceKind::FlatByHash
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
    raw_uri_path: &str,
    registry_hit: bool,
    verify_enabled: bool,
) -> Option<HashAlgo> {
    if !verify_enabled {
        return None;
    }
    match resource_kind {
        // Self-verifying: the algorithm is named in the URL.
        ResourceKind::ByHash | ResourceKind::FlatByHash => byhash_algo_from_uri_path(raw_uri_path),
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
                .lookup(host, mirror_path, key)
                .is_some()
        });
    stream_hash_algo(
        resource_kind,
        raw_uri_path,
        registry_hit,
        global_config().verify_checksums,
    )
}

/// The hash algorithm of a `.../by-hash/<algo>/<hex>` URL, taken from the
/// segment immediately after `by-hash`. This is the *authoritative* algorithm
/// for a by-hash resource; the digest length is only cross-checked against it
/// (in `index_parser::byhash_digest_for_algo`), never used to infer it.
/// `None` if `by-hash` is absent or the following segment is not a recognised
/// algorithm - the resource is then cached unverified rather than hashed with a
/// guessed algorithm.
fn byhash_algo_from_uri_path(raw_uri_path: &str) -> Option<HashAlgo> {
    let mut segs = raw_uri_path.split('/').filter(|s| !s.is_empty());
    while let Some(seg) = segs.next() {
        if seg == "by-hash" {
            return match segs.next()? {
                "SHA256" => Some(HashAlgo::Sha256),
                "SHA512" => Some(HashAlgo::Sha512),
                _ => None,
            };
        }
    }
    None
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
        Ok(m) => m.len(),
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
                warn!(
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

/// Parse a `Release` / `InRelease` file and insert its `Packages*` entries
/// into the registry. `release_dir` is the host-relative directory the
/// `Release` file lives in (`Release`'s entry paths are relative to it).
///
/// Only entries whose leaf matches a `Packages` file are inserted - those are
/// the only `Release`-listed resources the proxy verifies (layer C). Other
/// entries (`Contents-*`, `Translation-*`, ...) are skipped.
async fn ingest_release_file(
    registry: &ChecksumRegistry,
    host: &str,
    mirror_path: &str,
    path: &Path,
    release_dir: &str,
) -> std::io::Result<()> {
    let content = read_release_to_string(path).await?;

    for (rel, digest) in index_parser::parse_release_checksums(&content) {
        // Only Packages files are verified at layer C.
        let leaf = rel
            .rsplit('/')
            .next()
            .expect("rsplit yields at least one element");
        if PackagesCompression::from_filename(leaf).is_none() {
            continue;
        }
        // Resolve to the host-relative key (matches the Packages lookup key):
        // <release_dir>/<rel>.
        let key = format!("{}/{}", release_dir.trim_end_matches('/'), rel);
        registry.insert(host, mirror_path, &key, digest);
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
    if let Some(filename) = stanza.filename.as_deref()
        && let Some(sha256) = stanza.sha256
        && let Some(key) = index_parser::registry_key_from_filename_field(filename, format)
    {
        registry.insert(host, mirror_path, &key, sha256);
    }
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

    #[test]
    fn byhash_match_returns_proceed() {
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256),
            temp_path: f.path(),
            streamed: None,
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    /// The table must agree with `verify_and_rename`'s: exactly the kinds that
    /// can produce an expected digest opt in, and the by-hash ones take their
    /// algorithm from the URL rather than assuming SHA-256.
    #[cfg(feature = "splice")]
    #[test]
    fn stream_hash_algo_matches_the_verify_table() {
        const BYHASH_512: &str = "/debian/dists/sid/main/by-hash/SHA512/abc";
        const BYHASH_256: &str = "/debian/dists/sid/main/by-hash/SHA256/abc";
        const POOL: &str = "/debian/pool/main/h/hello/hello_1.0_amd64.deb";

        // By-hash resources carry their digest in the URL, so the registry is
        // not consulted for them at all.
        assert_eq!(
            stream_hash_algo(ResourceKind::ByHash, BYHASH_512, false, true),
            Some(HashAlgo::Sha512)
        );
        assert_eq!(
            stream_hash_algo(ResourceKind::FlatByHash, BYHASH_256, false, true),
            Some(HashAlgo::Sha256)
        );
        assert_eq!(
            stream_hash_algo(ResourceKind::Pool, POOL, true, true),
            Some(HashAlgo::Sha256)
        );
        assert_eq!(
            stream_hash_algo(ResourceKind::Packages, "/debian/x/Packages.xz", true, true),
            Some(HashAlgo::Sha256)
        );

        // Registry-backed kinds with no digest on file: `verify_temp_file`
        // would return before hashing anything, so hashing the body as it
        // arrives would buy nothing.
        assert_eq!(
            stream_hash_algo(ResourceKind::Pool, POOL, false, true),
            None
        );
        assert_eq!(
            stream_hash_algo(ResourceKind::Packages, "/debian/x/Packages.xz", false, true),
            None
        );

        // A by-hash URL with no recognised algorithm segment is unverifiable,
        // so there is nothing to hash towards.
        assert_eq!(
            stream_hash_algo(ResourceKind::ByHash, POOL, true, true),
            None
        );

        for kind in [
            ResourceKind::Release,
            ResourceKind::ComponentRelease,
            ResourceKind::Sources,
            ResourceKind::Translation,
            ResourceKind::Icon,
            ResourceKind::FlatMetadata,
            ResourceKind::FlatPool,
        ] {
            assert_eq!(stream_hash_algo(kind, POOL, true, true), None, "{kind:?}");
        }

        // Verification off: nothing is ever hashed.
        assert_eq!(
            stream_hash_algo(ResourceKind::Pool, POOL, true, false),
            None
        );
        assert_eq!(
            stream_hash_algo(ResourceKind::ByHash, BYHASH_512, true, false),
            None
        );
    }

    /// The key each registry-backed kind is looked up under, so a change to
    /// the commit-time lookup and the pre-download one cannot drift apart.
    #[test]
    fn registry_lookup_key_covers_the_registry_backed_kinds() {
        const POOL: &str = "/debian/pool/main/h/hello/hello_1.0_amd64.deb";

        assert_eq!(
            registry_lookup_key(ResourceKind::Pool, "hello_1.0_amd64.deb", POOL),
            Some("hello_1.0_amd64.deb")
        );
        assert_eq!(
            registry_lookup_key(
                ResourceKind::Packages,
                "Packages.xz",
                "/dists/sid/main/binary-amd64/Packages.xz"
            ),
            Some("dists/sid/main/binary-amd64/Packages.xz")
        );
        for kind in [
            ResourceKind::ByHash,
            ResourceKind::FlatByHash,
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
            kind: byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256),
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
            kind: byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256),
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
            kind: byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256),
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
            kind: byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256),
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
            kind: byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256),
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
            kind: byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256),
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
            kind: byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256),
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

    #[test]
    fn byhash_packages_heuristic() {
        assert!(byhash_path_looks_like_packages(
            "/debian/dists/sid/main/binary-amd64/by-hash/SHA256/abcd"
        ));
        assert!(byhash_path_looks_like_packages(
            "/debian/dists/sid/main/source/by-hash/SHA256/abcd"
        ));
        assert!(!byhash_path_looks_like_packages(
            "/debian/dists/sid/main/dep11/by-hash/SHA256/abcd"
        ));
        assert!(!byhash_path_looks_like_packages(
            "/debian/dists/sid/by-hash/SHA256/abcd"
        ));
    }

    #[test]
    fn byhash_algo_extraction() {
        assert_eq!(
            byhash_algo_from_uri_path("/debian/dists/sid/main/binary-amd64/by-hash/SHA256/abcd"),
            Some(HashAlgo::Sha256)
        );
        assert_eq!(
            byhash_algo_from_uri_path("/debian/dists/sid/main/binary-amd64/by-hash/SHA512/abcd"),
            Some(HashAlgo::Sha512)
        );
        // Unrecognised algorithm segment, or no by-hash marker at all.
        assert_eq!(
            byhash_algo_from_uri_path("/debian/dists/sid/main/binary-amd64/by-hash/MD5Sum/abcd"),
            None
        );
        assert_eq!(byhash_algo_from_uri_path("/debian/pool/x/foo.deb"), None);
    }

    #[test]
    fn byhash_length_algo_mismatch_caches_unverified() {
        // A SHA512 URL segment carrying a 64-hex (SHA256-length) digest is a
        // length/algo mismatch: it must NOT be hashed as SHA256. It resolves
        // to `Unknown` -> Proceed (cached unverified), never a spurious
        // mismatch.
        let kind = byhash_verify_kind(Some(HashAlgo::Sha512), HELLO_SHA256);
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
    fn byhash_missing_algo_caches_unverified() {
        // No algorithm from the URL -> unverifiable, even if the filename would
        // decode as some digest.
        let kind = byhash_verify_kind(None, HELLO_SHA256);
        assert!(
            matches!(kind, VerifyKind::Unknown),
            "a by-hash URL with no recognised algorithm segment must not become an expectation"
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
        let resolved = match byhash_verify_kind(Some(HashAlgo::Sha256), HELLO_SHA256) {
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
