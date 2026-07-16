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
use tokio::io::AsyncBufRead;
use tracing::{debug, error, warn};

use crate::error::ErrorReport;
use crate::limits::LimitedReader;
use crate::utils::{nofollow_options, tokio_nofollow_options};
use crate::xz_stream::xz_decoder;
use crate::{
    cache_layout::ResourceKind,
    index_parser::{self, HashAlgo, IndexFormat},
    metrics,
};
use crate::{global_checksum_registry, global_config, limits, warn_once_or_info};

/// Why a download could not be committed to the cache. All three variants are
/// handled by callers exactly as a pre-existing rename failure is handled
/// today (log, drop the barrier, skip DB records).
#[derive(Debug)]
pub(crate) enum CommitError {
    /// The downloaded content did not match its expected digest.
    ChecksumMismatch,
    /// Reading the temp file back for verification failed. Fail-closed: a file
    /// that cannot be verified does not enter the cache.
    VerifyIo(std::io::Error),
    /// `tokio::fs::rename` of the verified temp file failed.
    Rename(std::io::Error),
}

impl std::fmt::Display for CommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChecksumMismatch => f.write_str("checksum mismatch"),
            Self::VerifyIo(e) => write!(f, "verification I/O error: {e}"),
            Self::Rename(e) => write!(f, "rename failed: {e}"),
        }
    }
}

impl std::error::Error for CommitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ChecksumMismatch => None,
            Self::VerifyIo(e) | Self::Rename(e) => Some(e),
        }
    }
}

/// Input for [`verify_temp_file`]. Holds everything the decision needs as
/// plain values/borrows so the decision logic is global-free (no `global_config()`, no
/// process-wide registry) and therefore unit-testable. Note: `verify_temp_file`
/// performs file I/O (it reads and hashes `temp_path`) - it is not a pure
/// function, but it is free of process-global state.
pub(crate) struct VerifyInput<'a> {
    /// `config.verify_checksums`.
    pub(crate) verify_enabled: bool,
    pub(crate) kind: VerifyKind,
    pub(crate) temp_path: &'a Path,
}

/// What the downloaded temp file is verified against. Construction (in
/// `verify_and_rename`) encodes the resource-kind -> expected-digest mapping,
/// so the pure decision never has to re-derive it - and the old "`ByHash`
/// always carries a filename" invariant (previously a runtime `.expect()`) is
/// no longer representable as a mismatched field combination.
pub(crate) enum VerifyKind {
    /// By-hash (`ResourceKind::ByHash` / `FlatByHash`): the URL filename is the
    /// expected hex digest and `algo` is the authoritative algorithm taken from
    /// the `<algo>` URL path segment (`SHA256`/`SHA512`), NOT inferred from the
    /// digest length. Self-verifying - the digest is embedded in the request.
    /// `algo` is `None` when the by-hash URL carried no recognised algorithm
    /// segment (then treated as unverifiable).
    ByHash {
        algo: Option<HashAlgo>,
        filename: String,
    },
    /// Registry-backed (`Pool` .deb / `Packages`): expected SHA256 from the
    /// in-memory registry, if known. `None` -> cached unverified (best effort).
    Registry { digest: Option<[u8; 32]> },
    /// Not verifiable by this module today (other metadata, flat-pool .debs).
    Unverifiable,
}

/// Result of the pure verification decision.
#[derive(Debug)]
pub(crate) enum VerifyOutcome {
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
pub(crate) fn verify_temp_file(input: &VerifyInput<'_>) -> VerifyOutcome {
    if !input.verify_enabled {
        return VerifyOutcome::Proceed;
    }

    // Determine the expected (algo, digest), if any.
    let expected: Option<(HashAlgo, Vec<u8>)> = match &input.kind {
        VerifyKind::ByHash { algo, filename } => {
            let decoded = algo
                .and_then(|a| index_parser::byhash_digest_for_algo(a, filename).map(|d| (a, d)));
            if decoded.is_none() {
                // Defence in depth: the URL parser already rejects anything
                // other than `SHA256/<64-hex>` or `SHA512/<128-hex>` with the
                // algorithm segment cross-checked against the digest length, so
                // reaching this branch indicates a future divergence between
                // the parser and the digest decoder. Keep the warning visible.
                warn_once_or_info!(
                    "By-hash digest did not decode for its URL algorithm; caching unverified: `{}`",
                    filename
                );
            }
            decoded
        }
        VerifyKind::Registry { digest } => digest.map(|d| (HashAlgo::Sha256, d.to_vec())),
        // Flat-pool .debs (Layer-B path-alignment deferred) and other metadata
        // resources have no registry-backed digest today.
        VerifyKind::Unverifiable => None,
    };

    let Some((algo, expected)) = expected else {
        // Best-effort: no known digest -> cache unverified. Only count it for
        // kinds that *could* have been verified, so the metric reflects a real
        // coverage gap rather than every metadata / flat-pool file.
        if !matches!(input.kind, VerifyKind::Unverifiable) {
            metrics::CHECKSUM_UNVERIFIED.increment();
        }
        return VerifyOutcome::Proceed;
    };

    let computed = match hash_file(input.temp_path, algo) {
        Ok(c) => c,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read `{}` for {} verification:  {}",
                input.temp_path.display(),
                algo.as_str(),
                ErrorReport(&err),
            );
            return VerifyOutcome::Reject(CommitError::VerifyIo(err));
        }
    };

    if computed == expected {
        metrics::CHECKSUM_VERIFIED.increment();
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

/// Open `path` with `O_NOFOLLOW`, hint sequential read, and hash it.
fn hash_file(path: &Path, algo: HashAlgo) -> std::io::Result<Vec<u8>> {
    let mut file = nofollow_options().read(true).open(path)?;
    hint_sequential_read_std(&file, path);
    match algo {
        HashAlgo::Sha256 => index_parser::hash_open_file::<sha2::Sha256>(&mut file),
        HashAlgo::Sha512 => index_parser::hash_open_file::<sha2::Sha512>(&mut file),
    }
}

/// Hint sequential read on a `std::fs::File`. Mirrors the logic of
/// `crate::utils::hint_sequential_read`, which requires `&tokio::fs::File`
/// and cannot be called from a synchronous context.
fn hint_sequential_read_std(file: &std::fs::File, path: &Path) {
    use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};

    if let Err(errno) = posix_fadvise(file, 0, 0, PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL) {
        // Non-fatal: fall back to the kernel's default readahead policy.
        debug!(
            "posix_fadvise(SEQUENTIAL) failed for `{}`:  {errno}",
            path.display()
        );
    }
}

/// Everything `verify_and_rename` needs, assembled by each download backend at
/// its rename site and handed to `RenameBarrier::commit`.
pub(crate) struct RenamePlan {
    /// The finished `.partial` / temp file to verify and rename.
    pub(crate) temp_path: PathBuf,
    /// The final cache path to rename into.
    pub(crate) dest_path: PathBuf,
    /// Actual bytes on disk after download (passed through to the barrier's
    /// `Finished` accounting / quota finalisation). For resumed downloads
    /// this includes the pre-existing prefix.
    pub(crate) bytes_received: u64,
    /// Precise resource kind, from `ConnectionDetails::resource_kind`.
    pub(crate) resource_kind: ResourceKind,
    /// On-disk leaf name. For a by-hash resource this is the hex digest, used
    /// by `verify_temp_file` to decode the expected hash; for `Pool` it is
    /// the basename used as the registry-lookup key via
    /// `registry_key_for_download`; for other kinds it is kept only for log
    /// context.
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
/// the pattern in `active_downloads.rs` (`ActiveDownloadKeyRef`).
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
#[derive(Debug)]
pub(crate) struct ChecksumRegistry {
    inner: Mutex<RegistryInner>,
    cap: usize,
}

/// Per-scope relpath map: digest plus insert generation (see
/// `RegistryInner::next_gen`).
type ScopeEntries = HashMap<Arc<str>, ([u8; 32], u64)>;

#[derive(Debug)]
struct RegistryInner {
    /// `(host, mirror_path)` scope to per-relpath `(digest, generation)`.
    /// The generation is the value of `next_gen` at the moment of the most
    /// recent insert for that relpath. The scope `Arc` and relpath
    /// `Arc<str>` are shared with `order`, so `insert` allocates each
    /// string once.
    map: HashMap<Arc<RegistryScope>, ScopeEntries>,
    /// Total relpath entry count across all scopes (the outer map's `len`
    /// counts scopes, not entries).
    len: usize,
    /// Insertion-order log for FIFO eviction. Each entry pairs the key with
    /// the generation it was inserted at. Entries whose generation no longer
    /// matches the live entry are stale (the key was re-inserted later); the
    /// eviction loop skips them and `compact_order` periodically removes
    /// them.
    order: VecDeque<(Arc<RegistryScope>, Arc<str>, u64)>,
    /// Monotonic counter, incremented on every `insert`. Overflow at 2^64
    /// is unreachable in practice (millennia at any realistic insert rate).
    next_gen: u64,
}

impl RegistryInner {
    /// Live generation of `(scope, relpath)`, if present.
    fn live_generation(&self, scope: &Arc<RegistryScope>, relpath: &Arc<str>) -> Option<u64> {
        self.map
            .get(scope)
            .and_then(|submap| submap.get(relpath))
            .map(|&(_, generation)| generation)
    }
}

impl ChecksumRegistry {
    pub(crate) fn new(cap: NonZero<usize>) -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                map: HashMap::new(),
                len: 0,
                order: VecDeque::new(),
                next_gen: 0,
            }),
            cap: cap.get(),
        }
    }

    /// Insert (or refresh) an expected digest. At the cap, evicts the oldest
    /// ~25% of entries in one pass. Re-inserting an existing key refreshes
    /// its eviction-order position to most-recent.
    pub(crate) fn insert(&self, host: &str, mirror_path: &str, relpath: &str, digest: [u8; 32]) {
        let mut inner = self.inner.lock();
        let generation = inner.next_gen;
        inner.next_gen += 1;

        let scope_ref = RegistryScopeRef { host, mirror_path };
        let scope = match inner.map.get_key_value(&scope_ref) {
            Some((scope, _)) => Arc::clone(scope),
            None => {
                let scope = Arc::new(RegistryScope {
                    host: host.to_owned(),
                    mirror_path: mirror_path.to_owned(),
                });
                inner.map.insert(Arc::clone(&scope), ScopeEntries::new());
                scope
            }
        };

        let submap = inner
            .map
            .get_mut(&scope)
            .expect("scope was just looked up or inserted");
        // Reuse the existing relpath allocation on refresh; `Arc<str>:
        // Borrow<str>` makes the borrowed lookup allocation-free.
        let rel = match submap.get_key_value(relpath) {
            Some((rel, _)) => Arc::clone(rel),
            None => Arc::from(relpath),
        };
        if submap
            .insert(Arc::clone(&rel), (digest, generation))
            .is_none()
        {
            inner.len += 1;
        }
        inner.order.push_back((scope, rel, generation));

        if inner.len > self.cap {
            evict(&mut inner, self.cap);
        }
        if inner.order.len() > 2 * self.cap {
            compact_order(&mut inner);
        }
    }

    /// Look up an expected digest by `(host, mirror_path, relpath)`.
    /// Allocation-free via `hashbrown::Equivalent` and `Arc<str>:
    /// Borrow<str>`.
    pub(crate) fn lookup(&self, host: &str, mirror_path: &str, relpath: &str) -> Option<[u8; 32]> {
        let inner = self.inner.lock();
        inner
            .map
            .get(&RegistryScopeRef { host, mirror_path })
            .and_then(|submap| submap.get(relpath))
            .map(|&(digest, _)| digest)
    }

    /// Current entry count (for the web dashboard).
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().len
    }

    #[cfg(test)]
    pub(crate) fn order_len(&self) -> usize {
        self.inner.lock().order.len()
    }
}

/// FIFO eviction: pop from the front of `order`, drop live entries whose
/// generation still matches the map, skip stale ones (re-inserted keys whose
/// current generation is newer than the popped one). Stale skips do not
/// count against `quota`, so each pass frees `min(quota, live remaining)`
/// entries. Scopes whose submap drains empty are removed with it.
fn evict(inner: &mut RegistryInner, cap: usize) {
    let quota = (cap / 4).max(1);
    let mut live = 0usize;
    while live < quota {
        let Some((scope, rel, generation)) = inner.order.pop_front() else {
            break;
        };
        let Some(submap) = inner.map.get_mut(&scope) else {
            continue;
        };
        match submap.get(&rel) {
            Some(&(_, current_gen)) if current_gen == generation => {
                submap.remove(&rel);
                inner.len -= 1;
                live += 1;
                if submap.is_empty() {
                    inner.map.remove(&scope);
                }
            }
            _ => {
                // Stale entry: the key was re-inserted later (newer gen) or
                // already evicted. Drop it; do not consume eviction quota.
            }
        }
    }
}

/// Rebuild `order` keeping only entries whose generation matches the
/// current live entry in the map. Preserves FIFO order of live entries.
/// Triggered from `insert` when `order.len() > 2 * cap`, so amortized
/// O(1) per insert. Worst-case pass is O(order.len()).
fn compact_order(inner: &mut RegistryInner) {
    let mut compacted = VecDeque::with_capacity(inner.len);
    while let Some(entry) = inner.order.pop_front() {
        let (ref scope, ref rel, generation) = entry;
        if inner.live_generation(scope, rel) == Some(generation) {
            compacted.push_back(entry);
        }
    }
    inner.order = compacted;
}

/// Verify the finished temp file and, on success, rename it into place.
///
/// Returns `Ok(())` when the file is verified (or verification was
/// skipped/best-effort) and the rename succeeded. Returns `Err(CommitError)`
/// on mismatch, verification I/O failure, or rename failure -- in every case
/// the temp file is left for its `TempPath` drop guard to unlink.
pub(crate) async fn verify_and_rename(plan: &RenamePlan) -> Result<(), CommitError> {
    let verify_enabled = global_config().verify_checksums;

    // Build the verification kind. Layer-B/C registry lookups happen here -
    // synchronously, before spawn_blocking - so the pure decision stays
    // global-free. Skipped entirely when verification is disabled.
    let kind = if verify_enabled {
        match plan.resource_kind {
            ResourceKind::ByHash | ResourceKind::FlatByHash => VerifyKind::ByHash {
                algo: byhash_algo_from_uri_path(&plan.raw_uri_path),
                filename: plan.debname.clone(),
            },
            ResourceKind::Pool => VerifyKind::Registry {
                digest: global_checksum_registry().lookup(
                    &plan.host,
                    &plan.mirror_path,
                    &index_parser::registry_key_for_download(&plan.debname),
                ),
            },
            ResourceKind::Packages => {
                // Layer C: a Packages file's key is its full host-relative URI
                // path (what ingest_release_file inserted: "<release_dir>/<rel>").
                let key = plan.raw_uri_path.trim_start_matches('/');
                VerifyKind::Registry {
                    digest: global_checksum_registry().lookup(&plan.host, &plan.mirror_path, key),
                }
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
    let outcome = match tokio::task::spawn_blocking(move || {
        verify_temp_file(&VerifyInput {
            verify_enabled,
            kind,
            temp_path: &temp_path,
        })
    })
    .await
    {
        Ok(outcome) => outcome,
        Err(join_err) => {
            error!(
                "Verification task failed for `{}` from host `{}`:  {}",
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
                "Checksum mismatch for `{}` from host `{}`; not caching",
                plan.debname, plan.host,
            );
        }
        return Err(err);
    }

    tokio::fs::rename(&plan.temp_path, &plan.dest_path)
        .await
        .map_err(CommitError::Rename)?;

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

    #[expect(clippy::match_same_arms, reason = "prefer clarity")]
    let kind = match plan.resource_kind {
        ResourceKind::Packages => {
            PackagesCompression::from_filename(leaf).map(|c| IngestKind::Packages {
                compression: c,
                format: IndexFormat::Structured,
            })
        }
        // Flat Packages files are ingested into the registry (layer-B deb
        // verification).  Flat-layer-C (verifying a flat Packages file against
        // a flat Release) is not implemented - consistent with flat-pool layer-B
        // also being deferred.
        ResourceKind::FlatMetadata => {
            PackagesCompression::from_filename(leaf).map(|c| IngestKind::Packages {
                compression: c,
                format: IndexFormat::Flat,
            })
        }
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
            debug!(
                "Index ingestion of `{}` failed:  {}",
                dest.display(),
                ErrorReport(&err),
            );
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

/// Compression of a `Packages` file, derived from its filename extension.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum PackagesCompression {
    Raw,
    Gz,
    Xz,
}

impl PackagesCompression {
    /// Derive from a filename leaf. `None` if the leaf does not look like a
    /// `Packages` file at all.
    pub(crate) fn from_filename(name: &str) -> Option<Self> {
        if name == "Packages" {
            Some(Self::Raw)
        } else if name == "Packages.gz" {
            Some(Self::Gz)
        } else if name == "Packages.xz" {
            Some(Self::Xz)
        } else {
            None
        }
    }
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
pub(crate) async fn ingest_packages_file(
    registry: &ChecksumRegistry,
    host: &str,
    mirror_path: &str,
    path: &std::path::Path,
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
                "Could not stat `{}` for decompression-ratio guard during Packages ingestion:  {}",
                path.display(),
                ErrorReport(&err),
            );
            u64::MAX
        }
    };
    let decompressed_limit = match NonZero::new(compressed_size) {
        Some(cs) => limits::MAX_DECOMPRESSED_PACKAGES_SIZE
            .min(cs.saturating_mul(limits::MAX_DECOMPRESSION_RATIO)),
        None => limits::MAX_DECOMPRESSED_PACKAGES_SIZE,
    };

    let mut raw;
    let mut gz;
    let mut xz;
    let reader: &mut (dyn AsyncBufRead + Unpin + Send) = match compression {
        PackagesCompression::Raw => {
            // No inner BufReader here: file -> LimitedReader -> BufReader.
            // A decompression layer (Gz/Xz) benefits from buffering its
            // compressed input; raw bytes need no such amortisation.
            let limited = LimitedReader::new(file, decompressed_limit);
            raw = tokio::io::BufReader::with_capacity(buffer_size, limited);
            &mut raw
        }
        PackagesCompression::Gz => {
            let file_reader = tokio::io::BufReader::with_capacity(buffer_size, file);
            let decoder = async_compression::tokio::bufread::GzipDecoder::new(file_reader);
            let limited = LimitedReader::new(decoder, decompressed_limit);
            gz = tokio::io::BufReader::with_capacity(buffer_size, limited);
            &mut gz
        }
        PackagesCompression::Xz => {
            let file_reader = tokio::io::BufReader::with_capacity(buffer_size, file);
            let decoder = xz_decoder(file_reader);
            let limited = LimitedReader::new(decoder, decompressed_limit);
            xz = tokio::io::BufReader::with_capacity(buffer_size, limited);
            &mut xz
        }
    };

    let mut line = String::with_capacity(128);
    let mut line_buf: Vec<u8> = Vec::with_capacity(128);
    let mut stanza = index_parser::Stanza::new_sha256_only();
    loop {
        line.clear();
        match limits::read_line_capped(
            &mut *reader,
            &mut line,
            &mut line_buf,
            limits::MAX_METADATA_LINE_LEN,
        )
        .await
        {
            Ok(limits::CappedLine::Eof) => {
                flush_stanza_into_registry(&mut stanza, registry, host, mirror_path, format);
                return Ok(());
            }
            Ok(limits::CappedLine::Skipped) => {
                // A line longer than MAX_METADATA_LINE_LEN can't be one of
                // the fields the stanza parser cares about (Filename,
                // SHA256, SHA512 are all well under the cap). Treat it as a
                // non-blank line so the stanza isn't flushed prematurely.
            }
            Ok(limits::CappedLine::Line { bytes: _ }) => {
                if line.trim().is_empty() {
                    flush_stanza_into_registry(&mut stanza, registry, host, mirror_path, format);
                } else {
                    stanza.ingest(&line);
                }
            }
            Err(err) => {
                warn!(
                    "Failed to read `{}` during Packages ingestion (may exceed size/line limits):  {}",
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
pub(crate) async fn read_release_to_string(path: &std::path::Path) -> std::io::Result<String> {
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
pub(crate) async fn ingest_release_file(
    registry: &ChecksumRegistry,
    host: &str,
    mirror_path: &str,
    path: &std::path::Path,
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

fn flush_stanza_into_registry(
    stanza: &mut index_parser::Stanza,
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
    stanza.reset();
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

    #[test]
    fn byhash_match_returns_proceed() {
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::ByHash {
                algo: Some(HashAlgo::Sha256),
                filename: HELLO_SHA256.to_string(),
            },
            temp_path: f.path(),
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn byhash_mismatch_returns_reject() {
        let f = temp_file_with(b"tampered");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::ByHash {
                algo: Some(HashAlgo::Sha256),
                filename: HELLO_SHA256.to_string(),
            },
            temp_path: f.path(),
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
            kind: VerifyKind::ByHash {
                algo: Some(HashAlgo::Sha256),
                filename: HELLO_SHA256.to_string(),
            },
            temp_path: f.path(),
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
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn unreadable_temp_file_returns_reject_verifyio() {
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::ByHash {
                algo: Some(HashAlgo::Sha256),
                filename: HELLO_SHA256.to_string(),
            },
            temp_path: std::path::Path::new("/nonexistent/apt-cacher-rs/x"),
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
            kind: VerifyKind::Registry {
                digest: Some(index_parser::hex_decode_exact::<32>(HELLO_SHA256).unwrap()),
            },
            temp_path: f.path(),
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn pool_with_known_mismatching_digest_rejects() {
        let f = temp_file_with(b"tampered deb");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::Registry {
                digest: Some([0u8; 32]),
            },
            temp_path: f.path(),
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
            kind: VerifyKind::Registry {
                digest: Some(index_parser::hex_decode_exact::<32>(HELLO_SHA256).unwrap()),
            },
            temp_path: f.path(),
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn packages_with_mismatching_digest_rejects() {
        let f = temp_file_with(b"tampered packages");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::Registry {
                digest: Some([0u8; 32]),
            },
            temp_path: f.path(),
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
            kind: VerifyKind::Registry { digest: None },
            temp_path: f.path(),
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
        // length/algo mismatch: it must NOT be hashed as SHA256. It decodes to
        // None -> Proceed (cached unverified), never a spurious mismatch.
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::ByHash {
                algo: Some(HashAlgo::Sha512),
                filename: HELLO_SHA256.to_string(), // 64 hex chars
            },
            temp_path: f.path(),
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
    }

    #[test]
    fn byhash_missing_algo_caches_unverified() {
        // No algorithm from the URL -> unverifiable, even if the filename would
        // decode as some digest.
        let f = temp_file_with(b"hello world");
        let plan = VerifyInput {
            verify_enabled: true,
            kind: VerifyKind::ByHash {
                algo: None,
                filename: HELLO_SHA256.to_string(),
            },
            temp_path: f.path(),
        };
        assert!(matches!(verify_temp_file(&plan), VerifyOutcome::Proceed));
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
        // (until compaction fires at order.len() > 2*cap=8) but moves A to
        // the logical back of FIFO.
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
    fn registry_order_compaction_bounds_memory() {
        use std::num::NonZero;
        let reg = ChecksumRegistry::new(NonZero::new(4).unwrap());
        let d = [0u8; 32];
        reg.insert("h", "m", "a", d);
        // 20 re-inserts of the same key (well past the 2*cap=8 trigger).
        // Compaction must fire at least twice during this loop.
        for _ in 0..20 {
            reg.insert("h", "m", "a", d);
        }
        // After every insert, the compaction trigger (order.len() > 8) is
        // either inert (<=8) or fires and drops order back to map.len()=1.
        // So order_len observed from outside is always <= 8.
        assert!(
            reg.order_len() <= 2 * 4,
            "order_len={} should be bounded by 2*cap=8 after compaction",
            reg.order_len()
        );
        assert_eq!(reg.len(), 1, "map still holds exactly one live entry");
        assert!(reg.lookup("h", "m", "a").is_some());
    }
}
