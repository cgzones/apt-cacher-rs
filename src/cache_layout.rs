//! Where a `ResourceFile` lives on disk, and [`classify_request`], which
//! decodes, validates and classifies an incoming request.
//!
//! # Layout
//!
//! Two branches, chosen by [`CacheLayout::is_flat`]:
//!
//! ```text
//! Structured: {cache_directory}/{host[:port]}/{mirror_path}/{subdir?}/{debname}
//! Flat:       {cache_directory}/{host[:port]}/flat/{mirror_path}/{by-hash?}/{debname}
//! ```
//!
//! Flat repositories anchor at the host-level `flat/` sibling rather than
//! nesting beneath a per-mirror subdirectory.  The URL path becomes the
//! on-disk path verbatim, so a request for `apt/amd64/twilio_5.0.0_amd64.deb`
//! lands at `{cache}/{host}/flat/apt/amd64/twilio_5.0.0_amd64.deb`.
//!
//! # Per-variant mapping
//!
//! | `ResourceFile` variant       | host-level anchor | mirror subdir            | `debname` shape                                | `cached_flavor` |
//! |------------------------------|-------------------|--------------------------|------------------------------------------------|-----------------|
//! | `Pool`                       | `{mirror_path}`   | `None`                   | `{filename}`                                   | `Permanent`     |
//! | `Release`                    | `{mirror_path}`   | `Some("dists")`          | `{distribution}_{filename}`                    | `Volatile`      |
//! | `Packages`                   | `{mirror_path}`   | `Some("dists")`          | `{distribution}_{component}_{architecture}_{filename}` | `Volatile` |
//! | `ComponentRelease`           | `{mirror_path}`   | `Some("dists")`          | `{distribution}_{component}_{architecture}_{filename}` | `Volatile` |
//! | `Icon`/`Sources`/`Translation` | `{mirror_path}` | `Some("dists")`          | `{distribution}_{component}_{filename}`        | `Volatile`      |
//! | `ByHash`                     | `{mirror_path}`   | `Some("dists/by-hash")`  | `{filename}` (hex hash)                        | `Permanent`     |
//! | `Pdiff`                      | `{mirror_path}`   | `Some("dists")`          | `{distribution}_{component}[_{architecture}]_{index}.diff_{patch}` | `Permanent` |
//! | `Flat { Metadata }`          | `flat/{mirror_path}` | `None`                | `{filename}`                                   | `Volatile`      |
//! | `Flat { Pool }`              | `flat/{mirror_path}` | `None`                | `{filename}`                                   | `Permanent`     |
//! | `Flat { ByHash }`            | `flat/{mirror_path}` | `Some("by-hash")`     | `{filename}` (hex hash)                        | `Permanent`     |
//!
//! Pool flattens the deeply-nested URL path to a single filename per mirror
//! (the URL's `pool/main/<l>/<pkg>/` components are dropped).
//! Release/Packages/etc. prefix `debname` with `{distribution}_…` to
//! disambiguate per-distribution copies that share the same on-disk
//! `mirror_path`.  The joined fields therefore never hold a `_` of their
//! own: such a request is relayed uncached
//! ([`ClassifyError::JoinedFieldUnderscore`]), or `sid_main` + `x` and
//! `sid` + `main_x` would name one file.  For the same reason a `Packages`
//! index is cached only under `binary-<arch>` or a pseudo-architecture
//! ([`ClassifyError::PackagesOutsideArchitecture`]): its directory sits
//! where a component-scoped index's filename does, so `Translation-en` +
//! `Packages` would name the Translation file `Translation-en_Packages`.
//! And a component-scoped filename (`Translation-*`, `icons-*`, the open
//! ones) that forms a cached pdiff patch's name is refused
//! ([`ClassifyError::InvalidValue`]), or `i18n/Translation-en.diff_T-…` and
//! the patch `i18n/Translation-en.diff/T-…` would name one file.
//!
//! `ByHash` keys on the digest alone, but still carries the
//! `dists/<dist>/<comp>/<arch>/` scope it was fetched under: an
//! `Acquire-By-Hash: yes` mirror never sends a literal `Packages*` URL, so
//! that scope is its only source of an `Origin` row.
//!
//! The path joins themselves live in [`crate::cache_paths`].

use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    str::Utf8Error,
    sync::Arc,
};

use hashbrown::Equivalent;
use tracing::trace;

use crate::{
    cache_paths::{CachePaths, MirrorSite},
    client_info::ClientInfo,
    config::ClientHost,
    database_task::{DatabaseCommand, send_db_command_nonblocking},
    deb_mirror::{
        DistsScope, FlatKind, Mirror, MirrorKind, Origin, OriginFields, OriginSighting,
        ResourceFile, is_binary_arch, is_deb_package, is_flat_deb_filename, is_packages_directory,
        is_pdiff_patch_name, valid_directory, valid_filename, valid_mirrorname, valid_path_segment,
    },
    flat_blocklist::path_collides_with_flat_layout,
    index_parser::HashAlgo,
    metrics,
    partial_file::PARTIAL_SUFFIX,
    precise_instant::PreciseInstant,
};

// ---------------------------------------------------------------------------
// Cache-flavor and connection types
// ---------------------------------------------------------------------------

/// Whether a cached resource is permanent (`.deb` / by-hash / pdiff patch)
/// or volatile (refresh-checked metadata like `Release` / `Packages*`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CachedFlavor {
    Permanent,
    Volatile,
}

/// The [`crate::deb_mirror::ResourceFile`] variant a request classified to.
/// A resource's [`CachedFlavor`] and [`CacheLayout`] are derived from it,
/// never stored alongside, so the three cannot disagree.  The two by-hash
/// kinds carry the algorithm the parser validated for their
/// `by-hash/<ALGO>/` directory and what the directory holding that
/// `by-hash/` says about the object ([`ByHashContent`]), so neither the
/// verifier nor the ingest re-reads the request path.  Populated by
/// [`classify_request`]'s exhaustive match, so a new `ResourceFile` variant
/// is a compile error there and forces a decision here too.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResourceKind {
    /// Structured `pool/...` `.deb`/`.udeb`/`.ddeb`.
    Pool,
    /// Structured `dists/.../Release` / `InRelease` / `Release.gpg`.
    Release,
    /// Structured per-component `Release`.
    ComponentRelease,
    /// Structured `dists/.../binary-*/Packages*`.
    Packages,
    /// Structured `dists/.../source/Sources*`.
    Sources,
    /// `dists/.../i18n/Translation-*`.
    Translation,
    /// `dists/.../dep11/icons-*` / component metadata.
    Icon,
    /// Structured content-addressed `dists/.../by-hash/SHA*/<hex>`.
    ByHash(HashAlgo, ByHashContent),
    /// Flat-repository metadata file (`Packages*`, `Release`, ...).
    FlatMetadata,
    /// Flat-repository `.deb` pool file.
    FlatPool,
    /// Flat-repository content-addressed `by-hash/SHA*/<hex>`.
    FlatByHash(HashAlgo, ByHashContent),
    /// Structured by-name pdiff patch `dists/.../<index>.diff/T-…-F-….gz`:
    /// index data, but never changed under its name.
    Pdiff,
}

/// What a content-addressed object may be, judged by the directory its
/// validated `by-hash/` hangs in: `dists/sid/main/binary-amd64/by-hash/...`
/// holds the digests of that directory's `Packages*` files, while `dep11`,
/// `i18n`, a component-level `by-hash/` or `Packages.diff/` hold other
/// indexes.  Decided once by [`classify_request`] from the parsed, decoded
/// directory; a re-scan of the raw path could stop at a decoy `by-hash/`
/// segment in front of the validated one and answer differently.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum ByHashContent {
    /// Under `binary-<arch>` or `source`: may be a `Packages` (or `Sources`)
    /// index, which the ingest sniffs.  (`Sources` parses like `Packages`;
    /// its stanzas carry no `Filename:` line, so it registers nothing.)
    MaybePackages,
    /// Anything else.
    Other,
}

impl ByHashContent {
    /// The verdict for an object whose `by-hash/` sits in the decoded
    /// directory `dir` (`None` for one directly under `dists/` or a flat
    /// repository's base).
    #[must_use]
    fn of_directory(dir: Option<&str>) -> Self {
        match dir {
            Some(dir) if is_binary_arch(dir) || dir == "source" => Self::MaybePackages,
            Some(_) | None => Self::Other,
        }
    }
}

impl ResourceKind {
    #[must_use]
    const fn cached_flavor(self) -> CachedFlavor {
        match self {
            Self::Pool | Self::ByHash(..) | Self::FlatPool | Self::FlatByHash(..) | Self::Pdiff => {
                CachedFlavor::Permanent
            }
            Self::Release
            | Self::ComponentRelease
            | Self::Packages
            | Self::Sources
            | Self::Translation
            | Self::Icon
            | Self::FlatMetadata => CachedFlavor::Volatile,
        }
    }

    #[must_use]
    pub(crate) const fn layout(self) -> CacheLayout {
        match self {
            Self::Pool => CacheLayout::StructuredPool,
            Self::Release
            | Self::ComponentRelease
            | Self::Packages
            | Self::Sources
            | Self::Translation
            | Self::Icon
            | Self::Pdiff => CacheLayout::Dists,
            Self::ByHash(..) => CacheLayout::DistsByHash,
            Self::FlatMetadata | Self::FlatPool => CacheLayout::Flat,
            Self::FlatByHash(..) => CacheLayout::FlatByHash,
        }
    }

    #[must_use]
    const fn lookup_bucket(self) -> LookupBucket {
        match self {
            Self::Pool | Self::FlatPool => LookupBucket::Package,
            Self::ByHash(..) | Self::FlatByHash(..) | Self::Pdiff => LookupBucket::ByHash,
            Self::Release
            | Self::ComponentRelease
            | Self::Packages
            | Self::Sources
            | Self::Translation
            | Self::Icon
            | Self::FlatMetadata => LookupBucket::Index,
        }
    }
}

/// The hit/miss counter family a cache lookup is counted in.  The two
/// permanent buckets split `CACHE_HITS` / `CACHE_MISSES`, because their
/// remedies differ: a package miss rate points at clients naming one archive
/// under different mirrors (`aliases`), a by-hash one at index churn.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LookupBucket {
    /// A `.deb` from a structured or flat pool: `PACKAGE_HITS` /
    /// `PACKAGE_MISSES` under `CACHE_HITS` / `CACHE_MISSES`.
    Package,
    /// A content-addressed by-hash index, or a by-name pdiff patch (index
    /// data whose every change is a new name too): `BYHASH_HITS` /
    /// `BYHASH_MISSES` under `CACHE_HITS` / `CACHE_MISSES`.
    ByHash,
    /// A refresh-checked index: `VOLATILE_HIT` / `VOLATILE_REFETCHED`.
    Index,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum LookupOutcome {
    /// A usable file was served from the cache (for an index: a fresh one).
    Hit,
    /// No usable file: the request fetched upstream or joined an in-flight
    /// fetch (for an index: absent or stale).
    Miss(MissReason),
}

/// Why a lookup could not use a complete cached file. In-flight attachment
/// happens before disk inspection, so it must not claim the file is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MissReason {
    Absent,
    Expired,
    FutureTimestamp,
    #[cfg(feature = "sendfile")]
    InFlight,
}

/// Registration result, distinct from the earlier disk lookup.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FetchRole {
    Originator,
    Joiner,
    Refused,
}

/// On-disk cache layout for a request.  Doubles as the discriminator on
/// the `(mirror, debname)` keys for [`crate::active_downloads`] and
/// [`crate::cache_metadata`] — without it, a flat-pool file and a
/// structured-pool file with the same `debname` under the same mirror
/// path would collide on those keys (different files on disk, same
/// in-memory bookkeeping).
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum CacheLayout {
    /// Structured pool: file lives directly under `<host>/<mirror>/`.
    StructuredPool,
    /// Structured dists tree: `<host>/<mirror>/dists/`.
    Dists,
    /// Structured by-hash tree: `<host>/<mirror>/dists/by-hash/`.
    DistsByHash,
    /// Flat repository (metadata or pool): `<host>/flat/<mirror>/`.
    Flat,
    /// Flat repository, by-hash subtree: `<host>/flat/<mirror>/by-hash/`.
    FlatByHash,
}

impl CacheLayout {
    #[must_use]
    pub(crate) const fn is_flat(self) -> bool {
        match self {
            Self::Flat | Self::FlatByHash => true,
            Self::StructuredPool | Self::Dists | Self::DistsByHash => false,
        }
    }

    /// Coarser classification used as the `mirrors_v2.kind` column value.
    #[must_use]
    pub(crate) const fn mirror_kind(self) -> MirrorKind {
        if self.is_flat() {
            MirrorKind::Flat
        } else {
            MirrorKind::Structured
        }
    }
}

/// Identity of one cache entry across every per-entry store
/// (`active_downloads`, `cache_metadata`, `verify_throttle`) and the
/// download barrier chain.
///
/// [`Mirror::kind`] (inside `mirror`) and `layout` are redundant on the
/// structured-vs-flat axis, but only `layout` tells the structured subtrees
/// (`StructuredPool`, `Dists`, `DistsByHash`) apart.  Flat-pool `.deb`s in
/// different sub-directories (`apt/amd64/foo.deb` vs `apt/arm64/foo.deb`)
/// differ in [`Mirror::path`], since the URL path is the mirror path
/// verbatim under the flat layout.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CacheEntryKey {
    pub(crate) mirror: Mirror,
    pub(crate) debname: String,
    pub(crate) layout: CacheLayout,
}

impl CacheEntryKey {
    #[must_use]
    pub(crate) fn as_ref(&self) -> CacheEntryKeyRef<'_> {
        let Self {
            mirror,
            debname,
            layout,
        } = self;
        CacheEntryKeyRef {
            mirror,
            debname,
            layout: *layout,
        }
    }
}

/// Borrow-only counterpart to [`CacheEntryKey`], paired with it via
/// [`hashbrown::Equivalent`] so hot-path lookups never clone `Mirror` or
/// `debname`; only a cold-path insert materialises the owned form.
#[derive(Clone, Copy, Debug, Hash)]
pub(crate) struct CacheEntryKeyRef<'a> {
    pub(crate) mirror: &'a Mirror,
    pub(crate) debname: &'a str,
    pub(crate) layout: CacheLayout,
}

impl<'a> CacheEntryKeyRef<'a> {
    #[must_use]
    pub(crate) fn new(mirror: &'a Mirror, debname: &'a str, layout: CacheLayout) -> Self {
        Self {
            mirror,
            debname,
            layout,
        }
    }

    #[must_use]
    pub(crate) fn to_owned(self) -> CacheEntryKey {
        let Self {
            mirror,
            debname,
            layout,
        } = self;
        CacheEntryKey {
            mirror: mirror.clone(),
            debname: debname.to_owned(),
            layout,
        }
    }
}

impl Equivalent<CacheEntryKey> for CacheEntryKeyRef<'_> {
    fn equivalent(&self, key: &CacheEntryKey) -> bool {
        let &Self {
            mirror,
            debname,
            layout,
        } = self;
        let CacheEntryKey {
            mirror: kmirror,
            debname: kdebname,
            layout: klayout,
        } = key;
        mirror == kmirror && debname == kdebname && layout == *klayout
    }
}

/// Verdict of a cache-file lookup that found nothing serveable.
///
/// The producer counts the miss ([`ConnectionDetails::count_lookup`]) when
/// it builds one of these, so a consumer must never count it again.  The
/// stale copy travels with the verdict so the fetcher can revalidate against
/// it without a second open/stat.
#[derive(Debug)]
// Only the hyper backend revalidates from the carried copy; the splice
// backend re-opens the file on its own path, so in a splice-only build the
// verdict is built and dropped unread.
#[cfg_attr(
    not(feature = "hyper"),
    expect(dead_code, reason = "consumed only by hyper_conn::serve_cache_miss")
)]
pub(crate) enum CacheMiss {
    NotFound,
    /// A volatile copy exists but is older than `VOLATILE_CACHE_MAX_AGE`
    /// (or its mtime is in the future); revalidate it upstream.
    StaleVolatile {
        reason: MissReason,
        file: tokio::fs::File,
        /// The copy's on-disk size, for the quota reservation
        /// (`cache_quota.rs`: `prev_file_size`).
        size: u64,
    },
}

impl CacheMiss {
    pub(crate) const fn outcome(&self) -> LookupOutcome {
        LookupOutcome::Miss(match self {
            Self::NotFound => MissReason::Absent,
            Self::StaleVolatile {
                reason,
                file: _,
                size: _,
            } => *reason,
        })
    }
}

/// Per-request state carried across the cache pipeline.
#[derive(Clone, Debug)]
pub(crate) struct ConnectionDetails {
    pub(crate) client: ClientInfo,
    /// Monotonic instant the client request was parsed - origin of the
    /// `in <time>` total-proxy-time figure in download/serve logs.
    pub(crate) request_received_at: PreciseInstant,
    /// The canonical mirror: alias-resolved once in
    /// `request_dispatch::decide_request`, so the active-downloads key, the
    /// on-disk site, the DB rows and the logs all name the alias' main host.
    pub(crate) mirror: Mirror,
    /// The host the client named, which is where the upstream fetch goes
    /// (an alias is a real mirror serving the same content; the alias
    /// mapping only unifies the cache identity).  Equal to `mirror.host()`
    /// unless an alias matched.
    pub(crate) upstream_host: ClientHost,
    pub(crate) debname: String,
    pub(crate) resource_kind: ResourceKind,
    /// The `Origin` this request would register, for real-arch index
    /// requests only -- a `Packages*` URL, or the architecture-scoped
    /// `by-hash` URL an `Acquire-By-Hash: yes` mirror serves instead.  A
    /// probe the upstream 404s mints no row.  Boxed: only index requests
    /// carry one, and `ConnectionDetails` rides inside per-request enums
    /// whose size the other variants set.
    pub(crate) origin_fields: Option<Box<OriginFields>>,
}

impl ConnectionDetails {
    /// Enqueue this request's `Origin` row, if it carries one, for a request
    /// the upstream answered (fresh body or 304): the scope is proven, so the
    /// row is created if absent.
    ///
    /// Skipped for cleanup's synthetic index fetches, which are bookkeeping,
    /// not client demand.  Non-blocking: a saturated DB queue must not stall
    /// request handling.
    pub(crate) fn record_origin(&self) {
        self.send_origin(OriginSighting::Upstream);
    }

    /// As [`Self::record_origin`], for a request served entirely from cache:
    /// refreshes an existing row's `last_seen` — a warm mirror would
    /// otherwise age its own origins out — but creates none.
    ///
    /// A `ByHash` hit serves a `Permanent` entry keyed by `{mirror, digest}`
    /// without contacting the upstream, so it never checks that the requested
    /// `dists/<dist>/<comp>/<arch>/` exists; minting from one would put an
    /// unverified scope in `origins`, and cleanup then fetches a `Packages`
    /// whose 404 bails the mirror's sweep.  A `Packages` hit does carry its
    /// scope in the cache key, and loses nothing by taking this path too.
    pub(crate) fn refresh_origin(&self) {
        self.send_origin(OriginSighting::CacheHit);
    }

    fn send_origin(&self, sighting: OriginSighting) {
        let Some(fields) = &self.origin_fields else {
            return;
        };
        if self.client.is_cleanup_synthetic() {
            return;
        }
        let origin = Origin {
            mirror: self.mirror.clone(),
            fields: (**fields).clone(),
        };
        send_db_command_nonblocking(DatabaseCommand::Origin(origin, sighting));
    }

    /// Count one cache lookup of this request: the permanent buckets bump
    /// their parent (`CACHE_HITS` / `CACHE_MISSES`) first, then their part,
    /// so a reader loading the parts before the parent never sees them
    /// exceed it; an index bumps `VOLATILE_HIT` / `VOLATILE_REFETCHED`.
    ///
    /// Called only at the lookup sites, once per request.  Cleanup's
    /// synthetic index fetches count nothing.
    pub(crate) fn count_lookup(&self, outcome: LookupOutcome) {
        if self.client.is_cleanup_synthetic() {
            return;
        }
        let (parent, part) = match (self.resource_kind.lookup_bucket(), outcome) {
            (LookupBucket::Package, LookupOutcome::Hit) => {
                (&metrics::CACHE_HITS, &metrics::PACKAGE_HITS)
            }
            (LookupBucket::Package, LookupOutcome::Miss(_)) => {
                (&metrics::CACHE_MISSES, &metrics::PACKAGE_MISSES)
            }
            (LookupBucket::ByHash, LookupOutcome::Hit) => {
                (&metrics::CACHE_HITS, &metrics::BYHASH_HITS)
            }
            (LookupBucket::ByHash, LookupOutcome::Miss(_)) => {
                (&metrics::CACHE_MISSES, &metrics::BYHASH_MISSES)
            }
            (LookupBucket::Index, LookupOutcome::Hit) => {
                metrics::VOLATILE_HIT.increment();
                return;
            }
            (LookupBucket::Index, LookupOutcome::Miss(reason)) => {
                metrics::VOLATILE_REFETCHED.increment();
                match reason {
                    MissReason::Absent => metrics::VOLATILE_ABSENT.increment(),
                    MissReason::Expired => metrics::VOLATILE_EXPIRED.increment(),
                    MissReason::FutureTimestamp => metrics::VOLATILE_FUTURE.increment(),
                    #[cfg(feature = "sendfile")]
                    MissReason::InFlight => metrics::VOLATILE_IN_FLIGHT.increment(),
                }
                return;
            }
        };
        parent.increment();
        part.increment();
    }

    #[must_use]
    pub(crate) const fn cached_flavor(&self) -> CachedFlavor {
        self.resource_kind.cached_flavor()
    }

    #[must_use]
    pub(crate) const fn layout(&self) -> CacheLayout {
        self.resource_kind.layout()
    }

    /// The caller owns the admission decision; handoffs never repeat it.
    pub(crate) fn count_fetch_role(&self, role: FetchRole) {
        if self.client.is_cleanup_synthetic() || self.cached_flavor() != CachedFlavor::Volatile {
            return;
        }
        match role {
            FetchRole::Originator => metrics::VOLATILE_ORIGINATORS.increment(),
            FetchRole::Joiner => metrics::VOLATILE_JOINERS.increment(),
            FetchRole::Refused => metrics::VOLATILE_ADMISSION_REFUSED.increment(),
        }
    }

    #[must_use]
    pub(crate) fn key(&self) -> CacheEntryKeyRef<'_> {
        CacheEntryKeyRef::new(&self.mirror, &self.debname, self.layout())
    }

    /// The on-disk identity of this request's mirror.  `InitBarrier::site`
    /// derives the same site, so the `.partial` lands next to its rename
    /// target.
    #[must_use]
    pub(crate) fn site(&self) -> MirrorSite<'_> {
        self.mirror.site()
    }

    /// The `host[:port]` authority of the upstream the fetch dials: the
    /// host the client named, on the mirror's port.
    #[must_use]
    pub(crate) fn upstream_authority(&self) -> Cow<'_, str> {
        self.upstream_host.format_authority(self.mirror.port())
    }

    /// Dial the client-named host while retaining the canonical cache identity.
    #[cfg(feature = "splice")]
    #[must_use]
    pub(crate) fn upstream_endpoint(&self) -> crate::splice::UpstreamEndpoint<'_> {
        crate::splice::UpstreamEndpoint {
            host: &self.upstream_host,
            port: self.mirror.port(),
        }
    }

    /// Log suffix naming the alias the client used (` via alias host X`),
    /// empty when the request named the canonical host itself.
    #[must_use]
    pub(crate) const fn alias_suffix(&self) -> AliasSuffix<'_> {
        AliasSuffix(self)
    }

    #[must_use]
    pub(crate) fn cache_file_path(&self) -> PathBuf {
        CachePaths::global().entry_file(self.layout(), self.site(), Path::new(&self.debname))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AliasSuffix<'a>(&'a ConnectionDetails);

impl std::fmt::Display for AliasSuffix<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(conn_details) = self;
        if &conn_details.upstream_host == conn_details.mirror.host() {
            Ok(())
        } else {
            write!(f, " via alias host {}", conn_details.upstream_host)
        }
    }
}

// ---------------------------------------------------------------------------
// Classification types
// ---------------------------------------------------------------------------

/// Which named field of a request URL is being validated.
#[derive(Copy, Clone, Debug)]
pub(crate) enum ValidateKind {
    /// A structured mirror's path, which additionally may not pass through
    /// a `dists` segment (see
    /// [`crate::deb_mirror::RESERVED_STRUCTURED_MIRROR_PATH_SEGMENTS`]).
    MirrorPath,
    /// A flat repository's base path, anchored under the host's `flat/`.
    FlatMirrorPath,
    Distribution,
    Component,
    /// Both the `binary-<arch>` token and the `source` / `dep11` / `i18n`
    /// pseudo-architectures, which all reach it from the same URL slot.
    Architecture,
    /// A directory segment outside the cache name: see
    /// [`crate::deb_mirror::valid_directory`].
    Directory,
    Filename,
}

impl ValidateKind {
    #[must_use]
    fn accepts(self, decoded: &str) -> bool {
        match self {
            Self::MirrorPath => valid_mirrorname(decoded, MirrorKind::Structured),
            Self::FlatMirrorPath => valid_mirrorname(decoded, MirrorKind::Flat),
            Self::Distribution | Self::Component | Self::Architecture => {
                valid_path_segment(decoded)
            }
            Self::Directory => valid_directory(decoded),
            Self::Filename => valid_filename(decoded),
        }
    }

    /// Whether the `dists/` cache names join this field to its neighbours
    /// with `_` ([`dists_debname`] and siblings).  Such a field must not hold
    /// a `_` itself, or two URLs could spell one cache name.
    #[must_use]
    const fn joined_with_underscore(self) -> bool {
        match self {
            Self::Distribution | Self::Component | Self::Architecture => true,
            Self::MirrorPath | Self::FlatMirrorPath | Self::Directory | Self::Filename => false,
        }
    }

    /// Whether the field is a `/`-joined run of segments, split only after
    /// decoding (the mirror paths); every other field is one segment, whose
    /// validator refuses a `/`.
    #[must_use]
    const fn spans_segments(self) -> bool {
        match self {
            Self::MirrorPath | Self::FlatMirrorPath => true,
            Self::Distribution
            | Self::Component
            | Self::Architecture
            | Self::Directory
            | Self::Filename => false,
        }
    }
}

impl std::fmt::Display for ValidateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MirrorPath => "mirror path",
            Self::FlatMirrorPath => "flat mirror path",
            Self::Distribution => "distribution",
            Self::Component => "component",
            Self::Architecture => "architecture",
            Self::Directory => "directory",
            Self::Filename => "filename",
        })
    }
}

/// Linux's `NAME_MAX`: the longest file name, in bytes, a directory entry
/// can hold.
const NAME_MAX: usize = 255;

/// The longest `debname` the cache can store: [`NAME_MAX`] less the longest
/// suffix a download's temporary file appends to it (`.partial`;
/// `partial_file::tokio_tempfile`'s random `.XXXXXX` extension is a byte
/// shorter).  Every field of a `dists/` name is within its own cap, but
/// joined they can exceed this; the dispatcher relays such a request
/// uncached rather than fail to create its file.
pub(crate) const MAX_DEBNAME_LEN: usize = NAME_MAX - PARTIAL_SUFFIX.len();

/// Flatten an architecture-scoped `dists/` index into its cache debname.
///
/// [`classify_request`] mints the name for a client request, and
/// `cleanup::packages::DebnameKind` for the index fetches cleanup issues
/// itself.  If the two disagreed, cleanup would cache every index under a
/// path the serve path never reads.
#[must_use]
pub(crate) fn dists_debname(
    distribution: &str,
    component: &str,
    architecture: &str,
    filename: impl std::fmt::Display,
) -> String {
    format!("{distribution}_{component}_{architecture}_{filename}")
}

const PDIFF_SEPARATOR: &str = ".diff_";

/// Whether the cache name `debname` is that of a cached pdiff patch
/// (`…<index>.diff_T-<ts>-F-<ts>.gz`, see [`ResourceFile::Pdiff`]).  The
/// classifier refuses any other resource decoding to such a name, and
/// cleanup gives these files their own, shorter retention.
#[must_use]
pub(crate) fn is_cached_pdiff_patch(debname: &str) -> bool {
    debname
        .rsplit_once(PDIFF_SEPARATOR)
        .is_some_and(|(_, patch)| is_pdiff_patch_name(patch))
}

/// The result of [`classify_request`], with every field decoded and
/// validated.
#[derive(Debug)]
pub(crate) struct RequestClass {
    /// Shared, because it becomes [`Mirror`]'s path, which every clone of
    /// the request's mirror (active-downloads key, DB commands, rename plan)
    /// carries.
    pub(crate) mirror_path: Arc<str>,
    pub(crate) debname: String,
    pub(crate) resource_kind: ResourceKind,
    pub(crate) origin_fields: Option<OriginFields>,
}

/// A classified resource whose on-disk name or layout cannot be stored.
#[derive(Clone, Copy, Debug)]
pub(crate) enum StorageError {
    NameTooLong,
    FlatAnchoredMirror,
}

impl RequestClass {
    /// Validate the constructed storage identity separately from URL field
    /// classification, so request policy can give query handling precedence.
    pub(crate) fn validate_storage(&self) -> Result<(), StorageError> {
        if self.debname.len() > MAX_DEBNAME_LEN {
            return Err(StorageError::NameTooLong);
        }
        if !self.resource_kind.layout().is_flat()
            && path_collides_with_flat_layout(&self.mirror_path)
        {
            return Err(StorageError::FlatAnchoredMirror);
        }
        Ok(())
    }
}

/// Errors returned by [`classify_request`].  `request_dispatch::decide_request`
/// translates each into a rejection or a passthrough reason.
#[derive(Debug)]
pub(crate) enum ClassifyError<'a> {
    BadEncoding {
        kind: ValidateKind,
        raw: &'a str,
        source: Utf8Error,
    },
    /// The decoded field value did not pass its `valid_*` validator.
    InvalidValue {
        kind: ValidateKind,
        decoded: Cow<'a, str>,
    },
    /// A multi-segment field ([`ValidateKind::spans_segments`]) holding an
    /// encoded `/` (`%2F`).  Decoding turns it into a separator, so
    /// `public%2Fubuntu` and `public/ubuntu` -- distinct upstream URLs (RFC
    /// 3986 §2.2) -- would share one cache name.  `raw` is the value as sent.
    EncodedSeparator { kind: ValidateKind, raw: &'a str },
    /// A structured `Pool` filename whose extension is not `.deb` / `.udeb`
    /// / `.ddeb`, relayed uncached.
    ///
    /// `Flat::Pool` reaches this variant when the *decoded* filename fails
    /// the strict shape check: `parse_request_path` runs
    /// `is_flat_deb_filename` on the raw URL segment, which
    /// `foo%5fbar_1.0_amd64.deb` (2 underscores raw, 3 once decoded) passes.
    NonDebPool { filename: Cow<'a, str> },
    /// A distribution, component or architecture holding a `_`, the
    /// separator the `dists/` cache names join those fields with:
    /// `dists/sid_main_binary-amd64/Release` and
    /// `dists/sid/main/binary-amd64/Release` would share one cache file.  The
    /// value is valid, just not cacheable, so both dispatchers relay the
    /// request uncached.  Checked on every such field, the `by-hash` scope
    /// included, so none of them reaches an `Origin` row either (cleanup
    /// builds its index fetches' cache names from those rows).
    JoinedFieldUnderscore {
        kind: ValidateKind,
        decoded: Cow<'a, str>,
    },
    /// A `Packages` index under a directory that is neither `binary-<arch>`
    /// nor a pseudo-architecture ([`is_packages_directory`]).  Its cache
    /// name joins that directory where a component-scoped index joins its
    /// filename, so `dists/sid/main/Translation-en/Packages` would share
    /// `sid_main_Translation-en_Packages` with the Translation file
    /// `dists/sid/main/i18n/Translation-en_Packages`.  Relayed uncached like
    /// [`Self::JoinedFieldUnderscore`]; no archive puts a `Packages` index
    /// anywhere else.
    PackagesOutsideArchitecture { architecture: Cow<'a, str> },
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

/// Decode + validate every URL-borne field in `resource`, then derive the
/// on-disk classification (`debname`, `resource_kind`).  `client` only
/// labels trace logs.
pub(crate) fn classify_request<'a>(
    resource: &'a ResourceFile<'_>,
    client: &ClientInfo,
) -> Result<RequestClass, ClassifyError<'a>> {
    match resource {
        ResourceFile::Pool {
            mirror_path,
            dirs,
            filename,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            validate_directories(dirs)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            if !is_deb_package(&filename) {
                return Err(ClassifyError::NonDebPool { filename });
            }

            trace!(
                "Decoded mirror path: `{mirror_path}`; Decoded filename: `{filename}` (client {client})"
            );

            Ok(RequestClass {
                mirror_path: Arc::from(mirror_path),
                debname: filename.into_owned(),
                resource_kind: ResourceKind::Pool,
                origin_fields: None,
            })
        }
        ResourceFile::Release {
            mirror_path,
            distribution,
            filename,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            let distribution = decode_validate(distribution, ValidateKind::Distribution)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            trace!(
                "Decoded mirror path: `{mirror_path}`; Decoded distribution: `{distribution}`; Decoded filename: `{filename}` (client {client})"
            );

            Ok(RequestClass {
                mirror_path: Arc::from(mirror_path),
                debname: format!("{distribution}_{filename}"),
                resource_kind: ResourceKind::Release,
                origin_fields: None,
            })
        }
        ResourceFile::ByHash {
            mirror_path,
            dirs,
            algorithm,
            filename,
            scope,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            trace!(
                "Decoded mirror path: `{mirror_path}`; Decoded filename: `{filename}` (client {client})"
            );

            // On an `Acquire-By-Hash: yes` mirror this arm - not the
            // `Packages` one - is where the `Origin` row is earned.  The
            // scope is no part of the cache identity; it is decoded and
            // validated here because it reaches the upstream, the database
            // and cleanup's index-fetch URLs.  A run of any other depth
            // reaches only the upstream, and is validated just the same.
            let (origin_fields, content) = if let Some(DistsScope {
                distribution,
                component,
                architecture,
            }) = scope
            {
                let distribution = decode_validate(distribution, ValidateKind::Distribution)?;
                let component = decode_validate(component, ValidateKind::Component)?;
                let architecture = decode_validate(architecture, ValidateKind::Architecture)?;
                let content = ByHashContent::of_directory(Some(&architecture));

                (
                    OriginFields::of_scope(distribution, component, architecture),
                    content,
                )
            } else {
                let innermost = validate_directories(dirs)?;
                (None, ByHashContent::of_directory(innermost.as_deref()))
            };

            Ok(RequestClass {
                mirror_path: Arc::from(mirror_path),
                debname: filename.into_owned(),
                resource_kind: ResourceKind::ByHash(*algorithm, content),
                origin_fields,
            })
        }
        ResourceFile::Icon {
            mirror_path,
            distribution,
            component,
            filename,
        } => classify_component_scoped(
            mirror_path,
            distribution,
            component,
            filename,
            ResourceKind::Icon,
            client,
        ),
        ResourceFile::Sources {
            mirror_path,
            distribution,
            component,
            filename,
        } => classify_component_scoped(
            mirror_path,
            distribution,
            component,
            filename,
            ResourceKind::Sources,
            client,
        ),
        ResourceFile::Translation {
            mirror_path,
            distribution,
            component,
            filename,
        } => classify_component_scoped(
            mirror_path,
            distribution,
            component,
            filename,
            ResourceKind::Translation,
            client,
        ),
        ResourceFile::ComponentRelease {
            mirror_path,
            distribution,
            component,
            architecture,
            filename,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            let distribution = decode_validate(distribution, ValidateKind::Distribution)?;
            let component = decode_validate(component, ValidateKind::Component)?;
            let architecture = decode_validate(architecture, ValidateKind::Architecture)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            trace!(
                "Decoded mirror path: `{mirror_path}`; Decoded distribution: `{distribution}`; Decoded component: `{component}`; Decoded architecture: `{architecture}`; Decoded filename: `{filename}` (client {client})"
            );

            // A per-component Release is metadata about the indices, never
            // a per-binary origin.
            Ok(RequestClass {
                mirror_path: Arc::from(mirror_path),
                debname: dists_debname(&distribution, &component, &architecture, &filename),
                resource_kind: ResourceKind::ComponentRelease,
                origin_fields: None,
            })
        }
        ResourceFile::Packages {
            mirror_path,
            distribution,
            component,
            architecture,
            filename,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            let distribution = decode_validate(distribution, ValidateKind::Distribution)?;
            let component = decode_validate(component, ValidateKind::Component)?;
            let architecture = decode_validate(architecture, ValidateKind::Architecture)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            trace!(
                "Decoded mirror path: `{mirror_path}`; Decoded distribution: `{distribution}`; Decoded component: `{component}`; Decoded architecture: `{architecture}`; Decoded filename: `{filename}` (client {client})"
            );

            if !is_packages_directory(&architecture) {
                return Err(ClassifyError::PackagesOutsideArchitecture { architecture });
            }

            let debname = dists_debname(&distribution, &component, &architecture, &filename);

            let origin_fields = OriginFields::of_scope(distribution, component, architecture);

            Ok(RequestClass {
                mirror_path: Arc::from(mirror_path),
                debname,
                resource_kind: ResourceKind::Packages,
                origin_fields,
            })
        }
        ResourceFile::Pdiff {
            mirror_path,
            distribution,
            component,
            architecture,
            index,
            patch,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            let distribution = decode_validate(distribution, ValidateKind::Distribution)?;
            let component = decode_validate(component, ValidateKind::Component)?;
            // The parser admits no `%` in either, so decoding is the identity.
            let index = decode_validate(index, ValidateKind::Filename)?;
            let patch = decode_validate(patch, ValidateKind::Filename)?;

            trace!(
                "Decoded mirror path: `{mirror_path}`; Decoded distribution: `{distribution}`; Decoded component: `{component}`; Decoded pdiff patch: `{index}{PDIFF_SEPARATOR}{patch}` (client {client})"
            );

            // Only a `Packages` patch carries its slot, which joins the
            // name exactly where it does for the `Packages` index itself.
            // It also carries the index's origin: a client updating by
            // pdiff never fetches the full `Packages`, so without it the
            // origin would expire and cleanup sweep the debs still in use.
            let (debname, origin_fields) = match architecture {
                Some(architecture) => {
                    let architecture = decode_validate(architecture, ValidateKind::Architecture)?;
                    if !is_packages_directory(&architecture) {
                        return Err(ClassifyError::PackagesOutsideArchitecture { architecture });
                    }
                    let debname = dists_debname(
                        &distribution,
                        &component,
                        &architecture,
                        format_args!("{index}{PDIFF_SEPARATOR}{patch}"),
                    );
                    (
                        debname,
                        OriginFields::of_scope(distribution, component, architecture),
                    )
                }
                None => (
                    format!("{distribution}_{component}_{index}{PDIFF_SEPARATOR}{patch}"),
                    None,
                ),
            };

            Ok(RequestClass {
                mirror_path: Arc::from(mirror_path),
                debname,
                resource_kind: ResourceKind::Pdiff,
                origin_fields,
            })
        }
        ResourceFile::Flat {
            kind,
            mirror_path,
            filename,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::FlatMirrorPath)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            trace!(
                "Decoded flat mirror path: `{mirror_path}`; Decoded flat filename: `{filename}` (kind: {kind:?}; client {client})"
            );

            let resource_kind = match kind {
                FlatKind::Metadata => ResourceKind::FlatMetadata,
                FlatKind::Pool => {
                    // `parse_request_path` checked the *raw* URL segment,
                    // which a percent-encoded `_` can get past (see
                    // `ClassifyError::NonDebPool`).
                    if !is_flat_deb_filename(&filename) {
                        return Err(ClassifyError::NonDebPool { filename });
                    }
                    ResourceKind::FlatPool
                }
                // The `by-hash/` hangs in the flat base itself.
                FlatKind::ByHash(algorithm) => ResourceKind::FlatByHash(
                    *algorithm,
                    ByHashContent::of_directory(mirror_path.rsplit('/').next()),
                ),
            };

            Ok(RequestClass {
                mirror_path: Arc::from(mirror_path),
                debname: filename.into_owned(),
                resource_kind,
                origin_fields: None,
            })
        }
    }
}

/// Decode + validate a component-scoped `dists/` index.  `Icon`, `Sources`
/// and `Translation` share the field set, the `{distribution}_{component}_{filename}`
/// debname and the rule that such an index is never a per-binary origin.
fn classify_component_scoped<'a>(
    mirror_path: &'a str,
    distribution: &'a str,
    component: &'a str,
    filename: &'a str,
    resource_kind: ResourceKind,
    client: &ClientInfo,
) -> Result<RequestClass, ClassifyError<'a>> {
    let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
    let distribution = decode_validate(distribution, ValidateKind::Distribution)?;
    let component = decode_validate(component, ValidateKind::Component)?;
    let filename = decode_validate(filename, ValidateKind::Filename)?;

    trace!(
        "Decoded mirror path: `{mirror_path}`; Decoded distribution: `{distribution}`; Decoded component: `{component}`; Decoded filename: `{filename}` (client {client})"
    );

    let debname = format!("{distribution}_{component}_{filename}");
    // A filename that decodes to a cached pdiff patch's name
    // (`Translation-en%2Ediff_T-…`) would share the patch's file as a
    // volatile entry: refuse it like any name that would cache one resource
    // under another's.
    if is_cached_pdiff_patch(&debname) {
        return Err(ClassifyError::InvalidValue {
            kind: ValidateKind::Filename,
            decoded: filename,
        });
    }

    Ok(RequestClass {
        mirror_path: Arc::from(mirror_path),
        debname,
        resource_kind,
        origin_fields: None,
    })
}

/// Decode + validate every segment of a raw `/`-joined directory run that is
/// forwarded upstream but no part of the cache name (the `dirs` of
/// [`ResourceFile::Pool`] and [`ResourceFile::ByHash`]).  Per segment, so an
/// encoded `%2F` stays inside the segment it was sent in and fails there.
/// Returns the decoded innermost segment, `None` for an empty run.
fn validate_directories(dirs: &str) -> Result<Option<Cow<'_, str>>, ClassifyError<'_>> {
    if dirs.is_empty() {
        return Ok(None);
    }
    let mut innermost = None;
    for segment in dirs.split('/') {
        innermost = Some(decode_validate(segment, ValidateKind::Directory)?);
    }
    Ok(innermost)
}

/// URL-decode `raw` and check the result with the validator selected by
/// `kind`; a field the cache names join with `_` must additionally be free
/// of one ([`ClassifyError::JoinedFieldUnderscore`]).  Borrows the input
/// when no percent-escape was present, the common case.
fn decode_validate(raw: &str, kind: ValidateKind) -> Result<Cow<'_, str>, ClassifyError<'_>> {
    let decoded = match percent_encoding::percent_decode_str(raw).decode_utf8() {
        Ok(s) => s,
        Err(source) => {
            return Err(ClassifyError::BadEncoding { kind, raw, source });
        }
    };

    if kind.spans_segments()
        && matches!(decoded, Cow::Owned(_))
        && decoded.matches('/').count() != raw.matches('/').count()
    {
        return Err(ClassifyError::EncodedSeparator { kind, raw });
    }

    if !kind.accepts(&decoded) {
        return Err(ClassifyError::InvalidValue { kind, decoded });
    }

    if kind.joined_with_underscore() && decoded.contains('_') {
        return Err(ClassifyError::JoinedFieldUnderscore { kind, decoded });
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deb_mirror::parse_request_path, test_support::local_client};

    /// Fails to compile for a new `ResourceKind` variant, so it cannot
    /// escape [`ALL_KINDS`] (add it there too).
    const fn listed_in_all_kinds(kind: ResourceKind) {
        match kind {
            ResourceKind::Pool
            | ResourceKind::Release
            | ResourceKind::ComponentRelease
            | ResourceKind::Packages
            | ResourceKind::Sources
            | ResourceKind::Translation
            | ResourceKind::Icon
            | ResourceKind::ByHash(..)
            | ResourceKind::FlatMetadata
            | ResourceKind::FlatPool
            | ResourceKind::FlatByHash(..)
            | ResourceKind::Pdiff => {}
        }
    }

    /// Every kind, one per variant (the by-hash payloads do not matter).
    const ALL_KINDS: [ResourceKind; 12] = [
        ResourceKind::Pool,
        ResourceKind::Release,
        ResourceKind::ComponentRelease,
        ResourceKind::Packages,
        ResourceKind::Sources,
        ResourceKind::Translation,
        ResourceKind::Icon,
        ResourceKind::ByHash(HashAlgo::Sha256, ByHashContent::Other),
        ResourceKind::FlatMetadata,
        ResourceKind::FlatPool,
        ResourceKind::FlatByHash(HashAlgo::Sha256, ByHashContent::MaybePackages),
        ResourceKind::Pdiff,
    ];

    /// The lookup buckets are the flavor/layout split, not a second opinion:
    /// an index is exactly a volatile kind, a package a permanent pool file,
    /// a by-hash object a permanent by-hash file or a pdiff patch.
    #[test]
    fn lookup_buckets_agree_with_flavor_and_layout() {
        for kind in ALL_KINDS {
            listed_in_all_kinds(kind);
            let expected = match (kind.cached_flavor(), kind.layout()) {
                (CachedFlavor::Volatile, _) => LookupBucket::Index,
                (CachedFlavor::Permanent, CacheLayout::StructuredPool | CacheLayout::Flat) => {
                    LookupBucket::Package
                }
                // The one permanent kind directly under `dists/` is a pdiff
                // patch: immutable index data whose every change is a new
                // name, like a by-hash object.
                (
                    CachedFlavor::Permanent,
                    CacheLayout::DistsByHash | CacheLayout::FlatByHash | CacheLayout::Dists,
                ) => LookupBucket::ByHash,
            };
            assert_eq!(kind.lookup_bucket(), expected, "{kind:?}");
        }
    }

    #[test]
    fn classify_pool() {
        let res = ResourceFile::Pool {
            mirror_path: "debian",
            dirs: "main/f/foo",
            filename: "firefox-esr_115.9.1esr-1_amd64.deb",
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert_eq!(&*class.mirror_path, "debian");
        assert_eq!(class.debname, "firefox-esr_115.9.1esr-1_amd64.deb");
        assert_eq!(class.resource_kind, ResourceKind::Pool);
        assert!(class.origin_fields.is_none());
    }

    #[test]
    fn classify_pool_non_deb_extension_returns_non_deb_pool() {
        let res = ResourceFile::Pool {
            mirror_path: "debian",
            dirs: "main/f/foo",
            filename: "README.txt",
        };
        assert!(matches!(
            classify_request(&res, &local_client()),
            Err(ClassifyError::NonDebPool { filename }) if filename == "README.txt"
        ));
    }

    #[test]
    fn classify_release() {
        let res = ResourceFile::Release {
            mirror_path: "debian",
            distribution: "sid",
            filename: "InRelease",
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert_eq!(class.debname, "sid_InRelease");
        assert_eq!(class.resource_kind, ResourceKind::Release);
        assert!(class.origin_fields.is_none());
    }

    #[test]
    fn classify_packages_records_origin_for_real_arch() {
        let res = ResourceFile::Packages {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            architecture: "binary-amd64",
            filename: "Packages.gz",
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert_eq!(class.debname, "sid_main_binary-amd64_Packages.gz");
        assert_eq!(class.resource_kind, ResourceKind::Packages);
        let origin = class
            .origin_fields
            .expect("binary-amd64 must record an origin");
        assert_eq!(origin.distribution, "sid");
        assert_eq!(origin.component, "main");
        assert_eq!(origin.architecture, "binary-amd64");
    }

    #[test]
    fn classify_packages_skips_origin_for_pseudo_arch() {
        for arch in ["dep11", "i18n", "source"] {
            let res = ResourceFile::Packages {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                architecture: arch,
                filename: "Packages.gz",
            };
            let class = classify_request(&res, &local_client()).unwrap();
            assert!(
                class.origin_fields.is_none(),
                "{arch} must not record an origin"
            );
        }
    }

    #[test]
    fn classify_byhash() {
        let res = ResourceFile::ByHash {
            mirror_path: "debian",
            dirs: "trixie/main",
            algorithm: HashAlgo::Sha256,
            filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            scope: None,
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert_eq!(
            class.debname,
            "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
        );
        assert_eq!(
            class.resource_kind,
            ResourceKind::ByHash(HashAlgo::Sha256, ByHashContent::Other)
        );
    }

    /// An `Acquire-By-Hash: yes` mirror sends no literal `Packages*` URL, so
    /// this arm is the only source of the `Origin` rows cleanup reconciles
    /// its cached debs against.
    #[test]
    fn classify_byhash_mints_the_origin_a_packages_url_would() {
        const PATH: &str = "debian/dists/sid/main/binary-amd64/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";

        let byhash = parse_request_path(PATH).expect("by-hash path parses");
        let fields = classify_request(&byhash, &local_client())
            .unwrap()
            .origin_fields
            .expect("an architecture-scoped by-hash earns an origin");

        // Byte-for-byte what the `Packages.xz` sibling records: the two
        // URL shapes for one index must not produce two rows.
        let packages = parse_request_path("debian/dists/sid/main/binary-amd64/Packages.xz")
            .expect("Packages path parses");
        assert_eq!(
            Some(fields),
            classify_request(&packages, &local_client())
                .unwrap()
                .origin_fields
        );
    }

    /// The shapes that carry no per-binary origin: a pseudo-architecture, a
    /// component-scoped `by-hash` (the `Release` sibling), a deeper path
    /// such as `Packages.diff/by-hash`, and a directory at architecture depth
    /// that is no architecture (Ubuntu's `cnf`, the `uefi`/`signed` trees): a
    /// row minted from one has a `Packages` whose 404 bails the mirror's
    /// sweep.
    #[test]
    fn classify_byhash_without_a_real_architecture_records_nothing() {
        for path in [
            "debian/dists/sid/main/dep11/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            "debian/dists/sid/main/i18n/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            "debian/dists/sid/main/source/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            "debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            "debian/dists/sid/main/binary-amd64/Packages.diff/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            "ubuntu/dists/noble/main/cnf/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            "ubuntu/dists/noble/main/uefi/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            "ubuntu/dists/noble/main/signed/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
            "ubuntu/dists/noble/main/binary-/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
        ] {
            let res = parse_request_path(path).expect("by-hash path parses");
            let class = classify_request(&res, &local_client()).unwrap();
            assert!(
                matches!(
                    class.resource_kind,
                    ResourceKind::ByHash(HashAlgo::Sha256, _)
                ),
                "{path}"
            );
            assert!(class.origin_fields.is_none(), "{path} must mint no origin");
        }
    }

    #[test]
    fn classify_icon_sources_translation_share_layout() {
        let icon = ResourceFile::Icon {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            filename: "icons-128x128.tar.gz",
        };
        let class = classify_request(&icon, &local_client()).unwrap();
        assert_eq!(class.debname, "sid_main_icons-128x128.tar.gz");
        assert_eq!(class.resource_kind.layout(), CacheLayout::Dists);

        let sources = ResourceFile::Sources {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            filename: "Sources.gz",
        };
        let class = classify_request(&sources, &local_client()).unwrap();
        assert_eq!(class.debname, "sid_main_Sources.gz");

        let translation = ResourceFile::Translation {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            filename: "Translation-en.bz2",
        };
        let class = classify_request(&translation, &local_client()).unwrap();
        assert_eq!(class.debname, "sid_main_Translation-en.bz2");
    }

    #[test]
    fn classify_flat_metadata() {
        let res = ResourceFile::Flat {
            kind: FlatKind::Metadata,
            mirror_path: "apt",
            filename: "InRelease",
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert_eq!(class.debname, "InRelease");
        assert_eq!(class.resource_kind, ResourceKind::FlatMetadata);
    }

    #[test]
    fn classify_flat_pool() {
        let res = ResourceFile::Flat {
            kind: FlatKind::Pool,
            mirror_path: "apt",
            filename: "twilio-cli_5.0.0_amd64.deb",
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert_eq!(class.debname, "twilio-cli_5.0.0_amd64.deb");
        assert_eq!(class.resource_kind, ResourceKind::FlatPool);
    }

    #[test]
    fn classify_flat_pool_decoded_shape_failure() {
        // %5f decodes to `_`, so the decoded form has 4 components and
        // fails the strict <name>_<ver>_<arch>.<ext> check even though the
        // raw form (3 components) passed `parse_request_path`'s probe.
        let res = ResourceFile::Flat {
            kind: FlatKind::Pool,
            mirror_path: "apt",
            filename: "foo%5fbar_1.0_amd64.deb",
        };
        assert!(matches!(
            classify_request(&res, &local_client()),
            Err(ClassifyError::NonDebPool { filename }) if filename == "foo_bar_1.0_amd64.deb"
        ));
    }

    /// Regression: `dists` is reserved in a *structured* mirror path only (a
    /// mirror `X/dists` would nest into `X`'s index directory).  A flat tree
    /// lives under `{host}/flat/`, so Docker CE's real layout, a flat pool
    /// below a `dists/` directory, must still cache.
    #[test]
    fn classify_flat_pool_below_a_dists_directory() {
        let res = parse_request_path(
            "linux/debian/dists/bookworm/pool/stable/amd64/containerd.io_1.7.27-1_amd64.deb",
        )
        .expect("parses");
        let class = classify_request(&res, &local_client()).expect("classifies");
        assert_eq!(
            &*class.mirror_path,
            "linux/debian/dists/bookworm/pool/stable/amd64"
        );
        assert_eq!(class.resource_kind, ResourceKind::FlatPool);

        let res = ResourceFile::Pool {
            mirror_path: "debian/dists",
            dirs: "main/f/foo",
            filename: "foo_1.0_amd64.deb",
        };
        assert!(matches!(
            classify_request(&res, &local_client()),
            Err(ClassifyError::InvalidValue {
                kind: ValidateKind::MirrorPath,
                decoded,
            }) if decoded == "debian/dists"
        ));
    }

    #[test]
    fn classify_flat_byhash() {
        let res = ResourceFile::Flat {
            kind: FlatKind::ByHash(HashAlgo::Sha256),
            mirror_path: "apt",
            filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert!(matches!(
            class.resource_kind,
            ResourceKind::FlatByHash(HashAlgo::Sha256, _)
        ));
    }

    #[test]
    fn classify_bad_encoding_returns_raw_field() {
        // %ff%fe is not valid UTF-8 once decoded; the raw (still encoded)
        // value is preserved on the error so callers can log it.
        let res = ResourceFile::Pool {
            mirror_path: "debian",
            dirs: "main/f/foo",
            filename: "%ff%fe",
        };
        assert!(matches!(
            classify_request(&res, &local_client()),
            Err(ClassifyError::BadEncoding {
                kind: ValidateKind::Filename,
                raw,
                ..
            }) if raw == "%ff%fe"
        ));
    }

    #[test]
    fn classify_invalid_filename() {
        // valid_filename rejects names whose first byte is not alphanumeric.
        let res = ResourceFile::Pool {
            mirror_path: "debian",
            dirs: "main/f/foo",
            filename: "_foo.deb",
        };
        assert!(matches!(
            classify_request(&res, &local_client()),
            Err(ClassifyError::InvalidValue {
                kind: ValidateKind::Filename,
                decoded,
            }) if decoded == "_foo.deb"
        ));
    }

    #[test]
    fn classify_mirror_path_rejects_an_encoded_separator() {
        for mirror_path in ["public%2Fubuntu", "public%2fubuntu"] {
            let res = ResourceFile::Pool {
                mirror_path,
                dirs: "main/f/foo",
                filename: "foo_1.0_amd64.deb",
            };
            assert!(
                matches!(
                    classify_request(&res, &local_client()),
                    Err(ClassifyError::EncodedSeparator {
                        kind: ValidateKind::MirrorPath,
                        raw,
                    }) if raw == mirror_path
                ),
                "{mirror_path}"
            );
        }
        let res = ResourceFile::Flat {
            kind: FlatKind::Metadata,
            mirror_path: "a%2Fb",
            filename: "Packages.gz",
        };
        assert!(matches!(
            classify_request(&res, &local_client()),
            Err(ClassifyError::EncodedSeparator {
                kind: ValidateKind::FlatMirrorPath,
                raw: "a%2Fb",
            })
        ));
        // Other escapes still decode inside a segment.
        let res = ResourceFile::Pool {
            mirror_path: "public%2Dubuntu/x",
            dirs: "main/f/foo",
            filename: "foo_1.0_amd64.deb",
        };
        let class = classify_request(&res, &local_client()).expect("classifies");
        assert_eq!(&*class.mirror_path, "public-ubuntu/x");
    }

    #[test]
    fn classify_invalid_mirror_path_rejects_traversal() {
        // valid_mirrorname rejects `..` segments before any later field is
        // even decoded.
        let res = ResourceFile::Pool {
            mirror_path: "../escape",
            dirs: "main/f/foo",
            filename: "foo_1.0_amd64.deb",
        };
        assert!(matches!(
            classify_request(&res, &local_client()),
            Err(ClassifyError::InvalidValue {
                kind: ValidateKind::MirrorPath,
                decoded,
            }) if decoded == "../escape"
        ));
    }

    #[test]
    fn cached_pdiff_patch_debnames() {
        let p = "T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz";
        for ok in [
            format!("sid_main_binary-amd64_Packages.diff_{p}"),
            format!("sid_main_Sources.diff_{p}"),
            format!("sid_main_Translation-zh_CN.diff_{p}"),
        ] {
            assert!(is_cached_pdiff_patch(&ok), "{ok}");
        }
        for bad in [
            "sid_main_binary-amd64_Packages.xz",
            "sid_InRelease",
            p,
            "sid_main_Packages.diff_T-12345",
        ] {
            assert!(!is_cached_pdiff_patch(bad), "{bad}");
        }
    }

    #[test]
    fn classify_pdiff_patches() {
        const P: &str = "T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz";
        // A client updating by pdiff never fetches the full `Packages`, so
        // a `Packages` patch must carry its architecture's origin or the
        // origin expires and cleanup sweeps the debs it still references.
        for (dir, debname, origin_arch) in [
            (
                "binary-amd64/Packages.diff",
                "sid_main_binary-amd64_Packages.diff_",
                Some("binary-amd64"),
            ),
            // A pseudo-architecture has no `Packages` index for cleanup to
            // fetch, so its patch names no origin either.
            ("i18n/Packages.diff", "sid_main_i18n_Packages.diff_", None),
            ("source/Sources.diff", "sid_main_Sources.diff_", None),
            (
                "i18n/Translation-en.diff",
                "sid_main_Translation-en.diff_",
                None,
            ),
            (
                "i18n/Translation-zh_CN.diff",
                "sid_main_Translation-zh_CN.diff_",
                None,
            ),
        ] {
            let path = format!("debian/dists/sid/main/{dir}/{P}");
            let res = parse_request_path(&path).expect("parses");
            let class = classify_request(&res, &local_client()).expect(&path);
            assert_eq!(class.debname, format!("{debname}{P}"), "{path}");
            // Cleanup's retention and the collision guard recognise the
            // patch by the name minted here.
            assert!(is_cached_pdiff_patch(&class.debname), "{path}");
            assert_eq!(class.resource_kind, ResourceKind::Pdiff, "{path}");
            let expected = origin_arch.map(|architecture| OriginFields {
                distribution: "sid".to_owned(),
                component: "main".to_owned(),
                architecture: architecture.to_owned(),
            });
            assert_eq!(class.origin_fields, expected, "{path}");
        }

        let path = format!("debian/dists/sid/main/Translation-en/Packages.diff/{P}");
        let res = parse_request_path(&path).expect("parses");
        assert!(
            matches!(
                classify_request(&res, &local_client()),
                Err(ClassifyError::PackagesOutsideArchitecture { .. })
            ),
            "{path}"
        );
        for path in [
            format!("debian/dists/sid_x/main/binary-amd64/Packages.diff/{P}"),
            format!("debian/dists/sid/main/binary-amd64%5Fx/Packages.diff/{P}"),
        ] {
            let res = parse_request_path(&path).expect("parses");
            assert!(
                matches!(
                    classify_request(&res, &local_client()),
                    Err(ClassifyError::JoinedFieldUnderscore { .. })
                ),
                "{path}"
            );
        }
    }

    /// A component-scoped filename that is, or only decodes to, a cached
    /// patch's name would share the patch's file as a volatile entry.
    #[test]
    fn component_scoped_name_decoding_to_a_patch_is_refused() {
        for path in [
            "debian/dists/sid/main/i18n/Translation-en.diff_T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz",
            "debian/dists/sid/main/i18n/Translation-en%2Ediff_T-2024-09-24-2005%2E48-F-2024-09-23-2021%2E00.gz",
            "debian/dists/sid/main/dep11/icons-x%2Ediff_T-2024-09-24-2005%2E48-F-2024-09-23-2021%2E00.gz",
        ] {
            let res = parse_request_path(path).expect("parses");
            assert!(
                matches!(
                    res,
                    ResourceFile::Translation { .. } | ResourceFile::Icon { .. }
                ),
                "{path}: {res:?}"
            );
            assert!(
                matches!(
                    classify_request(&res, &local_client()),
                    Err(ClassifyError::InvalidValue {
                        kind: ValidateKind::Filename,
                        ..
                    })
                ),
                "{path}"
            );
        }
    }

    /// The whole `ResourceKind -> (CachedFlavor, CacheLayout)` table as one
    /// literal, so a new kind (or a moved one) is decided here, not defaulted.
    #[test]
    fn resource_kind_flavor_and_layout_table() {
        use CacheLayout::{Dists, DistsByHash, Flat, FlatByHash, StructuredPool};
        use CachedFlavor::{Permanent, Volatile};
        for (kind, flavor, layout) in [
            (ResourceKind::Pool, Permanent, StructuredPool),
            (ResourceKind::Release, Volatile, Dists),
            (ResourceKind::ComponentRelease, Volatile, Dists),
            (ResourceKind::Packages, Volatile, Dists),
            (ResourceKind::Sources, Volatile, Dists),
            (ResourceKind::Translation, Volatile, Dists),
            (ResourceKind::Icon, Volatile, Dists),
            (
                ResourceKind::ByHash(HashAlgo::Sha256, ByHashContent::Other),
                Permanent,
                DistsByHash,
            ),
            (
                ResourceKind::ByHash(HashAlgo::Sha512, ByHashContent::Other),
                Permanent,
                DistsByHash,
            ),
            (ResourceKind::FlatMetadata, Volatile, Flat),
            (ResourceKind::FlatPool, Permanent, Flat),
            (
                ResourceKind::FlatByHash(HashAlgo::Sha256, ByHashContent::Other),
                Permanent,
                FlatByHash,
            ),
            (ResourceKind::Pdiff, Permanent, Dists),
        ] {
            assert_eq!(kind.cached_flavor(), flavor, "{kind:?} flavor");
            assert_eq!(kind.layout(), layout, "{kind:?} layout");
        }
    }

    #[test]
    fn classify_component_release() {
        let res = ResourceFile::ComponentRelease {
            mirror_path: "debian",
            distribution: "trixie",
            component: "main",
            architecture: "binary-amd64",
            filename: "Release",
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert_eq!(class.debname, "trixie_main_binary-amd64_Release");
        assert_eq!(class.resource_kind, ResourceKind::ComponentRelease);
        // A per-component Release is metadata about the indices, never a
        // per-binary origin - not even for a real architecture.
        assert!(class.origin_fields.is_none());
    }

    #[test]
    fn classify_decodes_each_field_separately() {
        // `%69` decodes to `i`; the decoded values are what reach the mirror
        // path and the debname.
        let res = ResourceFile::Release {
            mirror_path: "deb%69an",
            distribution: "s%69d",
            filename: "InRelease",
        };
        let class = classify_request(&res, &local_client()).unwrap();
        assert_eq!(&*class.mirror_path, "debian");
        assert_eq!(class.debname, "sid_InRelease");
    }

    #[test]
    fn classify_rejects_encoded_separator_in_filename() {
        // Decoding happens per field, after `parse_request_path` assigned the
        // segments their roles: `%2F` therefore stays inside the filename
        // field, where the validator sees the decoded `/` and rejects it.  It
        // can never carve an extra directory level out of a leaf name.
        let res = ResourceFile::Pool {
            mirror_path: "debian",
            dirs: "main/f/foo",
            filename: "foo%2Fbar_1.0_amd64.deb",
        };
        assert!(matches!(
            classify_request(&res, &local_client()),
            Err(ClassifyError::InvalidValue {
                kind: ValidateKind::Filename,
                decoded,
            }) if decoded == "foo/bar_1.0_amd64.deb"
        ));
    }

    /// Regression (cache poisoning): the pool directories are no part of the
    /// cache name but are forwarded upstream verbatim, so a `..` among them
    /// fetched `/victim_...deb` from the mirror root and cached it as
    /// `debian/victim_...deb`, served to every later canonical request.
    #[test]
    fn classify_rejects_dot_segments_in_pool_directories() {
        for (path, bad) in [
            ("debian/pool/updates/../../../victim_1.0_amd64.deb", ".."),
            ("debian/pool/main/%2e%2e/%2e%2e/victim_1.0_amd64.deb", ".."),
            (
                "debian/pool/main/v/v%2F..%2F..%2Fx/victim_1.0_amd64.deb",
                "v/../../x",
            ),
        ] {
            let res = parse_request_path(path).expect("parses as a pool file");
            assert!(matches!(&res, ResourceFile::Pool { .. }), "{path}: {res:?}");
            assert!(
                matches!(
                    classify_request(&res, &local_client()),
                    Err(ClassifyError::InvalidValue {
                        kind: ValidateKind::Directory,
                        ref decoded,
                    }) if decoded == bad
                ),
                "{path}"
            );
        }
    }

    /// A `+` in a source package name (the pool `<package>` directory) is
    /// legitimate, raw or percent-encoded as APT sends it.
    #[test]
    fn classify_accepts_a_plus_in_the_pool_package_directory() {
        for path in [
            "debian/pool/main/g/gtk+3.0/libgtk-3-0_3.24.41-1_amd64.deb",
            "debian/pool/main/g/gtk%2b3.0/libgtk-3-0_3.24.41-1_amd64.deb",
            "debian-security/pool/updates/main/g/gtk%2B3.0/libgtk-3-0_3.24.41-1_amd64.deb",
        ] {
            let res = parse_request_path(path).expect("parses as a pool file");
            let class = classify_request(&res, &local_client()).expect(path);
            assert_eq!(class.debname, "libgtk-3-0_3.24.41-1_amd64.deb", "{path}");
        }
    }

    /// The `by-hash` directory run is validated at every depth, not only the
    /// three-segment one that yields an origin scope.
    #[test]
    fn classify_rejects_dot_segments_in_byhash_directories() {
        const H: &str = "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";
        for dirs in [
            "../..",
            "sid/..",
            "..",
            "sid/main/binary-amd64/../..",
            "%2e%2e/x",
        ] {
            let path = format!("debian/dists/{dirs}/by-hash/SHA256/{H}");
            let res = parse_request_path(&path).expect("parses as a by-hash object");
            assert!(
                matches!(&res, ResourceFile::ByHash { .. }),
                "{path}: {res:?}"
            );
            assert!(
                matches!(
                    classify_request(&res, &local_client()),
                    Err(ClassifyError::InvalidValue { .. })
                ),
                "{path}"
            );
        }
        // Every legitimate depth still classifies.
        for dirs in [
            "",
            "trixie",
            "trixie/main",
            "trixie/main/debian-installer/binary-amd64",
        ] {
            let path = if dirs.is_empty() {
                format!("debian/dists/by-hash/SHA256/{H}")
            } else {
                format!("debian/dists/{dirs}/by-hash/SHA256/{H}")
            };
            let res = parse_request_path(&path).expect("parses as a by-hash object");
            assert!(classify_request(&res, &local_client()).is_ok(), "{path}");
        }
    }

    /// Regression (cache-name collision): the `dists/` cache names join
    /// distribution, component and architecture with `_`, so a `_` inside
    /// one of them let two different URLs share one cache file. Such a field
    /// makes the request uncacheable; a `_` in a filename stays legal.
    #[test]
    fn classify_refuses_to_cache_an_underscore_in_a_joined_field() {
        const H: &str = "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";
        for (path, kind, field) in [
            // Would be `sid_main_binary-amd64_Release`, the per-component
            // Release of `dists/sid/main/binary-amd64/`.
            (
                "debian/dists/sid_main_binary-amd64/Release".to_owned(),
                "distribution",
                "sid_main_binary-amd64",
            ),
            // Would be `sid_c_Translation-x_binary-amd64_Packages`, which
            // a Translation file under component `c` can spell too.
            (
                "debian/dists/sid/c_Translation-x/binary-amd64/Packages".to_owned(),
                "component",
                "c_Translation-x",
            ),
            (
                "debian/dists/sid/main/binary-amd_64/Release".to_owned(),
                "architecture",
                "binary-amd_64",
            ),
            (
                "debian/dists/sid/ma%5Fin/source/Sources.xz".to_owned(),
                "component",
                "ma_in",
            ),
            (
                format!("debian/dists/sid/main/i18n_x/by-hash/SHA256/{H}"),
                "architecture",
                "i18n_x",
            ),
            (
                "debian/dists/s_id/main/dep11/icons-64x64.tar.gz".to_owned(),
                "distribution",
                "s_id",
            ),
        ] {
            let res = parse_request_path(&path).expect("parses");
            let err = classify_request(&res, &local_client()).expect_err(&path);
            assert!(
                matches!(
                    &err,
                    ClassifyError::JoinedFieldUnderscore { kind: got, decoded }
                        if got.to_string() == kind && decoded == field
                ),
                "{path}: expected a `{kind}` refusal, got {err:?}"
            );
        }

        // A `_` in a filename is part of the name, not a separator.
        let res =
            parse_request_path("debian/dists/sid/main/i18n/Translation-en_GB.xz").expect("parses");
        let class = classify_request(&res, &local_client()).expect("classifies");
        assert_eq!(class.debname, "sid_main_Translation-en_GB.xz");
    }

    /// Regression (cache-name collision): a `Packages` index joins its
    /// directory into the cache name the way a component-scoped index joins
    /// its filename, so a directory spelled like a Translation or icons
    /// filename collided with one: `dists/sid/main/Translation-en/Packages`
    /// and `dists/sid/main/i18n/Translation-en_Packages` both named
    /// `sid_main_Translation-en_Packages`.  Only `binary-<arch>` and the
    /// pseudo-architectures may hold a cached `Packages` index.
    #[test]
    fn classify_refuses_to_cache_a_packages_index_outside_an_architecture() {
        for (path, field) in [
            (
                "debian/dists/sid/main/Translation-en/Packages",
                "Translation-en",
            ),
            (
                "debian/dists/sid/main/icons-64x64/Packages.gz",
                "icons-64x64",
            ),
            // Decoded before the check, like every other field.
            (
                "debian/dists/sid/main/%54ranslation-en/Packages.xz",
                "Translation-en",
            ),
            ("ubuntu/dists/noble/main/cnf/Packages", "cnf"),
            ("debian/dists/sid/main/binary-/Packages", "binary-"),
        ] {
            let res = parse_request_path(path).expect("parses");
            let err = classify_request(&res, &local_client()).expect_err(path);
            assert!(
                matches!(
                    &err,
                    ClassifyError::PackagesOutsideArchitecture { architecture }
                        if architecture == field
                ),
                "{path}: expected a `{field}` refusal, got {err:?}"
            );
        }

        // The Translation file the first path collided with still caches.
        let res = parse_request_path("debian/dists/sid/main/i18n/Translation-en_Packages")
            .expect("parses");
        let class = classify_request(&res, &local_client()).expect("classifies");
        assert_eq!(class.debname, "sid_main_Translation-en_Packages");
        assert_eq!(class.resource_kind, ResourceKind::Translation);

        for arch in ["binary-amd64", "binary-all", "dep11", "i18n", "source"] {
            let path = format!("debian/dists/sid/main/{arch}/Packages.xz");
            let res = parse_request_path(&path).expect("parses");
            let class = classify_request(&res, &local_client()).expect(&path);
            assert_eq!(class.debname, format!("sid_main_{arch}_Packages.xz"));
            assert_eq!(class.resource_kind, ResourceKind::Packages);
        }
    }

    #[test]
    fn name_max_is_the_platform_limit() {
        assert_eq!(Ok(NAME_MAX), usize::try_from(nix::libc::NAME_MAX));
        assert_eq!(MAX_DEBNAME_LEN + ".partial".len(), NAME_MAX);
    }

    /// [`ValidateKind`] carries both a label and the validator to apply; this
    /// pins the per-field rules against each other so a mis-routed arm shows
    /// up here rather than as a mis-cached request.
    #[test]
    fn validate_kind_dispatches_to_its_own_rule() {
        // `/` separates mirror-path segments but is never legal in a leaf.
        assert!(ValidateKind::MirrorPath.accepts("debian/updates"));
        assert!(!ValidateKind::Filename.accepts("debian/updates"));
        // A reserved layout segment is a mirror-path rule only.
        assert!(!ValidateKind::MirrorPath.accepts("tmp"));
        assert!(ValidateKind::Distribution.accepts("tmp"));
        assert!(!ValidateKind::FlatMirrorPath.accepts("apt/tmp"));
        // `dists` is reserved in a structured mirror path only.
        assert!(!ValidateKind::MirrorPath.accepts("debian/dists"));
        assert!(ValidateKind::FlatMirrorPath.accepts("debian/dists"));
        // Segment rules: leading `.` is out, inner `-` is in.
        assert!(!ValidateKind::Distribution.accepts("../escape"));
        assert!(ValidateKind::Distribution.accepts("bookworm-security"));
        assert!(ValidateKind::Architecture.accepts("binary-amd64"));
        assert!(ValidateKind::Component.accepts("non-free-firmware"));
    }

    #[test]
    fn alias_suffix_names_only_an_alias_host() {
        let mut details = crate::test_support::connection_details("foo_1.0_amd64.deb");
        assert_eq!(details.alias_suffix().to_string(), "");
        details.upstream_host = ClientHost::new("alias.test").unwrap();
        assert_eq!(
            details.alias_suffix().to_string(),
            " via alias host alias.test"
        );
    }
}
