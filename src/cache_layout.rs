//! On-disk cache layout for cached resources.
//!
//! This module owns the single source of truth for **where** a `ResourceFile`
//! lives on disk, and the unified [`classify_request`] entry point that
//! decodes, validates, and classifies an incoming request.
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
//! lands at `{cache}/{host}/flat/apt/amd64/twilio_5.0.0_amd64.deb` — no
//! registry lookup, no longest-prefix base resolution.
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
//! | `Flat { Metadata }`          | `flat/{mirror_path}` | `None`                | `{filename}`                                   | `Volatile`      |
//! | `Flat { Pool }`              | `flat/{mirror_path}` | `None`                | `{filename}`                                   | `Permanent`     |
//! | `Flat { ByHash }`            | `flat/{mirror_path}` | `Some("by-hash")`     | `{filename}` (hex hash)                        | `Permanent`     |
//!
//! Pool flattens the deeply-nested URL path to a single filename per mirror
//! (the URL's `pool/main/<l>/<pkg>/` components are dropped).
//! Release/Packages/etc. prefix `debname` with `{distribution}_…` to
//! disambiguate per-distribution copies that share the same on-disk
//! `mirror_path`.
//!
//! # Paths
//!
//! The joins themselves - and the subdirectory names (`dists/`, `flat/`,
//! `by-hash/`, `tmp/`) - live in [`crate::cache_paths`]: this module decides
//! *which* [`CacheLayout`] a resource has, [`crate::cache_paths::CachePaths`]
//! turns a layout plus a [`crate::cache_paths::MirrorSite`] into the
//! directory, and every scan / cleanup task derives its roots from the same
//! helper.

use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    string::FromUtf8Error,
};

use hashbrown::Equivalent;
use tracing::trace;

use crate::{
    cache_paths::{CachePaths, MirrorSite},
    client_info::ClientInfo,
    config::ClientHost,
    database_task::{DatabaseCommand, DbCmdOrigin, send_db_command_nonblocking},
    deb_mirror::{
        FlatKind, Mirror, MirrorKind, Origin, ResourceFile, is_deb_package, is_flat_deb_filename,
        valid_architecture, valid_component, valid_distribution, valid_filename, valid_mirrorname,
    },
    precise_instant::PreciseInstant,
};

// ---------------------------------------------------------------------------
// Cache-flavor and connection types (moved from main.rs)
// ---------------------------------------------------------------------------

/// Whether a cached resource is permanent (`.deb` / by-hash) or volatile
/// (refresh-checked metadata like `Release` / `Packages*`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CachedFlavor {
    Permanent,
    Volatile,
}

/// Owned discriminator for the [`crate::deb_mirror::ResourceFile`] variant a
/// request classified to, and the single truth table behind a resource's
/// [`CachedFlavor`] and [`CacheLayout`] ([`Self::cached_flavor`] /
/// [`Self::layout`]).  Nothing stores those two alongside the kind: every
/// consumer derives them, so a kind whose layout disagrees with its flavor is
/// unrepresentable.  The precise kind is still needed on its own - integrity
/// picks a verification strategy by it and decides whether to ingest the file
/// as an index, which `(flavor, layout)` cannot tell (`Packages` vs any other
/// `Dists`/`Volatile` metadata).  Populated by [`classify_request`]'s
/// exhaustive match, so a new `ResourceFile` variant compile-errors the
/// classifier (the existing safety net) and forces a decision here too.
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
    ByHash,
    /// Flat-repository metadata file (`Packages*`, `Release`, ...).
    FlatMetadata,
    /// Flat-repository `.deb` pool file.
    FlatPool,
    /// Flat-repository content-addressed `by-hash/SHA*/<hex>`.
    FlatByHash,
}

impl ResourceKind {
    /// Whether this kind is refresh-checked metadata or content that never
    /// changes under its name.  `Release`-family files and every index are
    /// `Volatile`; pool packages and content-addressed by-hash blobs are
    /// `Permanent`.
    #[must_use]
    pub(crate) const fn cached_flavor(self) -> CachedFlavor {
        match self {
            Self::Pool | Self::ByHash | Self::FlatPool | Self::FlatByHash => {
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

    /// The on-disk tree this kind is cached under (see the module-level
    /// per-variant table).
    #[must_use]
    pub(crate) const fn layout(self) -> CacheLayout {
        match self {
            Self::Pool => CacheLayout::StructuredPool,
            Self::Release
            | Self::ComponentRelease
            | Self::Packages
            | Self::Sources
            | Self::Translation
            | Self::Icon => CacheLayout::Dists,
            Self::ByHash => CacheLayout::DistsByHash,
            Self::FlatMetadata | Self::FlatPool => CacheLayout::Flat,
            Self::FlatByHash => CacheLayout::FlatByHash,
        }
    }
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
    /// Whether this layout is anchored under the per-host `flat/`
    /// subdirectory rather than directly under `{host}/{mirror_path}/`.
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
/// download barrier chain: the in-flight and post-flight views of a resource
/// must agree on what "the same file" is, so they all key on this one type.
///
/// Both [`Mirror::kind`] (inside `mirror`) and `layout` are part of the key:
///
/// - `Mirror::kind` distinguishes structured vs flat mirror identities for
///   the same `(host, port, path)` tuple - the coarse "which subtree does
///   this entry live in" axis.
/// - `layout` carries the finer-grained on-disk shape within a subtree (e.g.
///   `StructuredPool` vs `Dists` vs `DistsByHash` all share the same
///   structured `Mirror::kind`). This is the value the cache pipeline already
///   threads through [`ConnectionDetails`], so reusing it keeps the key
///   uniform across the structured/flat split.
///
/// The two are redundant on the structured-vs-flat axis but not overall;
/// dropping `layout` would lose the structured-subtree distinctions.
/// Disambiguation between flat-pool `.deb`s living in different
/// sub-directories (`apt/amd64/foo.deb` vs `apt/arm64/foo.deb`) is implicit
/// in [`Mirror::path`], since the URL path becomes the mirror path verbatim
/// under the host-anchored flat layout.
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

/// Verdict of a cache-file lookup that found nothing serveable for a
/// [`ConnectionDetails`], produced by whichever backend ran the lookup and
/// consumed by the backend that fetches.
///
/// Hit/miss/refetch accounting belongs to the lookup site: the producer bumps
/// `CACHE_MISSES` / `VOLATILE_REFETCHED` when it builds one of these, so a
/// consumer must never bump them again.  The stale copy travels with the
/// verdict so the fetcher can revalidate against it without a second
/// open/stat.
#[derive(Debug)]
// Only the hyper backend revalidates from the carried copy; the splice
// backend re-opens the file on its own path, so in a splice-only build the
// verdict is built and dropped unread.
#[cfg_attr(
    not(feature = "hyper"),
    expect(dead_code, reason = "consumed only by hyper_conn::serve_cache_miss")
)]
pub(crate) enum CacheMiss {
    /// No cache file on disk.
    NotFound,
    /// A volatile copy exists but is older than `VOLATILE_CACHE_MAX_AGE`
    /// (or its mtime is in the future); revalidate it upstream.
    StaleVolatile {
        file: tokio::fs::File,
        /// The copy's mtime, the `If-Modified-Since` value for revalidation.
        modified: std::time::SystemTime,
        /// The copy's on-disk size, for the quota reservation
        /// (`cache_quota.rs`: `prev_file_size`).
        size: u64,
    },
}

/// Per-request state carried across the cache pipeline.  Owns enough of the
/// classified resource to assemble the on-disk path via
/// [`Self::cache_file_path`].
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
    /// The classified kind; [`Self::cached_flavor`] and [`Self::layout`] are
    /// derived from it rather than stored, so the three cannot disagree.
    pub(crate) resource_kind: ResourceKind,
    /// The `Origin` this request would register, for real-arch `Packages`
    /// requests only.  Recorded by [`Self::record_origin`] once the request
    /// is *answered* (a cache hit, or a 2xx/304 upstream head) -- never at
    /// dispatch time, so a probe the upstream 404s mints no row.  Boxed:
    /// only index requests carry one, and `ConnectionDetails` rides inside
    /// per-request enums whose size the other variants set.
    pub(crate) origin_fields: Option<Box<OriginFields>>,
}

impl ConnectionDetails {
    /// Enqueue this request's `Origin` row, if it carries one.  Idempotent
    /// per request (the DB batch dedups identical rows) and skipped for
    /// cleanup's synthetic index fetches, which are bookkeeping, not client
    /// demand.  Non-blocking: it runs on the request path, so a saturated
    /// DB queue must not stall request handling.
    pub(crate) fn record_origin(&self) {
        let Some(fields) = &self.origin_fields else {
            return;
        };
        if self.client.is_cleanup_synthetic() {
            return;
        }
        let origin = Origin {
            mirror: self.mirror.clone(),
            distribution: fields.distribution.clone(),
            component: fields.component.clone(),
            architecture: fields.architecture.clone(),
        };
        send_db_command_nonblocking(DatabaseCommand::Origin(DbCmdOrigin { origin }));
    }

    /// [`ResourceKind::cached_flavor`] of this request's resource.
    #[must_use]
    pub(crate) const fn cached_flavor(&self) -> CachedFlavor {
        self.resource_kind.cached_flavor()
    }

    /// [`ResourceKind::layout`] of this request's resource.
    #[must_use]
    pub(crate) const fn layout(&self) -> CacheLayout {
        self.resource_kind.layout()
    }

    /// The entry identity every per-entry store keys on.
    #[must_use]
    pub(crate) fn key(&self) -> CacheEntryKeyRef<'_> {
        CacheEntryKeyRef::new(&self.mirror, &self.debname, self.layout())
    }

    /// The on-disk identity of this request's mirror.  `mirror` is already
    /// canonical, so this is a plain projection; `InitBarrier::site` derives
    /// the same site, so the `.partial` lands next to its rename target.
    #[must_use]
    pub(crate) fn site(&self) -> MirrorSite<'_> {
        MirrorSite {
            host: self.mirror.host().as_cache_host(),
            port: self.mirror.port(),
            path: self.mirror.path(),
        }
    }

    /// The `host[:port]` authority of the upstream the fetch dials: the
    /// host the client named, on the mirror's port.
    #[must_use]
    pub(crate) fn upstream_authority(&self) -> Cow<'_, str> {
        self.upstream_host.format_authority(self.mirror.port())
    }

    /// The mirror to dial for an upstream fetch: the canonical mirror with
    /// the client-named host swapped in.  Only for upstream dispatch and
    /// formatting; never persisted or used as a key.
    #[cfg(feature = "splice")]
    #[must_use]
    pub(crate) fn upstream_mirror(&self) -> Mirror {
        Mirror::new(
            self.upstream_host.clone(),
            self.mirror.port(),
            self.mirror.path().to_owned(),
            self.mirror.kind(),
        )
    }

    /// Log suffix naming the alias the client used, empty when the request
    /// named the canonical host itself.
    #[must_use]
    pub(crate) fn alias_suffix(&self) -> String {
        if &self.upstream_host == self.mirror.host() {
            String::new()
        } else {
            format!(" via alias host {}", self.upstream_host)
        }
    }

    /// The absolute directory holding this request's cached file
    /// ([`CachePaths::entry_dir`] for its layout and site).  The full file
    /// path is [`Self::cache_file_path`]; the leaf is appended there, not
    /// by callers.
    #[must_use]
    pub(crate) fn cache_dir_path(&self) -> PathBuf {
        CachePaths::global().entry_dir(self.layout(), self.site())
    }

    /// [`Self::cache_dir_path`] plus the `debname` leaf, in one pre-sized
    /// allocation - use this instead of pushing/joining the filename onto
    /// the directory path.
    #[must_use]
    pub(crate) fn cache_file_path(&self) -> PathBuf {
        CachePaths::global().entry_file(self.layout(), self.site(), Path::new(&self.debname))
    }
}

// ---------------------------------------------------------------------------
// Classification types
// ---------------------------------------------------------------------------

/// Which named field of a request URL is being validated.  Used both as a
/// label in error messages/logs and to dispatch to the right `valid_*`
/// validator inside [`classify_request`].
#[derive(Copy, Clone, Debug)]
pub(crate) enum ValidateKind {
    MirrorPath,
    Distribution,
    Component,
    Architecture,
    Filename,
}

impl std::fmt::Display for ValidateKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MirrorPath => "mirror path",
            Self::Distribution => "distribution",
            Self::Component => "component",
            Self::Architecture => "architecture",
            Self::Filename => "filename",
        })
    }
}

/// The deferred `Origin` payload populated for `Packages` requests with a
/// non-special architecture; `None` for every other variant (and for the
/// `dep11`/`i18n`/`source` pseudo-architectures, which are never recorded as
/// origins).
#[derive(Clone, Debug)]
pub(crate) struct OriginFields {
    pub(crate) distribution: String,
    pub(crate) component: String,
    pub(crate) architecture: String,
}

/// Returns `true` for Debian-archive "pseudo-architectures" — values that
/// appear in the `architecture` position of a `Packages` URL but do not
/// describe a real binary architecture and therefore are never recorded as
/// per-binary origins.
///
/// The current pseudo-arches are `dep11` (`AppStream` component metadata),
/// `i18n` (Translation indices), and `source` (source-package indices).
///
/// This helper is the single source of truth for the list; adding a future
/// pseudo-arch (e.g. `signed-by`) is a one-line change here. Call sites:
/// the `origin_fields` arm in [`classify_request`] and the deferred-`Origin`
/// DB-emission filters in `hyper_conn.rs`, `splice/mod.rs` and `splice/simple_proxy.rs`.
#[must_use]
pub(crate) fn is_pseudo_arch(arch: &str) -> bool {
    matches!(arch, "dep11" | "i18n" | "source")
}

/// Flatten an architecture-scoped `dists/` index into its cache debname.
///
/// Single source of truth for the `{distribution}_{component}_{architecture}_
/// {filename}` convention: [`classify_request`] mints the name for a client
/// request, and `cleanup::engine::DebnameKind` mints the same name for the
/// index fetches cleanup issues itself. If the two ever disagree, cleanup
/// caches every index under a path the serve path never reads — an invisible
/// shadow copy plus a re-download every cycle.
#[must_use]
pub(crate) fn dists_debname(
    distribution: &str,
    component: &str,
    architecture: &str,
    filename: &str,
) -> String {
    format!("{distribution}_{component}_{architecture}_{filename}")
}

/// The result of [`classify_request`]: the decoded, validated mirror path,
/// the per-variant `(debname, resource_kind)` pair needed to build
/// [`ConnectionDetails`] (flavor and layout derive from the kind), and any
/// deferred origin record to be sent post-hoc.
#[derive(Debug)]
pub(crate) struct RequestClass {
    pub(crate) mirror_path: String,
    pub(crate) debname: String,
    pub(crate) resource_kind: ResourceKind,
    pub(crate) origin_fields: Option<OriginFields>,
}

/// Errors returned by [`classify_request`].  Each call site translates these
/// into its own response shape (HTTP `quick_response` for the hyper path,
/// `SendfileResult::Invalid` / `SendfileResult::NotApplicable` for sendfile).
#[derive(Debug)]
pub(crate) enum ClassifyError<'a> {
    /// URL-decoding the field value failed.
    BadEncoding {
        kind: ValidateKind,
        raw: &'a str,
        source: FromUtf8Error,
    },
    /// The decoded field value did not pass its `valid_*` validator.
    InvalidValue {
        kind: ValidateKind,
        decoded: Cow<'a, str>,
    },
    /// A structured `Pool` request had a filename whose extension is not
    /// `.deb` / `.udeb` / `.ddeb`.  Both dispatchers treat this as a
    /// non-cacheable request and fall through to the simple proxy.
    ///
    /// `Flat::Pool` reaches this variant when the *decoded* filename fails
    /// the strict shape check: `parse_request_path` runs
    /// `is_flat_deb_filename` on the raw URL segment, and a percent-encoded
    /// segment like `foo%5fbar_1.0_amd64.deb` (2 underscores raw, 3 once
    /// decoded) can pass the raw check yet decode to a name that does not
    /// match `<name>_<ver>_<arch>.<ext>`.  Re-checking the decoded form
    /// closes that bypass.
    NonDebPool { filename: Cow<'a, str> },
}

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

/// Decode + validate every URL-borne field in `resource`, then derive the
/// on-disk classification (`debname`, `resource_kind`).  This is
/// the single source of truth behind `request_dispatch::dispatch_request`,
/// shared by the hyper (`hyper_conn.rs`) and sendfile (`sendfile_conn.rs`)
/// dispatchers.
///
/// On success, the caller wraps `RequestClass` into a `ConnectionDetails`
/// and routes the request through `process_cache_request` (or the sendfile
/// pipeline equivalent).  On failure, each backend translates the
/// `ClassifyError` variant into its own error response — see the variant
/// docs.
///
/// `client` is borrowed only for inclusion in trace logs; nothing about the
/// classification depends on the caller's identity.
pub(crate) fn classify_request<'a>(
    resource: &'a ResourceFile<'_>,
    client: &ClientInfo,
) -> Result<RequestClass, ClassifyError<'a>> {
    // Each arm decodes/validates only the fields that variant carries, then
    // assembles the (mirror_path, debname, resource_kind, origin_fields)
    // `RequestClass`; flavor and layout follow from the kind.
    match resource {
        ResourceFile::Pool {
            mirror_path,
            filename,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            if !is_deb_package(&filename) {
                return Err(ClassifyError::NonDebPool { filename });
            }

            trace!(
                "Decoded mirror path: `{mirror_path}`; Decoded filename: `{filename}` (client {client})"
            );

            Ok(RequestClass {
                mirror_path: mirror_path.into_owned(),
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
                mirror_path: mirror_path.into_owned(),
                debname: format!("{distribution}_{filename}"),
                resource_kind: ResourceKind::Release,
                origin_fields: None,
            })
        }
        ResourceFile::ByHash {
            mirror_path,
            filename,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            trace!(
                "Decoded mirror path: `{mirror_path}`; Decoded filename: `{filename}` (client {client})"
            );

            Ok(RequestClass {
                mirror_path: mirror_path.into_owned(),
                debname: filename.into_owned(),
                resource_kind: ResourceKind::ByHash,
                origin_fields: None,
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

            // Per-component Release is metadata about Packages; it is never
            // recorded as a per-binary origin (those come from the .deb
            // fetch path), so `origin_fields` is unconditionally `None`.
            Ok(RequestClass {
                mirror_path: mirror_path.into_owned(),
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

            // dep11 / i18n / source aren't real architectures and don't map
            // to per-binary origins.
            let origin_fields = if is_pseudo_arch(&architecture) {
                None
            } else {
                Some(OriginFields {
                    distribution: distribution.to_string(),
                    component: component.to_string(),
                    architecture: architecture.to_string(),
                })
            };

            Ok(RequestClass {
                mirror_path: mirror_path.into_owned(),
                debname: dists_debname(&distribution, &component, &architecture, &filename),
                resource_kind: ResourceKind::Packages,
                origin_fields,
            })
        }
        ResourceFile::Flat {
            kind,
            mirror_path,
            filename,
        } => {
            let mirror_path = decode_validate(mirror_path, ValidateKind::MirrorPath)?;
            let filename = decode_validate(filename, ValidateKind::Filename)?;

            trace!(
                "Decoded flat mirror path: `{mirror_path}`; Decoded flat filename: `{filename}` (kind: {kind:?}; client {client})"
            );

            let resource_kind = match kind {
                FlatKind::Metadata => ResourceKind::FlatMetadata,
                FlatKind::Pool => {
                    // `parse_request_path` runs `is_flat_deb_filename` on
                    // the *raw* URL segment, so a percent-encoded
                    // underscore can sneak a non-shape filename past the
                    // strict check (e.g. `foo%5fbar_1.0_amd64.deb` ⇒ 2
                    // raw underscores, but decoded to 3).  Re-validate the
                    // decoded filename to keep flat-pool caching limited
                    // to genuine `<name>_<ver>_<arch>.<ext>` packages.
                    if !is_flat_deb_filename(&filename) {
                        return Err(ClassifyError::NonDebPool { filename });
                    }
                    ResourceKind::FlatPool
                }
                FlatKind::ByHash => ResourceKind::FlatByHash,
            };

            Ok(RequestClass {
                mirror_path: mirror_path.into_owned(),
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

    Ok(RequestClass {
        mirror_path: mirror_path.into_owned(),
        debname: format!("{distribution}_{component}_{filename}"),
        resource_kind,
        origin_fields: None,
    })
}

/// URL-decode `raw` and check the result with the validator selected by
/// `kind`.  Returns a `Cow` borrowing the input when no percent-escape was
/// present (the common case for ASCII Debian paths), so callers that feed
/// the result into `format!` or a `&str`-taking validator pay no extra
/// allocation; callers needing an owned `String` (e.g. `RequestClass.mirror_path`)
/// call `.into_owned()` at the move site.
fn decode_validate(raw: &str, kind: ValidateKind) -> Result<Cow<'_, str>, ClassifyError<'_>> {
    let decoded = match urlencoding::decode(raw) {
        Ok(s) => s,
        Err(source) => {
            return Err(ClassifyError::BadEncoding { kind, raw, source });
        }
    };

    let ok = match kind {
        ValidateKind::MirrorPath => valid_mirrorname(&decoded),
        ValidateKind::Distribution => valid_distribution(&decoded),
        ValidateKind::Component => valid_component(&decoded),
        ValidateKind::Architecture => valid_architecture(&decoded),
        ValidateKind::Filename => valid_filename(&decoded),
    };

    if !ok {
        return Err(ClassifyError::InvalidValue { kind, decoded });
    }

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_info::ClientInfo;
    use crate::deb_mirror::{FlatKind, ResourceFile};
    use crate::test_support::local_client;

    fn fake_client() -> ClientInfo {
        local_client()
    }

    #[test]
    fn classify_pool() {
        let res = ResourceFile::Pool {
            mirror_path: "debian",
            filename: "firefox-esr_115.9.1esr-1_amd64.deb",
        };
        let class = classify_request(&res, &fake_client()).unwrap();
        assert_eq!(class.mirror_path, "debian");
        assert_eq!(class.debname, "firefox-esr_115.9.1esr-1_amd64.deb");
        assert_eq!(class.resource_kind.cached_flavor(), CachedFlavor::Permanent);
        assert_eq!(class.resource_kind.layout(), CacheLayout::StructuredPool);
        assert!(class.origin_fields.is_none());
    }

    #[test]
    fn classify_pool_non_deb_extension_returns_non_deb_pool() {
        let res = ResourceFile::Pool {
            mirror_path: "debian",
            filename: "README.txt",
        };
        assert!(matches!(
            classify_request(&res, &fake_client()),
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
        let class = classify_request(&res, &fake_client()).unwrap();
        assert_eq!(class.debname, "sid_InRelease");
        assert_eq!(class.resource_kind.cached_flavor(), CachedFlavor::Volatile);
        assert_eq!(class.resource_kind.layout(), CacheLayout::Dists);
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
        let class = classify_request(&res, &fake_client()).unwrap();
        assert_eq!(class.debname, "sid_main_binary-amd64_Packages.gz");
        assert_eq!(class.resource_kind.cached_flavor(), CachedFlavor::Volatile);
        assert_eq!(class.resource_kind.layout(), CacheLayout::Dists);
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
            let class = classify_request(&res, &fake_client()).unwrap();
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
            filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
        };
        let class = classify_request(&res, &fake_client()).unwrap();
        assert_eq!(
            class.debname,
            "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
        );
        assert_eq!(class.resource_kind.cached_flavor(), CachedFlavor::Permanent);
        assert_eq!(class.resource_kind.layout(), CacheLayout::DistsByHash);
    }

    #[test]
    fn classify_icon_sources_translation_share_layout() {
        let icon = ResourceFile::Icon {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            filename: "icons-128x128.tar.gz",
        };
        let class = classify_request(&icon, &fake_client()).unwrap();
        assert_eq!(class.debname, "sid_main_icons-128x128.tar.gz");
        assert_eq!(class.resource_kind.layout(), CacheLayout::Dists);

        let sources = ResourceFile::Sources {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            filename: "Sources.gz",
        };
        let class = classify_request(&sources, &fake_client()).unwrap();
        assert_eq!(class.debname, "sid_main_Sources.gz");

        let translation = ResourceFile::Translation {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            filename: "Translation-en.bz2",
        };
        let class = classify_request(&translation, &fake_client()).unwrap();
        assert_eq!(class.debname, "sid_main_Translation-en.bz2");
    }

    #[test]
    fn classify_flat_metadata() {
        let res = ResourceFile::Flat {
            kind: FlatKind::Metadata,
            mirror_path: "apt",
            filename: "InRelease",
        };
        let class = classify_request(&res, &fake_client()).unwrap();
        assert_eq!(class.debname, "InRelease");
        assert_eq!(class.resource_kind.cached_flavor(), CachedFlavor::Volatile);
        assert_eq!(class.resource_kind.layout(), CacheLayout::Flat);
    }

    #[test]
    fn classify_flat_pool() {
        let res = ResourceFile::Flat {
            kind: FlatKind::Pool,
            mirror_path: "apt",
            filename: "twilio-cli_5.0.0_amd64.deb",
        };
        let class = classify_request(&res, &fake_client()).unwrap();
        assert_eq!(class.debname, "twilio-cli_5.0.0_amd64.deb");
        assert_eq!(class.resource_kind.cached_flavor(), CachedFlavor::Permanent);
        assert_eq!(class.resource_kind.layout(), CacheLayout::Flat);
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
            classify_request(&res, &fake_client()),
            Err(ClassifyError::NonDebPool { filename }) if filename == "foo_bar_1.0_amd64.deb"
        ));
    }

    #[test]
    fn classify_gitea_flat_pool() {
        // issue #162: a non-canonical Gitea pool path arrives as Flat { Pool } and
        // classifies as a permanent flat-pool resource under the host flat layout.
        let res = ResourceFile::Flat {
            kind: FlatKind::Pool,
            mirror_path: "api/packages/85/debian/pool/php-zts/main",
            filename: "php-zts-cli_8.5.7-1_amd64.deb",
        };
        let class = classify_request(&res, &fake_client()).unwrap();
        assert_eq!(
            class.mirror_path,
            "api/packages/85/debian/pool/php-zts/main"
        );
        assert_eq!(class.debname, "php-zts-cli_8.5.7-1_amd64.deb");
        assert_eq!(class.resource_kind.cached_flavor(), CachedFlavor::Permanent);
        assert_eq!(class.resource_kind.layout(), CacheLayout::Flat);
        assert_eq!(class.resource_kind, ResourceKind::FlatPool);
    }

    #[test]
    fn classify_flat_byhash() {
        let res = ResourceFile::Flat {
            kind: FlatKind::ByHash,
            mirror_path: "apt",
            filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
        };
        let class = classify_request(&res, &fake_client()).unwrap();
        assert_eq!(class.resource_kind.layout(), CacheLayout::FlatByHash);
        assert_eq!(class.resource_kind.cached_flavor(), CachedFlavor::Permanent);
    }

    #[test]
    fn classify_bad_encoding_returns_raw_field() {
        // %ff%fe is not valid UTF-8 once decoded; the raw (still encoded)
        // value is preserved on the error so callers can log it.
        let res = ResourceFile::Pool {
            mirror_path: "debian",
            filename: "%ff%fe",
        };
        assert!(matches!(
            classify_request(&res, &fake_client()),
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
            filename: "_foo.deb",
        };
        assert!(matches!(
            classify_request(&res, &fake_client()),
            Err(ClassifyError::InvalidValue {
                kind: ValidateKind::Filename,
                decoded,
            }) if decoded == "_foo.deb"
        ));
    }

    #[test]
    fn classify_invalid_mirror_path_rejects_traversal() {
        // valid_mirrorname rejects `..` segments before any later field is
        // even decoded.
        let res = ResourceFile::Pool {
            mirror_path: "../escape",
            filename: "foo_1.0_amd64.deb",
        };
        assert!(matches!(
            classify_request(&res, &fake_client()),
            Err(ClassifyError::InvalidValue {
                kind: ValidateKind::MirrorPath,
                decoded,
            }) if decoded == "../escape"
        ));
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
            (ResourceKind::ByHash, Permanent, DistsByHash),
            (ResourceKind::FlatMetadata, Volatile, Flat),
            (ResourceKind::FlatPool, Permanent, Flat),
            (ResourceKind::FlatByHash, Permanent, FlatByHash),
        ] {
            assert_eq!(kind.cached_flavor(), flavor, "{kind:?} flavor");
            assert_eq!(kind.layout(), layout, "{kind:?} layout");
        }
    }

    #[test]
    fn classify_sets_resource_kind() {
        let pool = ResourceFile::Pool {
            mirror_path: "debian",
            filename: "foo_1.0_amd64.deb",
        };
        assert_eq!(
            classify_request(&pool, &fake_client())
                .unwrap()
                .resource_kind,
            ResourceKind::Pool
        );

        let pkgs = ResourceFile::Packages {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            architecture: "binary-amd64",
            filename: "Packages.xz",
        };
        assert_eq!(
            classify_request(&pkgs, &fake_client())
                .unwrap()
                .resource_kind,
            ResourceKind::Packages
        );

        let byhash = ResourceFile::ByHash {
            mirror_path: "debian",
            filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
        };
        assert_eq!(
            classify_request(&byhash, &fake_client())
                .unwrap()
                .resource_kind,
            ResourceKind::ByHash
        );

        let rel = ResourceFile::Release {
            mirror_path: "debian",
            distribution: "sid",
            filename: "Release",
        };
        assert_eq!(
            classify_request(&rel, &fake_client())
                .unwrap()
                .resource_kind,
            ResourceKind::Release
        );
    }
}
