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
//! # Subdir constants
//!
//! Use [`SUBDIR_DISTS`], [`SUBDIR_DISTS_BYHASH`], [`SUBDIR_FLAT`], and
//! [`SUBDIR_FLAT_BYHASH`] anywhere a layout subdirectory is referenced —
//! both in dispatch sites that build [`ConnectionDetails`] and in cleanup
//! / scan tasks that walk the cache tree.  Wrap with `Path::new(...)` at
//! the use site.  [`KNOWN_MIRROR_SUBDIRS`] is the list of legitimate
//! mirror-level subdirectories the startup scan recurses into.

use std::{
    borrow::Cow,
    path::{Path, PathBuf},
    string::FromUtf8Error,
};

use tracing::trace;

use crate::{
    ClientInfo,
    config::CacheHost,
    deb_mirror::{
        FlatKind, Mirror, MirrorKind, ResourceFile, is_deb_package, is_flat_deb_filename,
        valid_architecture, valid_component, valid_distribution, valid_filename, valid_mirrorname,
    },
    global_config,
    precise_instant::PreciseInstant,
};

// ---------------------------------------------------------------------------
// Subdir constants
// ---------------------------------------------------------------------------

// Subdirectory string constants.  Callers wrap with `Path::new(...)` at the
// use site since `Path::new` is not yet stable as a `const fn` in static
// context.
//
// TODO: convert these to `&'static Path` constants once `Path::new` is
// stable as a `const fn` in static context (tracking issue
// https://github.com/rust-lang/rust/issues/143874).  Call sites then drop
// their `Path::new(...)` wrappers.

/// Subdirectory holding `dists/`-anchored metadata (`Release`, `Packages*`,
/// etc.) under each `{host}/{mirror_path}/` cache root.
pub(crate) const SUBDIR_DISTS: &str = "dists";

/// Subdirectory holding by-hash content-addressed files belonging to the
/// structured `dists/` layout.
pub(crate) const SUBDIR_DISTS_BYHASH: &str = "dists/by-hash";

/// Host-level subdirectory anchoring every flat (trivial) repository served
/// from a given host.  The on-disk layout below it mirrors the URL path
/// verbatim: e.g. a flat-pool request for
/// `apt/amd64/twilio_5.0.0_amd64.deb` lands at
/// `{cache}/{host}/flat/apt/amd64/twilio_5.0.0_amd64.deb`.
pub(crate) const SUBDIR_FLAT: &str = "flat";

/// Prefix for mirror paths that collide with the host-level flat layout
/// (i.e. paths starting with `"flat/"`).  Used by [`crate::flat_blocklist`]
/// to detect collision patterns.
pub(crate) const SUBDIR_FLAT_PREFIX: &str = "flat/";

/// Subdirectory holding by-hash content-addressed files belonging to a flat
/// repository.  Appended below `{cache}/{host}/flat/{mirror_path}/` for a
/// `Flat::ByHash` request.
pub(crate) const SUBDIR_FLAT_BYHASH: &str = "by-hash";

/// Partial-download scratch directory.  Lives per-mirror at
/// `{cache}/{host}/{mirror_path}/tmp/` (structured) and
/// `{cache}/{host}/flat/{mirror_path}/tmp/` (flat).  Files here are owned by
/// `cleanup_tmp_dir`, never tallied in the cache-size sweep.
pub(crate) const SUBDIR_TMP: &str = "tmp";

/// Layout subdirectory names that may legitimately appear under each
/// `{cache_directory}/{host}/{mirror_path}/` directory.  The startup cache
/// scan recurses into each and tallies its size; anything else triggers an
/// "Unrecognized entry" warning.
///
/// `tmp/` is intentionally **not** listed here: it is partial-download
/// scratch space (not part of the served cache layout), is handled
/// separately by `task_cache_scan` with its own skip branch, and is reaped
/// by `cleanup_tmp_dir` rather than tallied.
pub(crate) const KNOWN_MIRROR_SUBDIRS: &[&str] = &[SUBDIR_DISTS];

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
/// request classified to.  [`RequestClass`] flattens a resource into
/// `(cached_flavor, layout)`, which cannot tell `Packages` apart from other
/// `Dists`/`Volatile` metadata; integrity needs the precise kind both to pick
/// a verification strategy and to decide whether to ingest the file as an
/// index.  Populated by [`classify_request`]'s exhaustive match, so a new
/// `ResourceFile` variant compile-errors the classifier (the existing safety
/// net) and forces a decision here too.
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
    /// On-disk subdir below the layout-anchored cache root for this
    /// variant.  Returns `None` when the file lives directly under the
    /// anchored root (structured pool, flat metadata / flat pool); the
    /// `by-hash` segment is the only suffix represented here.
    #[must_use]
    pub(crate) fn cache_subdir(self) -> Option<&'static Path> {
        match self {
            Self::StructuredPool | Self::Flat => None,
            Self::Dists => Some(Path::new(SUBDIR_DISTS)),
            Self::DistsByHash => Some(Path::new(SUBDIR_DISTS_BYHASH)),
            Self::FlatByHash => Some(Path::new(SUBDIR_FLAT_BYHASH)),
        }
    }

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

/// Per-request state carried across the cache pipeline.  Owns enough of the
/// classified resource to assemble the on-disk path via
/// [`Self::cache_dir_path`].
#[derive(Clone, Debug)]
pub(crate) struct ConnectionDetails {
    pub(crate) client: ClientInfo,
    /// Monotonic instant the client request was parsed - origin of the
    /// `in <time>` total-proxy-time figure in download/serve logs.
    pub(crate) request_received_at: PreciseInstant,
    pub(crate) mirror: Mirror,
    pub(crate) aliased_host: Option<&'static CacheHost>,
    pub(crate) debname: String,
    pub(crate) cached_flavor: CachedFlavor,
    pub(crate) layout: CacheLayout,
    pub(crate) resource_kind: ResourceKind,
}

impl ConnectionDetails {
    /// Build the absolute directory path holding this request's cached file.
    /// The full file path is `<this>/<debname>`; the leaf is appended by the
    /// caller.
    ///
    /// Structured layouts → `{cache}/{host}/{mirror_path}/{subdir?}/`
    /// Flat layouts        → `{cache}/{host}/flat/{mirror_path}/{by-hash?}/`
    ///
    /// The flat branch embeds the URL path verbatim under the host-level
    /// `flat/` sibling, so disambiguation between flat-pool subdirs
    /// (e.g. `apt/amd64/foo.deb` vs `apt/arm64/foo.deb`) is implicit in
    /// `mirror.path()` rather than a separately threaded field.
    #[must_use]
    pub(crate) fn cache_dir_path(&self) -> PathBuf {
        self.cache_path_impl(None)
    }

    /// [`Self::cache_dir_path`] plus the `debname` leaf, in one pre-sized
    /// allocation — use this instead of pushing/joining the filename onto
    /// the directory path.
    #[must_use]
    pub(crate) fn cache_file_path(&self) -> PathBuf {
        self.cache_path_impl(Some(&self.debname))
    }

    #[expect(
        clippy::pathbuf_init_then_push,
        reason = "the auto-suggestion `.join()` allocates a fresh PathBuf and \
                  throws away the with_capacity sizing we want here"
    )]
    fn cache_path_impl(&self, leaf: Option<&str>) -> PathBuf {
        let root = &global_config().cache_directory;

        let host = match self.aliased_host {
            Some(cache) => cache.format_cache_dir(self.mirror.port()),
            None => self.mirror.host().format_cache_dir(self.mirror.port()),
        };
        assert!(
            Path::new(host.as_ref()).is_relative(),
            "path construction must not contain absolute components"
        );

        let uri_path = self.mirror.path();
        assert!(
            Path::new(uri_path).is_relative(),
            "path construction must not contain absolute components"
        );

        let subdir = self.layout.cache_subdir().unwrap_or_else(|| Path::new(""));
        assert!(
            subdir.is_relative(),
            "path construction must not contain absolute components"
        );

        if let Some(leaf) = leaf {
            assert!(
                Path::new(leaf).is_relative(),
                "path construction must not contain absolute components"
            );
        }

        // Pre-size for the final length (+1 per separator) so `push` doesn't
        // grow the underlying OsString — this runs once per request on both
        // dispatch hot paths (same rationale as `mirror_cache_path_impl`).
        let is_flat = self.layout.is_flat();
        let capacity = root.as_os_str().len()
            + 1
            + host.len()
            + 1
            + if is_flat { SUBDIR_FLAT.len() + 1 } else { 0 }
            + uri_path.len()
            + 1
            + subdir.as_os_str().len()
            + 1
            + leaf.map_or(0, |l| l.len() + 1);

        let mut path = PathBuf::with_capacity(capacity);
        path.push(root.as_path());
        path.push(host.as_ref());
        if is_flat {
            path.push(SUBDIR_FLAT);
        }
        path.push(uri_path);
        path.push(subdir);
        if let Some(leaf) = leaf {
            path.push(leaf);
        }

        path
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
#[derive(Debug)]
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
/// DB-emission filters in `hyper_conn.rs` and `splice_conn.rs`.
#[must_use]
pub(crate) fn is_pseudo_arch(arch: &str) -> bool {
    matches!(arch, "dep11" | "i18n" | "source")
}

/// The result of [`classify_request`]: the decoded, validated mirror path,
/// the per-variant `(debname, cached_flavor, layout)` triple needed to build
/// [`ConnectionDetails`], and any deferred origin record to be sent post-hoc.
#[derive(Debug)]
pub(crate) struct RequestClass {
    pub(crate) mirror_path: String,
    pub(crate) debname: String,
    pub(crate) cached_flavor: CachedFlavor,
    pub(crate) layout: CacheLayout,
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
/// on-disk classification (`debname`, `cached_flavor`, `layout`).  This is
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
    // assembles the (mirror_path, debname, cached_flavor, layout,
    // resource_kind, origin_fields) `RequestClass`.
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
                cached_flavor: CachedFlavor::Permanent,
                layout: CacheLayout::StructuredPool,
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
                cached_flavor: CachedFlavor::Volatile,
                layout: CacheLayout::Dists,
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
                cached_flavor: CachedFlavor::Permanent,
                layout: CacheLayout::DistsByHash,
                resource_kind: ResourceKind::ByHash,
                origin_fields: None,
            })
        }
        ResourceFile::Icon {
            mirror_path,
            distribution,
            component,
            filename,
        } => {
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
                cached_flavor: CachedFlavor::Volatile,
                layout: CacheLayout::Dists,
                resource_kind: ResourceKind::Icon,
                origin_fields: None,
            })
        }
        ResourceFile::Sources {
            mirror_path,
            distribution,
            component,
            filename,
        } => {
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
                cached_flavor: CachedFlavor::Volatile,
                layout: CacheLayout::Dists,
                resource_kind: ResourceKind::Sources,
                origin_fields: None,
            })
        }
        ResourceFile::Translation {
            mirror_path,
            distribution,
            component,
            filename,
        } => {
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
                cached_flavor: CachedFlavor::Volatile,
                layout: CacheLayout::Dists,
                resource_kind: ResourceKind::Translation,
                origin_fields: None,
            })
        }
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
                debname: format!("{distribution}_{component}_{architecture}_{filename}"),
                cached_flavor: CachedFlavor::Volatile,
                layout: CacheLayout::Dists,
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
                debname: format!("{distribution}_{component}_{architecture}_{filename}"),
                cached_flavor: CachedFlavor::Volatile,
                layout: CacheLayout::Dists,
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

            let (cached_flavor, layout, resource_kind) = match kind {
                FlatKind::Metadata => (
                    CachedFlavor::Volatile,
                    CacheLayout::Flat,
                    ResourceKind::FlatMetadata,
                ),
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
                    (
                        CachedFlavor::Permanent,
                        CacheLayout::Flat,
                        ResourceKind::FlatPool,
                    )
                }
                FlatKind::ByHash => (
                    CachedFlavor::Permanent,
                    CacheLayout::FlatByHash,
                    ResourceKind::FlatByHash,
                ),
            };

            Ok(RequestClass {
                mirror_path: mirror_path.into_owned(),
                debname: filename.into_owned(),
                cached_flavor,
                layout,
                resource_kind,
                origin_fields: None,
            })
        }
    }
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
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use super::*;
    use crate::ClientInfo;
    use crate::deb_mirror::{FlatKind, ResourceFile};

    fn fake_client() -> ClientInfo {
        ClientInfo::new(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
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
        assert_eq!(class.cached_flavor, CachedFlavor::Permanent);
        assert_eq!(class.layout, CacheLayout::StructuredPool);
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
        assert_eq!(class.cached_flavor, CachedFlavor::Volatile);
        assert_eq!(class.layout, CacheLayout::Dists);
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
        assert_eq!(class.cached_flavor, CachedFlavor::Volatile);
        assert_eq!(class.layout, CacheLayout::Dists);
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
        assert_eq!(class.cached_flavor, CachedFlavor::Permanent);
        assert_eq!(class.layout, CacheLayout::DistsByHash);
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
        assert_eq!(class.layout, CacheLayout::Dists);

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
        assert_eq!(class.cached_flavor, CachedFlavor::Volatile);
        assert_eq!(class.layout, CacheLayout::Flat);
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
        assert_eq!(class.cached_flavor, CachedFlavor::Permanent);
        assert_eq!(class.layout, CacheLayout::Flat);
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
        assert_eq!(class.cached_flavor, CachedFlavor::Permanent);
        assert_eq!(class.layout, CacheLayout::Flat);
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
        assert_eq!(class.layout, CacheLayout::FlatByHash);
        assert_eq!(class.cached_flavor, CachedFlavor::Permanent);
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
