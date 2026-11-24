use std::{
    borrow::Cow,
    num::NonZero,
    sync::{Arc, OnceLock},
};

use hashbrown::HashMap;
use tracing::debug;

use crate::{
    cache_layout::classify_request,
    cache_paths::{MirrorSite, SUBDIR_DISTS, SUBDIR_FLAT_BYHASH, SUBDIR_TMP},
    client_info::ClientInfo,
    config::{CacheHost, ClientHost},
    database::{self, MirrorEntry},
    index_parser::HashAlgo,
};

/// On-disk layout family of a mirror, stored in the `mirrors_v2.kind`
/// INTEGER column.  The row's unique key remains `(host, port, path)`: the
/// upsert latches `kind` to `Structured` on conflict, so the flat-collision
/// blocklist still records a structured request that arrived after a flat
/// row already existed for the same tuple.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MirrorKind {
    Structured,
    Flat,
}

impl MirrorKind {
    /// The `mirrors_v2.kind` encoding, fixed by the migration's column
    /// default.
    #[must_use]
    pub(crate) const fn as_db_int(self) -> i64 {
        match self {
            Self::Structured => 0,
            Self::Flat => 1,
        }
    }

    /// `None` for an unknown value; the caller skips such rows so
    /// `cleanup_invalid_rows` can drop them later.
    #[must_use]
    pub(crate) const fn from_db_int(i: i64) -> Option<Self> {
        match i {
            0 => Some(Self::Structured),
            1 => Some(Self::Flat),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Mirror {
    host: ClientHost,
    port: Option<NonZero<u16>>,
    /// Shared like the host's text, so a clone (an active-downloads key, a
    /// DB command, a registry entry) bumps a refcount instead of copying it.
    path: Arc<str>,
    kind: MirrorKind,
    /// Cache of `host.format_authority(port)` when that allocates (an IPv6
    /// host or a port).  Derived, so left out of `Hash`/`Eq`/`Clone`.
    cached_authority: OnceLock<Box<str>>,
}

impl Mirror {
    #[must_use]
    pub(crate) const fn new(
        host: ClientHost,
        port: Option<NonZero<u16>>,
        path: Arc<str>,
        kind: MirrorKind,
    ) -> Self {
        Self {
            host,
            port,
            path,
            kind,
            cached_authority: OnceLock::new(),
        }
    }

    #[must_use]
    pub(crate) const fn kind(&self) -> MirrorKind {
        self.kind
    }

    #[must_use]
    pub(crate) fn format_authority(&self) -> &str {
        // Fast path: no allocation needed for DNS/IPv4 hosts without a port.
        if self.port.is_none() && !self.host.is_ipv6() {
            return self.host.as_str();
        }
        self.cached_authority.get_or_init(|| {
            self.host
                .format_authority(self.port)
                .into_owned()
                .into_boxed_str()
        })
    }

    #[must_use]
    pub(crate) const fn host(&self) -> &ClientHost {
        &self.host
    }

    #[must_use]
    pub(crate) const fn port(&self) -> Option<NonZero<u16>> {
        self.port
    }

    #[must_use]
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// The on-disk identity of this mirror: a plain projection, so callers
    /// must hold the canonical (alias-resolved) mirror.
    #[must_use]
    pub(crate) fn site(&self) -> MirrorSite<'_> {
        MirrorSite {
            host: self.host.as_cache_host(),
            port: self.port,
            path: self.path(),
        }
    }

    /// The heap this value owns beyond its inline size: the host text, the
    /// path and the rendered authority once cached. The host and path texts
    /// are shared allocations when the value is a clone, and are counted
    /// anyway.
    #[must_use]
    pub(crate) fn heap_bytes(&self) -> usize {
        let Self {
            host,
            port: _,
            path,
            kind: _,
            cached_authority,
        } = self;
        host.as_str().len()
            + path.len()
            + cached_authority
                .get()
                .map_or(0, |authority| authority.len())
    }
}

impl PartialEq for Mirror {
    fn eq(&self, other: &Self) -> bool {
        let Self {
            host,
            port,
            path,
            kind,
            cached_authority: _,
        } = self;
        let Self {
            host: ohost,
            port: oport,
            path: opath,
            kind: okind,
            cached_authority: _,
        } = other;
        // `kind` is part of identity so the `database_task` mirror-id
        // cache hits the DB once per kind, letting the structured upsert
        // latch the row's `kind` column without being masked by a
        // sibling flat cache entry.
        host == ohost && port == oport && path == opath && kind == okind
    }
}

impl Clone for Mirror {
    fn clone(&self) -> Self {
        let Self {
            host,
            port,
            path,
            kind,
            cached_authority: _,
        } = self;
        Self {
            host: host.clone(),
            port: *port,
            path: Arc::clone(path),
            kind: *kind,
            cached_authority: OnceLock::new(),
        }
    }
}

impl Eq for Mirror {}

impl std::hash::Hash for Mirror {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let Self {
            host,
            port,
            path,
            kind,
            cached_authority: _,
        } = self;
        host.hash(state);
        port.hash(state);
        path.hash(state);
        kind.hash(state);
    }
}

impl std::fmt::Display for Mirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.format_authority(), self.path)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Origin {
    pub(crate) mirror: Mirror,
    pub(crate) fields: OriginFields,
}

/// The `(distribution, component, architecture)` triple that, together with a
/// [`Mirror`], names an `origins` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OriginFields {
    pub(crate) distribution: String,
    pub(crate) component: String,
    pub(crate) architecture: String,
}

impl OriginFields {
    /// The origin a decoded `dists/<dist>/<comp>/<arch>/` scope names. Only
    /// `binary-<arch>` is a real architecture ([`is_binary_arch`]); the
    /// metadata trees sharing its depth (`dep11`, `i18n`, `source`, Ubuntu's
    /// `cnf`) map to no origin.
    pub(crate) fn of_scope(
        distribution: Cow<'_, str>,
        component: Cow<'_, str>,
        architecture: Cow<'_, str>,
    ) -> Option<Self> {
        is_binary_arch(&architecture).then(|| Self {
            distribution: distribution.into_owned(),
            component: component.into_owned(),
            architecture: architecture.into_owned(),
        })
    }
}

/// How much a request proved about the `dists/<d>/<c>/<a>/` scope it carried.
///
/// A `by-hash` cache entry is keyed by `{mirror, digest}` with the scope
/// deliberately outside the cache identity, so a hit confirms nothing about
/// the scope the client spelled. Only a request the upstream answered may
/// create a row; a hit refreshes one that already exists.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum OriginSighting {
    /// The upstream answered (fresh body or 304): creates the row, or
    /// refreshes it.
    Upstream,
    /// Served from cache, so the scope is unverified: refreshes an existing
    /// row's `last_seen`, never creates one.
    CacheHit,
}

/// Returns `true` for the `dists/<dist>/<comp>/<slot>/` segment that names a
/// real binary architecture (`binary-<arch>`) — the only slot with a
/// `Packages` index, and therefore the only one recorded as a per-binary
/// origin.
///
/// An allowlist rather than a denylist of metadata directories, because the
/// slot is just the third segment of a `dists/` URL and archives put more
/// than architectures there: `dep11`, `i18n`, `source`, Ubuntu's `cnf`, the
/// `uefi`/`signed` trees. A wrongly minted row costs more than a missed one —
/// cleanup fetches `<slot>/Packages` for every active origin, and that 404
/// bails the mirror's whole sweep. (`debian-installer/binary-<arch>` sits a
/// segment deeper than the three-segment scope both callers accept.)
#[must_use]
pub(crate) fn is_binary_arch(arch: &str) -> bool {
    arch.strip_prefix("binary-")
        .is_some_and(|arch| !arch.is_empty())
}

/// The metadata trees sitting at the `binary-<arch>` depth of
/// `dists/<dist>/<comp>/`, which hold no `Packages` index of their own and
/// therefore mint no origin.
const PSEUDO_ARCHITECTURES: &[&str] = &["dep11", "i18n", "source"];

/// Whether a `Packages` index under the `dists/<dist>/<comp>/<slot>/`
/// directory `slot` may be cached: a real architecture ([`is_binary_arch`])
/// or one of the [`PSEUDO_ARCHITECTURES`].
///
/// An allowlist because the slot joins the cache name
/// (`{dist}_{comp}_{slot}_{filename}`) exactly where a component-scoped
/// index joins its filename (`{dist}_{comp}_{filename}`): a slot spelled
/// like a Translation or icons filename (`Translation-en`) would name the
/// same cache file as `i18n/Translation-en_Packages`.  Neither allowed form
/// can begin such a filename.
#[must_use]
pub(crate) fn is_packages_directory(slot: &str) -> bool {
    is_binary_arch(slot) || PSEUDO_ARCHITECTURES.contains(&slot)
}

impl Origin {
    /// The [`Origin`] a request for `path` on `host`/`port` would register
    /// if it were cached: `path` is parsed, normalised, percent-decoded and
    /// validated exactly as `request_dispatch::decide_request` does it for
    /// a cache request, so only `binary-<arch>` `Packages*`, `by-hash` and
    /// `Packages` pdiff patch URLs yield one.
    ///
    /// For the passthrough relays, which forward what the classifier
    /// declined: an origin row names a mirror, feeds cleanup's index fetches
    /// and can disable flat caching for a whole host
    /// ([`crate::flat_blocklist`]), so it must never come from a shape the
    /// cache itself refuses.  `client` only labels trace lines.
    #[must_use]
    pub(crate) fn from_path(
        path: &str,
        host: ClientHost,
        port: Option<NonZero<u16>>,
        client: &ClientInfo,
    ) -> Option<Self> {
        let normalized = normalize_uri_path(path);
        let resource = parse_request_path(&normalized)?;
        let class = classify_request(&resource, client).ok()?;
        if is_unsafe_cache_path(&normalized) {
            return None;
        }
        class.validate_storage().ok()?;
        let kind = class.resource_kind.layout().mirror_kind();
        let fields = class.origin_fields?;
        Some(Self {
            mirror: Mirror::new(host, port, class.mirror_path, kind),
            fields,
        })
    }
}

pub(crate) trait UriFormat {
    #[must_use]
    fn uri(&self) -> String;
}

fn format_origin_uri(
    host: &ClientHost,
    port: Option<NonZero<u16>>,
    mirror_path: &str,
    dist: &str,
    comp: &str,
    arch: &str,
) -> String {
    let authority = host.format_authority(port);
    format!("http://{authority}/{mirror_path}/dists/{dist}/{comp}/{arch}/Packages")
}

impl UriFormat for Origin {
    #[inline]
    fn uri(&self) -> String {
        format_origin_uri(
            &self.mirror.host,
            self.mirror.port,
            &self.mirror.path,
            &self.fields.distribution,
            &self.fields.component,
            &self.fields.architecture,
        )
    }
}

impl UriFormat for &database::OriginEntry {
    #[inline]
    fn uri(&self) -> String {
        format_origin_uri(
            &self.host,
            self.port(),
            &self.mirror_path,
            &self.distribution,
            &self.component,
            &self.architecture,
        )
    }
}

/// Classification of a flat (trivial) repository resource.
///
/// Flat repositories serve apt resources directly under a base directory
/// without the `dists/<dist>/<component>/binary-<arch>/` and `pool/...`
/// hierarchies of structured Debian archives.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum FlatKind {
    /// `Release`, `Release.gpg`, `InRelease`, `Packages{,.gz,.xz}`,
    /// `Sources{,.gz,.xz}`.
    Metadata,
    /// A binary package (`.deb`, `.udeb`, `.ddeb`) served from the flat tree.
    Pool,
    /// A by-hash content-addressed file at `<base>/by-hash/SHA*/<hex>`,
    /// with the algorithm its `SHA*` directory names.
    ByHash(HashAlgo),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResourceFile<'a> {
    Pool {
        mirror_path: &'a str,
        /// The raw `[updates/]<component>/<prefix>/<package>` run between
        /// `pool/` and the filename.  No part of the cache identity (the
        /// file caches flat under the mirror), but the upstream is asked for
        /// it verbatim, so [`crate::cache_layout::classify_request`] decodes
        /// and validates every segment: an unchecked `..` here would fetch
        /// one file and cache it under another's name.
        dirs: &'a str,
        filename: &'a str,
    },
    /// The archive-level `Release` / `InRelease` / `Release.gpg`.
    Release {
        mirror_path: &'a str,
        distribution: &'a str,
        filename: &'a str,
    },
    /// A per-component, per-architecture `Release` index sibling to the
    /// `Packages*` file: `dists/<dist>/<component>/(binary-<arch>|source)/Release`.
    /// The `architecture` field carries the `binary-<arch>` token or the
    /// literal `source` for source-component releases.  `InRelease` has no
    /// per-component form in the Debian spec.
    ComponentRelease {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        architecture: &'a str,
        filename: &'a str,
    },
    Packages {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        architecture: &'a str,
        filename: &'a str,
    },
    /// A file named and acquired by its hash value
    ByHash {
        mirror_path: &'a str,
        /// The raw `/`-joined directory run between `dists/` and `/by-hash/`,
        /// empty when there is none.  Like the `Pool` directories no part of
        /// the cache identity but forwarded upstream, so every segment is
        /// decoded and validated by [`crate::cache_layout::classify_request`].
        dirs: &'a str,
        /// The algorithm the `by-hash/<ALGO>/` directory names, validated
        /// against the digest's length: the one the download is verified
        /// with.
        algorithm: HashAlgo,
        filename: &'a str,
        /// The `dists/<dist>/<comp>/<arch>/` scope the object hangs under,
        /// when the path has exactly that shape; `None` at any other depth
        /// (a component-scoped `Release` sibling, or `Packages.diff/`).  No
        /// part of the cache identity - it exists so
        /// [`crate::cache_layout::classify_request`] can mint the `Origin`
        /// row a literal `Packages*` request would.
        scope: Option<DistsScope<'a>>,
    },
    /// A by-name pdiff patch,
    /// `dists/<dist>/<component>/<slot>/<index>.diff/T-<ts>-F-<ts>.gz`: a
    /// merged patch from one index state to another, whose name never
    /// names other bytes.  APT always fetches these by name, never by-hash.
    Pdiff {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        /// The `Packages` slot (`binary-<arch>` or a pseudo-architecture);
        /// `None` for `Sources` / `Translation-*`, whose scope directory is
        /// fixed.
        architecture: Option<&'a str>,
        /// The index base without `.diff`: `Packages`, `Sources` or
        /// `Translation-<lang>`.
        index: &'a str,
        patch: &'a str,
    },
    Icon {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        filename: &'a str,
    },
    Sources {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        filename: &'a str,
    },
    /// A translation file (`Translation-LANG{,.bz2,.gz,.xz}`).
    Translation {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        filename: &'a str,
    },
    /// A resource served from a flat (trivial) repository.
    /// See <https://wiki.debian.org/DebianRepository/Format#Flat_Repository_Format>.
    Flat {
        kind: FlatKind,
        mirror_path: &'a str,
        filename: &'a str,
    },
}

/// Collapse `//` runs and strip standalone `.` segments (RFC 3986 §5.2.4)
/// in a URL path.
///
/// APT clients with a trailing slash in their `sources.list` mirror URI
/// produce request paths like `/debian//dists/...`; flat-repo entries of
/// the form `deb URI /` cause apt to emit `/./` between the base URI and
/// the filename (e.g. NVIDIA's CUDA repos).  `..` is intentionally
/// preserved so `is_unsafe_proxy_path` can still reject real traversal
/// attempts.  Idempotent; borrows when nothing changes.
#[must_use]
pub(crate) fn normalize_uri_path(path: &str) -> Cow<'_, str> {
    if !needs_normalization(path) {
        return Cow::Borrowed(path);
    }

    let leading_slash = path.starts_with('/');
    let trailing_slash = path.len() > 1 && path.ends_with('/');

    let mut out = String::with_capacity(path.len());
    if leading_slash {
        out.push('/');
    }
    let mut wrote_any = false;
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if wrote_any {
            out.push('/');
        }
        out.push_str(seg);
        wrote_any = true;
    }
    if trailing_slash && !out.ends_with('/') {
        out.push('/');
    }
    Cow::Owned(out)
}

#[must_use]
fn needs_normalization(path: &str) -> bool {
    if path.contains("//") {
        return true;
    }
    path.split('/').any(|seg| seg == ".")
}

/// The `<dist>/<component>/<architecture>` scope an index file or a
/// `by-hash` object sits under.  The architecture slot is the raw URL segment
/// (`binary-amd64`, or a pseudo-arch such as `dep11`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct DistsScope<'a> {
    pub(crate) distribution: &'a str,
    pub(crate) component: &'a str,
    pub(crate) architecture: &'a str,
}

/// The `<dist>/<component>/<slot>` run of a `dists/` path, if it has exactly
/// that shape.  `parts` is the `rsplit('/')` iterator just past the segments
/// to its right, so the segments arrive innermost-first.
fn dists_scope<'a>(mut parts: impl Iterator<Item = &'a str>) -> Option<DistsScope<'a>> {
    let architecture = parts.next()?;
    let component = parts.next()?;
    let distribution = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some(DistsScope {
        distribution,
        component,
        architecture,
    })
}

/// [`dists_scope`] for the index families that live under one fixed `slot`
/// (`source` for `Sources`, `i18n` for `Translation`, `dep11` for `Icon`).
fn dists_scope_in<'a>(parts: impl Iterator<Item = &'a str>, slot: &str) -> Option<DistsScope<'a>> {
    dists_scope(parts).filter(|scope| scope.architecture == slot)
}

/// Parses a request path into the mirror path and the filename.
///
/// The directory name "pool" is not supported as part of the mirror path.
/// The directory name "dists" should be avoided as part of the mirror path.
///
/// A trailing slash is rejected (the empty last segment matches no
/// filename): APT never sends one, so accepting it would let an
/// oddly-shaped client request alias to a cached file.
#[must_use]
pub(crate) fn parse_request_path(path: &str) -> Option<ResourceFile<'_>> {
    let path = path.trim_start_matches('/');

    /*
     * debian/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb
     * debian-security/pool/updates/main/c/chromium/chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb
     */
    if let Some((mirror_path, pool_path)) = path.split_once("/pool/") {
        // Canonical Debian-archive pool layout. On a non-canonical pool path
        // (e.g. Gitea/Forgejo `pool/<dist>/<comp>/<file>`, which the Debian
        // repository format permits via an arbitrary `Filename:` value) fall
        // through to the flat handler, which keys by the URL directory verbatim
        // and gates on the strict `<name>_<ver>_<arch>.<ext>` shape. A `/pool/`
        // path is never reinterpreted as a `/dists/` path.
        return parse_structured_pool(mirror_path, pool_path).or_else(|| parse_flat_resource(path));
    }

    /*
     * debian/dists/sid/InRelease
     * debs/dists/vscodium/main/binary-amd64/Packages.gz
     * debian/dists/sid/main/source/Sources.xz
     * debian/dists/sid/main/dep11/icons-128x128.tar.gz
     * debian/dists/unstable/main/i18n/Translation-en.bz2
     * debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba
     */
    if let Some((mirror_path, dists_path)) = path.rsplit_once("/dists/") {
        let mut parts = dists_path.rsplit('/');

        let filename = parts.next()?;
        if is_release_filename(filename) {
            // `rsplit` walks segments right-to-left.  The first segment may
            // be either the distribution (top-level Release/InRelease/Release.gpg)
            // or the `binary-<arch>` / `source` scope of a per-component
            // Release.
            let next = parts.next()?;

            match parts.next() {
                None => {
                    return Some(ResourceFile::Release {
                        mirror_path,
                        distribution: next,
                        filename,
                    });
                }
                Some(component) => {
                    // Per-component Release: dists/<dist>/<component>/(binary-<arch>|source)/Release.
                    // `InRelease` and `Release.gpg` have no per-component form.
                    if filename != "Release" {
                        return None;
                    }
                    let architecture = next;
                    if !is_binary_arch(architecture) && architecture != "source" {
                        return None;
                    }
                    let distribution = parts.next()?;
                    if parts.next().is_some() {
                        return None;
                    }
                    return Some(ResourceFile::ComponentRelease {
                        mirror_path,
                        distribution,
                        component,
                        architecture,
                        filename,
                    });
                }
            }
        } else if is_packages_filename(filename) {
            let DistsScope {
                distribution,
                component,
                architecture,
            } = dists_scope(parts)?;
            return Some(ResourceFile::Packages {
                mirror_path,
                distribution,
                component,
                architecture,
                filename,
            });
        } else if is_sources_filename(filename) {
            let DistsScope {
                distribution,
                component,
                architecture: _,
            } = dists_scope_in(parts, "source")?;
            return Some(ResourceFile::Sources {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if is_translation_filename(filename) {
            let DistsScope {
                distribution,
                component,
                architecture: _,
            } = dists_scope_in(parts, "i18n")?;
            return Some(ResourceFile::Translation {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if filename.starts_with("icons-") {
            let DistsScope {
                distribution,
                component,
                architecture: _,
            } = dists_scope_in(parts, "dep11")?;
            return Some(ResourceFile::Icon {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if is_byhash_digest_shape(filename) {
            let algorithm = byhash_pair(parts.next()?, filename)?;

            if parts.next()? != "by-hash" {
                return None;
            }

            // Everything before `by-hash/<ALGO>/<hex>`; empty for a
            // `dists/by-hash/...` object.
            let dirs = dists_path.rsplitn(4, '/').nth(3).unwrap_or_default();

            // Exactly three directories are the `<dist>/<comp>/<arch>` scope
            // an `Origin` is made of.  Any other depth yields no scope
            // rather than rejecting the request: the object is still
            // cacheable by its digest.
            let scope = dists_scope(parts);

            return Some(ResourceFile::ByHash {
                mirror_path,
                dirs,
                algorithm,
                filename,
                scope,
            });
        } else if is_pdiff_patch_name(filename) {
            let index = parts.next()?.strip_suffix(".diff")?;
            // Only a `Packages` patch keeps its slot: `Sources` and
            // `Translation-*` sit in a fixed scope directory.
            let (scope, architecture) = match index {
                "Packages" => {
                    let scope = dists_scope(parts)?;
                    (scope, Some(scope.architecture))
                }
                "Sources" => (dists_scope_in(parts, "source")?, None),
                _ if is_pdiff_translation_base(index) => (dists_scope_in(parts, "i18n")?, None),
                _ => return None,
            };
            return Some(ResourceFile::Pdiff {
                mirror_path,
                distribution: scope.distribution,
                component: scope.component,
                architecture,
                index,
                patch: filename,
            });
        }

        return None;
    }

    parse_flat_resource(path)
}

/// Parse the canonical Debian-archive pool layout
/// `pool/<component>/<letter>/<source>/<file>` (optionally with a leading
/// `updates/` segment for security archives). `mirror_path` is the part
/// before `/pool/`, `pool_path` the part after it.
fn parse_structured_pool<'a>(mirror_path: &'a str, pool_path: &'a str) -> Option<ResourceFile<'a>> {
    let (dirs, filename) = pool_path.rsplit_once('/')?;

    let mut parts = dirs.rsplit('/');

    let package = parts.next()?;

    let prefix = parts.next()?;
    if !package.starts_with(prefix) {
        return None;
    }

    let _component = parts.next()?;

    if parts
        .next()
        .is_some_and(|s| s != "updates" || parts.next().is_some())
    {
        return None;
    }

    Some(ResourceFile::Pool {
        mirror_path,
        dirs,
        filename,
    })
}

/// Parse a flat (trivial) repository resource from an already
/// leading-slash-trimmed `path`. A mirror namespace prefix is required even
/// for flat repos:
/// the host root has no namespace to disambiguate a root-served flat repo from
/// the structured `dists/` / `flat/` siblings, so the spec's empty-directory
/// form is declined.
/// See <https://wiki.debian.org/DebianRepository/Format#Flat_Repository_Format>.
fn parse_flat_resource(path: &str) -> Option<ResourceFile<'_>> {
    /*
     * apt/InRelease
     * apt/Release.gpg
     * apt/Packages.gz
     * apt/twilio-cli_5.0.0_amd64.deb
     * apt/by-hash/SHA256/<hex>
     */
    let Some((mirror_path, tail)) = path.rsplit_once('/') else {
        debug!(
            "Rejecting request `{path}` with no mirror namespace prefix; \
             apt-cacher-rs requires one even for flat repositories"
        );
        return None;
    };
    if mirror_path.is_empty() {
        return None;
    }

    // By-hash: `<base>/by-hash/<ALGO>/<hex>`; the digest shape and algorithm
    // directory name are cross-checked. On structural mismatch fall through to
    // None rather than reclassifying as a pool file.
    if is_byhash_digest_shape(tail) {
        if let Some((base, hash_algo)) = mirror_path.rsplit_once('/')
            && let Some(algorithm) = byhash_pair(hash_algo, tail)
            && let Some((flat_base, by_hash_dir)) = base.rsplit_once('/')
            && by_hash_dir == "by-hash"
            && !flat_base.is_empty()
        {
            return Some(ResourceFile::Flat {
                kind: FlatKind::ByHash(algorithm),
                mirror_path: flat_base,
                filename: tail,
            });
        }
        return None;
    }

    // Metadata: closed allowlist of canonical flat-repo filenames, the same
    // index families the structured `dists/` arm recognises.
    if is_release_filename(tail)
        || is_packages_filename(tail)
        || is_sources_filename(tail)
        || is_translation_filename(tail)
    {
        return Some(ResourceFile::Flat {
            kind: FlatKind::Metadata,
            mirror_path,
            filename: tail,
        });
    }

    // Pool data: enforce the strict `<name>_<version>_<arch>.<ext>` shape.
    if is_flat_deb_filename(tail) {
        return Some(ResourceFile::Flat {
            kind: FlatKind::Pool,
            mirror_path,
            filename: tail,
        });
    }

    None
}

/// Whether `name` is acceptable as a cache-entry leaf (the `debname` a
/// request resolves to): 4..=255 bytes, ASCII, no control characters, no
/// path separator, and an alphanumeric first byte - so no dotfiles and no
/// `-`-leading name that a tool could read as an option.  Applied to the
/// *decoded* value, which is what makes a percent-encoded `/` a rejection
/// rather than an extra directory level.
#[must_use]
pub(crate) fn valid_filename(name: &str) -> bool {
    name.len() >= 4
        && name.len() <= 255
        && name.bytes().enumerate().all(|(i, b)| {
            (i > 0 || b.is_ascii_alphanumeric())
                && b.is_ascii()
                && !b.is_ascii_control()
                && b != std::path::MAIN_SEPARATOR as u8
                && b != b'/'
        })
}

/// Dispatched both when the configuration setting `reject_pdiff_requests` is
/// on (to refuse with 410) and when it is off (to suppress the "Unrecognized
/// resource path" warning for a pdiff shape the parser does not cache, such
/// as a malformed patch name; strict names are cached as
/// [`ResourceFile::Pdiff`]).
///
/// Example request paths:
/// - `http://deb.debian.org/debian-debug/dists/sid-debug/main/binary-i386/Packages.diff/T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz`
/// - `http://deb.debian.org/debian/dists/unstable/main/i18n/Translation-en.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz`
/// - `http://deb.debian.org/debian/dists/unstable/main/i18n/Translation-de.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz`
/// - `http://deb.debian.org/debian/dists/sid/main/source/Sources.diff/T-2024-10-03-1409.04-F-2024-10-03-1409.04.gz`
#[must_use]
pub(crate) fn is_diff_request_path(uri_path: &str) -> bool {
    // Skip the first segment: a match requires the preceding slash. Looking
    // only at adjacent segments avoids rescanning the whole remaining path
    // for every malformed Translation prefix.
    let mut segments = uri_path.split('/').skip(1).peekable();
    while let Some(segment) = segments.next() {
        if segment.strip_suffix(".diff").is_some_and(|index| {
            matches!(index, "Packages" | "Sources") || is_pdiff_translation_base(index)
        }) && segments.peek().is_some_and(|next| next.starts_with("T-"))
        {
            return true;
        }
    }
    false
}

/// `Translation-<lang>`, the base of a Translation pdiff directory
/// (`Translation-<lang>.diff/`).  Language tags in Debian translations are
/// of the form `en`, `de`, `zh_CN`, `pt_BR` - alphanumeric with optional
/// underscore - so no `%` (and no percent-decoding surprise) can appear.
#[must_use]
fn is_pdiff_translation_base(base: &str) -> bool {
    base.strip_prefix("Translation-").is_some_and(|lang| {
        !lang.is_empty() && lang.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    })
}

/// The byte length of a pdiff patch timestamp.
const PDIFF_TIMESTAMP_LEN: usize = "YYYY-MM-DD-HHMM.SS".len();
/// The byte length of every pdiff patch name, `T-<ts>-F-<ts>.gz`.
pub(crate) const PDIFF_PATCH_NAME_LEN: usize = "T--F-.gz".len() + 2 * PDIFF_TIMESTAMP_LEN;

/// Whether `name` is a merged pdiff patch as dak publishes it:
/// `T-<ts>-F-<ts>.gz`, each timestamp exactly `YYYY-MM-DD-HHMM.SS`.  Strict
/// on purpose: the name becomes part of a cache name, and holds no `%` or
/// `_`, so decoding cannot change it and it cannot split a joined name.
#[must_use]
pub(crate) fn is_pdiff_patch_name(name: &str) -> bool {
    name.strip_prefix("T-")
        .and_then(|rest| rest.strip_suffix(".gz"))
        .and_then(|stamps| stamps.split_once("-F-"))
        .is_some_and(|(to, from)| is_pdiff_timestamp(to) && is_pdiff_timestamp(from))
}

/// `YYYY-MM-DD-HHMM.SS`, the timestamp in a pdiff patch name.
#[must_use]
fn is_pdiff_timestamp(stamp: &str) -> bool {
    stamp.len() == PDIFF_TIMESTAMP_LEN
        && stamp.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 | 10 => b == b'-',
            15 => b == b'.',
            _ => b.is_ascii_digit(),
        })
}

/// Check whether a raw URI path is safe to forward upstream
/// (percent-decoding is applied internally before inspection).
///
/// Rejects traversal segments (`..`, `.`) and control characters (including null bytes).
#[must_use]
pub(crate) fn is_unsafe_proxy_path(raw_path: &str) -> bool {
    let decoded = match percent_encoding::percent_decode_str(raw_path).decode_utf8() {
        Ok(d) => d,
        Err(_err @ std::str::Utf8Error { .. }) => return true,
    };

    decoded.split('/').any(is_unsafe_segment)
}

/// The cache-route sibling of [`is_unsafe_proxy_path`], for a request the
/// classifier accepted: `normalized_path` is the [`normalize_uri_path`] form,
/// so the `//` runs and `.` segments APT itself emits are already gone, and
/// any empty, `.` or `..` segment left after percent-decoding - or a control
/// byte - is refused.  A cached request is forwarded upstream as sent while
/// its cache name comes from the validated fields alone, so a traversal the
/// validators missed would store one resource under another's name.
#[must_use]
pub(crate) fn is_unsafe_cache_path(normalized_path: &str) -> bool {
    let decoded = match percent_encoding::percent_decode_str(normalized_path).decode_utf8() {
        Ok(d) => d,
        Err(_err @ std::str::Utf8Error { .. }) => return true,
    };

    decoded
        .strip_prefix('/')
        .unwrap_or(&decoded)
        .split('/')
        .any(|seg| seg.is_empty() || is_unsafe_segment(seg))
}

/// A decoded path segment that is a dot segment or carries a control byte.
#[must_use]
fn is_unsafe_segment(seg: &str) -> bool {
    // Byte scan: UTF-8 never reuses an ASCII byte inside a multi-byte
    // sequence, so this matches exactly the ASCII control characters.
    seg == "." || seg == ".." || seg.bytes().any(|b| b.is_ascii_control())
}

/// Whether `s` is a hex string of one of the supported digest lengths.  The
/// cross-check against the algorithm directory is [`byhash_pair`].
#[must_use]
fn is_byhash_digest_shape(s: &str) -> bool {
    HashAlgo::for_digest(s).is_some()
}

/// The algorithm of a supported by-hash pair, `None` for any other: `algo`
/// names a [`HashAlgo`] and `digest` is a hex string of that
/// algorithm's digest length.  What the parser hands on, so verification
/// hashes with the algorithm this check accepted rather than re-reading one
/// from the path.
#[must_use]
fn byhash_pair(algo: &str, digest: &str) -> Option<HashAlgo> {
    HashAlgo::parse(algo).filter(|algo| algo.matches_digest(digest))
}

/// The `Release` family: the archive-level index and its two signature
/// forms.  No compression variants exist for these.
#[must_use]
fn is_release_filename(name: &str) -> bool {
    matches!(name, "InRelease" | "Release" | "Release.gpg")
}

/// The `Packages` index in every compression this proxy recognises.
#[must_use]
fn is_packages_filename(name: &str) -> bool {
    // `limits::PackagesCompression` is the enum of the compressions the
    // decode ladder supports, i.e. exactly the `Packages*` leaves that exist.
    crate::limits::PackagesCompression::from_filename(name).is_some()
}

/// The `Sources` index in every compression this proxy recognises.
#[must_use]
fn is_sources_filename(name: &str) -> bool {
    matches!(name, "Sources" | "Sources.gz" | "Sources.xz")
}

/// Recognise any of: `Translation-LANG`, `Translation-LANG.bz2`,
/// `Translation-LANG.gz`, `Translation-LANG.xz`. The language code is
/// not validated beyond non-empty: Debian language codes carry tags like
/// `sr@Latn` that don't fit a simple alpha/underscore allowlist.
#[must_use]
fn is_translation_filename(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("Translation-") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    match rest.rsplit_once('.') {
        None => true,
        Some((lang, ext)) => !lang.is_empty() && matches!(ext, "gz" | "xz" | "bz2"),
    }
}

const VALID_DEB_EXTENSIONS: &[&str] = &["deb", "udeb", "ddeb"];

#[must_use]
pub(crate) fn is_deb_package(filename: &str) -> bool {
    let extension = filename.rsplit_once('.').map(|(_, ext)| ext);

    matches!(extension, Some(ext) if VALID_DEB_EXTENSIONS.contains(&ext))
}

/// Whether the filename matches the strict `<name>_<version>_<arch>.<ext>`
/// shape expected for binary packages served from a flat (trivial) repository.
///
/// This is intentionally stricter than [`is_deb_package`] so that an arbitrary
/// `.deb`-suffixed filename in an unrelated S3 path isn't auto-cached just
/// because the flat-repo fallback matched.
#[must_use]
pub(crate) fn is_flat_deb_filename(filename: &str) -> bool {
    let Some((stem, ext)) = filename.rsplit_once('.') else {
        return false;
    };
    if !VALID_DEB_EXTENSIONS.contains(&ext) {
        return false;
    }
    let mut parts = stem.split('_');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(name), Some(version), Some(arch), None)
            if !name.is_empty() && !version.is_empty() && !arch.is_empty()
    )
}

/// Maximum number of `/`-separated segments allowed in a mirror path.
///
/// Caps the on-disk directory depth a single request can carve out under
/// `{cache}/{host}/flat/<mirror_path>/`.  Real-world flat repositories
/// nest at most 2-3 levels (e.g. `apt/amd64/Packages.gz`); 16 is a
/// generous ceiling that still prevents pathological readdir/inode
/// pressure from an attacker-supplied URL with hundreds of segments.
const MAX_MIRROR_PATH_SEGMENTS: usize = 16;

/// Maximum byte length of a single `/`-separated path segment (mirror path
/// segment, distribution, component, architecture). Also reused by
/// `valid_mirrorname` as a cap on the total length of a mirror name, not
/// just one of its segments.
///
/// 128 bytes is generous for real-world Debian mirror names while providing a
/// meaningful bound against overlong inputs.
const MAX_SEGMENT_LEN: usize = 128;

/// Path-segment names reserved for the per-mirror on-disk cache layout.
///
/// A mirror path containing any of these as a `/`-separated segment would
/// collide with cache plumbing — `tmp/` is the partial-download scratch
/// dir, `by-hash/` is the content-addressed subtree under each mirror.
/// The host-level `flat/` anchor is *not* reserved here: a structured
/// request under `flat` is relayed uncached instead of refused
/// (`PassthroughReason::FlatAnchoredMirror`), and such a mirror row from
/// before that rule still disables flat caching for its host through the
/// per-host collision blocklist (`flat_blocklist`: "structured wins").
pub(crate) const RESERVED_MIRROR_PATH_SEGMENTS: &[&str] = &[SUBDIR_TMP, SUBDIR_FLAT_BYHASH];

/// Path-segment names reserved in a *structured* mirror path on top of
/// [`RESERVED_MIRROR_PATH_SEGMENTS`]: `dists/` holds each structured
/// mirror's index files, so a mirror `X/dists` would nest into `X`'s index
/// directory.  A flat tree lives under the host-level `flat/` anchor and
/// cannot reach it, and real flat repositories keep their pool below a
/// `dists/` directory (Docker CE's
/// `linux/debian/dists/<codename>/pool/stable/<arch>/`).
pub(crate) const RESERVED_STRUCTURED_MIRROR_PATH_SEGMENTS: &[&str] = &[SUBDIR_DISTS];

#[must_use]
fn is_reserved_mirror_path_segment(segment: &str, kind: MirrorKind) -> bool {
    RESERVED_MIRROR_PATH_SEGMENTS.contains(&segment)
        || match kind {
            MirrorKind::Structured => RESERVED_STRUCTURED_MIRROR_PATH_SEGMENTS.contains(&segment),
            MirrorKind::Flat => false,
        }
}

/// For the startup warning about pre-existing DB rows that the validator
/// would now reject on insertion.
#[must_use]
pub(crate) fn mirror_path_has_reserved_segment(path: &str, kind: MirrorKind) -> bool {
    path.split('/')
        .any(|segment| is_reserved_mirror_path_segment(segment, kind))
}

/// Whether `path` is a strict descendant of `ancestor` in `/`-separated
/// segment terms — i.e. `path == "<ancestor>/<rest>"` for non-empty
/// `<rest>`.  Returns `false` when `path == ancestor`.
///
/// Segment alignment matters: `apt-tools` is not a descendant of `apt`
/// even though it shares the prefix byte-wise.
#[must_use]
fn is_strict_path_descendant(path: &str, ancestor: &str) -> bool {
    path.len() > ancestor.len()
        && path.starts_with(ancestor)
        && path.as_bytes()[ancestor.len()] == b'/'
}

/// Whether `path` equals `prefix` or is a strict descendant of it,
/// segment-aligned.
#[must_use]
fn path_starts_with_segment(path: &str, prefix: &str) -> bool {
    path == prefix || is_strict_path_descendant(path, prefix)
}

/// Derive the paths of mirrors registered under the same `(host, port)` that
/// live *inside* `mirror_path` (segment-aligned), given the sorted list of
/// sibling paths on that host (which may include `mirror_path` itself; self
/// is filtered out by the segment-alignment check).
///
/// The empty-`mirror_path` case denotes a host-root mirror that nests every
/// other path on the host.
///
/// Sorted input lets the lookup skip directly to the prefix region via
/// `partition_point`.  Within that region, lexicographic order can still
/// interleave non-segment-aligned siblings (e.g. `debian-security` between
/// `debian` and `debian/...` since `-` < `/` in ASCII), so segment alignment
/// is enforced via `is_strict_path_descendant`; the surrounding `take_while`
/// only ends the scan, since entries sharing the byte prefix are contiguous.
#[must_use]
fn derive_nested_paths(mirror_path: &str, host_paths_sorted: &[&str]) -> Vec<String> {
    if mirror_path.is_empty() {
        return host_paths_sorted
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| (*p).to_owned())
            .collect();
    }
    let start = host_paths_sorted.partition_point(|p| *p <= mirror_path);
    host_paths_sorted[start..]
        .iter()
        .take_while(|p| p.starts_with(mirror_path))
        .filter(|p| is_strict_path_descendant(p, mirror_path))
        .map(|p| (*p).to_owned())
        .collect()
}

/// The [`derive_nested_paths`] of every row of `mirrors`, in row order: the
/// paths of the other rows nested inside it, which bound its walks.
///
/// Rows are canonical (alias-resolved at dispatch, legacy rows folded at
/// startup), so the row host *is* the `<cache>/<host>/` tree the per-host
/// bucket must follow.
///
/// The startup cache scan and cleanup both derive their boundaries here and
/// match directories against them with [`nested_mirror_relation`], so the
/// two agree on where one mirror's tree ends (or the quota reconcile reports
/// a spurious `Repaired cache size discrepancy`).
#[must_use]
pub(crate) fn nested_paths_per_row(mirrors: &[MirrorEntry]) -> Vec<Vec<String>> {
    let mut paths_by_host: HashMap<(&CacheHost, Option<NonZero<u16>>), Vec<&str>> = HashMap::new();
    for entry in mirrors {
        let site = entry.site();
        paths_by_host
            .entry((site.host, site.port))
            .or_default()
            .push(site.path);
    }
    for paths in paths_by_host.values_mut() {
        paths.sort_unstable();
    }
    mirrors
        .iter()
        .map(|entry| {
            let site = entry.site();
            let host_paths = paths_by_host
                .get(&(site.host, site.port))
                .map_or_default(Vec::as_slice);
            derive_nested_paths(site.path, host_paths)
        })
        .collect()
}

/// The mirror-path equivalent of the directory `rel` (relative to the mirror
/// directory of `mirror_path`), the `candidate` [`nested_mirror_relation`]
/// matches: `<mirror_path>/<rel>`, or `rel` alone for a host-root mirror.
#[must_use]
pub(crate) fn mirror_relative_path<'a>(mirror_path: &str, rel: &'a str) -> Cow<'a, str> {
    if mirror_path.is_empty() {
        Cow::Borrowed(rel)
    } else {
        Cow::Owned(format!("{mirror_path}/{rel}"))
    }
}

/// How a directory found inside a mirror's tree relates to the mirrors
/// registered *below* that mirror on the same host (its
/// [`nested_paths_per_row`] entry).  `candidate` is the directory's
/// mirror-path equivalent ([`mirror_relative_path`]); matching is
/// segment-aligned, so `apt-tools` never relates to `apt`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NestedMirrorRelation {
    /// `candidate` is a registered nested mirror's root or lies inside one
    /// (`apt/amd64` or `apt/amd64/foo` against the registered `apt/amd64`).
    /// The nested mirror owns everything there: walks stop and count / clean
    /// nothing below it.
    Boundary,
    /// A registered nested mirror lies strictly below `candidate`
    /// (`apt/amd64` against the registered `apt/amd64/special`).  The
    /// directory is a legitimate filesystem container, not a stray entry: a
    /// flat cleanup descends to reach the real boundary, the structured size
    /// scan skips it silently.
    Container,
    /// No registered nested mirror at, inside or below `candidate`.
    Unrelated,
}

#[must_use]
pub(crate) fn nested_mirror_relation(
    candidate: &str,
    nested_paths: &[String],
) -> NestedMirrorRelation {
    let mut container = false;
    for nested in nested_paths {
        if path_starts_with_segment(candidate, nested) {
            return NestedMirrorRelation::Boundary;
        }
        if is_strict_path_descendant(nested, candidate) {
            container = true;
        }
    }
    if container {
        NestedMirrorRelation::Container
    } else {
        NestedMirrorRelation::Unrelated
    }
}

/// For a flat-pool mirror path containing a `/pool/` segment, split it into the
/// structured archive root (everything before the first `/pool/`) and the
/// lookup prefix (the in-archive sub-path with a trailing `/`) to strip from
/// `dists/.../Packages` `Filename:` values during strict cleanup.
///
/// `api/packages/85/debian/pool/php-zts/main`
///   -> ("api/packages/85/debian", "pool/php-zts/main/")
///
/// Returns `None` when there is no `/pool/` segment or no archive root before
/// it, in which case strict reconciliation does not apply (issue #162 Phase 2).
#[must_use]
pub(crate) fn flat_pool_archive_root(mirror_path: &str) -> Option<(&str, String)> {
    let (archive_root, pool_tail) = mirror_path.split_once("/pool/")?;
    if archive_root.is_empty() {
        return None;
    }
    let pool_tail = pool_tail.trim_end_matches('/');
    let prefix = if pool_tail.is_empty() {
        "pool/".to_owned()
    } else {
        format!("pool/{pool_tail}/")
    };
    Some((archive_root, prefix))
}

/// Whether `name` is acceptable as a mirror path of `kind`: non-empty, at
/// most [`MAX_SEGMENT_LEN`] bytes overall, at most
/// [`MAX_MIRROR_PATH_SEGMENTS`] `/`-separated segments, every segment a
/// [`valid_path_segment`] and none of them reserved by that kind's cache
/// layout ([`is_reserved_mirror_path_segment`]).
#[must_use]
pub(crate) fn valid_mirrorname(name: &str, kind: MirrorKind) -> bool {
    if name.is_empty() || name.len() > MAX_SEGMENT_LEN {
        return false;
    }
    let mut segment_count: usize = 0;
    for segment in name.split('/') {
        segment_count += 1;
        if segment_count > MAX_MIRROR_PATH_SEGMENTS {
            return false;
        }
        if !valid_path_segment(segment) {
            return false;
        }
        if is_reserved_mirror_path_segment(segment, kind) {
            return false;
        }
    }
    true
}

/// Whether `name` is acceptable as one `/`-separated URL path segment:
/// 1..=[`MAX_SEGMENT_LEN`] bytes of ASCII alphanumerics, plus `-`, `.` and
/// `_` anywhere but the first byte.  The alphanumeric-first rule is what
/// keeps `.` and `..` out of every field validated through here.
#[must_use]
pub(crate) fn valid_path_segment(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SEGMENT_LEN
        && name.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphanumeric() || (i > 0 && (b == b'-' || b == b'.' || b == b'_'))
        })
}

/// Whether `name` is acceptable as one intermediate directory of a cached
/// URL that is no part of its cache name - a pool
/// `[updates/]<component>/<prefix>/<package>` segment, or a directory of a
/// `by-hash` object's `dists/` run: a [`valid_path_segment`] that may also
/// carry `+` past its first byte, which Debian source package names (the
/// pool `<package>` directory, e.g. `gtk+3.0`) allow.
#[must_use]
pub(crate) fn valid_directory(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SEGMENT_LEN
        && name.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphanumeric() || (i > 0 && matches!(b, b'-' | b'.' | b'_' | b'+'))
        })
}

#[cfg(test)]
mod tests {
    use crate::{nonzero, test_support::local_client};

    use super::*;

    /// The scope has to survive the parse for `classify_request` to mint an
    /// `Origin` from it: exactly `<dist>/<comp>/<arch>` before `by-hash`,
    /// nothing else.
    #[test]
    fn byhash_carries_the_origin_scope_at_exactly_three_segments() {
        const SHA256: &str = "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";
        const PATH: &str = "debian/dists/sid/main/binary-amd64/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";

        let scoped = parse_request_path(PATH).expect("architecture-scoped by-hash parses");
        assert_eq!(
            scoped,
            ResourceFile::ByHash {
                mirror_path: "debian",
                dirs: "sid/main/binary-amd64",
                algorithm: HashAlgo::Sha256,
                filename: SHA256,
                scope: Some(DistsScope {
                    distribution: "sid",
                    component: "main",
                    architecture: "binary-amd64"
                })
            }
        );

        // Parser and `Origin::from_path` must not drift apart on the same
        // URL.
        let origin = Origin::from_path(
            PATH,
            ClientHost::new("deb.debian.org").unwrap(),
            None,
            &local_client(),
        )
        .expect("the same URL mints an Origin");
        assert_eq!(origin.fields.distribution, "sid");
        assert_eq!(origin.fields.component, "main");
        assert_eq!(origin.fields.architecture, "binary-amd64");
    }

    /// A relayed answer must not mint the structured mirror row the cache
    /// refuses: under `flat` it would disable flat caching for the host.
    #[test]
    fn a_structured_mirror_path_under_flat_mints_no_origin() {
        for path in [
            "/flat/dists/sid/main/binary-amd64/Packages",
            "/flat/x/dists/sid/main/binary-amd64/Packages",
        ] {
            assert!(
                Origin::from_path(
                    path,
                    ClientHost::new("deb.debian.org").unwrap(),
                    None,
                    &local_client(),
                )
                .is_none(),
                "{path}"
            );
        }
    }

    #[test]
    fn origin_from_path_names_the_mirror_and_its_packages_uri() {
        const PACKAGES: &str = "/debian/dists/sid/main/binary-amd64/Packages";
        for (path, host, port, mirror_path, distribution, uri) in [
            (
                PACKAGES,
                "deb.debian.org",
                None,
                "debian",
                "sid",
                "http://deb.debian.org/debian/dists/sid/main/binary-amd64/Packages",
            ),
            (
                "/private/debian/dists/sid/main/binary-amd64/by-hash/SHA256/\
                 84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83",
                "site.example.com",
                Some(nonzero!(80)),
                "private/debian",
                "sid",
                "http://site.example.com:80/private/debian/dists/sid/main/binary-amd64/Packages",
            ),
            (
                "/unstable/dists/llvm-toolchain-19/main/binary-amd64/Packages.gz",
                "apt.llvm.org",
                Some(nonzero!(443)),
                "unstable",
                "llvm-toolchain-19",
                "http://apt.llvm.org:443/unstable/dists/llvm-toolchain-19/main/binary-amd64/Packages",
            ),
            (
                PACKAGES,
                "2001:db8::1",
                None,
                "debian",
                "sid",
                "http://[2001:db8::1]/debian/dists/sid/main/binary-amd64/Packages",
            ),
            (
                PACKAGES,
                "::1",
                Some(nonzero!(8080)),
                "debian",
                "sid",
                "http://[::1]:8080/debian/dists/sid/main/binary-amd64/Packages",
            ),
        ] {
            let host = || ClientHost::new(host).unwrap();
            let origin = Origin::from_path(path, host(), port, &local_client()).expect(path);
            assert_eq!(
                origin,
                Origin {
                    mirror: Mirror::new(host(), port, mirror_path.into(), MirrorKind::Structured),
                    fields: OriginFields {
                        distribution: distribution.to_owned(),
                        component: "main".to_owned(),
                        architecture: "binary-amd64".to_owned(),
                    },
                },
                "{path}"
            );
            assert_eq!(origin.uri(), uri);
        }
    }

    #[test]
    fn test_parse_request_path() {
        /*
         * success
         */

        assert_eq!(
            parse_request_path("debian/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                dirs: "main/f/firefox-esr",
                filename: "firefox-esr_115.9.1esr-1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "private/ubuntu/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"
            ),
            Some(ResourceFile::Pool {
                mirror_path: "private/ubuntu",
                dirs: "main/f/firefox-esr",
                filename: "firefox-esr_115.9.1esr-1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path("debian/pool/main/libs/libssh/libssh-doc_0.10.6-2_all.deb"),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                dirs: "main/libs/libssh",
                filename: "libssh-doc_0.10.6-2_all.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/pool/main/libt/libtirpc/libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
            ),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                dirs: "main/libt/libtirpc",
                filename: "libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path("debian/pool/main/m/mesa/libgl1-mesa-dri_24.0.5-1_amd64.deb"),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                dirs: "main/m/mesa",
                filename: "libgl1-mesa-dri_24.0.5-1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path("public/debian/dists/sid/InRelease"),
            Some(ResourceFile::Release {
                mirror_path: "public/debian",
                distribution: "sid",
                filename: "InRelease"
            })
        );

        assert_eq!(
            parse_request_path("very///private/debian/dists/trixie/Release"),
            Some(ResourceFile::Release {
                mirror_path: "very///private/debian",
                distribution: "trixie",
                filename: "Release"
            })
        );

        // `Release.gpg` is the detached signature for `Release`; APT fetches
        // it when `InRelease` is absent or unusable.
        assert_eq!(
            parse_request_path("debian/dists/sid/Release.gpg"),
            Some(ResourceFile::Release {
                mirror_path: "debian",
                distribution: "sid",
                filename: "Release.gpg"
            })
        );

        // Per-component per-architecture Release files (sibling to Packages*).
        assert_eq!(
            parse_request_path("debian/dists/trixie/main/binary-amd64/Release"),
            Some(ResourceFile::ComponentRelease {
                mirror_path: "debian",
                distribution: "trixie",
                component: "main",
                architecture: "binary-amd64",
                filename: "Release"
            })
        );

        assert_eq!(
            parse_request_path("debian/dists/trixie/main/source/Release"),
            Some(ResourceFile::ComponentRelease {
                mirror_path: "debian",
                distribution: "trixie",
                component: "main",
                architecture: "source",
                filename: "Release"
            })
        );

        assert_eq!(
            parse_request_path("debian/dists/bookworm/contrib/binary-arm64/Release"),
            Some(ResourceFile::ComponentRelease {
                mirror_path: "debian",
                distribution: "bookworm",
                component: "contrib",
                architecture: "binary-arm64",
                filename: "Release"
            })
        );

        assert_eq!(
            parse_request_path("debs/dists/vscodium/main/binary-amd64/Packages.gz"),
            Some(ResourceFile::Packages {
                mirror_path: "debs",
                distribution: "vscodium",
                component: "main",
                architecture: "binary-amd64",
                filename: "Packages.gz"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian-security/dists/bookworm-security/main/binary-amd64/Packages.xz"
            ),
            Some(ResourceFile::Packages {
                mirror_path: "debian-security",
                distribution: "bookworm-security",
                component: "main",
                architecture: "binary-amd64",
                filename: "Packages.xz"
            })
        );

        assert_eq!(
            parse_request_path(
                "/pool/dists/unstable/dists/llvm-toolchain/main/binary-amd64/Packages.gz"
            ),
            Some(ResourceFile::Packages {
                mirror_path: "pool/dists/unstable",
                distribution: "llvm-toolchain",
                component: "main",
                architecture: "binary-amd64",
                filename: "Packages.gz"
            })
        );

        assert_eq!(
            parse_request_path(
                "/pool/dists/debian-security/pool/updates/main/c/chromium/chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
            ),
            Some(ResourceFile::Pool {
                mirror_path: "pool/dists/debian-security",
                dirs: "updates/main/c/chromium",
                filename: "chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/binary-amd64/Packages.diff/by-hash/SHA256/491ddac17f4b86d771a457e6b084c499dfeb9ee29004b92d5d05fe79f1f0dede"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                dirs: "sid/main/binary-amd64/Packages.diff",
                algorithm: HashAlgo::Sha256,
                filename: "491ddac17f4b86d771a457e6b084c499dfeb9ee29004b92d5d05fe79f1f0dede",
                // Four segments before `by-hash`: not the origin shape.
                scope: None
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/dep11/by-hash/SHA256/cf31e359ca5863e438c1b2d3ddaa1d473519ad26bd71e3dac7803dade82e4482"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                dirs: "sid/main/dep11",
                algorithm: HashAlgo::Sha256,
                filename: "cf31e359ca5863e438c1b2d3ddaa1d473519ad26bd71e3dac7803dade82e4482",
                // A pseudo-arch still yields a scope; the "no origin"
                // rule is `is_binary_arch`, applied by `classify_request`.
                scope: Some(DistsScope {
                    distribution: "sid",
                    component: "main",
                    architecture: "dep11"
                })
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                dirs: "trixie/main",
                algorithm: HashAlgo::Sha256,
                filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
                // Component-scoped (the `Release` sibling): no architecture,
                // so no origin.
                scope: None
            })
        );

        assert_eq!(
            parse_request_path("debian/dists/sid/main/dep11/icons-128x128.tar.gz"),
            Some(ResourceFile::Icon {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "icons-128x128.tar.gz"
            })
        );

        assert_eq!(
            parse_request_path("debian/dists/sid/main/source/Sources.gz"),
            Some(ResourceFile::Sources {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "Sources.gz"
            })
        );

        assert_eq!(
            parse_request_path("debian/dists/unstable/main/i18n/Translation-en.bz2"),
            Some(ResourceFile::Translation {
                mirror_path: "debian",
                distribution: "unstable",
                component: "main",
                filename: "Translation-en.bz2"
            })
        );

        /*
         * Flat (trivial) repository format
         */

        assert_eq!(
            parse_request_path("apt/InRelease"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "apt",
                filename: "InRelease"
            })
        );

        assert_eq!(
            parse_request_path("apt/Release.gpg"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "apt",
                filename: "Release.gpg"
            })
        );

        assert_eq!(
            parse_request_path("foo/bar/baz/Packages.gz"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "foo/bar/baz",
                filename: "Packages.gz"
            })
        );

        assert_eq!(
            parse_request_path("apt/Sources.xz"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "apt",
                filename: "Sources.xz"
            })
        );

        assert_eq!(
            parse_request_path("apt/twilio-cli_5.0.0_amd64.deb"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Pool,
                mirror_path: "apt",
                filename: "twilio-cli_5.0.0_amd64.deb"
            })
        );

        // Flat package nested below the base directory (Packages may list
        // entries with relative subpaths).
        assert_eq!(
            parse_request_path("apt/sub/twilio-cli_5.0.0_amd64.deb"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Pool,
                mirror_path: "apt/sub",
                filename: "twilio-cli_5.0.0_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "apt/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            Some(ResourceFile::Flat {
                kind: FlatKind::ByHash(HashAlgo::Sha256),
                mirror_path: "apt",
                filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            })
        );

        // With a leading slash.
        assert_eq!(
            parse_request_path("/apt/InRelease"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "apt",
                filename: "InRelease"
            })
        );

        // Paths with neither `/pool/` nor `/dists/` that nonetheless carry a
        // valid flat-shaped filename are accepted as flat — even if the path
        // segments look like a typo'd structured layout.  No collision with
        // structured caches because flat resources live under a `flat/` subdir.
        assert_eq!(
            parse_request_path("debian/loop/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Pool,
                mirror_path: "debian/loop/main/f/firefox-esr",
                filename: "firefox-esr_115.9.1esr-1_amd64.deb"
            })
        );

        /*
         * failures
         */

        // A wrong-letter pool is not rejected: it caches as flat (issue
        // #162 uniform fall-through). APT never emits wrong-letter URLs, so
        // this only widens what gets cached.
        assert_eq!(
            parse_request_path("debian/pool/main/g/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Pool,
                mirror_path: "debian/pool/main/g/firefox-esr",
                filename: "firefox-esr_115.9.1esr-1_amd64.deb",
            })
        );

        assert_eq!(parse_request_path("debian/dists/sid/Foo"), None);

        assert_eq!(parse_request_path("debian/dists/a/b/InRelease"), None);

        // Per-component Release: `InRelease` has no per-component form.
        assert_eq!(
            parse_request_path("debian/dists/trixie/main/binary-amd64/InRelease"),
            None
        );

        // Per-component Release: `Release.gpg` has no per-component form.
        assert_eq!(
            parse_request_path("debian/dists/trixie/main/binary-amd64/Release.gpg"),
            None
        );

        // Per-component Release: scope must be `binary-*` or `source`.
        assert_eq!(
            parse_request_path("debian/dists/trixie/main/dep11/Release"),
            None
        );
        assert_eq!(
            parse_request_path("debian/dists/trixie/main/i18n/Release"),
            None
        );

        // Per-component Release: `binary-` with empty architecture is rejected.
        assert_eq!(
            parse_request_path("debian/dists/trixie/main/binary-/Release"),
            None
        );

        // Per-component Release: rejected if deeper than the canonical depth.
        assert_eq!(
            parse_request_path("debian/dists/trixie/main/binary-amd64/extra/Release"),
            None
        );

        assert_eq!(
            parse_request_path("debian/dists/trixie/main/by-hash/SHA256/Packages"),
            None
        );

        assert_eq!(
            parse_request_path("debian/dists/trixie/main/by-hash/SHA256/cf31e359ca5"),
            None
        );

        // Empty mirror path before the flat resource.
        assert_eq!(parse_request_path("InRelease"), None);
        assert_eq!(parse_request_path("/InRelease"), None);

        // Flat .deb shape with an extra underscore (four components).
        assert_eq!(parse_request_path("apt/foo_1.0_amd64_extra.deb"), None);

        // Flat .deb missing one component.
        assert_eq!(parse_request_path("apt/foo_1.0.deb"), None);

        // Flat .deb with an empty component.
        assert_eq!(parse_request_path("apt/_3.5_amd64.deb"), None);
        assert_eq!(parse_request_path("apt/foo__amd64.deb"), None);

        // Single-component filename without underscores.
        assert_eq!(parse_request_path("apt/foo.deb"), None);

        // Flat by-hash with non-`SHA` algorithm segment.
        assert_eq!(
            parse_request_path(
                "apt/by-hash/MD5/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            None
        );

        // Flat by-hash with hex tail shorter than 64 chars (excludes weak hashes).
        assert_eq!(
            parse_request_path("apt/by-hash/SHA1/cf31e359ca586340c1b2d3ddaa1d473519ad26bd"),
            None
        );

        // by-hash with algorithm/length mismatch — SHA256 paired with a 128-hex
        // digest, or SHA512 with a 64-hex digest — rejected.  Prevents an
        // upstream from pairing an algo directory with a digest of the wrong
        // size.
        assert_eq!(
            parse_request_path(
                "debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            None
        );
        assert_eq!(
            parse_request_path(
                "apt/by-hash/SHA512/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            None
        );

        // by-hash with an unsupported algorithm name (SHA384, lowercase variants,
        // future algorithms).  Only the spec-named `SHA256` / `SHA512` are
        // accepted.
        assert_eq!(
            parse_request_path(
                "apt/by-hash/SHA384/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba4f8878062744fae5ff91f1ad0f3efecc"
            ),
            None
        );
        assert_eq!(
            parse_request_path(
                "apt/by-hash/sha256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            None
        );

        // SHA512 (128-char hex) paired with the `SHA512` algorithm directory:
        // accepted.
        assert_eq!(
            parse_request_path(
                "apt/by-hash/SHA512/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            Some(ResourceFile::Flat {
                kind: FlatKind::ByHash(HashAlgo::Sha512),
                mirror_path: "apt",
                filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            })
        );
        assert_eq!(
            parse_request_path(
                "debian/dists/trixie/main/by-hash/SHA512/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                dirs: "trixie/main",
                algorithm: HashAlgo::Sha512,
                filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba",
                scope: None
            })
        );

        // Hex tail at an unrecognized location must not be reclassified as Pool.
        assert_eq!(
            parse_request_path(
                "apt/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            None
        );

        // Arbitrary non-apt filename in an otherwise flat-shaped path.
        assert_eq!(parse_request_path("apt/random.txt"), None);
    }

    #[test]
    fn test_parse_request_path_pool_flat_fallback() {
        // issue #162: Gitea/Forgejo serve pool debs at the spec-conformant but
        // non-canonical `pool/<dist>/<comp>/<file>`. They must fall through to the
        // flat handler, keyed by the URL directory verbatim.
        assert_eq!(
            parse_request_path(
                "api/packages/85/debian/pool/php-zts/main/php-zts-cli_8.5.7-1_amd64.deb"
            ),
            Some(ResourceFile::Flat {
                kind: FlatKind::Pool,
                mirror_path: "api/packages/85/debian/pool/php-zts/main",
                filename: "php-zts-cli_8.5.7-1_amd64.deb",
            })
        );

        // Non-canonical pool with a non-deb tail is still rejected at the filename
        // gate (strictness preserved).
        assert_eq!(
            parse_request_path("api/packages/85/debian/pool/php-zts/main/README"),
            None
        );

        // A non-canonical /pool/ path whose tail is a metadata filename caches as
        // flat metadata: the uniform fall-through routes the whole URL to the flat
        // handler, which also accepts the metadata allowlist. Intentional and
        // harmless (volatile, keyed by the URL path verbatim).
        assert_eq!(
            parse_request_path("api/packages/85/debian/pool/php-zts/main/Packages.gz"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "api/packages/85/debian/pool/php-zts/main",
                filename: "Packages.gz",
            })
        );
    }

    #[test]
    fn test_invalid_filename() {
        /* valid */
        assert!(valid_filename("firefox-esr_115.9.1esr-1_amd64.deb"));

        /* invalid */
        assert!(!valid_filename(""));
        assert!(!valid_filename("."));
        assert!(!valid_filename(".."));
        assert!(!valid_filename("-foo"));
        assert!(!valid_filename(".foo"));
        assert!(!valid_filename("_foo"));
        assert!(!valid_filename("foo\nbar"));
        assert!(!valid_filename("foo/bar"));
        assert!(!valid_filename("foo/./bar"));
        assert!(!valid_filename("foo/../bar"));
        assert!(!valid_filename("foo//bar"));
        assert!(!valid_filename("/"));
        assert!(!valid_filename("/debian"));
        assert!(!valid_filename("~/foo"));
        assert!(!valid_filename("~foo"));
    }

    #[test]
    fn test_invalid_mirrorname() {
        use MirrorKind::{Flat, Structured};
        for (name, kind, valid) in [
            ("debian", Structured, true),
            ("public/ubuntu", Structured, true),
            ("public/private/kali", Structured, true),
            ("foo/bar", Structured, true),
            ("", Structured, false),
            (".", Structured, false),
            ("..", Structured, false),
            ("-foo", Structured, false),
            (".foo", Structured, false),
            ("_foo", Structured, false),
            ("foo\nbar", Structured, false),
            ("foo/./bar", Structured, false),
            ("foo/../bar", Structured, false),
            ("foo//bar", Structured, false),
            ("/", Structured, false),
            ("/debian", Structured, false),
            ("~/foo", Structured, false),
            ("~foo", Structured, false),
            ("public%2Fubuntu", Structured, false),
            // Reserved segments collide with cache-layout plumbing.
            ("tmp", Structured, false),
            ("by-hash", Structured, false),
            ("foo/tmp", Structured, false),
            ("foo/by-hash/bar", Structured, false),
            // `dists` would nest a mirror into its parent's `dists/` tree,
            ("dists", Structured, false),
            ("debian/dists", Structured, false),
            ("debian/dists/x", Structured, false),
            // while a flat tree, anchored under `flat/`, may pass through one.
            ("linux/debian/dists/bookworm/pool/stable/amd64", Flat, true),
            ("foo/tmp", Flat, false),
            ("foo/by-hash/bar", Flat, false),
            // Non-segment occurrences are fine.
            ("tmpfile", Structured, true),
            ("by-hash-deb", Structured, true),
            ("dists-archive", Structured, true),
        ] {
            assert_eq!(valid_mirrorname(name, kind), valid, "{name:?} as {kind:?}");
        }

        // The caps: the whole name's length and its segment count.
        let segments = |count| vec!["x"; count].join("/");
        for (name, valid) in [
            ("x".repeat(MAX_SEGMENT_LEN), true),
            ("x".repeat(MAX_SEGMENT_LEN + 1), false),
            (segments(MAX_MIRROR_PATH_SEGMENTS), true),
            (segments(MAX_MIRROR_PATH_SEGMENTS + 1), false),
        ] {
            assert_eq!(valid_mirrorname(&name, Structured), valid, "{name}");
        }
    }

    #[test]
    fn test_mirror_path_has_reserved_segment() {
        use MirrorKind::{Flat, Structured};
        for (path, kind, reserved) in [
            ("tmp", Structured, true),
            ("by-hash", Structured, true),
            ("foo/tmp", Structured, true),
            ("foo/by-hash/bar", Structured, true),
            ("foo/dists", Structured, true),
            ("debian", Structured, false),
            ("tmpfile", Structured, false),
            ("foo/by-hash-deb", Structured, false),
            ("foo/dists", Flat, false),
            ("foo/tmp", Flat, true),
        ] {
            assert_eq!(
                mirror_path_has_reserved_segment(path, kind),
                reserved,
                "{path} as {kind:?}"
            );
        }
    }

    #[test]
    fn test_invalid_path_segment() {
        for segment in [
            "sid",
            "lunar-updates",
            "main",
            "non-free",
            "mysql-8.0",
            "foo_bar",
            "binary-amd64",
        ] {
            assert!(valid_path_segment(segment), "{segment:?}");
        }
        for segment in [
            "",
            ".",
            "..",
            "-foo",
            ".foo",
            "_foo",
            "foo\nbar",
            "foo/bar",
            "foo/./bar",
            "foo/../bar",
            "foo//bar",
            "/",
            "/debian",
            "~/foo",
            "~foo",
        ] {
            assert!(!valid_path_segment(segment), "{segment:?}");
        }
    }

    #[test]
    fn test_normalize_uri_path() {
        use std::borrow::Cow;

        // Fast path: no `//` → borrowed, no allocation.
        let p = "/debian/dists/sid/InRelease";
        let out = normalize_uri_path(p);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, "/debian/dists/sid/InRelease");

        assert!(matches!(normalize_uri_path(""), Cow::Borrowed(_)));
        assert!(matches!(normalize_uri_path("/"), Cow::Borrowed(_)));

        // Slow path: collapse internal `//`.
        let out = normalize_uri_path("/debian//dists/trixie/Release");
        assert!(matches!(out, Cow::Owned(_)));
        assert_eq!(out, "/debian/dists/trixie/Release");

        // Triple and longer slash runs collapse to one.
        assert_eq!(
            normalize_uri_path("/debian///dists/trixie/Release"),
            "/debian/dists/trixie/Release"
        );
        assert_eq!(
            normalize_uri_path("/debian/////dists/trixie/Release"),
            "/debian/dists/trixie/Release"
        );

        // Multiple separate `//` clusters each collapse independently.
        assert_eq!(
            normalize_uri_path("/foo//bar///baz//qux"),
            "/foo/bar/baz/qux"
        );

        // Trailing and leading runs.
        assert_eq!(normalize_uri_path("//"), "/");
        assert_eq!(normalize_uri_path("///"), "/");
        assert_eq!(normalize_uri_path("/foo//"), "/foo/");
        assert_eq!(normalize_uri_path("//foo"), "/foo");

        // Idempotent.
        let once = normalize_uri_path("/debian//dists/trixie/Release");
        let twice = normalize_uri_path(&once);
        assert_eq!(once, twice);

        // Non-ASCII codepoints in the slow path survive verbatim.  In
        // practice hyper rejects raw non-ASCII bytes in request paths, but
        // the helper must not corrupt UTF-8 if it ever sees them.
        assert_eq!(
            normalize_uri_path("/foo//\u{00e9}/bar"),
            "/foo/\u{00e9}/bar"
        );
        assert_eq!(
            normalize_uri_path("/foo//\u{1f600}//bar").as_bytes(),
            "/foo/\u{1f600}/bar".as_bytes()
        );

        // End-to-end: helper + parser handles the original bug-report URL.
        let normalized = normalize_uri_path("/debian//dists/trixie/main/binary-amd64/Release");
        assert_eq!(
            parse_request_path(&normalized),
            Some(ResourceFile::ComponentRelease {
                mirror_path: "debian",
                distribution: "trixie",
                component: "main",
                architecture: "binary-amd64",
                filename: "Release"
            })
        );

        // End-to-end: helper + parser handles `//` in the pool path.
        let normalized = normalize_uri_path(
            "/debian//pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb",
        );
        assert_eq!(
            parse_request_path(&normalized),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                dirs: "main/f/firefox-esr",
                filename: "firefox-esr_115.9.1esr-1_amd64.deb"
            })
        );

        // End-to-end: helper + parser handles `///` in the mirror path.
        let normalized = normalize_uri_path("/debian///dists/trixie/InRelease");
        assert_eq!(
            parse_request_path(&normalized),
            Some(ResourceFile::Release {
                mirror_path: "debian",
                distribution: "trixie",
                filename: "InRelease"
            })
        );
    }

    #[test]
    fn test_normalize_uri_path_dot_segments() {
        use std::borrow::Cow;

        // Fast path: no bare `.` segment → borrowed.
        let p = "/foo/bar";
        assert!(matches!(normalize_uri_path(p), Cow::Borrowed(_)));

        // Slow path: standalone `.` segment is removed (RFC 3986 §5.2.4).
        let out = normalize_uri_path("/foo/./bar");
        assert!(matches!(out, Cow::Owned(_)));
        assert_eq!(out, "/foo/bar");

        // Leading, trailing, repeated, and root-only dot segments.
        assert_eq!(normalize_uri_path("/./foo"), "/foo");
        assert_eq!(normalize_uri_path("/foo/./"), "/foo/");
        assert_eq!(normalize_uri_path("/./"), "/");
        assert_eq!(normalize_uri_path("/."), "/");
        assert_eq!(normalize_uri_path("/foo/./bar/./baz"), "/foo/bar/baz");

        // Mixed `//` and `/./` collapse together.
        assert_eq!(normalize_uri_path("/foo//./bar"), "/foo/bar");
        assert_eq!(normalize_uri_path("/foo/.//bar"), "/foo/bar");

        // Idempotent.
        let once = normalize_uri_path("/foo/./bar");
        let twice = normalize_uri_path(&once);
        assert_eq!(once, twice);

        // Negative: a `.` *inside* a longer segment is part of a legitimate
        // name (`.well-known`, `apt.llvm.org`, `Packages.gz`, dotfiles) and
        // must not be touched.
        assert!(matches!(
            normalize_uri_path("/.well-known/foo"),
            Cow::Borrowed(_)
        ));
        assert_eq!(normalize_uri_path("/foo/.bar"), "/foo/.bar");
        assert_eq!(normalize_uri_path("/foo/bar."), "/foo/bar.");
        assert_eq!(normalize_uri_path("/foo/..bar"), "/foo/..bar");
        assert_eq!(
            normalize_uri_path("/dists/sid/main/binary-amd64/Packages.gz"),
            "/dists/sid/main/binary-amd64/Packages.gz"
        );

        // Negative: `..` is a real traversal and must be preserved so that
        // `is_unsafe_proxy_path` can still reject it downstream.
        assert!(matches!(
            normalize_uri_path("/foo/../bar"),
            Cow::Borrowed(_)
        ));
        assert_eq!(normalize_uri_path("/foo/../bar"), "/foo/../bar");

        // Negative: percent-encoded `%2E` is opaque at this layer — we only
        // collapse literal `.` segments. Decoding happens later.
        assert!(matches!(
            normalize_uri_path("/foo/%2E/bar"),
            Cow::Borrowed(_)
        ));

        // End-to-end: NVIDIA-style flat-repo URL with apt's `./` artifact
        // parses + classifies successfully after normalisation.
        let normalized = normalize_uri_path("/compute/cuda/repos/debian13/x86_64/./InRelease");
        assert_eq!(
            parse_request_path(&normalized),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "compute/cuda/repos/debian13/x86_64",
                filename: "InRelease",
            })
        );
    }

    #[test]
    fn test_origin_from_path_double_slash() {
        let host = || ClientHost::new("deb.debian.org").unwrap();

        // `//` in the mirror path resolves to the same Origin as the
        // un-doubled form thanks to internal normalisation.
        let raw = Origin::from_path(
            "/debian/dists/sid/main/binary-amd64/Packages",
            host(),
            None,
            &local_client(),
        )
        .expect("baseline parse");
        let doubled = Origin::from_path(
            "/debian//dists/sid/main/binary-amd64/Packages",
            host(),
            None,
            &local_client(),
        )
        .expect("`//` in mirror path should still parse after normalisation");
        assert_eq!(raw.fields, doubled.fields);

        // Triple slash is collapsed too.
        let tripled = Origin::from_path(
            "/debian///dists/sid/main/binary-amd64/Packages",
            host(),
            None,
            &local_client(),
        )
        .expect("`///` in mirror path should still parse after normalisation");
        assert_eq!(raw.fields, tripled.fields);
    }

    /// The pseudo-architectures mint no `origins` row: cleanup would treat
    /// one as a per-architecture index and fetch a `Packages` file that does
    /// not exist. Only the `by-hash` shape can carry one this far, since
    /// `dep11`/`i18n`/`source` have no `Packages*` file of their own -- so
    /// that is the shape to pin.
    #[test]
    fn pseudo_architectures_mint_no_origin() {
        const DIGEST: &str = "84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83";
        let host = || ClientHost::new("deb.debian.org").unwrap();
        for arch in ["dep11", "i18n", "source"] {
            let path = format!("/debian/dists/sid/main/{arch}/by-hash/SHA256/{DIGEST}");
            assert_eq!(
                Origin::from_path(&path, host(), None, &local_client()),
                None,
                "{arch} is a pseudo-architecture"
            );
        }
        let real = format!("/debian/dists/sid/main/binary-amd64/by-hash/SHA256/{DIGEST}");
        assert!(
            Origin::from_path(&real, host(), None, &local_client()).is_some(),
            "a real architecture still parses"
        );
    }

    /// Depth alone does not make a segment an architecture.  Ubuntu's
    /// `dists/<dist>/<comp>/cnf/by-hash/...` sits at `binary-<arch>` depth; a
    /// row minted from it makes cleanup fetch a `cnf/Packages` whose 404
    /// bails the mirror's sweep.
    #[test]
    fn non_binary_directories_mint_no_origin() {
        const DIGEST: &str = "84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83";
        let host = || ClientHost::new("archive.ubuntu.com").unwrap();
        // `binary-` with an empty suffix names no architecture either.
        for dir in ["cnf", "uefi", "signed", "binary-"] {
            let path = format!("/ubuntu/dists/noble/main/{dir}/by-hash/SHA256/{DIGEST}");
            assert_eq!(
                Origin::from_path(&path, host(), None, &local_client()),
                None,
                "`{dir}` is not an architecture and has no Packages index"
            );
        }
    }

    #[test]
    fn test_origin_from_path_byhash_validates_algo_and_digest() {
        let host = || ClientHost::new("deb.debian.org").unwrap();

        // SHA512 with a 128-char hex digest: accepted.
        let sha512_digest = "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba\
                             4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";
        let path = format!("/debian/dists/sid/main/binary-amd64/by-hash/SHA512/{sha512_digest}");
        assert_eq!(
            Origin::from_path(&path, host(), None, &local_client()),
            Some(Origin {
                mirror: crate::test_support::structured_mirror("deb.debian.org", "debian"),
                fields: OriginFields {
                    distribution: String::from("sid"),
                    component: String::from("main"),
                    architecture: String::from("binary-amd64"),
                },
            })
        );

        // Unsupported algorithm: rejected.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/by-hash/MD5/\
                 84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83",
                host(),
                None,
                &local_client(),
            ),
            None
        );

        // SHA256 paired with a 128-char digest: length mismatch → rejected.
        let path = format!("/debian/dists/sid/main/binary-amd64/by-hash/SHA256/{sha512_digest}");
        assert_eq!(
            Origin::from_path(&path, host(), None, &local_client()),
            None
        );

        // Non-hex digest: rejected.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/by-hash/SHA256/\
                 zzz902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83",
                host(),
                None,
                &local_client(),
            ),
            None
        );

        // Missing digest segment: rejected.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/by-hash/SHA256",
                host(),
                None,
                &local_client(),
            ),
            None
        );

        // Missing both algo and digest segments: rejected.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/by-hash",
                host(),
                None,
                &local_client(),
            ),
            None
        );

        // Lowercase algorithm name (not spec-named): rejected.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/by-hash/sha256/\
                 84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83",
                host(),
                None,
                &local_client(),
            ),
            None
        );
    }

    #[test]
    fn test_origin_from_path_rejects_trailing_junk() {
        let host = || ClientHost::new("deb.debian.org").unwrap();

        // Trailing non-empty segment after `Packages`: rejected.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/Packages/extra",
                host(),
                None,
                &local_client(),
            ),
            None
        );
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/Packages/extra/garbage",
                host(),
                None,
                &local_client(),
            ),
            None
        );
        // Same for pdiff index suffixes — apt fetches a real Packages* on
        // first contact, so dropping the Origin record on these tail forms is
        // safe.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/Packages.diff/Index",
                host(),
                None,
                &local_client(),
            ),
            None
        );

        // Trailing junk after a by-hash digest: rejected.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/by-hash/SHA256/\
                 84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83/extra",
                host(),
                None,
                &local_client(),
            ),
            None
        );

        // A trailing slash is no index either: the cache refuses the shape,
        // so no passthrough of it may mint a row.
        assert_eq!(
            Origin::from_path(
                "/debian/dists/sid/main/binary-amd64/Packages/",
                host(),
                None,
                &local_client(),
            ),
            None
        );
    }

    /// `from_path` accepts exactly what `classify_request` caches: a
    /// passthrough of `flat/dists/a/b/binary-x/Packages/` must not register
    /// a structured mirror named `flat`, which disables flat caching for the
    /// host.
    #[test]
    fn test_origin_from_path_validates_like_the_classifier() {
        let host = || ClientHost::new("deb.debian.org").unwrap();
        let from = |path: &str| Origin::from_path(path, host(), None, &local_client());

        for path in [
            // Structured mirrors under the host's flat tree.
            "/flat/dists/a/b/binary-x/Packages",
            "/flat/x/dists/a/b/binary-x/Packages",
            // Trailing slash.
            "/flat/dists/a/b/binary-x/Packages/",
            "/debian/dists/sid/main/binary-amd64/Packages.xz/",
            // Reserved mirror-path segments.
            "/tmp/dists/sid/main/binary-amd64/Packages",
            "/debian/by-hash/dists/sid/main/binary-amd64/Packages",
            "/x/dists/dists/sid/main/binary-amd64/Packages",
            // Dot segments, raw or encoded.
            "/debian/../dists/sid/main/binary-amd64/Packages",
            "/debian/dists/%2e%2e/main/binary-amd64/Packages",
            // Fields that fail their validator once decoded.
            "/debian/dists/si%2Fd/main/binary-amd64/Packages",
            "/debian/dists/sid/ma%00in/binary-amd64/Packages",
            "/debian/dists/_sid/main/binary-amd64/Packages",
            "/debian/dists/sid/main/binary-amd64/Packages%ff",
            // A `_` in a field the cache names join with `_`.
            "/debian/dists/s_id/main/binary-amd64/Packages",
            "/debian/dists/sid/ma_in/binary-amd64/by-hash/SHA256/84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83",
        ] {
            assert_eq!(from(path), None, "{path}");
        }

        // Fields are percent-decoded, each on its own.
        let decoded = from("/deb%69an/dists/s%69d/main/binary-amd64/Packages.gz")
            .expect("an encoded letter is still the same index");
        assert_eq!(decoded.mirror.path(), "debian");
        assert_eq!(decoded.fields.distribution, "sid");

        // Individually valid fields can join to a name the cache cannot
        // store. Origin registration shares the same exact byte boundary.
        let distribution = "a".repeat(128);
        let fixed_len = distribution.len() + "__binary-amd64_Packages".len();
        let max_len = crate::cache_layout::MAX_DEBNAME_LEN;
        for name_len in [max_len, max_len + 1] {
            let path = format!(
                "/debian/dists/{distribution}/{}/binary-amd64/Packages",
                "b".repeat(name_len - fixed_len)
            );
            assert_eq!(from(&path).is_some(), name_len == max_len, "{path}");
        }
    }

    #[test]
    fn test_is_unsafe_proxy_path() {
        // safe paths
        assert!(!is_unsafe_proxy_path(
            "/debian/pool/main/a/apt/apt_2.9.8_amd64.deb"
        ));
        assert!(!is_unsafe_proxy_path("/debian/dists/sid/InRelease"));
        assert!(!is_unsafe_proxy_path("/"));
        assert!(!is_unsafe_proxy_path(""));
        // legitimate percent-encoded characters
        assert!(!is_unsafe_proxy_path(
            "/debian/pool/main/c/chromium/chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
        ));
        assert!(!is_unsafe_proxy_path(
            "/debian/pool/main/libt/libtirpc/libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
        ));
        // literal '%' in path (encoded as %25) is legitimate and must not be rejected
        assert!(!is_unsafe_proxy_path(
            "/debian/pool/main/foo%25bar/file.deb"
        ));
        // double-encoded sequences must be allowed (decoded once)
        assert!(!is_unsafe_proxy_path("/debian/foo%2520bar/file.deb"));

        // traversal
        assert!(is_unsafe_proxy_path("/debian/../etc/passwd"));
        assert!(is_unsafe_proxy_path("/debian/./pool/file.deb"));
        assert!(is_unsafe_proxy_path("/.."));
        assert!(is_unsafe_proxy_path("/."));
        // percent-encoded traversal
        assert!(is_unsafe_proxy_path("/debian/%2e%2e/etc/passwd"));
        assert!(is_unsafe_proxy_path("/debian/%2E%2E/etc/passwd"));

        // control characters / NUL
        assert!(is_unsafe_proxy_path("/debian/foo\nbar"));
        assert!(is_unsafe_proxy_path("/debian/foo%00bar"));
        assert!(is_unsafe_proxy_path("/debian/foo%0abar"));

        // invalid UTF-8 in percent-encoding
        assert!(is_unsafe_proxy_path("/debian/%ff%fe"));
    }

    #[test]
    fn test_is_unsafe_cache_path() {
        // What a classified request looks like once normalised: the `/./`
        // and `//` APT itself emits are gone, legitimate escapes stay.
        assert!(!is_unsafe_cache_path(
            "/debian/pool/main/a/apt/apt_2.9.8_amd64.deb"
        ));
        assert!(!is_unsafe_cache_path(
            "/debian/pool/main/libt/libtirpc/libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
        ));
        assert!(!is_unsafe_cache_path(&normalize_uri_path(
            "/cuda/repos/./debian12//x86_64/Packages.gz"
        )));

        // Dot segments, raw or encoded.
        assert!(is_unsafe_cache_path(
            "/debian/pool/updates/../../../victim_1.0_amd64.deb"
        ));
        assert!(is_unsafe_cache_path(
            "/debian/pool/main/%2e%2e/%2E%2E/victim_1.0_amd64.deb"
        ));
        assert!(is_unsafe_cache_path("/debian/dists/%2e/Release"));
        // An empty segment only an encoded separator can produce.
        assert!(is_unsafe_cache_path(
            "/debian/pool/main%2F%2Fx/y/y_1_all.deb"
        ));
        assert!(is_unsafe_cache_path("/debian/pool/main/x/y/%2Fy_1_all.deb"));
        // Control bytes and undecodable escapes.
        assert!(is_unsafe_cache_path("/debian/dists/sid%00/Release"));
        assert!(is_unsafe_cache_path("/debian/dists/sid%0a/Release"));
        assert!(is_unsafe_cache_path("/debian/dists/%ff%fe/Release"));
    }

    #[test]
    fn test_valid_directory() {
        for ok in [
            "main",
            "updates",
            "f",
            "libt",
            "firefox-esr",
            "gtk+3.0",
            "0ad",
            "binary-amd64",
        ] {
            assert!(valid_directory(ok), "{ok}");
        }
        for bad in [
            "", ".", "..", "+x", "-x", "_x", "a/b", "a b", "a%2e", "a\0b",
        ] {
            assert!(!valid_directory(bad), "{bad:?}");
        }
        assert!(!valid_directory(&"a".repeat(MAX_SEGMENT_LEN + 1)));
    }

    #[test]
    fn test_is_diff_request_path() {
        // valid
        assert!(is_diff_request_path(
            "/debian/dists/unstable/main/i18n/Translation-en.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz"
        ));
        assert!(is_diff_request_path(
            "/debian/dists/unstable/main/i18n/Translation-de.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz"
        ));
        assert!(is_diff_request_path(
            "/debian/dists/sid/main/source/Sources.diff/T-2024-10-03-1409.04-F-2024-10-03-1409.04.gz"
        ));
        assert!(is_diff_request_path(
            "/debian/dists/sid/main/binary-i386/Packages.diff/T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz"
        ));

        // invalid — not diff paths
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/binary-amd64/Packages.gz"
        ));
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/binary-amd64/Packages.xz"
        ));
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/source/Sources.gz"
        ));
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/i18n/Translation-en.gz"
        ));
        assert!(!is_diff_request_path("/debian/dists/sid/InRelease"));
        assert!(!is_diff_request_path(
            "/debian/pool/main/a/apt/apt_2.9.8_amd64.deb"
        ));
        assert!(!is_diff_request_path(""));
        assert!(!is_diff_request_path("/"));
        // Contains "diff" but not in the expected pattern
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/binary-amd64/Packages.diff/"
        ));
        assert!(!is_diff_request_path(
            "/debian/dists/sid/main/source/Sources.diff/Index"
        ));
    }

    #[test]
    fn translation_diffs_require_adjacent_segments_and_a_valid_language() {
        for path in [
            "/Translation-en.diff/T-",
            "/Translation-zh_CN.diff/T-patch.gz",
            "/Translation-bad-lang.diff/T-x/Translation-en.diff/T-good",
        ] {
            assert!(is_diff_request_path(path), "{path}");
        }
        for path in [
            "Translation-en.diff/T-x",
            "Packages.diff/T-x",
            "/NotSources.diff/T-x",
            "/Packages.diff//T-x",
            "/Translation-.diff/T-x",
            "/Translation-en-US.diff/T-x",
            "/Translation-en/else.diff/T-x",
            "/Translation-en.diff//T-x",
            "/Translation-en.diff/not-a-patch",
        ] {
            assert!(!is_diff_request_path(path), "{path}");
        }
        let mut repeated = "/Translation-en".repeat(500);
        assert!(!is_diff_request_path(&repeated));
        repeated.push_str("/Translation-en.diff/T-good");
        assert!(is_diff_request_path(&repeated));
    }

    #[test]
    fn pdiff_patch_name_shape() {
        for ok in [
            "T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz",
            "T-2026-11-23-1403.38-F-2026-11-23-1403.38.gz",
        ] {
            assert!(is_pdiff_patch_name(ok), "{ok}");
        }
        for bad in [
            "T-12345",
            "T-2024-09-24-2005.48-F-2024-09-23-2021.00",
            "T-2024-09-24-2005.48-F-2024-09-23-2021.00.xz",
            "2024-09-24-2005.48.gz",
            "T-2024-09-24-2005.48.gz",
            "T-2024-09-24-2005.4-F-2024-09-23-2021.00.gz",
            "T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz.gz",
            "T-2024-09-24_2005.48-F-2024-09-23-2021.00.gz",
            "T-2024-09-24-2005%2e48-F-2024-09-23-2021.00.gz",
            "t-2024-09-24-2005.48-F-2024-09-23-2021.00.gz",
            "",
        ] {
            assert!(!is_pdiff_patch_name(bad), "{bad}");
        }
    }

    #[test]
    fn parse_pdiff_patches() {
        const P: &str = "T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz";
        let pdiff = |architecture, index| ResourceFile::Pdiff {
            mirror_path: "debian",
            distribution: "sid",
            component: "main",
            architecture,
            index,
            patch: P,
        };
        for (dir, expected) in [
            (
                "binary-amd64/Packages.diff",
                pdiff(Some("binary-amd64"), "Packages"),
            ),
            ("i18n/Packages.diff", pdiff(Some("i18n"), "Packages")),
            ("source/Sources.diff", pdiff(None, "Sources")),
            ("i18n/Translation-en.diff", pdiff(None, "Translation-en")),
        ] {
            let path = format!("debian/dists/sid/main/{dir}/{P}");
            assert_eq!(parse_request_path(&path), Some(expected), "{path}");
            // Whatever the parser caches as a patch, the 410 gate must refuse:
            // a patch family added to the parser needs its row here.
            assert!(is_diff_request_path(&path), "{path}");
        }
        for path in [
            "debian/dists/sid/main/binary-amd64/Packages.diff/T-12345".to_owned(),
            "debian/dists/sid/main/binary-amd64/Packages.diff/Index".to_owned(),
            format!("debian/dists/sid/main/Packages.diff/{P}"),
            format!("debian/dists/sid/main/source/Translation-en.diff/{P}"),
            format!("debian/dists/sid/main/binary-amd64/Contents.diff/{P}"),
            format!("debian/dists/x/sid/main/binary-amd64/Packages.diff/{P}"),
            format!("debian/dists/sid/main/i18n/Translation-.diff/{P}"),
            format!("debian/dists/sid/main/i18n/Translation-e%6E.diff/{P}"),
        ] {
            assert_eq!(parse_request_path(&path), None, "{path}");
        }
    }

    #[test]
    fn test_is_flat_deb_filename() {
        // valid
        assert!(is_flat_deb_filename("twilio-cli_5.0.0_amd64.deb"));
        assert!(is_flat_deb_filename("firefox-esr_115.9.1esr-1_amd64.deb"));
        assert!(is_flat_deb_filename("libssh-doc_0.10.6-2_all.deb"));
        assert!(is_flat_deb_filename("foo_1.0_amd64.udeb"));
        assert!(is_flat_deb_filename("foo_1.0_amd64.ddeb"));
        // URL-encoded characters in version are tolerated.
        assert!(is_flat_deb_filename(
            "libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
        ));

        // invalid: wrong extension
        assert!(!is_flat_deb_filename("twilio-cli_5.0.0_amd64.dsc"));
        assert!(!is_flat_deb_filename("twilio-cli_5.0.0_amd64.tar.gz"));
        assert!(!is_flat_deb_filename("Packages.gz"));

        // invalid: no extension
        assert!(!is_flat_deb_filename("twilio-cli_5.0.0_amd64"));

        // invalid: too few components
        assert!(!is_flat_deb_filename("foo.deb"));
        assert!(!is_flat_deb_filename("foo_1.0.deb"));

        // invalid: too many components
        assert!(!is_flat_deb_filename("foo_1.0_amd64_extra.deb"));

        // invalid: empty component
        assert!(!is_flat_deb_filename("_1.0_amd64.deb"));
        assert!(!is_flat_deb_filename("foo__amd64.deb"));
        assert!(!is_flat_deb_filename("foo_1.0_.deb"));
    }

    #[test]
    fn is_translation_filename_accepts_canonical_forms() {
        assert!(is_translation_filename("Translation-en"));
        assert!(is_translation_filename("Translation-en.gz"));
        assert!(is_translation_filename("Translation-en.xz"));
        assert!(is_translation_filename("Translation-en.bz2"));
        assert!(is_translation_filename("Translation-en_US.xz"));
        assert!(is_translation_filename("Translation-sr@Latn.gz"));
    }

    #[test]
    fn is_translation_filename_rejects_bogus_inputs() {
        assert!(!is_translation_filename("Translation-"));
        assert!(!is_translation_filename("Translation-.gz")); // empty lang with ext
        assert!(!is_translation_filename("translation-en.gz")); // wrong case
        assert!(!is_translation_filename("Translation"));
        assert!(!is_translation_filename("Translation-en.zst")); // unknown ext
        assert!(!is_translation_filename("Translation-en.diff")); // pdiff
        assert!(!is_translation_filename("NotTranslation-en.gz"));
    }

    #[test]
    fn parse_sources_and_translation_names() {
        assert_eq!(
            parse_request_path("debian/dists/sid/main/source/Sources"),
            Some(ResourceFile::Sources {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "Sources",
            })
        );
        for filename in ["Translation-en", "Translation-en.gz", "Translation-en.xz"] {
            assert_eq!(
                parse_request_path(&format!("debian/dists/sid/main/i18n/{filename}")),
                Some(ResourceFile::Translation {
                    mirror_path: "debian",
                    distribution: "sid",
                    component: "main",
                    filename,
                })
            );
        }
        for filename in ["Translation-en", "Translation-en.gz"] {
            assert_eq!(
                parse_request_path(&format!("apt/{filename}")),
                Some(ResourceFile::Flat {
                    kind: FlatKind::Metadata,
                    mirror_path: "apt",
                    filename,
                })
            );
        }
    }

    #[test]
    fn parse_request_path_rejects_traversal_after_normalize() {
        // Even with `//` collapsed, traversal segments still get caught.
        assert!(parse_request_path("debian/dists/../passwd").is_none());
    }

    #[test]
    fn flat_pool_archive_root_splits_at_the_pool_segment() {
        for (mirror_path, expected) in [
            // Gitea's layout.
            (
                "api/packages/85/debian/pool/php-zts/main",
                Some(("api/packages/85/debian", "pool/php-zts/main/")),
            ),
            ("repo/pool/", Some(("repo", "pool/"))),
            ("apt/amd64", None),
            // `/pool/` requires a leading archive-root segment; a path that
            // merely starts with `pool/` has no `/pool/` substring.
            ("pool/php-zts/main", None),
        ] {
            assert_eq!(
                flat_pool_archive_root(mirror_path),
                expected.map(|(root, prefix)| (root, prefix.to_owned())),
                "{mirror_path}"
            );
        }
    }

    #[test]
    fn derive_nested_paths_table() {
        for (mirror_path, host_paths, expected) in [
            (
                "debian",
                &["debian", "debian/security", "debian/x/y", "unrelated"][..],
                &["debian/security", "debian/x/y"][..],
            ),
            // `debian-security` and `debian_updates` share the byte prefix
            // but are no nested children; `debian-security` also sorts
            // between `debian` and `debian/...` (`-` < `/`), so the
            // segment-alignment filter must skip it without ending the scan.
            (
                "debian",
                &[
                    "debian",
                    "debian-security",
                    "debian_updates",
                    "debian/foo",
                    "debian/security",
                ],
                &["debian/foo", "debian/security"],
            ),
            // A host-root mirror nests every other path.
            (
                "",
                &["", "debian", "debian/security"],
                &["debian", "debian/security"],
            ),
            // Self is excluded.
            ("debian", &["debian"], &[]),
            ("ubuntu", &["apt", "debian"], &[]),
        ] {
            let mut sorted = host_paths.to_vec();
            sorted.sort_unstable();
            assert_eq!(
                derive_nested_paths(mirror_path, &sorted),
                expected,
                "{mirror_path:?} among {host_paths:?}"
            );
        }
    }

    #[test]
    fn nested_mirror_relation_table() {
        use NestedMirrorRelation::{Boundary, Container, Unrelated};
        for (candidate, nested, expected) in [
            ("apt/amd64", &["apt/amd64"][..], Boundary),
            // The walker has already entered the nested subtree.
            ("apt/amd64/foo", &["apt/amd64"], Boundary),
            // A strict ancestor of a registered nested root is no boundary:
            // a flat walk has to continue down to reach the real nested
            // root, and the size scan must not report it as stray.
            ("apt/amd64", &["apt/amd64/special"], Container),
            // Registered itself and holding a deeper one: the nested
            // `apt/amd64` row owns the subtree.
            ("apt/amd64", &["apt/amd64", "apt/amd64/special"], Boundary),
            // Segment-aligned, in both directions.
            ("apt-tools", &["apt"], Unrelated),
            ("apt", &["apt-tools"], Unrelated),
            ("apt", &["debian", "ubuntu/jammy"], Unrelated),
            ("apt", &[], Unrelated),
        ] {
            let nested_paths: Vec<String> = nested.iter().map(|p| (*p).to_owned()).collect();
            assert_eq!(
                nested_mirror_relation(candidate, &nested_paths),
                expected,
                "{candidate} against {nested:?}"
            );
        }
    }

    /// The whole `(directory name, digest length)` table as one literal, so a
    /// new algorithm is decided here rather than defaulted.
    #[test]
    fn by_hash_algorithm_table() {
        let sha256 = "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";
        let sha512 = "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba\
                      4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba";
        for (algo, name, digest) in [
            (HashAlgo::Sha256, "SHA256", sha256),
            (HashAlgo::Sha512, "SHA512", sha512),
        ] {
            assert_eq!(algo.as_str(), name, "{algo:?} directory name");
            assert_eq!(algo.digest_len(), digest.len(), "{algo:?} digest length");
            assert_eq!(HashAlgo::parse(name), Some(algo));
            assert_eq!(HashAlgo::for_digest(digest), Some(algo));
            assert!(algo.matches_digest(digest), "{algo:?} accepts its digest");
        }

        // Cross-pairing is rejected in both directions.
        assert!(!HashAlgo::Sha256.matches_digest(sha512));
        assert!(!HashAlgo::Sha512.matches_digest(sha256));

        // Unsupported / mis-spelt algorithm directories have no variant.
        for name in [
            "MD5Sum", "SHA1", "SHA224", "SHA384", "sha256", "", "SHA256 ",
        ] {
            assert_eq!(
                HashAlgo::parse(name),
                None,
                "{name} must not name an algorithm"
            );
        }

        // Non-hex, and lengths around the supported ones.
        assert!(!is_byhash_digest_shape(&"ab".repeat(31)));
        assert!(!is_byhash_digest_shape(&format!("{sha256}ab")));
        assert!(!is_byhash_digest_shape(&sha256.replace('4', "z")));
        assert!(is_byhash_digest_shape(sha256));
        assert!(is_byhash_digest_shape(sha512));
        assert_eq!(byhash_pair("SHA256", sha256), Some(HashAlgo::Sha256));
        assert_eq!(byhash_pair("SHA512", sha256), None);
    }

    /// The recognised index leaves, i.e. exactly which compression suffixes
    /// the parser knows about.
    #[test]
    fn index_family_predicates() {
        for name in ["InRelease", "Release", "Release.gpg"] {
            assert!(is_release_filename(name), "{name} is a Release leaf");
            assert!(!is_packages_filename(name));
            assert!(!is_sources_filename(name));
        }
        for name in ["Packages", "Packages.gz", "Packages.xz"] {
            assert!(is_packages_filename(name), "{name} is a Packages leaf");
        }
        for name in ["Sources", "Sources.gz", "Sources.xz"] {
            assert!(is_sources_filename(name), "{name} is a Sources leaf");
        }
        // Compressions we do not serve, and the pdiff siblings.
        for name in [
            "Packages.bz2",
            "Packages.zst",
            "Packages.diff",
            "Sources.bz2",
            "packages",
            "Release.asc",
        ] {
            assert!(!is_release_filename(name), "{name} is not a Release leaf");
            assert!(!is_packages_filename(name), "{name} is not a Packages leaf");
            assert!(!is_sources_filename(name), "{name} is not a Sources leaf");
        }
    }
}
