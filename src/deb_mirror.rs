use std::{borrow::Cow, num::NonZero, path::PathBuf, sync::OnceLock};

use crate::{
    config::{CacheHost, ClientHost},
    database,
};

/// On-disk layout family of a mirror.  Stored in the `mirrors_v2.kind`
/// INTEGER column (added by the `20260512155314_mirror_kind` migration);
/// the row's unique key remains `(host, port, path)`.  A single
/// `(host, port, path)` row tracks the strictest layout ever seen for
/// that mirror — the upsert latches `kind` to `Structured` on conflict
/// so the flat-collision blocklist still records a structured request
/// that arrived after a flat row already existed for the same tuple.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MirrorKind {
    Structured,
    Flat,
}

impl MirrorKind {
    /// SQL/DB encoding stored in `mirrors_v2.kind` (INTEGER).
    /// `0` = structured, `1` = flat — fixed by the migration default and
    /// the application-side validation in [`Self::from_db_int`].
    #[must_use]
    pub(crate) const fn as_db_int(self) -> i64 {
        match self {
            Self::Structured => 0,
            Self::Flat => 1,
        }
    }

    /// Reverse of [`Self::as_db_int`].  Returns `None` for any value not
    /// matching the encoded set; the caller skips such rows so
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
    path: String,
    kind: MirrorKind,
    /// Lazily-populated cache of `host.format_authority(port)` when the result
    /// is owned (i.e. requires allocation: an IPv6 host or a non-empty port).
    /// Skipped from `Hash`/`Eq`/`Clone` impls because it is purely derived
    /// from `host` + `port`.
    cached_authority: OnceLock<Box<str>>,
}

impl Mirror {
    #[must_use]
    pub(crate) const fn new(
        host: ClientHost,
        port: Option<NonZero<u16>>,
        path: String,
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
    pub(crate) fn format_authority(&self) -> Cow<'_, str> {
        // Fast path: no allocation needed for DNS/IPv4 hosts without a port.
        if self.port.is_none() && !self.host.is_ipv6() {
            return Cow::Borrowed(self.host.as_str());
        }
        Cow::Borrowed(self.cached_authority.get_or_init(|| {
            self.host
                .format_authority(self.port)
                .into_owned()
                .into_boxed_str()
        }))
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
    pub(crate) const fn path(&self) -> &str {
        self.path.as_str()
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
            path: path.clone(),
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

#[expect(
    clippy::pathbuf_init_then_push,
    reason = "the auto-suggestion `.join()` allocates a fresh PathBuf and \
              throws away the with_capacity sizing we want here"
)]
pub(crate) fn mirror_cache_path_impl(
    host: &CacheHost,
    port: Option<NonZero<u16>>,
    path: &str,
) -> PathBuf {
    let host_dir = host.format_cache_dir(port);
    // Pre-size for the eventual final length so PathBuf::push doesn't grow
    // the underlying OsString.  +1 for the path separator inserted between
    // the two pushes.  This path is built per served file and showed up at
    // 95 % of worker stacks in profiles dominated by Path/Vec growth.
    let mut cache_path = PathBuf::with_capacity(host_dir.len() + 1 + path.len());
    cache_path.push(host_dir.as_ref());
    cache_path.push(path);

    assert!(
        cache_path.is_relative(),
        "cache path must be relative in order to be joined with the host directory"
    );

    cache_path
}

#[derive(Debug, PartialEq)]
pub(crate) struct Origin {
    pub(crate) mirror: Mirror,
    pub(crate) distribution: String,
    pub(crate) component: String,
    pub(crate) architecture: String,
}

impl Origin {
    #[must_use]
    pub(crate) fn from_path(
        path: &str,
        host: ClientHost,
        port: Option<NonZero<u16>>,
    ) -> Option<Self> {
        /* /debian/dists/sid/main/binary-amd64/Packages{,.diff,.gz,.xz} */

        let path = normalize_uri_path(path);
        let path = path.trim_start_matches('/');

        let (mirror_path, origin_path) = path.rsplit_once("/dists/")?;

        let mut parts = origin_path.split('/');

        let distribution = parts.next()?;

        let component = parts.next()?;

        let architecture = parts.next()?;

        let filename = parts.next()?;
        if !matches!(
            filename,
            "Packages" | "Packages.gz" | "Packages.xz" | "Packages.diff" | "by-hash"
        ) {
            return None;
        }

        Some(Self {
            // Origin URLs always parse from `<path>/dists/...` paths, which
            // are exclusively a structured-layout shape.
            mirror: Mirror::new(host, port, mirror_path.to_owned(), MirrorKind::Structured),
            distribution: distribution.to_owned(),
            component: component.to_owned(),
            architecture: architecture.to_owned(),
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
    // deb.debian.org/debian/dists/sid/main/binary-amd64/Packages

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
            &self.distribution,
            &self.component,
            &self.architecture,
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
    /// A by-hash content-addressed file at `<base>/by-hash/SHA*/<hex>`.
    ByHash,
}

#[derive(Debug, PartialEq)]
pub(crate) enum ResourceFile<'a> {
    /// A pool file
    Pool {
        mirror_path: &'a str,
        filename: &'a str,
    },
    /// A dists file
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
    /// A packages file
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
        filename: &'a str,
    },
    /// An icons file
    Icon {
        mirror_path: &'a str,
        distribution: &'a str,
        component: &'a str,
        filename: &'a str,
    },
    /// A sources file
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

/// Collapse runs of consecutive ASCII forward-slashes in a URL path to a
/// single `/`.
///
/// APT clients with a trailing slash in their `sources.list` mirror URI
/// produce request paths like `/debian//dists/...`; without normalisation
/// the `//` pollutes the parsed `mirror_path`.  The fast path returns
/// `Cow::Borrowed` (zero allocation) when no `//` is present; the slow
/// path allocates a single normalised `String`.  Idempotent and safe to
/// call twice.  Iterates `chars()` so non-ASCII codepoints are preserved
/// verbatim; later percent-decoding and non-ASCII rejection in
/// `decode_validate` / `is_unsafe_proxy_path` get the original byte
/// sequence.
#[must_use]
pub(crate) fn normalize_uri_path(path: &str) -> Cow<'_, str> {
    if !path.contains("//") {
        return Cow::Borrowed(path);
    }
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for c in path.chars() {
        if c == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(c);
            prev_slash = false;
        }
    }
    Cow::Owned(out)
}

/// Parses a request path into the mirror path and the filename.
///
/// The directory name "pool" is not supported as part of the mirror path.
/// The directory name "dists" should be avoided as part of the mirror path.
#[must_use]
pub(crate) fn parse_request_path(path: &str) -> Option<ResourceFile<'_>> {
    let path = path.trim_start_matches('/');

    /*
     * debian/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb
     * debian-security/pool/updates/main/c/chromium/chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb
     */
    if let Some((mirror_path, pool_path)) = path.split_once("/pool/") {
        let mut parts = pool_path.rsplit('/');

        let filename = parts.next()?;

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

        return Some(ResourceFile::Pool {
            mirror_path,
            filename,
        });
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
        if filename == "Release" || filename == "InRelease" {
            // `rsplit` walks segments right-to-left.  The first segment may
            // be either the distribution (top-level Release/InRelease) or
            // the `binary-<arch>` / `source` scope of a per-component
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
                    // `InRelease` has no per-component form.
                    if filename != "Release" {
                        return None;
                    }
                    let architecture = next;
                    let valid_binary = architecture
                        .strip_prefix("binary-")
                        .is_some_and(|arch| !arch.is_empty());
                    if !valid_binary && architecture != "source" {
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
        } else if filename == "Packages.gz" || filename == "Packages.xz" || filename == "Packages" {
            let architecture = parts.next()?;
            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Packages {
                mirror_path,
                distribution,
                component,
                architecture,
                filename,
            });
        } else if filename == "Sources" || filename == "Sources.gz" || filename == "Sources.xz" {
            if parts.next()? != "source" {
                return None;
            }

            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Sources {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if is_translation_filename(filename) {
            if parts.next()? != "i18n" {
                return None;
            }

            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Translation {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if filename.starts_with("icons-") {
            if parts.next()? != "dep11" {
                return None;
            }

            let component = parts.next()?;
            let distribution = parts.next()?;

            if parts.next().is_some() {
                return None;
            }

            return Some(ResourceFile::Icon {
                mirror_path,
                distribution,
                component,
                filename,
            });
        } else if filename.len() >= 64 && filename.bytes().all(|b| b.is_ascii_hexdigit()) {
            let hash_algorithm = parts.next()?;

            // The filename length >= 64 characters ensures that only SHA >= SHA256 is supported
            if !hash_algorithm.starts_with("SHA") {
                return None;
            }

            if parts.next()? != "by-hash" {
                return None;
            }

            return Some(ResourceFile::ByHash {
                mirror_path,
                filename,
            });
        }

        return None;
    }

    /*
     * Flat (trivial) repository format — only reached when neither `/pool/`
     * nor `/dists/` matched, so structured-layout rejections are preserved.
     *
     * apt/InRelease
     * apt/Release.gpg
     * apt/Packages.gz
     * apt/twilio-cli_5.0.0_amd64.deb
     * apt/by-hash/SHA256/<hex>
     */
    let (mirror_path, tail) = path.rsplit_once('/')?;
    if mirror_path.is_empty() {
        return None;
    }

    // By-hash: `<base>/by-hash/SHA*/<hex>` — hex tail of length >= 64 ensures
    // SHA256 or stronger.  On structural mismatch fall through to None rather
    // than reclassifying as a pool file.
    if tail.len() >= 64 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
        if let Some((base, hash_algo)) = mirror_path.rsplit_once('/')
            && hash_algo.starts_with("SHA")
            && let Some((flat_base, by_hash_dir)) = base.rsplit_once('/')
            && by_hash_dir == "by-hash"
            && !flat_base.is_empty()
        {
            return Some(ResourceFile::Flat {
                kind: FlatKind::ByHash,
                mirror_path: flat_base,
                filename: tail,
            });
        }
        return None;
    }

    // Metadata: closed allowlist of canonical filenames documented by the
    // flat-repo spec.  `Release.gpg` is accepted only here; the structured
    // matcher's narrower set stays as-is.
    if matches!(
        tail,
        "InRelease"
            | "Release"
            | "Release.gpg"
            | "Packages"
            | "Packages.gz"
            | "Packages.xz"
            | "Sources"
            | "Sources.gz"
            | "Sources.xz"
    ) || is_translation_filename(tail)
    {
        return Some(ResourceFile::Flat {
            kind: FlatKind::Metadata,
            mirror_path,
            filename: tail,
        });
    }

    // Pool data: enforce the strict `<name>_<version>_<arch>.<ext>` shape.
    // Anything else falls through to the splice proxy.
    if is_flat_deb_filename(tail) {
        return Some(ResourceFile::Flat {
            kind: FlatKind::Pool,
            mirror_path,
            filename: tail,
        });
    }

    None
}

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

/// Check whether the given URI path is a diff request path.
///
/// Note: calls should be guarded by the configuration setting `reject_pdiff_requests`.
///
/// Example request paths:
/// - `http://deb.debian.org/debian-debug/dists/sid-debug/main/binary-i386/Packages.diff/T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz`
/// - `http://deb.debian.org/debian/dists/unstable/main/i18n/Translation-en.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz`
/// - `http://deb.debian.org/debian/dists/unstable/main/i18n/Translation-de.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz`
/// - `http://deb.debian.org/debian/dists/sid/main/source/Sources.diff/T-2024-10-03-1409.04-F-2024-10-03-1409.04.gz`
///
/// A regex-based implementation was considered but rejected: the linear-scan
/// contains/find approach avoids pulling in the `regex` crate solely for this
/// check and stays linear in the path length with no allocation.
#[must_use]
pub(crate) fn is_diff_request_path(uri_path: &str) -> bool {
    const FIXED_MARKERS: &[&str] = &["/Packages.diff/T-", "/Sources.diff/T-"];
    FIXED_MARKERS.iter().any(|m| uri_path.contains(m)) || contains_translation_diff(uri_path)
}

/// Check whether the path contains a `Translation-XX.diff/T-` segment for any language.
#[must_use]
fn contains_translation_diff(uri_path: &str) -> bool {
    const PREFIX: &str = "/Translation-";
    const SUFFIX: &str = ".diff/T-";

    let mut haystack = uri_path;
    while let Some(idx) = haystack.find(PREFIX) {
        let rest = haystack.split_at(idx + PREFIX.len()).1;
        if let Some(diff_idx) = rest.find(SUFFIX) {
            let lang = rest.split_at(diff_idx).0;
            // Language tags in Debian translations are of the form `en`, `de`,
            // `zh_CN`, `pt_BR` — alphanumeric with optional underscore.  Reject
            // arbitrary separator runs (e.g. `---`) that the previous matcher
            // accepted.
            if !lang.is_empty() && lang.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return true;
            }
        }
        haystack = rest;
    }
    false
}

/// Check whether a percent-decoded URI path is safe to forward upstream.
///
/// Rejects traversal segments (`..`, `.`) and control characters (including null bytes).
///
/// Returns `true` if the path is unsafe and should be rejected.
#[must_use]
pub(crate) fn is_unsafe_proxy_path(raw_path: &str) -> bool {
    let decoded = match urlencoding::decode(raw_path) {
        Ok(d) => d,
        // Failed to decode — reject as unsafe
        Err(_err @ std::string::FromUtf8Error { .. }) => return true,
    };

    decoded
        .split('/')
        .any(|seg| seg == "." || seg == ".." || seg.contains(|c: char| c.is_ascii_control()))
}

/// Recognise any of: `Translation-LANG`, `Translation-LANG.bz2`,
/// `Translation-LANG.gz`, `Translation-LANG.xz`. The language code is
/// not validated beyond non-empty -- matches the existing arm's trust
/// posture, and Debian language codes carry tags like `sr@Latn` that
/// don't fit a simple alpha/underscore allowlist.
#[must_use]
pub(crate) fn is_translation_filename(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("Translation-") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    match rest.rsplit_once('.') {
        None => true,
        Some((_, ext)) => matches!(ext, "gz" | "xz" | "bz2"),
    }
}

/// Valid Debian package extensions (`.deb`, `.udeb`, `.ddeb`).
pub(crate) const VALID_DEB_EXTENSIONS: &[&str] = &["deb", "udeb", "ddeb"];

/// Whether the filename represents a Debian binary package (`.deb`, `.udeb`, `.ddeb`).
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

/// Path-segment names reserved for the per-mirror on-disk cache layout.
///
/// A mirror path containing any of these as a `/`-separated segment would
/// collide with cache plumbing — `tmp/` is the partial-download scratch
/// dir, `by-hash/` is the content-addressed subtree under each mirror.
/// The host-level `flat/` anchor is *not* reserved here: structured
/// mirrors named `flat` are handled by the per-host collision blocklist
/// (`flat_blocklist`) so that "structured wins" without permanently
/// banning such mirror paths.
///
/// Shared with the startup migration scan in `main.rs`, which warns about
/// pre-existing `mirrors_v2` rows that would now fail validation.
pub(crate) const RESERVED_MIRROR_PATH_SEGMENTS: &[&str] = &["tmp", "by-hash"];

/// Whether `segment` is one of the [`RESERVED_MIRROR_PATH_SEGMENTS`].
#[must_use]
pub(crate) fn is_reserved_mirror_path_segment(segment: &str) -> bool {
    RESERVED_MIRROR_PATH_SEGMENTS.contains(&segment)
}

/// Whether `path` is invalid as a mirror path because some `/`-separated
/// segment is reserved.  Used by the startup migration warning so the
/// daemon can flag pre-existing DB rows that the validator would now
/// reject on insertion.
#[must_use]
pub(crate) fn mirror_path_has_reserved_segment(path: &str) -> bool {
    path.split('/').any(is_reserved_mirror_path_segment)
}

/// Whether `path` is a strict descendant of `ancestor` in `/`-separated
/// segment terms — i.e. `path == "<ancestor>/<rest>"` for non-empty
/// `<rest>`.  Returns `false` when `path == ancestor`.
///
/// Segment alignment matters: `apt-tools` is not a descendant of `apt`
/// even though it shares the prefix byte-wise.
#[must_use]
pub(crate) fn is_strict_path_descendant(path: &str, ancestor: &str) -> bool {
    path.len() > ancestor.len()
        && path.starts_with(ancestor)
        && path.as_bytes()[ancestor.len()] == b'/'
}

/// Whether `path` equals `prefix` or is a strict descendant of it,
/// segment-aligned.  Useful when a scan wants to treat a registered
/// nested-mirror path as a *boundary* — either at the boundary itself
/// or inside it.
#[must_use]
pub(crate) fn path_starts_with_segment(path: &str, prefix: &str) -> bool {
    path == prefix || is_strict_path_descendant(path, prefix)
}

#[must_use]
pub(crate) fn valid_mirrorname(name: &str) -> bool {
    if name.is_empty() || name.len() > 128 {
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
        if is_reserved_mirror_path_segment(segment) {
            return false;
        }
    }
    true
}

#[must_use]
fn valid_path_segment(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphanumeric() || (i > 0 && (b == b'-' || b == b'.' || b == b'_'))
        })
}

#[must_use]
pub(crate) fn valid_distribution(name: &str) -> bool {
    valid_path_segment(name)
}

#[must_use]
pub(crate) fn valid_component(name: &str) -> bool {
    valid_path_segment(name)
}

#[must_use]
pub(crate) fn valid_architecture(name: &str) -> bool {
    valid_path_segment(name)
}

#[cfg(test)]
mod tests {
    use crate::nonzero;

    use super::*;

    #[test]
    fn test_parse_1() {
        let result = Origin::from_path(
            "/debian/dists/sid/main/binary-amd64/Packages/",
            ClientHost::new("deb.debian.org".to_string()).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror::new(
                    ClientHost::new("deb.debian.org".to_string()).unwrap(),
                    None,
                    "debian".to_string(),
                    MirrorKind::Structured,
                ),
                distribution: "sid".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "http://deb.debian.org/debian/dists/sid/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_2() {
        let result = Origin::from_path(
            "/private/debian/dists/sid/main/binary-amd64/by-hash/SHA256/\
        84b902c50d12a499fb2156ca2190ddaa9bb9dd8c7354aaccfc56590318bc0b83",
            ClientHost::new("site.example.com".to_string()).unwrap(),
            Some(nonzero!(80)),
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror::new(
                    ClientHost::new("site.example.com".to_string()).unwrap(),
                    Some(nonzero!(80)),
                    "private/debian".to_string(),
                    MirrorKind::Structured,
                ),
                distribution: "sid".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "http://site.example.com:80/private/debian/dists/sid/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_3() {
        let result = Origin::from_path(
            "/unstable/dists/llvm-toolchain-19/main/binary-amd64/Packages.gz",
            ClientHost::new("apt.llvm.org".to_string()).unwrap(),
            Some(nonzero!(443)),
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror::new(
                    ClientHost::new("apt.llvm.org".to_string()).unwrap(),
                    Some(nonzero!(443)),
                    "unstable".to_string(),
                    MirrorKind::Structured,
                ),
                distribution: "llvm-toolchain-19".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "http://apt.llvm.org:443/unstable/dists/llvm-toolchain-19/main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_parse_ipv6() {
        let result = Origin::from_path(
            "/debian/dists/sid/main/binary-amd64/Packages/",
            ClientHost::new("2001:db8::1".to_string()).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            result,
            Origin {
                mirror: Mirror::new(
                    ClientHost::new("2001:db8::1".to_string()).unwrap(),
                    None,
                    "debian".to_string(),
                    MirrorKind::Structured,
                ),
                distribution: "sid".to_string(),
                component: "main".to_string(),
                architecture: "binary-amd64".to_string()
            }
        );
        assert_eq!(
            result.uri(),
            "http://[2001:db8::1]/debian/dists/sid/main/binary-amd64/Packages"
        );

        // IPv6 with port
        let result = Origin::from_path(
            "/debian/dists/sid/main/binary-amd64/Packages/",
            ClientHost::new("::1".to_string()).unwrap(),
            Some(nonzero!(8080)),
        )
        .unwrap();
        assert_eq!(
            result.uri(),
            "http://[::1]:8080/debian/dists/sid/main/binary-amd64/Packages"
        );
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
                filename: "firefox-esr_115.9.1esr-1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "private/ubuntu/pool/main/f/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"
            ),
            Some(ResourceFile::Pool {
                mirror_path: "private/ubuntu",
                filename: "firefox-esr_115.9.1esr-1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path("debian/pool/main/libs/libssh/libssh-doc_0.10.6-2_all.deb"),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                filename: "libssh-doc_0.10.6-2_all.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/pool/main/libt/libtirpc/libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
            ),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
                filename: "libtirpc3t64_1.3.4%2bds-1.2_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path("debian/pool/main/m/mesa/libgl1-mesa-dri_24.0.5-1_amd64.deb"),
            Some(ResourceFile::Pool {
                mirror_path: "debian",
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
                filename: "chromium-common_141.0.7390.65-1%7edeb12u1_amd64.deb"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/binary-amd64/Packages.diff/by-hash/SHA256/491ddac17f4b86d771a457e6b084c499dfeb9ee29004b92d5d05fe79f1f0dede"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                filename: "491ddac17f4b86d771a457e6b084c499dfeb9ee29004b92d5d05fe79f1f0dede"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/dep11/by-hash/SHA256/cf31e359ca5863e438c1b2d3ddaa1d473519ad26bd71e3dac7803dade82e4482"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                filename: "cf31e359ca5863e438c1b2d3ddaa1d473519ad26bd71e3dac7803dade82e4482"
            })
        );

        assert_eq!(
            parse_request_path(
                "debian/dists/trixie/main/by-hash/SHA256/4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            ),
            Some(ResourceFile::ByHash {
                mirror_path: "debian",
                filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
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
         * TODO: support those?
         */

        assert_eq!(
            parse_request_path(
                "debian/dists/sid/main/binary-amd64/Packages.diff/T-2024-04-16-1405.22-F-2024-04-15-2018.42.gz"
            ),
            None
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
                kind: FlatKind::ByHash,
                mirror_path: "apt",
                filename: "4f8878062744fae5ff91f1ad0f3efecc760514381bf029d06bdf7023cfc379ba"
            })
        );

        // The reporter's exact request path.
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

        assert_eq!(
            parse_request_path("debian/pool/main/g/firefox-esr/firefox-esr_115.9.1esr-1_amd64.deb"),
            None
        );

        assert_eq!(parse_request_path("debian/dists/sid/Foo"), None);

        assert_eq!(parse_request_path("debian/dists/a/b/InRelease"), None);

        // Per-component Release: `InRelease` has no per-component form.
        assert_eq!(
            parse_request_path("debian/dists/trixie/main/binary-amd64/InRelease"),
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
        /* valid */
        assert!(valid_mirrorname("debian"));
        assert!(valid_mirrorname("public/ubuntu"));
        assert!(valid_mirrorname("public/private/kali"));
        assert!(valid_mirrorname("foo/bar"));

        /* invalid */
        assert!(!valid_mirrorname(""));
        assert!(!valid_mirrorname("."));
        assert!(!valid_mirrorname(".."));
        assert!(!valid_mirrorname("-foo"));
        assert!(!valid_mirrorname(".foo"));
        assert!(!valid_mirrorname("_foo"));
        assert!(!valid_mirrorname("foo\nbar"));
        assert!(!valid_mirrorname("foo/./bar"));
        assert!(!valid_mirrorname("foo/../bar"));
        assert!(!valid_mirrorname("foo//bar"));
        assert!(!valid_mirrorname("/"));
        assert!(!valid_mirrorname("/debian"));
        assert!(!valid_mirrorname("~/foo"));
        assert!(!valid_mirrorname("~foo"));
        assert!(!valid_mirrorname("public%2Fubuntu"));

        /* reserved segments collide with cache-layout plumbing */
        assert!(!valid_mirrorname("tmp"));
        assert!(!valid_mirrorname("by-hash"));
        assert!(!valid_mirrorname("foo/tmp"));
        assert!(!valid_mirrorname("foo/by-hash/bar"));
        /* but non-segment occurrences are fine */
        assert!(valid_mirrorname("tmpfile"));
        assert!(valid_mirrorname("by-hash-deb"));
    }

    #[test]
    fn test_mirror_path_has_reserved_segment() {
        assert!(mirror_path_has_reserved_segment("tmp"));
        assert!(mirror_path_has_reserved_segment("by-hash"));
        assert!(mirror_path_has_reserved_segment("foo/tmp"));
        assert!(mirror_path_has_reserved_segment("foo/by-hash/bar"));
        assert!(!mirror_path_has_reserved_segment("debian"));
        assert!(!mirror_path_has_reserved_segment("tmpfile"));
        assert!(!mirror_path_has_reserved_segment("foo/by-hash-deb"));
    }

    #[test]
    fn test_invalid_distribution() {
        /* valid */
        assert!(valid_distribution("sid"));
        assert!(valid_distribution("lunar-updates"));

        /* invalid */
        assert!(!valid_distribution(""));
        assert!(!valid_distribution("."));
        assert!(!valid_distribution(".."));
        assert!(!valid_distribution("-foo"));
        assert!(!valid_distribution(".foo"));
        assert!(!valid_distribution("_foo"));
        assert!(!valid_distribution("foo\nbar"));
        assert!(!valid_distribution("foo/bar"));
        assert!(!valid_distribution("foo/./bar"));
        assert!(!valid_distribution("foo/../bar"));
        assert!(!valid_distribution("foo//bar"));
        assert!(!valid_distribution("/"));
        assert!(!valid_distribution("/debian"));
        assert!(!valid_distribution("~/foo"));
        assert!(!valid_distribution("~foo"));
    }

    #[test]
    fn test_invalid_component() {
        /* valid */
        assert!(valid_component("main"));
        assert!(valid_component("non-free"));
        assert!(valid_component("mysql-8.0"));
        assert!(valid_component("foo_bar"));

        /* invalid */
        assert!(!valid_component(""));
        assert!(!valid_component("."));
        assert!(!valid_component(".."));
        assert!(!valid_component("-foo"));
        assert!(!valid_component(".foo"));
        assert!(!valid_component("_foo"));
        assert!(!valid_component("foo\nbar"));
        assert!(!valid_component("foo/bar"));
        assert!(!valid_component("foo/./bar"));
        assert!(!valid_component("foo/../bar"));
        assert!(!valid_component("foo//bar"));
        assert!(!valid_component("/"));
        assert!(!valid_component("/debian"));
        assert!(!valid_component("~/foo"));
        assert!(!valid_component("~foo"));
    }

    #[test]
    fn test_invalid_architecture() {
        /* valid */
        assert!(valid_architecture("binary-amd64"));

        /* invalid */
        assert!(!valid_architecture(""));
        assert!(!valid_architecture("."));
        assert!(!valid_architecture(".."));
        assert!(!valid_architecture("-foo"));
        assert!(!valid_architecture(".foo"));
        assert!(!valid_architecture("_foo"));
        assert!(!valid_architecture("foo\nbar"));
        assert!(!valid_architecture("foo/bar"));
        assert!(!valid_architecture("foo/./bar"));
        assert!(!valid_architecture("foo/../bar"));
        assert!(!valid_architecture("foo//bar"));
        assert!(!valid_architecture("/"));
        assert!(!valid_architecture("/debian"));
        assert!(!valid_architecture("~/foo"));
        assert!(!valid_architecture("~foo"));
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
    fn test_origin_from_path_double_slash() {
        let host = || ClientHost::new("deb.debian.org".to_string()).unwrap();

        // `//` in the mirror path resolves to the same Origin as the
        // un-doubled form thanks to internal normalisation.
        let raw = Origin::from_path("/debian/dists/sid/main/binary-amd64/Packages", host(), None)
            .expect("baseline parse");
        let doubled = Origin::from_path(
            "/debian//dists/sid/main/binary-amd64/Packages",
            host(),
            None,
        )
        .expect("`//` in mirror path should still parse after normalisation");
        assert_eq!(raw.distribution, doubled.distribution);
        assert_eq!(raw.component, doubled.component);
        assert_eq!(raw.architecture, doubled.architecture);

        // Triple slash is collapsed too.
        let tripled = Origin::from_path(
            "/debian///dists/sid/main/binary-amd64/Packages",
            host(),
            None,
        )
        .expect("`///` in mirror path should still parse after normalisation");
        assert_eq!(raw.architecture, tripled.architecture);
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
        assert!(!is_translation_filename("translation-en.gz")); // wrong case
        assert!(!is_translation_filename("Translation"));
        assert!(!is_translation_filename("Translation-en.zst")); // unknown ext
        assert!(!is_translation_filename("Translation-en.diff")); // pdiff
        assert!(!is_translation_filename("NotTranslation-en.gz"));
    }

    #[test]
    fn parse_sources_uncompressed_structured() {
        assert_eq!(
            parse_request_path("debian/dists/sid/main/source/Sources"),
            Some(ResourceFile::Sources {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "Sources",
            })
        );
    }

    #[test]
    fn parse_translation_uncompressed_structured() {
        assert_eq!(
            parse_request_path("debian/dists/sid/main/i18n/Translation-en"),
            Some(ResourceFile::Translation {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "Translation-en",
            })
        );
    }

    #[test]
    fn parse_translation_gz_structured() {
        assert_eq!(
            parse_request_path("debian/dists/sid/main/i18n/Translation-en.gz"),
            Some(ResourceFile::Translation {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "Translation-en.gz",
            })
        );
    }

    #[test]
    fn parse_translation_xz_structured() {
        assert_eq!(
            parse_request_path("debian/dists/sid/main/i18n/Translation-en.xz"),
            Some(ResourceFile::Translation {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "Translation-en.xz",
            })
        );
    }

    #[test]
    fn parse_translation_bz2_structured() {
        // Regression: the form that worked before F55 must keep working.
        assert_eq!(
            parse_request_path("debian/dists/sid/main/i18n/Translation-en.bz2"),
            Some(ResourceFile::Translation {
                mirror_path: "debian",
                distribution: "sid",
                component: "main",
                filename: "Translation-en.bz2",
            })
        );
    }

    #[test]
    fn parse_flat_translation_gz() {
        assert_eq!(
            parse_request_path("apt/Translation-en.gz"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "apt",
                filename: "Translation-en.gz",
            })
        );
    }

    #[test]
    fn parse_flat_translation_uncompressed() {
        assert_eq!(
            parse_request_path("apt/Translation-en"),
            Some(ResourceFile::Flat {
                kind: FlatKind::Metadata,
                mirror_path: "apt",
                filename: "Translation-en",
            })
        );
    }
}
