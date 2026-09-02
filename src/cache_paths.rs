//! Every on-disk path below the cache directory, derived in one place.
//!
//! [`CachePaths`] is the only code that joins the layout directory names
//! (`flat/`, `dists/`, `by-hash/`, `tmp/`) onto a cache root.  The serve
//! path (`ConnectionDetails::cache_file_path`), the `.partial` placement
//! (`partial_file::create_partial_file`), cleanup's unit roots
//! (`cleanup::model::classify_mirror`), the startup cache scan
//! (`task_cache_scan`), the web interface's per-mirror size walk and the
//! legacy-layout migration probe all derive their paths here, so they cannot
//! disagree about where a file lives.  `root` is a parameter, so every helper
//! is pure and unit-testable; the one `global_config()` read is
//! [`CachePaths::global`].
//!
//! # Layout
//!
//! ```text
//! {root}/tmp/                                        scratch_dir / scratch_file
//! {root}/{host[:port]}/                              host_dir
//! {root}/{host[:port]}/{mirror_path}/                mirror_dir  = entry_dir(StructuredPool)
//! {root}/{host[:port]}/{mirror_path}/dists/          entry_dir(Dists)
//! {root}/{host[:port]}/{mirror_path}/dists/by-hash/  entry_dir(DistsByHash)
//! {root}/{host[:port]}/{mirror_path}/tmp/            tmp_dir(structured layouts)
//! {root}/{host[:port]}/flat/                         flat_root
//! {root}/{host[:port]}/flat/{mirror_path}/           entry_dir(Flat)
//! {root}/{host[:port]}/flat/{mirror_path}/by-hash/   entry_dir(FlatByHash)
//! {root}/{host[:port]}/flat/{mirror_path}/tmp/       tmp_dir(flat layouts)
//! {root}/{host[:port]}/{mirror_path}/flat/           legacy_flat_dir (pre-fix layout, probed only)
//! ```
//!
//! Flat repositories anchor at the host-level `flat/` sibling rather than
//! nesting beneath a per-mirror subdirectory, and the URL path becomes the
//! on-disk path verbatim below it.  `{host}` is the alias-resolved cache
//! host ([`MirrorSite`]); the `{mirror_path}` and leaf strings are validated
//! relative before they get here (`valid_mirrorname` / `valid_filename`),
//! which every join re-asserts.
//!
//! The directory *names* walkers compare against (`SUBDIR_FLAT_BYHASH`,
//! `SUBDIR_TMP`, ...) live here too so a rename is one edit; the `dists`
//! names are consumed by [`CachePaths`] alone.

use std::{
    num::NonZero,
    path::{Path, PathBuf},
};

use crate::{cache_layout::CacheLayout, config::CacheHost, global_config};

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
const SUBDIR_DISTS: &str = "dists";

/// Subdirectory holding by-hash content-addressed files belonging to the
/// structured `dists/` layout.
const SUBDIR_DISTS_BYHASH: &str = "dists/by-hash";

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
/// `{cache}/{host}/flat/{mirror_path}/tmp/` (flat), and once more directly
/// under the cache root for volatile downloads ([`CachePaths::scratch_dir`]).
/// Files here are owned by `cleanup_tmp_dir`, never tallied in the
/// cache-size sweep.
pub(crate) const SUBDIR_TMP: &str = "tmp";

/// Layout subdirectory names that may legitimately appear under each
/// `{cache_directory}/{host}/{mirror_path}/` directory.  The startup cache
/// scan recurses into each and tallies its size; anything else triggers an
/// "Unrecognized directory entry" warning.
///
/// `tmp/` is intentionally **not** listed here: it is partial-download
/// scratch space (not part of the served cache layout), is handled
/// separately by `task_cache_scan` with its own skip branch, and is reaped
/// by `cleanup_tmp_dir` rather than tallied.
pub(crate) const KNOWN_MIRROR_SUBDIRS: &[&str] = &[SUBDIR_DISTS];

/// On-disk subdirectory below the layout's anchor for this variant, or
/// `None` when the file lives directly under the anchor (structured pool,
/// flat metadata / flat pool).  The `by-hash` segment is the only suffix
/// represented here.
const fn layout_subdir(layout: CacheLayout) -> Option<&'static str> {
    match layout {
        CacheLayout::StructuredPool | CacheLayout::Flat => None,
        CacheLayout::Dists => Some(SUBDIR_DISTS),
        CacheLayout::DistsByHash => Some(SUBDIR_DISTS_BYHASH),
        CacheLayout::FlatByHash => Some(SUBDIR_FLAT_BYHASH),
    }
}

/// The alias-resolved identity that places a mirror on disk: the cache host
/// (an alias' `main` host when the request arrived via an alias), its port
/// and the mirror path.  Every [`CachePaths`] helper takes one, so alias
/// resolution happens once, by whoever owns the mirror
/// (`ConnectionDetails::site`, `MirrorEntry::site`, `InitBarrier::site`),
/// never inside a join - and two owners that resolve differently produce
/// visibly different sites rather than silently different paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MirrorSite<'a> {
    pub(crate) host: &'a CacheHost,
    pub(crate) port: Option<NonZero<u16>>,
    pub(crate) path: &'a str,
}

impl std::fmt::Display for MirrorSite<'_> {
    /// `{host[:port]}/{mirror_path}` - the mirror's directory relative to
    /// the host level, for log lines naming a mirror by where it is cached.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { host, port, path } = self;
        write!(f, "{}/{path}", host.format_cache_dir(*port))
    }
}

/// Path derivation below one cache root.  `Copy` so it can be handed around
/// by value; construct it with [`Self::new`] from a `Config` the caller
/// already holds, or [`Self::global`] from the daemon-wide config.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CachePaths<'a> {
    root: &'a Path,
}

impl<'a> CachePaths<'a> {
    #[must_use]
    pub(crate) const fn new(root: &'a Path) -> Self {
        Self { root }
    }

    /// The daemon's configured cache directory.  The single
    /// `global_config()` read in this module; unit tests use [`Self::new`].
    #[must_use]
    pub(crate) fn global() -> CachePaths<'static> {
        CachePaths::new(&global_config().cache_directory)
    }

    /// The cache root itself.
    #[must_use]
    pub(crate) const fn root(self) -> &'a Path {
        self.root
    }

    /// `{root}/tmp/`: scratch space for volatile downloads, which are
    /// written to a random temp file rather than a per-mirror `.partial`.
    #[must_use]
    pub(crate) fn scratch_dir(self) -> PathBuf {
        self.assemble([Some(Path::new(SUBDIR_TMP))])
    }

    /// `{root}/tmp/{leaf}`.
    #[must_use]
    pub(crate) fn scratch_file(self, leaf: &Path) -> PathBuf {
        self.assemble([Some(Path::new(SUBDIR_TMP)), Some(leaf)])
    }

    /// `{root}/{host[:port]}/`: the directory holding every structured
    /// mirror of one cache host plus its `flat/` sibling.
    #[must_use]
    pub(crate) fn host_dir(self, host: &CacheHost, port: Option<NonZero<u16>>) -> PathBuf {
        let host_dir = host.format_cache_dir(port);
        self.assemble([Some(Path::new(host_dir.as_ref()))])
    }

    /// `{root}/{host[:port]}/flat/`: the host-level anchor of every flat
    /// repository served from `host`, scanned once per host.
    #[must_use]
    pub(crate) fn flat_root(self, host: &CacheHost, port: Option<NonZero<u16>>) -> PathBuf {
        let host_dir = host.format_cache_dir(port);
        self.assemble([
            Some(Path::new(host_dir.as_ref())),
            Some(Path::new(SUBDIR_FLAT)),
        ])
    }

    /// `{root}/{host[:port]}/{mirror_path}/`: the structured anchor of a
    /// mirror - where its pool lives and what `dists/` and `tmp/` hang off.
    #[must_use]
    pub(crate) fn mirror_dir(self, site: MirrorSite<'_>) -> PathBuf {
        self.below_anchor(false, site, None, None)
    }

    /// `{root}/{host[:port]}/{mirror_path}/flat/`: where the pre-fix layout
    /// cached a mirror's flat-repository files.  Nothing reads or writes
    /// it any more; startup probes it to warn about reclaimable space.
    #[must_use]
    pub(crate) fn legacy_flat_dir(self, site: MirrorSite<'_>) -> PathBuf {
        self.below_anchor(false, site, Some(Path::new(SUBDIR_FLAT)), None)
    }

    /// The directory a `layout`'s cache entries live in directly:
    /// `{anchor}/{subdir?}/` where the anchor is the structured mirror
    /// directory or its `flat/{mirror_path}` counterpart, and `subdir` is
    /// the layout's `dists/`, `dists/by-hash/` or `by-hash/` (see the
    /// module-level table).
    #[must_use]
    pub(crate) fn entry_dir(self, layout: CacheLayout, site: MirrorSite<'_>) -> PathBuf {
        self.below_anchor(
            layout.is_flat(),
            site,
            layout_subdir(layout).map(Path::new),
            None,
        )
    }

    /// [`Self::entry_dir`] plus the `leaf` file name, in one pre-sized
    /// allocation - the serve path's per-request cache file path.
    #[must_use]
    pub(crate) fn entry_file(
        self,
        layout: CacheLayout,
        site: MirrorSite<'_>,
        leaf: &Path,
    ) -> PathBuf {
        self.below_anchor(
            layout.is_flat(),
            site,
            layout_subdir(layout).map(Path::new),
            Some(leaf),
        )
    }

    /// `{anchor}/tmp/`: the per-mirror partial-download directory for a
    /// `layout`, a sibling of the layout's entries so the final `rename(2)`
    /// stays on one filesystem.  Structured layouts share the structured
    /// anchor's `tmp/`; flat layouts share the flat anchor's.
    #[must_use]
    pub(crate) fn tmp_dir(self, layout: CacheLayout, site: MirrorSite<'_>) -> PathBuf {
        self.below_anchor(layout.is_flat(), site, Some(Path::new(SUBDIR_TMP)), None)
    }

    /// [`Self::tmp_dir`] plus the `leaf` file name (`{debname}.partial`).
    #[must_use]
    pub(crate) fn partial_file(
        self,
        layout: CacheLayout,
        site: MirrorSite<'_>,
        leaf: &Path,
    ) -> PathBuf {
        self.below_anchor(
            layout.is_flat(),
            site,
            Some(Path::new(SUBDIR_TMP)),
            Some(leaf),
        )
    }

    /// `{root}/{host}/{flat/?}{mirror_path}/{tail?}/{leaf?}`.
    fn below_anchor(
        self,
        flat: bool,
        site: MirrorSite<'_>,
        tail: Option<&Path>,
        leaf: Option<&Path>,
    ) -> PathBuf {
        let MirrorSite { host, port, path } = site;
        let host_dir = host.format_cache_dir(port);
        self.assemble([
            Some(Path::new(host_dir.as_ref())),
            flat.then_some(Path::new(SUBDIR_FLAT)),
            Some(Path::new(path)),
            tail,
            leaf,
        ])
    }

    /// Join the present `parts` below the root in one pre-sized allocation
    /// (+1 per separator): this runs once per request on both dispatch hot
    /// paths and once per served file in the size walks, and `PathBuf`
    /// growth showed up in profiles dominated by Path/Vec reallocation.
    ///
    /// Every part must be relative - an absolute one would make `push`
    /// discard everything before it - and non-empty, since pushing an empty
    /// path only appends a trailing separator.
    #[expect(
        clippy::pathbuf_init_then_push,
        reason = "the auto-suggestion `.join()` allocates a fresh PathBuf per part and \
                  throws away the with_capacity sizing we want here"
    )]
    fn assemble<const N: usize>(self, parts: [Option<&Path>; N]) -> PathBuf {
        let mut capacity = self.root.as_os_str().len();
        for part in parts.iter().flatten() {
            assert!(
                part.is_relative(),
                "path construction must not contain absolute components"
            );
            assert!(
                !part.as_os_str().is_empty(),
                "path construction must not contain empty components"
            );
            capacity += part.as_os_str().len() + 1;
        }

        let mut path = PathBuf::with_capacity(capacity);
        path.push(self.root);
        for part in parts.into_iter().flatten() {
            path.push(part);
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientHost;

    fn cache_host(s: &str) -> CacheHost {
        ClientHost::new(s.to_owned())
            .expect("valid host")
            .into_cache_host()
    }

    /// Every test derives below `/cache`.
    #[expect(non_snake_case, reason = "reads as the constant it stands in for")]
    fn PATHS() -> CachePaths<'static> {
        CachePaths::new(Path::new("/cache"))
    }

    #[test]
    fn structured_layouts_hang_off_the_mirror_dir() {
        let host = cache_host("deb.debian.org");
        let site = MirrorSite {
            host: &host,
            port: None,
            path: "debian",
        };
        assert_eq!(
            PATHS().mirror_dir(site),
            PathBuf::from("/cache/deb.debian.org/debian")
        );
        assert_eq!(
            PATHS().entry_dir(CacheLayout::StructuredPool, site),
            PathBuf::from("/cache/deb.debian.org/debian")
        );
        assert_eq!(
            PATHS().entry_file(
                CacheLayout::StructuredPool,
                site,
                Path::new("foo_1.0_amd64.deb")
            ),
            PathBuf::from("/cache/deb.debian.org/debian/foo_1.0_amd64.deb")
        );
        assert_eq!(
            PATHS().entry_file(CacheLayout::Dists, site, Path::new("sid_InRelease")),
            PathBuf::from("/cache/deb.debian.org/debian/dists/sid_InRelease")
        );
        assert_eq!(
            PATHS().entry_file(CacheLayout::DistsByHash, site, Path::new("4f88")),
            PathBuf::from("/cache/deb.debian.org/debian/dists/by-hash/4f88")
        );
        assert_eq!(
            PATHS().tmp_dir(CacheLayout::Dists, site),
            PathBuf::from("/cache/deb.debian.org/debian/tmp")
        );
        assert_eq!(
            PATHS().partial_file(
                CacheLayout::StructuredPool,
                site,
                Path::new("foo_1.0_amd64.deb.partial")
            ),
            PathBuf::from("/cache/deb.debian.org/debian/tmp/foo_1.0_amd64.deb.partial")
        );
        assert_eq!(
            PATHS().legacy_flat_dir(site),
            PathBuf::from("/cache/deb.debian.org/debian/flat")
        );
    }

    #[test]
    fn flat_layouts_hang_off_the_host_flat_root_with_port() {
        let host = cache_host("apt.example.org");
        let port = NonZero::new(8080);
        let site = MirrorSite {
            host: &host,
            port,
            path: "apt/amd64",
        };
        assert_eq!(
            PATHS().host_dir(&host, port),
            PathBuf::from("/cache/apt.example.org:8080")
        );
        assert_eq!(
            PATHS().flat_root(&host, port),
            PathBuf::from("/cache/apt.example.org:8080/flat")
        );
        assert_eq!(
            PATHS().entry_dir(CacheLayout::Flat, site),
            PathBuf::from("/cache/apt.example.org:8080/flat/apt/amd64")
        );
        assert_eq!(
            PATHS().entry_file(CacheLayout::Flat, site, Path::new("twilio_5.0.0_amd64.deb")),
            PathBuf::from("/cache/apt.example.org:8080/flat/apt/amd64/twilio_5.0.0_amd64.deb")
        );
        assert_eq!(
            PATHS().entry_file(CacheLayout::FlatByHash, site, Path::new("4f88")),
            PathBuf::from("/cache/apt.example.org:8080/flat/apt/amd64/by-hash/4f88")
        );
        assert_eq!(
            PATHS().tmp_dir(CacheLayout::FlatByHash, site),
            PathBuf::from("/cache/apt.example.org:8080/flat/apt/amd64/tmp")
        );
        assert_eq!(
            PATHS().partial_file(CacheLayout::Flat, site, Path::new("x.deb.partial")),
            PathBuf::from("/cache/apt.example.org:8080/flat/apt/amd64/tmp/x.deb.partial")
        );
        // The structured anchor of the same site ignores the flat root.
        assert_eq!(
            PATHS().mirror_dir(site),
            PathBuf::from("/cache/apt.example.org:8080/apt/amd64")
        );
    }

    #[test]
    fn scratch_paths_live_directly_under_the_root() {
        assert_eq!(PATHS().scratch_dir(), PathBuf::from("/cache/tmp"));
        assert_eq!(
            PATHS().scratch_file(Path::new("sid_InRelease")),
            PathBuf::from("/cache/tmp/sid_InRelease")
        );
        assert_eq!(PATHS().root(), Path::new("/cache"));
    }

    #[test]
    fn every_entry_dir_is_the_flat_root_or_mirror_dir_the_scan_walks() {
        // The startup scan walks `mirror_dir` (descending into `dists/`)
        // and `flat_root` (descending into every URL dir); each layout's
        // entry directory must be inside one of those two trees, or the scan
        // never counts what the serve path writes.
        let host = cache_host("deb.debian.org");
        let site = MirrorSite {
            host: &host,
            port: None,
            path: "debian/security",
        };
        let mirror_dir = PATHS().mirror_dir(site);
        let flat_root = PATHS().flat_root(&host, None);
        for layout in [
            CacheLayout::StructuredPool,
            CacheLayout::Dists,
            CacheLayout::DistsByHash,
        ] {
            assert!(
                PATHS().entry_dir(layout, site).starts_with(&mirror_dir),
                "{layout:?} is below the mirror dir"
            );
        }
        for layout in [CacheLayout::Flat, CacheLayout::FlatByHash] {
            assert!(
                PATHS().entry_dir(layout, site).starts_with(&flat_root),
                "{layout:?} is below the flat root"
            );
        }
        assert_eq!(
            PATHS().entry_dir(CacheLayout::Flat, site),
            flat_root.join("debian/security")
        );
    }

    #[test]
    fn root_with_trailing_separator_does_not_double_it() {
        let host = cache_host("deb.debian.org");
        let paths = CachePaths::new(Path::new("/cache/"));
        assert_eq!(
            paths.host_dir(&host, None),
            PathBuf::from("/cache/deb.debian.org")
        );
    }

    #[test]
    fn mirror_site_displays_as_host_dir_and_path() {
        let host = cache_host("deb.debian.org");
        assert_eq!(
            MirrorSite {
                host: &host,
                port: NonZero::new(3142),
                path: "debian",
            }
            .to_string(),
            "deb.debian.org:3142/debian"
        );
        assert_eq!(
            MirrorSite {
                host: &host,
                port: None,
                path: "debian",
            }
            .to_string(),
            "deb.debian.org/debian"
        );
    }

    #[test]
    #[should_panic(expected = "absolute components")]
    fn absolute_leaf_is_refused() {
        let host = cache_host("deb.debian.org");
        let site = MirrorSite {
            host: &host,
            port: None,
            path: "debian",
        };
        drop(PATHS().entry_file(CacheLayout::StructuredPool, site, Path::new("/etc/passwd")));
    }
}
