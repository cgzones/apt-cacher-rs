//! What each directory of the on-disk cache layout means to a walk over it.
//!
//! The startup / reconcile size scan (`task_cache_scan`) and the dashboard's
//! per-mirror size walk (`web::footprint`) descend the same layout: a mirror
//! directory holding its pool, `dists/` and `tmp/`; the host-level `flat/`
//! tree recursed verbatim; the content-addressed `by-hash/` and partial
//! `tmp/` leaves (see the `cache_paths` layout table). [`Level`] is the
//! walker tag both carry, and [`classify_dir`] / [`is_unexpected_file`] the
//! one statement of which directory a level enters and which entry it
//! reports, so the two walks cannot disagree about what a subtree holds.
//!
//! What a caller does *around* these rules stays its own: the scan rounds
//! sizes to quota blocks and counts orphaned partials, and decides a mirror
//! directory's non-layout subdirectories from the registered nested mirror
//! paths; the dashboard stops at every other row's anchor directory.

use std::ffi::OsStr;

use crate::{
    cache_paths::{KNOWN_MIRROR_SUBDIRS, SUBDIR_FLAT_BYHASH, SUBDIR_TMP},
    deb_mirror::is_deb_package,
};

/// What a directory reached by a layout walk means, carried as the walker's
/// per-directory tag so each entry's policy is decided without re-deriving
/// it from the path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    /// `<host>/<mirror_path>/`: the pool's files, `dists/` entered as
    /// [`Level::Structured`] and `tmp/` as [`Level::Tmp`]; any other
    /// directory is a [`DirRole::MirrorSubdir`] for the caller to decide.
    Mirror,
    /// `dists/`-style: files, and a `by-hash/` subdir entered as
    /// [`Level::ByHash`]; any other directory is stray.
    Structured,
    /// Host-level `flat/` subtree: files, `by-hash/` and `tmp/` entered as
    /// their leaves, every other directory recursed into (the URL path is
    /// the on-disk path verbatim).
    Flat,
    /// Content-addressed leaf: files only; subdirs are stray.
    ByHash,
    /// Partial-download directory: files (the `.partial`s, and any foreign
    /// file until cleanup reaps it); subdirs are stray.
    Tmp,
}

/// What [`classify_dir`] makes of a directory found at some [`Level`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum DirRole {
    /// A layout directory: descend into it with this tag.
    Layout(Level),
    /// A non-layout directory directly in a mirror directory: a nested
    /// mirror's root, the container of one, or a stray directory. Which one
    /// is the caller's knowledge (registered mirror paths), not the
    /// layout's.
    MirrorSubdir,
    /// No layout allows a directory here.
    Stray,
}

/// The role of a directory named `name` found in a directory of `level`.
#[must_use]
pub(crate) fn classify_dir(level: Level, name: &OsStr) -> DirRole {
    match level {
        Level::Mirror => {
            if KNOWN_MIRROR_SUBDIRS.iter().any(|known| name == *known) {
                DirRole::Layout(Level::Structured)
            } else if name == SUBDIR_TMP {
                DirRole::Layout(Level::Tmp)
            } else {
                DirRole::MirrorSubdir
            }
        }
        Level::Structured | Level::Flat if name == SUBDIR_FLAT_BYHASH => {
            DirRole::Layout(Level::ByHash)
        }
        Level::Flat if name == SUBDIR_TMP => DirRole::Layout(Level::Tmp),
        Level::Flat => DirRole::Layout(Level::Flat),
        Level::Structured | Level::ByHash | Level::Tmp => DirRole::Stray,
    }
}

/// Whether a regular file named `name` found in a directory of `level` is
/// out of place: a mirror directory holds the pool (`.deb`/`.udeb`/`.ddeb`)
/// directly, so any other file there is an operator artefact cleanup never
/// touches. Deeper levels take every regular file at face value. Either way
/// a walk tallying sizes still counts the file.
#[must_use]
pub(crate) fn is_unexpected_file(level: Level, name: &OsStr) -> bool {
    level == Level::Mirror && !name.to_str().is_some_and(is_deb_package)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_level_enters_exactly_its_layout_directories() {
        let role = |level, name: &str| classify_dir(level, OsStr::new(name));
        assert_eq!(
            role(Level::Mirror, "dists"),
            DirRole::Layout(Level::Structured)
        );
        assert_eq!(role(Level::Mirror, "tmp"), DirRole::Layout(Level::Tmp));
        // A pool holds no `by-hash/`: it is under `dists/`.
        assert_eq!(role(Level::Mirror, "by-hash"), DirRole::MirrorSubdir);
        assert_eq!(role(Level::Mirror, "security"), DirRole::MirrorSubdir);
        assert_eq!(
            role(Level::Structured, "by-hash"),
            DirRole::Layout(Level::ByHash)
        );
        assert_eq!(role(Level::Structured, "main"), DirRole::Stray);
        assert_eq!(role(Level::Flat, "by-hash"), DirRole::Layout(Level::ByHash));
        assert_eq!(role(Level::Flat, "tmp"), DirRole::Layout(Level::Tmp));
        assert_eq!(role(Level::Flat, "dists"), DirRole::Layout(Level::Flat));
        assert_eq!(role(Level::Flat, "amd64"), DirRole::Layout(Level::Flat));
        for leaf in [Level::ByHash, Level::Tmp] {
            for name in ["by-hash", "tmp", "dists", "x"] {
                assert_eq!(role(leaf, name), DirRole::Stray, "{leaf:?}/{name}");
            }
        }
    }

    #[test]
    fn only_a_mirror_directory_expects_nothing_but_packages() {
        let odd = |level, name: &str| is_unexpected_file(level, OsStr::new(name));
        assert!(!odd(Level::Mirror, "pkg_1.0_amd64.deb"));
        assert!(odd(Level::Mirror, "README"));
        for level in [Level::Structured, Level::Flat, Level::ByHash, Level::Tmp] {
            assert!(!odd(level, "README"), "{level:?}");
        }
    }
}
