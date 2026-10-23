//! Which directories each mirror row's dashboard disk figures come from
//! ([`Footprint`], planned for all rows at once by [`plan_footprints`]), and
//! the walk that tallies one ([`walk_footprint`]).
//!
//! This is dashboard attribution, not cleanup's ownership: cleanup runs each
//! row's units on their own and arbitrates nothing across rows. The rules:
//!
//! - Every row owns its flat directory `{host}/flat/{path}/`; a structured
//!   row also its mirror directory `{host}/{path}/`. A `Flat` row never
//!   wrote a mirror directory (`kind` latches one-way to `Structured`,
//!   `cleanup::model::classify_mirror`), and the path it would name can be
//!   another row's live directory: a flat path may hold `dists` or start
//!   with `flat`.
//! - A walk applies the layout rules the startup scan applies
//!   (`cache_tree`) and never enters another row's root, at any depth: a
//!   nested mirror's directory, a flat row `<p>/dists` below a structured
//!   row's `dists/`, a legacy structured `flat/...` row's directory inside
//!   the host's flat tree. Comparing physical paths, not mirror paths, is
//!   what catches the overlaps across the two layouts.
//! - The one way two rows own the very same directory: a legacy structured
//!   row `flat/<p>` (`flat_blocklist`), whose mirror directory is row
//!   `<p>`'s flat directory. That directory is one root, attributed to the
//!   row whose mirror directory it is (the blocklist's "structured wins")
//!   and walked with the flat rules, which enter every directory the mirror
//!   rules do, so neither row's files drop out of the figures.
//! - A root is walked confined to its host directory
//!   (`Walker::confined_to`): a symlinked root would let two rows count one
//!   tree, or a row count a tree outside the cache.
//!
//! So every regular file the layout rules reach from some root is counted by
//! exactly one row. What no root reaches counts for none: a stray directory
//! and the legacy `{path}/flat/` (which the quota scan skips too), a flat
//! tree no row owns (which the quota scan counts), and the files directly in
//! a container directory above a nested mirror. Beside that and the quota's
//! 4 KiB rounding, the rows' sum can differ from the quota's cache size by
//! downloads in flight and the age of either figure.

use std::{
    collections::BTreeMap,
    ops::Bound,
    path::{Path, PathBuf},
};

use hashbrown::HashMap;
use tracing::trace;

use crate::{
    cache_layout::CacheLayout,
    cache_paths::{CachePaths, MirrorSite},
    cache_tree::{DirRole, Level, classify_dir, is_unexpected_file},
    cache_walk::{AnomalyLevel, DirFailure, EntryKind, OnMissing, WalkContext, Walker},
    deb_mirror::MirrorKind,
};

use super::tables::DirStats;

/// One directory a row owns, and the layout rules its walk starts with.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Root {
    path: PathBuf,
    level: Level,
}

/// Everything one row's figures are computed from. A cached result is
/// reused only for an equal footprint, so a row that gains a nested mirror,
/// or loses a directory to a legacy row, is walked again at once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Footprint {
    /// The host directory every root lies in; the confinement base.
    host_dir: PathBuf,
    roots: Vec<Root>,
    /// Every other root strictly inside one of `roots`, sorted: a walk does
    /// not enter them, and the directories above them are containers.
    boundaries: Vec<PathBuf>,
}

impl Footprint {
    /// A footprint telling itself apart from others by `host_dir` alone, for
    /// the cache tests.
    #[cfg(test)]
    pub(super) fn with_host_dir(host_dir: &str) -> Self {
        Self {
            host_dir: PathBuf::from(host_dir),
            ..Self::default()
        }
    }

    /// Whether `dir` is a container: some boundary lies strictly below it.
    fn contains_boundary(&self, dir: &Path) -> bool {
        let next = self.boundaries.partition_point(|b| b.as_path() <= dir);
        self.boundaries
            .get(next)
            .is_some_and(|boundary| boundary.starts_with(dir))
    }
}

/// The footprint of each of `rows` (a row's site and kind), in order. Rows
/// are canonical, so the site's host is the `{host[:port]}` directory the
/// row's files live in.
#[must_use]
pub(super) fn plan_footprints(
    rows: &[(MirrorSite<'_>, MirrorKind)],
    paths: CachePaths<'_>,
) -> Vec<Footprint> {
    /// A root's row and the rules its walk starts with.
    struct Owner {
        row: usize,
        level: Level,
    }

    // Per host directory, every root by path: the sort order puts a root's
    // descendants right behind it (`Path` compares by component).
    let mut hosts: HashMap<PathBuf, BTreeMap<PathBuf, Owner>> = HashMap::new();
    // Mirror directories first, so a flat directory coinciding with one
    // finds its owner already in place.
    for (row, (site, kind)) in rows.iter().enumerate() {
        if *kind == MirrorKind::Structured {
            hosts
                .entry(paths.host_dir(site.host, site.port))
                .or_default()
                .insert(
                    paths.mirror_dir(*site),
                    Owner {
                        row,
                        level: Level::Mirror,
                    },
                );
        }
    }
    for (row, (site, _kind)) in rows.iter().enumerate() {
        hosts
            .entry(paths.host_dir(site.host, site.port))
            .or_default()
            .entry(paths.entry_dir(CacheLayout::Flat, *site))
            .and_modify(|owner| owner.level = Level::Flat)
            .or_insert(Owner {
                row,
                level: Level::Flat,
            });
    }

    let mut footprints = vec![Footprint::default(); rows.len()];
    for (host_dir, roots) in &hosts {
        for (path, owner) in roots {
            let footprint = &mut footprints[owner.row];
            footprint.host_dir.clone_from(host_dir);
            footprint.roots.push(Root {
                path: path.clone(),
                level: owner.level,
            });
            footprint.boundaries.extend(
                roots
                    .range::<Path, _>((Bound::Excluded(path.as_path()), Bound::Unbounded))
                    .map(|(inner, _)| inner)
                    .take_while(|inner| inner.starts_with(path))
                    .cloned(),
            );
        }
    }
    for footprint in &mut footprints {
        footprint.boundaries.sort_unstable();
        footprint.boundaries.dedup();
    }
    footprints
}

static DASHBOARD_WALK: WalkContext = WalkContext {
    what: "a mirror directory",
    dir_failure: DirFailure::Continue("excluding its unread entries from the reported cache size"),
    entry_failure: "excluding it from the reported cache size",
    non_regular: "excluding it from the reported cache size",
    anomalies: AnomalyLevel::Debug,
};

/// Tally `footprint` for the dashboard's Mirrors table.
///
/// The layout rules are the startup scan's (`cache_tree`), so this counts
/// what the quota counts within these roots. Failures (a stat failure, an
/// unreadable subdirectory) are logged and counted by the walker like
/// everywhere else and the walk carries on, so one bad entry does not drop
/// the whole mirror from the table. Anomalies are logged at `debug` only
/// ([`AnomalyLevel::Debug`]): a viewer's refresh re-runs this walk, and the
/// startup scan and cleanup already warn about the same entry.
pub(super) async fn walk_footprint(footprint: &Footprint) -> DirStats {
    let mut stats = DirStats::default();
    for root in &footprint.roots {
        let mut walker = Walker::new(&root.path, &DASHBOARD_WALK, OnMissing::Tolerate, root.level)
            .stat_files()
            .confined_to(&footprint.host_dir);
        while let Some(mut entry) = walker.next().await {
            match entry.kind() {
                EntryKind::NonRegular => {}
                EntryKind::File => {
                    if is_unexpected_file(entry.tag(), entry.name()) {
                        entry.report_unexpected("counting it towards the reported cache size");
                    }
                    let in_byhash = entry.tag() == Level::ByHash;
                    if let Some(metadata) = entry.metadata().await {
                        stats.add_file(entry.name(), &metadata, in_byhash);
                    }
                }
                EntryKind::Dir => {
                    let path = entry.path();
                    if footprint.boundaries.binary_search(&path).is_ok() {
                        trace!(
                            "Skipping `{}` for the dashboard: another mirror's directory",
                            path.display()
                        );
                        continue;
                    }
                    match classify_dir(entry.tag(), entry.name()) {
                        DirRole::Layout(level) => entry.descend(level),
                        // Holds a nested mirror's directory further down.
                        DirRole::MirrorSubdir if footprint.contains_boundary(&path) => {}
                        DirRole::MirrorSubdir | DirRole::Stray => entry.report_unexpected(
                            "excluding it and its contents from the reported cache size",
                        ),
                    }
                }
            }
        }
    }
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientHost;

    /// The tree below, each file sized a distinct power of two so a row's
    /// byte total names exactly the files it counted: `(path below the host
    /// directory, the row expected to count it)`, `None` for a file no row
    /// owns.
    const FILES: &[(&str, Option<&str>)] = &[
        // A structured mirror: its pool, a non-deb beside it, `dists/` with
        // its by-hash, `tmp/`.
        ("debian/a_1_all.deb", Some("debian")),
        ("debian/README", Some("debian")),
        ("debian/dists/sid_Release", Some("debian")),
        ("debian/dists/by-hash/ab", Some("debian")),
        ("debian/tmp/b_1_all.deb.partial", Some("debian")),
        // Its nested mirror, never the parent's.
        ("debian/security/c_1_all.deb", Some("debian/security")),
        // A stray directory and the legacy flat directory: nobody's.
        ("debian/stray/d", None),
        ("debian/flat/e_1_all.deb", None),
        // A container above a nested mirror: its own files are nobody's.
        ("ubuntu/ports/f", None),
        ("ubuntu/ports/arm/g_1_all.deb", Some("ubuntu/ports/arm")),
        // A structured row's flat files are its own too.
        ("flat/debian/h_1_all.deb", Some("debian")),
        // A flat row with a nested flat row; by-hash and tmp under both.
        ("flat/repo/sub/i_1_all.deb", Some("repo/sub")),
        ("flat/repo/sub/by-hash/j", Some("repo/sub")),
        ("flat/repo/sub/tmp/k_1_all.deb.partial", Some("repo/sub")),
        // The legacy structured row `flat/repo` owns `flat/repo/`, which is
        // also flat row `repo`'s directory: walked with the flat rules
        // (`by-hash/` and `dists/` included), for the structured row.
        ("flat/repo/l_1_all.deb", Some("flat/repo")),
        ("flat/repo/by-hash/m", Some("flat/repo")),
        ("flat/repo/dists/stable/n_1_all.deb", Some("flat/repo")),
        // A flat row `x/dists` would name structured row `x`'s `dists/` as
        // its mirror directory: that stays `x`'s.
        ("x/dists/sid_Release", Some("x")),
        ("flat/x/dists/o_1_all.deb", Some("x/dists")),
        // A flat directory reached through a symlink counts for nobody; its
        // target for its own row.
        ("flat/other/p_1_all.deb", Some("other")),
    ];

    const ROWS: &[(&str, MirrorKind)] = &[
        ("debian", MirrorKind::Structured),
        ("debian/security", MirrorKind::Structured),
        ("ubuntu/ports/arm", MirrorKind::Structured),
        ("repo", MirrorKind::Flat),
        ("repo/sub", MirrorKind::Flat),
        ("flat/repo", MirrorKind::Structured),
        ("x", MirrorKind::Structured),
        ("x/dists", MirrorKind::Flat),
        ("link", MirrorKind::Flat),
        ("other", MirrorKind::Flat),
    ];

    fn size_of(index: usize) -> u64 {
        1 << index
    }

    #[tokio::test]
    async fn every_reachable_file_is_counted_by_exactly_its_row() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = CachePaths::new(dir.path());
        let host = ClientHost::new("mirror.test")
            .expect("host")
            .into_cache_host();
        let host_dir = paths.host_dir(&host, None);
        for (index, (rel, _)) in FILES.iter().enumerate() {
            let path = host_dir.join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, vec![0; usize::try_from(size_of(index)).unwrap()])
                .expect("write");
        }
        std::os::unix::fs::symlink(host_dir.join("flat/other"), host_dir.join("flat/link"))
            .expect("symlink");

        let rows: Vec<_> = ROWS
            .iter()
            .map(|(path, kind)| {
                (
                    MirrorSite {
                        host: &host,
                        port: None,
                        path,
                    },
                    *kind,
                )
            })
            .collect();
        let footprints = plan_footprints(&rows, paths);

        let mut counted = 0;
        for ((row, _), footprint) in ROWS.iter().zip(&footprints) {
            let stats = walk_footprint(footprint).await;
            let expected: u64 = FILES
                .iter()
                .enumerate()
                .filter(|(_, (_, owner))| *owner == Some(*row))
                .map(|(index, _)| size_of(index))
                .sum();
            assert_eq!(stats.size, expected, "row {row}: {stats:?}");
            assert_eq!(counted & stats.size, 0, "row {row} recounts a file");
            counted |= stats.size;
        }
        let owned: u64 = FILES
            .iter()
            .enumerate()
            .filter(|(_, (_, owner))| owner.is_some())
            .map(|(index, _)| size_of(index))
            .sum();
        assert_eq!(counted, owned, "every owned file is counted");
    }

    /// The by-hash and deb tallies follow the layout level, not the path.
    #[tokio::test]
    async fn byhash_and_deb_counts_follow_the_layout() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = CachePaths::new(dir.path());
        let host = ClientHost::new("mirror.test")
            .expect("host")
            .into_cache_host();
        let host_dir = paths.host_dir(&host, None);
        for rel in [
            "debian/a_1_all.deb",
            "debian/dists/by-hash/ab",
            "debian/dists/sid_Release",
            "flat/debian/by-hash/cd",
        ] {
            let path = host_dir.join(rel);
            std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            std::fs::write(&path, b"x").expect("write");
        }
        let site = MirrorSite {
            host: &host,
            port: None,
            path: "debian",
        };
        let footprints = plan_footprints(&[(site, MirrorKind::Structured)], paths);
        let stats = walk_footprint(&footprints[0]).await;
        assert_eq!(
            (stats.deb_files, stats.metadata_files, stats.byhash_files),
            (1, 3, 2)
        );
    }
}
