//! The cache-size scan: one pass over the whole cache tree producing the byte
//! and file totals `cache_quota` reconciles its running tally against.
//!
//! Runs at startup (awaited before the listener binds, so nothing is in
//! flight) and after every cleanup cycle.  The partial downloads in `tmp/`
//! are tallied like cached files: `cache_quota` counts the kept partials a
//! failed download leaves behind, which cleanup reaps only once they age
//! out. The cache root's `.apt-cacher-rs.tmp/` (volatile scratch files,
//! purged at startup) is not counted.
//!
//! The scan only counts.  Anything the layout does not allow is reported
//! and left on disk.
//!
//! Among the `tmp/` partials it also counts the *orphaned* ones, those no
//! running download claims, and a successful scan publishes that figure for
//! the dashboard.

use std::{net::Ipv6Addr, num::NonZero, path::Path};

use hashbrown::HashMap;
use tracing::{debug, error, trace};

use crate::{
    cache_paths::{CachePaths, SUBDIR_SCRATCH},
    cache_quota::accounted_size,
    cache_tree::{DirRole, Level, classify_dir, is_unexpected_file},
    cache_walk::{
        AnomalyLevel, DirFailure, Entry, EntryKind, OnMissing, WalkContext, WalkOutcome, Walker,
    },
    config::CacheHost,
    database::{Database, MirrorEntry},
    deb_mirror::{
        MirrorKind, NestedMirrorRelation, mirror_relative_path, nested_mirror_relation,
        nested_paths_per_row,
    },
    error::ErrorReport,
    global_config, healthcheck, metrics,
    partial_claim::is_claimed,
    partial_file::PARTIAL_SUFFIX,
    sqlite_error::SqlxErrorReport,
    task_setup, warn_once_or_info,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheScanError {
    #[error("{}", ErrorReport(.0))]
    Io(std::io::Error),
    #[error("{}", SqlxErrorReport(.0))]
    Sqlx(sqlx::Error),
}

/// Tally of one scan pass.  The file count is what makes an `ENOSPC` from
/// inode exhaustion legible next to a modest byte total.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScanTotals {
    /// Each file's `cache_quota::accounted_size`, the unit the quota counts in.
    pub(crate) bytes: u64,
    pub(crate) files: u64,
    /// The `.partial`s in a `tmp/` no download claimed when the scan reached
    /// them; a subset of `files`, their accounted sizes a subset of `bytes`.
    orphaned_files: u64,
    orphaned_bytes: u64,
}

impl ScanTotals {
    fn add_file(&mut self, size: u64) {
        self.bytes = self.bytes.saturating_add(size);
        self.files = self.files.saturating_add(1);
    }

    /// Count a file [`Self::add_file`] already counted as an orphaned partial.
    fn add_orphan(&mut self, size: u64) {
        self.orphaned_bytes = self.orphaned_bytes.saturating_add(size);
        self.orphaned_files = self.orphaned_files.saturating_add(1);
    }

    /// Publish the orphaned-partial figures of a completed scan, the
    /// timestamp last so a reader finding it set finds the pair set too.
    fn publish_orphans(self) {
        metrics::ORPHANED_PARTIAL_FILES.set(self.orphaned_files);
        metrics::ORPHANED_PARTIAL_BYTES.set(self.orphaned_bytes);
        metrics::ORPHANED_PARTIALS_SCANNED_AT
            .set(coarsetime::Clock::now_since_epoch().as_secs().max(1));
    }
}

impl std::ops::AddAssign for ScanTotals {
    fn add_assign(&mut self, rhs: Self) {
        let Self {
            bytes,
            files,
            orphaned_files,
            orphaned_bytes,
        } = rhs;
        self.bytes = self.bytes.saturating_add(bytes);
        self.files = self.files.saturating_add(files);
        self.orphaned_files = self.orphaned_files.saturating_add(orphaned_files);
        self.orphaned_bytes = self.orphaned_bytes.saturating_add(orphaned_bytes);
    }
}

/// The mirror rows sharing one `{host[:port]}` cache directory, each with
/// its nested-mirror boundaries ([`nested_paths_per_row`]).
struct HostBucket<'a> {
    host: &'a CacheHost,
    port: Option<NonZero<u16>>,
    mirrors: Vec<(&'a MirrorEntry, &'a [String])>,
}

static CACHE_ROOT_WALK: WalkContext = WalkContext {
    what: "the cache directory",
    dir_failure: DirFailure::Abort("abandoning the cache scan"),
    entry_failure: "excluding it from the cache size",
    non_regular: "not counting it towards the cache size",
    anomalies: AnomalyLevel::Warn,
};

static MIRROR_WALK: WalkContext = WalkContext {
    what: "a mirror directory",
    dir_failure: DirFailure::Continue("excluding its unread entries from the cache size"),
    entry_failure: "excluding it from the cache size",
    non_regular: "not counting it towards the cache size",
    anomalies: AnomalyLevel::Warn,
};

static FLAT_WALK: WalkContext = WalkContext {
    what: "a flat repository directory",
    dir_failure: DirFailure::Continue("excluding its unread entries from the cache size"),
    entry_failure: "excluding it from the cache size",
    non_regular: "not counting it towards the cache size",
    anomalies: AnomalyLevel::Warn,
};

/// Before IPv6 cache directories were bracketed, an IPv6 alias target
/// could create a bare address, optionally followed by `:port`. The two
/// forms can be ambiguous, so recognition must not guess a destination.
fn is_legacy_ipv6_dir(name: &str) -> bool {
    name.parse::<Ipv6Addr>().is_ok()
        || name.rsplit_once(':').is_some_and(|(host, port)| {
            host.parse::<Ipv6Addr>().is_ok() && port.parse::<NonZero<u16>>().is_ok()
        })
}

/// Files that cannot be accessed are not included; a message is logged for each.
pub(crate) async fn task_cache_scan(database: &Database) -> Result<ScanTotals, CacheScanError> {
    let config = global_config();

    let mirrors = match database.get_mirrors().await {
        Ok(m) => m,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to fetch the mirrors for the cache scan; abandoning the scan:  {}",
                SqlxErrorReport(&err)
            );
            return Err(CacheScanError::Sqlx(err));
        }
    };

    let paths = CachePaths::new(&config.cache_directory);
    let cache_path = paths.root();

    trace!("Scanning directory `{}`...", cache_path.display());

    // Keyed by the alias-resolved host directory name.
    let nested = nested_paths_per_row(&mirrors);
    let mut mirrors_by_dir: HashMap<String, HostBucket<'_>> = HashMap::with_capacity(mirrors.len());
    for (mirror, nested) in mirrors.iter().zip(&nested) {
        let site = mirror.site();
        mirrors_by_dir
            .entry(site.host.format_authority(site.port).into_owned())
            .or_insert_with(|| HostBucket {
                host: site.host,
                port: site.port,
                mirrors: Vec::new(),
            })
            .mirrors
            .push((mirror, nested));
    }

    let mut totals = ScanTotals::default();

    let mut walker = Walker::new(cache_path, &CACHE_ROOT_WALK, OnMissing::Fail, ());
    while let Some(entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => continue,
            EntryKind::File => {
                // The healthcheck probe is created and unlinked at the
                // cache root (a scan racing that window must not flag it),
                // and the instance lock file lives there for the whole
                // process lifetime.
                if entry.name() == healthcheck::PROBE_FILENAME
                    || entry.name() == task_setup::LOCK_FILENAME
                {
                    continue;
                }
                entry.report_unexpected("not counting it towards the cache size");
                continue;
            }
            EntryKind::Dir => {}
        }

        if entry.name() == SUBDIR_SCRATCH {
            continue;
        }

        // A non-UTF-8 entry could never match a registered mirror dir
        // (mirror hosts are validated as ASCII), so it is as unrecognized as
        // an unknown host dir.
        let Some(bucket) = entry
            .name()
            .to_str()
            .and_then(|name| mirrors_by_dir.get(name))
        else {
            entry.report_unexpected(
                if entry.name().to_str().is_some_and(is_legacy_ipv6_dir) {
                    "it is a legacy IPv6 cache directory with an unbracketed host name, so its contents are no longer served or counted towards the cache size or disk quota; stop the daemon and verify the original host and port before moving its contents to the current authority directory (bracketed IPv6, or IPv4 for a mapped address), or remove the obsolete directory"
                } else {
                    "no registered mirror matches it, so not counting it or its contents towards the cache size"
                },
            );
            continue;
        };

        // Mirror rows registered under an alias are consolidated under their
        // `main` host directory: the intended layout, not a per-row anomaly.
        debug_assert_eq!(
            entry.path(),
            paths.host_dir(bucket.host, bucket.port),
            "the walked host directory must be the one CachePaths derives for its bucket"
        );
        for &(mirror, nested) in &bucket.mirrors {
            let mirror_dir = paths.mirror_dir(mirror.site());
            totals += scan_mirror_dir(cache_path, &mirror_dir, mirror, nested).await;
        }

        // The host-level `flat/` subtree is a sibling of mirror dirs: scanned
        // once per host regardless of how many mirror rows live under it.
        // The confined walk vets its root itself (absent, symlink,
        // non-directory).
        let flat_path = paths.flat_root(bucket.host, bucket.port);
        let (_outcome, flat_totals) =
            scan_tree(cache_path, &flat_path, &FLAT_WALK, Level::Flat, "", &[]).await;
        totals += flat_totals;
    }

    match walker.finish() {
        WalkOutcome::Complete | WalkOutcome::RootMissing => {
            totals.publish_orphans();
            Ok(totals)
        }
        WalkOutcome::Aborted { logged: _, err } => Err(CacheScanError::Io(err)),
    }
}

/// `nested` lists the registered mirror paths strictly below `mirror.path`
/// on this host, which the walk treats as foreign territory.
#[must_use]
async fn scan_mirror_dir(
    cache_root: &Path,
    mirror_path: &Path,
    mirror: &MirrorEntry,
    nested: &[String],
) -> ScanTotals {
    trace!("Scanning mirror directory `{}`...", mirror_path.display());

    let (outcome, totals) = scan_tree(
        cache_root,
        mirror_path,
        &MIRROR_WALK,
        Level::Mirror,
        &mirror.path,
        nested,
    )
    .await;

    if matches!(outcome, WalkOutcome::RootMissing) {
        // For a `Flat`-kind row the structured-pool path is expected not to
        // exist: `kind` latches to `Structured` on the very first structured
        // request, so a `Flat` row has never written to
        // `<host>/<mirror_path>/`. For `Structured` rows the absence is
        // potentially a real inconsistency.
        if mirror.kind() == MirrorKind::Flat {
            debug!(
                "Mirror directory `{}` not found (flat-kind mirror, expected)",
                mirror_path.display()
            );
        } else {
            warn_once_or_info!(
                "Structured mirror directory `{}` not found; counting this mirror as empty in the cache size",
                mirror_path.display()
            );
        }
        return ScanTotals::default();
    }

    trace!(
        "Size of mirror directory `{}`: {} in {} files",
        mirror_path.display(),
        totals.bytes,
        totals.files
    );

    totals
}

/// Walk one tree tallying regular-file sizes.  `mirror_path` / `nested` only
/// matter at [`Level::Mirror`].
///
/// `root` is reached from `cache_root` through directories only: a mirror
/// directory replaced by a symlink is reported and counted as empty, so the
/// quota never counts a tree twice, or one outside the cache.
#[must_use]
async fn scan_tree(
    cache_root: &Path,
    root: &Path,
    ctx: &'static WalkContext,
    root_level: Level,
    mirror_path: &str,
    nested: &[String],
) -> (WalkOutcome, ScanTotals) {
    let mut totals = ScanTotals::default();
    let mut walker = Walker::below(cache_root, root, ctx, root_level).stat_files();

    while let Some(mut entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => {}
            EntryKind::File => {
                let Some(mdata) = entry.metadata().await else {
                    continue;
                };
                let size = accounted_size(mdata.len());
                totals.add_file(size);
                if entry.tag() == Level::Tmp
                    && entry
                        .name()
                        .as_encoded_bytes()
                        .ends_with(PARTIAL_SUFFIX.as_bytes())
                    && !is_claimed(&entry.path())
                {
                    totals.add_orphan(size);
                }
                if is_unexpected_file(entry.tag(), entry.name()) {
                    entry.report_unexpected(
                        "counting it towards the cache size but excluding it from cleanup",
                    );
                }
            }
            EntryKind::Dir => match classify_dir(entry.tag(), entry.name()) {
                DirRole::Layout(level) => entry.descend(level),
                DirRole::MirrorSubdir => classify_mirror_subdir(&entry, mirror_path, nested),
                DirRole::Stray => entry
                    .report_unexpected("not counting it or its contents towards the cache size"),
            },
        }
    }

    (walker.finish(), totals)
}

/// A subdir that is itself a registered mirror path under the same host
/// (e.g. `debian/security` when scanning `debian`), or the container of one,
/// is silently skipped: it is walked under its own mirror row. Anything
/// else is a stray directory and reported.
fn classify_mirror_subdir(entry: &Entry<'_, Level>, mirror_path: &str, nested: &[String]) {
    let Some(name_str) = entry.name().to_str() else {
        entry.report_unexpected("not counting it or its contents towards the cache size");
        return;
    };
    let expected = mirror_relative_path(mirror_path, name_str);
    match nested_mirror_relation(&expected, nested) {
        NestedMirrorRelation::Boundary => trace!(
            "Skipping `{}` - it is a sub-mirror of `{mirror_path}`",
            entry.path().display()
        ),
        NestedMirrorRelation::Container => trace!(
            "Skipping `{}` - intermediate dir for a nested sub-mirror under `{mirror_path}`",
            entry.path().display()
        ),
        NestedMirrorRelation::Unrelated => {
            entry.report_unexpected("not counting it or its contents towards the cache size");
        }
    }
}

/// Scan the structured mirror `debian` below `cache_root`.
#[cfg(test)]
async fn scan_debian(cache_root: &Path, nested: &[String]) -> (WalkOutcome, ScanTotals) {
    let mirror = cache_root.join("debian");
    scan_tree(
        cache_root,
        &mirror,
        &MIRROR_WALK,
        Level::Mirror,
        "debian",
        nested,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cache_quota::QUOTA_BLOCK_SIZE, partial_claim::PartialClaim};

    #[test]
    fn legacy_ipv6_directories_include_aliases_and_mapped_addresses() {
        for name in [
            "2001:db8::1",
            "2001:db8::1:8080", // Could also be a portless IPv6 address.
            "2001:db8::1:65535",
            "::ffff:192.0.2.1",
            "::ffff:192.0.2.1:3142",
        ] {
            assert!(is_legacy_ipv6_dir(name), "{name}");
        }
        for name in [
            "[2001:db8::1]",
            "[2001:db8::1]:8080",
            "192.0.2.1:8080",
            "deb.debian.org:8080",
            "tmp",
            "2001:db8::1:65536",
            "2001:db8::1:port",
        ] {
            assert!(!is_legacy_ipv6_dir(name), "{name}");
        }
    }

    #[tokio::test]
    async fn scan_tallies_the_partials_in_tmp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mirror = dir.path().join("debian");
        std::fs::create_dir_all(mirror.join("tmp")).expect("mkdir");
        std::fs::write(mirror.join("foo_1.0_amd64.deb"), b"12345").expect("deb");
        std::fs::write(mirror.join("tmp/bar_1.0_amd64.deb.partial"), b"123").expect("partial");
        let (_outcome, totals) = scan_debian(dir.path(), &[]).await;
        assert_eq!((totals.bytes, totals.files), (2 * QUOTA_BLOCK_SIZE, 2));

        let flat = dir.path().join("flat");
        std::fs::create_dir_all(flat.join("repo/tmp")).expect("mkdir");
        std::fs::write(flat.join("repo/Packages"), b"12").expect("index");
        std::fs::write(flat.join("repo/tmp/x_1_all.deb.partial"), b"1234").expect("partial");
        let (_outcome, totals) =
            scan_tree(dir.path(), &flat, &FLAT_WALK, Level::Flat, "", &[]).await;
        assert_eq!((totals.bytes, totals.files), (2 * QUOTA_BLOCK_SIZE, 2));
        assert_eq!(
            (totals.orphaned_files, totals.orphaned_bytes),
            (1, QUOTA_BLOCK_SIZE)
        );
    }

    #[tokio::test]
    async fn only_unclaimed_partials_in_tmp_are_orphans() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mirror = dir.path().join("debian");
        std::fs::create_dir_all(mirror.join("tmp")).expect("mkdir");
        let held = mirror.join("tmp/held_1.0_amd64.deb.partial");
        std::fs::write(&held, b"123").expect("partial");
        std::fs::write(mirror.join("tmp/left_1.0_amd64.deb.partial"), b"12345").expect("partial");
        std::fs::write(mirror.join("tmp/stray.txt"), b"1").expect("foreign");
        std::fs::write(mirror.join("pool_1.0_amd64.deb.partial"), b"1").expect("misplaced");
        let claim = PartialClaim::acquire(held).expect("unclaimed");

        let (_outcome, totals) = scan_debian(dir.path(), &[]).await;
        assert_eq!(totals.files, 4);
        assert_eq!(
            (totals.orphaned_files, totals.orphaned_bytes),
            (1, QUOTA_BLOCK_SIZE)
        );
        drop(claim);

        let (_outcome, totals) = scan_debian(dir.path(), &[]).await;
        assert_eq!(totals.orphaned_files, 2, "released, it is left behind too");
    }
}

#[cfg(test)]
mod layout_totals_tests {
    use super::*;
    use crate::cache_quota::QUOTA_BLOCK_SIZE;

    fn file(path: &Path, len: usize) {
        std::fs::create_dir_all(path.parent().expect("has a parent")).expect("mkdir");
        std::fs::write(path, vec![b'x'; len]).expect("write");
    }

    #[tokio::test]
    async fn a_mixed_tree_counts_what_the_layout_allows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mirror = dir.path().join("debian");
        // Counted: the pool, a non-deb operator artefact beside it (reported
        // but counted), `dists/` with its by-hash, the partials in `tmp/`.
        file(&mirror.join("a_1.0_all.deb"), 10);
        file(&mirror.join("README"), 5);
        file(&mirror.join("dists/sid_Release"), 7);
        file(&mirror.join("dists/by-hash/ab"), 3);
        file(&mirror.join("tmp/b_1.0_all.deb.partial"), 4);
        // Not counted: a nested mirror, the container of one, a stray
        // directory, the legacy flat directory, and any directory below
        // `dists/` (cache names are flattened), its `by-hash/` or `tmp/`.
        file(&mirror.join("security/c_1.0_all.deb"), 100);
        file(&mirror.join("ports/arm/d_1.0_all.deb"), 100);
        file(&mirror.join("stray/e"), 100);
        file(&mirror.join("flat/f_1.0_all.deb"), 100);
        file(&mirror.join("tmp/sub/g"), 100);
        file(&mirror.join("dists/sid/main/h"), 100);
        file(&mirror.join("dists/by-hash/SHA256/i"), 100);
        let nested = ["debian/security".to_owned(), "debian/ports/arm".to_owned()];
        let (outcome, totals) = scan_debian(dir.path(), &nested).await;
        assert!(matches!(outcome, WalkOutcome::Complete));
        assert_eq!((totals.bytes, totals.files), (5 * QUOTA_BLOCK_SIZE, 5));
        assert_eq!(totals.orphaned_files, 1);

        // The host-level flat tree: every directory recursed into, `dists/`
        // included, but `by-hash/` and `tmp/` are leaves.
        let flat = dir.path().join("flat");
        file(&flat.join("repo/i_1.0_all.deb"), 1);
        file(&flat.join("repo/dists/bookworm/pool/j_1.0_all.deb"), 1);
        file(&flat.join("repo/by-hash/k"), 1);
        file(&flat.join("repo/tmp/l_1.0_all.deb.partial"), 1);
        file(&flat.join("other/deep/m_1.0_all.deb"), 1);
        file(&flat.join("repo/by-hash/sub/n"), 100);
        file(&flat.join("repo/tmp/sub/o"), 100);
        let (outcome, totals) =
            scan_tree(dir.path(), &flat, &FLAT_WALK, Level::Flat, "", &[]).await;
        assert!(matches!(outcome, WalkOutcome::Complete));
        assert_eq!((totals.bytes, totals.files), (5 * QUOTA_BLOCK_SIZE, 5));
        assert_eq!(totals.orphaned_files, 1);
    }

    #[tokio::test]
    async fn a_mirror_directory_behind_a_symlink_counts_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        file(&outside.path().join("a_1.0_all.deb"), 10);
        std::os::unix::fs::symlink(outside.path(), dir.path().join("debian")).expect("symlink");
        let before = metrics::CACHE_NON_REGULAR.get();
        let (_outcome, totals) = scan_debian(dir.path(), &[]).await;
        assert_eq!((totals.bytes, totals.files), (0, 0));
        assert_eq!(metrics::CACHE_NON_REGULAR.get(), before + 1);
    }

    /// An absent root is an empty tree, a symlink there is reported as
    /// non-regular and a regular file as an unreadable directory.
    #[tokio::test]
    async fn the_flat_root_is_vetted_by_its_walk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let host = dir.path().join("example.org");
        let flat = host.join("flat");
        std::fs::create_dir(&host).expect("mkdir");
        let scan = async || scan_tree(dir.path(), &flat, &FLAT_WALK, Level::Flat, "", &[]).await;

        let (outcome, totals) = scan().await;
        assert!(matches!(outcome, WalkOutcome::RootMissing), "{outcome:?}");
        assert_eq!(totals.files, 0);

        let outside = tempfile::tempdir().expect("tempdir");
        file(&outside.path().join("repo/a_1.0_all.deb"), 10);
        std::os::unix::fs::symlink(outside.path(), &flat).expect("symlink");
        let (non_regular, io_failure) = (
            metrics::CACHE_NON_REGULAR.get(),
            metrics::CACHE_IO_FAILURE.get(),
        );
        let (outcome, totals) = scan().await;
        assert!(matches!(outcome, WalkOutcome::Complete), "{outcome:?}");
        assert_eq!((totals.bytes, totals.files), (0, 0));
        assert_eq!(metrics::CACHE_NON_REGULAR.get(), non_regular + 1);
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), io_failure);

        std::fs::remove_file(&flat).expect("unlink symlink");
        file(&flat, 10);
        let (outcome, totals) = scan().await;
        assert!(matches!(outcome, WalkOutcome::Complete), "{outcome:?}");
        assert_eq!((totals.bytes, totals.files), (0, 0));
        assert_eq!(metrics::CACHE_NON_REGULAR.get(), non_regular + 1);
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), io_failure + 1);
    }
}
