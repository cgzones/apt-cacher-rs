use std::{borrow::Cow, num::NonZero, path::Path};

use hashbrown::HashMap;
use tracing::{debug, error, trace};

use crate::{
    cache_paths::{CachePaths, KNOWN_MIRROR_SUBDIRS, SUBDIR_FLAT_BYHASH, SUBDIR_TMP},
    cache_walk::{DirFailure, Entry, EntryKind, OnMissing, WalkContext, WalkOutcome, Walker},
    config::CacheHost,
    database::{Database, MirrorEntry},
    deb_mirror::{
        MirrorKind, NestedMirrorRelation, derive_nested_paths, is_deb_package,
        nested_mirror_relation,
    },
    error::ErrorReport,
    global_config, healthcheck, metrics, task_setup,
    utils::probe_dir,
    warn_once_or_info,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum CacheScanError {
    #[error("{}", ErrorReport(.0))]
    Io(std::io::Error),
    #[error("{}", ErrorReport(.0))]
    Sqlx(sqlx::Error),
}

/// Tally of one scan pass: the bytes counted towards the cache size and the
/// number of regular files they came from.  The file count is what makes an
/// `ENOSPC` from inode exhaustion legible next to a modest byte total, and it
/// is directly comparable with cleanup's `retained`/`removed` file counts.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScanTotals {
    pub(crate) bytes: u64,
    pub(crate) files: u64,
}

impl ScanTotals {
    fn add_file(&mut self, size: u64) {
        self.bytes = self.bytes.saturating_add(size);
        self.files = self.files.saturating_add(1);
    }
}

impl std::ops::AddAssign for ScanTotals {
    fn add_assign(&mut self, rhs: Self) {
        self.bytes = self.bytes.saturating_add(rhs.bytes);
        self.files = self.files.saturating_add(rhs.files);
    }
}

/// What a directory reached by [`scan_tree`] means, carried as the walker's
/// per-directory tag so each entry's policy is decided without re-deriving
/// it from the path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Level {
    /// `<host>/<mirror_path>/`: tally every regular file (warning about
    /// non-deb ones), dispatch `dists/` to [`Level::Structured`], skip
    /// `tmp/` and nested-mirror directories, warn on anything else.
    Mirror,
    /// `dists/`-style: tally files, dispatch a `by-hash/` subdir to
    /// [`Level::ByHash`], warn on any other directory.
    Structured,
    /// Host-level `flat/` subtree: tally files, dispatch `by-hash/`, skip
    /// `tmp/`, recurse into every other directory (URL-path verbatim).
    Flat,
    /// Content-addressed leaf: tally files only; subdirs are unexpected.
    ByHash,
}

/// The mirror rows sharing one `{host[:port]}` cache directory, keyed by
/// that directory's name, plus the resolved host the name came from so the
/// host-level `flat/` root can be derived once per bucket.
struct HostBucket<'a> {
    host: &'a CacheHost,
    port: Option<NonZero<u16>>,
    mirrors: Vec<&'a MirrorEntry>,
}

static CACHE_ROOT_WALK: WalkContext = WalkContext {
    what: "the cache directory",
    dir_failure: DirFailure::Abort("abandoning the cache scan"),
    entry_failure: "excluding it from the cache size",
    non_regular: "not counting it towards the cache size",
};

static MIRROR_WALK: WalkContext = WalkContext {
    what: "a mirror directory",
    dir_failure: DirFailure::Continue("excluding its unread entries from the cache size"),
    entry_failure: "excluding it from the cache size",
    non_regular: "not counting it towards the cache size",
};

static FLAT_WALK: WalkContext = WalkContext {
    what: "a flat repository directory",
    dir_failure: DirFailure::Continue("excluding its unread entries from the cache size"),
    entry_failure: "excluding it from the cache size",
    non_regular: "not counting it towards the cache size",
};

/// Returns the size in bytes and the file count of the entire cache.
/// Files that cannot be accessed are not included; a message is logged for each.
pub(crate) async fn task_cache_scan(database: &Database) -> Result<ScanTotals, CacheScanError> {
    let config = global_config();

    let mirrors = match database.get_mirrors().await {
        Ok(m) => m,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to fetch the mirrors for the cache scan; abandoning the scan:  {}",
                ErrorReport(&err)
            );
            return Err(CacheScanError::Sqlx(err));
        }
    };

    let paths = CachePaths::new(&config.cache_directory);
    let cache_path = paths.root();

    trace!("Scanning directory `{}`...", cache_path.display());

    // Group mirrors by alias-resolved host directory name once, so each
    // cache entry is matched via an O(1) HashMap lookup instead of an inner
    // O(m) scan.  `paths_by_host_dir` shares the same key — every mirror
    // contributes both its `MirrorEntry` row and its `path` to the per-host
    // bucket (sorted, as `derive_nested_paths` requires).  Keys are owned
    // `String`s because the `Cow` from `format_cache_dir` may borrow from
    // local data (the formatted port).
    let mut mirrors_by_dir: HashMap<String, HostBucket<'_>> = HashMap::with_capacity(mirrors.len());
    let mut paths_by_host_dir: HashMap<String, Vec<&str>> = HashMap::with_capacity(mirrors.len());
    for mirror in &mirrors {
        let site = mirror.site_with_aliases(&config.aliases);
        let dir_name = site.host.format_cache_dir(site.port).into_owned();
        paths_by_host_dir
            .entry(dir_name.clone())
            .or_default()
            .push(mirror.path.as_str());
        mirrors_by_dir
            .entry(dir_name)
            .or_insert_with(|| HostBucket {
                host: site.host,
                port: site.port,
                mirrors: Vec::new(),
            })
            .mirrors
            .push(mirror);
    }
    for mirror_paths in paths_by_host_dir.values_mut() {
        mirror_paths.sort_unstable();
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
                // A regular file at the cache root is an operator
                // artefact (the cache root only ever holds host
                // directories), not a tampering signal — the walker
                // buckets it separately from FIFO/socket/device entries.
                entry.report_unexpected("not counting it towards the cache size");
                continue;
            }
            EntryKind::Dir => {}
        }

        if entry.name() == SUBDIR_TMP {
            continue;
        }

        // HashMap lookup needs a UTF-8 key.  A non-UTF-8 entry could never
        // match a registered mirror dir (mirror hosts are validated as
        // ASCII), so it is as unrecognized as an unknown host dir.
        let Some(name_str) = entry.name().to_str() else {
            entry.report_unexpected(
                "no registered mirror matches it, so not counting it or its contents towards the cache size",
            );
            continue;
        };

        let Some(bucket) = mirrors_by_dir.get(name_str) else {
            entry.report_unexpected(
                "no registered mirror matches it, so not counting it or its contents towards the cache size",
            );
            continue;
        };

        // `name_str` is the alias-resolved host, so any mirror rows
        // registered via alias names are silently consolidated under
        // their `main` host directory — no per-row warning needed
        // since this is the intended layout.
        //
        // Per-host mirror paths were precomputed above so each mirror row's
        // nested-mirror set costs one sorted-prefix scan, not an inner O(n)
        // scan per directory entry.
        let host_paths = paths_by_host_dir
            .get(name_str)
            .map(Vec::as_slice)
            .unwrap_or_default();

        // The bucket key is the host directory's name, so the walker's entry
        // and the derived host dir must be the same directory.
        debug_assert_eq!(
            entry.path(),
            paths.host_dir(bucket.host, bucket.port),
            "the walked host directory must be the one CachePaths derives for its bucket"
        );
        for mirror in &bucket.mirrors {
            let nested = derive_nested_paths(&mirror.path, host_paths);
            let mirror_dir = paths.mirror_dir(mirror.site_with_aliases(&config.aliases));
            totals += scan_mirror_dir(&mirror_dir, mirror, &nested).await;
        }

        // The host-level `flat/` subtree is a sibling of mirror dirs.
        // Scan once per host regardless of how many mirror rows live
        // under it — flat content is owned at the host level.
        let flat_path = paths.flat_root(bucket.host, bucket.port);
        match probe_dir(&flat_path, "host-level flat root").await {
            Ok(true) => {
                let (_outcome, flat_totals) =
                    scan_tree(&flat_path, &FLAT_WALK, Level::Flat, "", &[]).await;
                totals += flat_totals;
            }
            Ok(false) => {}
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to probe host-level flat root `{}`; excluding its subtree from the cache size:  {}",
                    flat_path.display(),
                    ErrorReport(&err)
                );
            }
        }
    }

    match walker.finish() {
        WalkOutcome::Complete | WalkOutcome::RootMissing => Ok(totals),
        WalkOutcome::Aborted { logged: _, err } => Err(CacheScanError::Io(err)),
    }
}

/// Tally one mirror row's `<host>/<mirror_path>/` tree at `mirror_path`
/// (`CachePaths::mirror_dir`).  `nested` lists the registered mirror paths
/// strictly below `mirror.path` on this host (see `derive_nested_paths`),
/// which the walk treats as foreign territory.
#[must_use]
async fn scan_mirror_dir(
    mirror_path: &Path,
    mirror: &MirrorEntry,
    nested: &[String],
) -> ScanTotals {
    trace!("Scanning mirror directory `{}`...", mirror_path.display());

    let (outcome, totals) = scan_tree(
        mirror_path,
        &MIRROR_WALK,
        Level::Mirror,
        &mirror.path,
        nested,
    )
    .await;

    if matches!(outcome, WalkOutcome::RootMissing) {
        // For a `Flat`-kind row the structured-pool path is expected
        // not to exist — `kind` latches to `Structured` on the very
        // first structured request (see `upsert_mirror_get_id`), so a
        // `Flat` row has by construction never written to
        // `<host>/<mirror_path>/`. Logging above debug here would just
        // add noise on every startup / SIGUSR2 cleanup. For
        // `Structured` rows the absence is potentially a real
        // inconsistency, so it warns once there and repeats at info.
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

/// Walk one tree tallying regular-file sizes; the [`Level`] tag decides,
/// per directory, which subdirectories are descended into (`dists/`,
/// `by-hash/`, every flat URL-dir), skipped (`tmp/`, nested mirrors), or
/// reported as unexpected.  `mirror_path` / `nested` only matter at
/// [`Level::Mirror`].
///
/// The walker owns the "Failed to read / iterate / get metadata" lines and
/// the anomaly counters; a directory-level failure skips that directory's
/// unread remainder and the walk carries on.
#[must_use]
async fn scan_tree(
    root: &Path,
    ctx: &'static WalkContext,
    root_level: Level,
    mirror_path: &str,
    nested: &[String],
) -> (WalkOutcome, ScanTotals) {
    let mut totals = ScanTotals::default();
    let mut walker = Walker::new(root, ctx, OnMissing::Tolerate, root_level);

    while let Some(mut entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => {}
            EntryKind::File => {
                let Some(mdata) = entry.metadata().await else {
                    continue;
                };
                totals.add_file(mdata.len());
                // A mirror directory holds the pool (`.deb`/`.udeb`/`.ddeb`)
                // directly; any other regular file there is an operator
                // artefact cleanup will never touch.  Deeper levels take
                // every regular file at face value.
                if entry.tag() == Level::Mirror
                    && !entry.name().to_str().is_some_and(is_deb_package)
                {
                    entry.report_unexpected(
                        "counting it towards the cache size but excluding it from cleanup",
                    );
                }
            }
            EntryKind::Dir => match entry.tag() {
                Level::Mirror => {
                    // Recognized mirror-level layout subdir (`dists/`) gets
                    // its size tallied; `tmp/` is skipped (partial-download
                    // scratch space).  A subdir that is itself a registered
                    // mirror path under the same host (e.g. `debian/security`
                    // when scanning `debian`) is silently skipped — it'll be
                    // walked under its own mirror row.  Flat repositories
                    // live under `<host>/flat/` (host-level sibling of mirror
                    // dirs), not below any mirror, so no `flat/` arm here.
                    if KNOWN_MIRROR_SUBDIRS
                        .iter()
                        .any(|known| entry.name() == *known)
                    {
                        entry.descend(Level::Structured);
                    } else if entry.name() != SUBDIR_TMP {
                        classify_mirror_subdir(&entry, mirror_path, nested);
                    }
                }
                Level::Structured | Level::Flat if entry.name() == SUBDIR_FLAT_BYHASH => {
                    entry.descend(Level::ByHash);
                }
                // Inside the host-level `flat/` subtree, any directory is a
                // nested URL-dir under a flat repo (the URL path becomes the
                // on-disk path verbatim) and is recursed into.  `tmp/` is
                // the partial-download scratch space (flat partials land at
                // `<host>/flat/<mirror_path>/tmp/`) and is owned by
                // `cleanup_tmp_dir`, so it is skipped here to avoid
                // inflating cache-size accounting with short-lived partials.
                Level::Flat if entry.name() == SUBDIR_TMP => {}
                Level::Flat => entry.descend(Level::Flat),
                Level::Structured | Level::ByHash => entry
                    .report_unexpected("not counting it or its contents towards the cache size"),
            },
        }
    }

    (walker.finish(), totals)
}

/// Decide what an unknown directory directly under `<host>/<mirror_path>/`
/// is: a nested mirror's territory (skipped silently), the container of one
/// (also silent), or a stray directory (reported).
fn classify_mirror_subdir(entry: &Entry<'_, Level>, mirror_path: &str, nested: &[String]) {
    let Some(name_str) = entry.name().to_str() else {
        entry.report_unexpected("not counting it or its contents towards the cache size");
        return;
    };
    let expected = if mirror_path.is_empty() {
        Cow::Borrowed(name_str)
    } else {
        Cow::Owned(format!("{mirror_path}/{name_str}"))
    };
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
