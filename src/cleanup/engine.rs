use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use coarsetime::Clock;
use hashbrown::HashMap;
use tracing::{debug, error, info, trace, warn};

use crate::{
    AppState, RETENTION_TIME,
    cache_layout::CacheLayout,
    config::Config,
    database::MirrorEntry,
    deb_mirror::{Mirror, MirrorKind, UriFormat as _},
    error::ProxyCacheError,
    humanfmt::HumanFmt,
    metrics,
};

use http::{StatusCode, header::CONTENT_LENGTH};

use crate::cleanup::model::{
    CleanupUnit, DistGate, FlatFetch, GroupOutcome, GroupResult, IndexSource, KeymapSpec,
    OriginOwner, RepoFacet, RetentionPolicy, SkipReason, SourceGroup, SweepAction, decide_sweep,
};
use crate::cleanup::packages::{
    FetchFailure, KeyMapper, PackageFormat, PackagesLayout, ReduceContext, body_is_incomplete,
    packages_body_to_memfd, try_fetch_packages_file,
};
use crate::cleanup::partials::cleanup_tmp_dir;
use crate::cleanup::refs::{
    ByHashReferenceSet, active_origin_distributions, build_byhash_reference_set, byhash_dir_present,
};
use crate::cleanup::scan::{
    AnomalyOutcome, DirAction, ScanSpec, handle_anomalous_entry, scan_candidates,
};
use crate::cleanup::sweep::{SpanTable, SweepResult, sweep_aged_metadata, sweep_candidates};

/// A scanned cache-tree entry: its on-disk path plus the retention class that
/// selects which sweep span gates its removal. Produced by
/// [`scan_candidates`](crate::cleanup::scan::scan_candidates), reduced by the
/// index sources, and swept by
/// [`sweep_candidates`](crate::cleanup::sweep::sweep_candidates).
#[derive(Debug, Clone)]
pub(super) struct Candidate {
    pub path: PathBuf,
    pub class: SpanClass,
}

/// Retention class of a [`Candidate`], selecting its sweep span from the
/// `SpanTable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SpanClass {
    /// A pool/flat `.deb`: swept past the policy grace (or age fallback).
    Deb,
    /// A by-hash file whose algorithm the current `Release` set covers but
    /// which no `Release` referenced: swept past the by-hash grace, counted as
    /// `removed_unreferenced`.
    ByHashCovered,
    /// A by-hash file in age mode / uncovered algorithm / unclassifiable name:
    /// swept past the by-hash backstop.
    ByHashUncovered,
}

pub(super) struct CleanupDone {
    pub(super) mirror: Mirror,
    pub(super) files_retained: u64,
    pub(super) files_removed: u64,
    pub(super) bytes_removed: u64,
    /// Subset of `files_removed` reclaimed as unreferenced-but-covered by-hash
    /// files; surfaced by the orchestrator as `CLEANUP_BYHASH_UNREFERENCED`.
    pub(super) removed_unreferenced: u64,
}

impl CleanupDone {
    pub(super) fn tally(
        mirror: Mirror,
        total: u64,
        files_removed: u64,
        bytes_removed: u64,
        removed_unreferenced: u64,
    ) -> Self {
        Self {
            mirror,
            files_retained: total.saturating_sub(files_removed),
            files_removed,
            bytes_removed,
            removed_unreferenced,
        }
    }
}

/// Per-unit cleanup counters returned by [`run_unit`], folded into the
/// per-mirror [`CleanupDone`] by [`run_mirror_units`].
#[derive(Default)]
pub(super) struct UnitStats {
    pub scanned: u64,
    pub removed: u64,
    pub bytes_removed: u64,
    /// Subset of `removed` deleted as unreferenced-but-covered by-hash files,
    /// summed by [`run_mirror_units`] into `CleanupDone::removed_unreferenced`
    /// and surfaced as `CLEANUP_BYHASH_UNREFERENCED` by the orchestrator.
    pub removed_unreferenced: u64,
}

/// Which `Packages` index a [`FetchPlan`] targets, and therefore how its
/// cached/buffered file is named. `cache_name` is the on-disk debname under
/// which the fetched index is cached (capital-P `Packages`); `memfd_name` is
/// the throwaway in-memory buffer name (lowercase-p `packages`).
pub(super) enum DebnameKind {
    OriginScoped {
        distribution: String,
        component: String,
        architecture: String,
    },
    Flat,
}

impl DebnameKind {
    fn cache_name(&self, fmt: PackageFormat) -> String {
        match self {
            Self::OriginScoped {
                distribution,
                component,
                architecture,
            } => format!(
                "{distribution}_{component}_{architecture}_Packages{}",
                fmt.extension()
            ),
            Self::Flat => format!("Packages{}", fmt.extension()),
        }
    }

    fn memfd_name(&self, fmt: PackageFormat) -> String {
        match self {
            Self::OriginScoped {
                distribution,
                component,
                architecture,
            } => format!(
                "{distribution}_{component}_{architecture}_packages{}",
                fmt.extension()
            ),
            Self::Flat => format!("flat_packages{}", fmt.extension()),
        }
    }
}

/// A single fetch-buffer-reduce unit: where to fetch a `Packages` index, how
/// to name it, and how to map its `Filename:` values onto scanned candidates.
pub(super) struct FetchPlan<'a> {
    pub mirror: Mirror,
    // deb-owning mirror used to key `cache_metadata` invalidation on a
    // checksum-mismatch eviction. Equals `mirror` for the structured-pool and
    // co-located flat plans, but differs for the flat-root and strict-flat-pool
    // fallbacks where `mirror` is the (truncated) Packages-fetch mirror while the
    // candidate debs live under the original sub-path mirror.
    pub owner_mirror: Mirror,
    pub base_uri: String,
    pub layout: PackagesLayout,
    // deb-cache layout for metadata invalidation; distinct from the Packages fetch `layout`
    pub cache_layout: CacheLayout,
    pub debname: DebnameKind,
    pub keymap: KeyMapper<'a>,
}

/// Outcome of reducing the candidate set against one `Packages` index.
pub(super) enum ReduceOutcome {
    /// Index fetched and reduced; candidates remain.
    Reduced,
    /// Index fetched and reduced; no candidates remain.
    Exhausted,
    /// Index could not be fetched (conservative bail for the mirror).
    FetchFailed(FetchFailure),
}

/// Running per-unit cleanup counters, finished into [`UnitStats`].
#[derive(Default)]
pub(super) struct Tally {
    total: u64,
    removed: u64,
    bytes_removed: u64,
    removed_unreferenced: u64,
}

impl Tally {
    pub(super) fn scanned(&mut self, n: u64) {
        self.total = n;
    }

    pub(super) fn fold(&mut self, swept: SweepResult) {
        self.removed += swept.files_removed;
        self.bytes_removed += swept.bytes_removed;
        self.removed_unreferenced += swept.removed_unreferenced;
    }

    /// Snapshot the running tally as [`UnitStats`] for the generic engine. The
    /// reconcile facets (`StructuredPool`/`FlatTree`) only sweep `Deb`-class
    /// candidates, so `removed_unreferenced` stays zero there; the by-hash
    /// facets thread it through their own path.
    fn unit_stats(&self) -> UnitStats {
        UnitStats {
            scanned: self.total,
            removed: self.removed,
            bytes_removed: self.bytes_removed,
            removed_unreferenced: self.removed_unreferenced,
        }
    }
}

/// Fetch one `Packages` index for `plan`, buffer it, and reduce `candidates`
/// against it (verifying matched cache files and evicting genuine
/// checksum mismatches, whose removals fold straight into `tally`).
///
/// A *fetch miss* (non-200), a *body-transfer failure* (upstream read timeout,
/// rate abort, memfd/IO buffer error), or a *silently-truncated body* (the 200
/// header arrived but the download aborted mid-stream, leaving fewer bytes than
/// the announced `Content-Length`) all yield `Ok(ReduceOutcome::FetchFailed(_))`
/// so the caller can bail the mirror conservatively. Only a *reduce parse error*
/// (decompression bomb, malformed index, local read failure) propagates as
/// `Err`; every caller now treats that conservatively too.
pub(super) async fn reduce_against(
    plan: &FetchPlan<'_>,
    candidates: &mut HashMap<String, Candidate>,
    tally: &mut Tally,
    appstate: &AppState,
    config: &Config,
) -> Result<ReduceOutcome, ProxyCacheError> {
    let (mut response, pkgfmt) = match try_fetch_packages_file(
        &plan.mirror,
        &plan.base_uri,
        plan.layout,
        |fmt| plan.debname.cache_name(fmt),
        appstate,
    )
    .await
    {
        Ok(r) => r,
        Err(failure) => return Ok(ReduceOutcome::FetchFailed(failure)),
    };

    // The 200 reflects only the upstream *response header*; the body streams
    // afterwards and can fail or truncate. Capture the announced length so a
    // complete fetch can be told from a broken one.
    let announced: Option<u64> = response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    let memfdname = plan.debname.memfd_name(pkgfmt);
    // Error-frame aborts (MirrorDownloadRate / ContentTooLarge) and memfd/IO
    // failures: skip the mirror conservatively and retry next cycle
    // (packages_body_to_memfd already logged the cause).
    let Ok((file, written)) = packages_body_to_memfd(&memfdname, response.body_mut(), config).await
    else {
        return Ok(ReduceOutcome::FetchFailed(FetchFailure {
            status: StatusCode::BAD_GATEWAY,
            upstream: None,
        }));
    };
    if body_is_incomplete(announced, written) {
        debug!(
            "cleanup: Packages `{memfdname}` truncated (announced {}, buffered {written}); treating as fetch failure",
            announced.unwrap_or(0)
        );
        return Ok(ReduceOutcome::FetchFailed(FetchFailure {
            status: StatusCode::BAD_GATEWAY,
            upstream: None,
        }));
    }

    let mut mismatch_files = 0u64;
    let mut mismatch_bytes = 0u64;
    {
        let mut ctx = ReduceContext {
            mirror: &plan.owner_mirror,
            layout: plan.cache_layout,
            mismatch_files: &mut mismatch_files,
            mismatch_bytes: &mut mismatch_bytes,
            keymap: &plan.keymap,
        };
        pkgfmt
            .reduce_file_list(file, &memfdname, candidates, &mut ctx, config)
            .await?;
    }
    tally.removed += mismatch_files;
    tally.bytes_removed += mismatch_bytes;

    Ok(if candidates.is_empty() {
        ReduceOutcome::Exhausted
    } else {
        ReduceOutcome::Reduced
    })
}

/// Build the `FetchPlan` for a flat-repo *root* `Packages` index, stripping the
/// in-mirror `prefix` (trailing `/`) from `Filename:` values so a root index
/// reconciles a sub-path mirror's cached debs. Shared by the root-first fast
/// path and the co-located cascade's Step 2 fallback.
pub(super) fn flat_root_fetch_plan<'a>(
    mirror: &Mirror,
    seg: &str,
    prefix: &'a str,
) -> FetchPlan<'a> {
    let root_mirror = Mirror::new(
        mirror.host().clone(),
        mirror.port(),
        seg.to_owned(),
        MirrorKind::Flat,
    );
    FetchPlan {
        base_uri: format!(
            "http://{}/{}/Packages",
            root_mirror.format_authority(),
            root_mirror.path()
        ),
        mirror: root_mirror,
        // The debs live under the original sub-path `mirror`, not the flat-repo
        // root, so metadata invalidation must key by `mirror`, not `root_mirror`.
        owner_mirror: mirror.clone(),
        layout: PackagesLayout::Flat,
        cache_layout: CacheLayout::Flat,
        debname: DebnameKind::Flat,
        keymap: KeyMapper::RelpathUnderPrefix { prefix },
    }
}

/// Run every `unit` of one mirror in order, folding their [`UnitStats`] into a
/// single per-mirror [`CleanupDone`]. A unit's hard error is logged (matching
/// the old outer-arm `"Error in cleanup task:  {err}"`) and does NOT abort the
/// remaining units for that mirror.
pub(super) async fn run_mirror_units(
    entry: MirrorEntry,
    units: Vec<CleanupUnit>,
    appstate: AppState,
    config: &'static Config,
) -> Result<CleanupDone, ProxyCacheError> {
    let mirror: Mirror = entry.clone().into();

    // One reference instant per mirror, injected into every unit's sweep so a
    // single cleanup cycle ages every tree against the same `now` (and so the
    // by-hash / metadata deletion paths are testable, birthtime not being
    // backdatable on Linux).
    let now = SystemTime::now();

    let mut scanned = 0u64;
    let mut removed = 0u64;
    let mut bytes_removed = 0u64;
    let mut removed_unreferenced = 0u64;

    for unit in &units {
        match run_unit(unit, &mirror, &entry, &appstate, config, now).await {
            Ok(stats) => {
                scanned += stats.scanned;
                removed += stats.removed;
                bytes_removed += stats.bytes_removed;
                removed_unreferenced += stats.removed_unreferenced;
            }
            Err(err) => {
                error!("Error in cleanup task:  {err}");
            }
        }
    }

    Ok(CleanupDone::tally(
        mirror,
        scanned,
        removed,
        bytes_removed,
        removed_unreferenced,
    ))
}

/// Immutable context threaded through the reconcile-unit resolvers (the
/// candidate map and tally are the only mutable state, kept separate).
struct ReconcileCtx<'a> {
    unit: &'a CleanupUnit,
    mirror: &'a Mirror,
    entry: &'a MirrorEntry,
    appstate: &'a AppState,
    config: &'a Config,
}

/// Signal from a source-group resolver back to the generic tail.
enum GroupResolution {
    /// The group ran and produced this result (pushed onto the tail's results).
    Ran(GroupResult),
    /// Reducing emptied the candidate map: short-circuit the whole
    /// unit — there is nothing left to sweep.
    Exhausted,
    /// The group's precondition did not hold (no candidates, no index to fetch),
    /// so it contributes no result; `decide_sweep` proceeds on the groups that
    /// did run (for an empty result set that is `Grace`).
    Skipped,
}

/// Execute one [`CleanupUnit`]. The candidate-reconcile facets (`StructuredPool`
/// / `FlatTree`) route through the generic reconcile engine; the by-hash,
/// metadata, and partials facets each run their own narrow arm.
pub(super) async fn run_unit(
    unit: &CleanupUnit,
    mirror: &Mirror,
    entry: &MirrorEntry,
    appstate: &AppState,
    config: &Config,
    now: SystemTime,
) -> Result<UnitStats, ProxyCacheError> {
    match unit.facet {
        RepoFacet::StructuredPool | RepoFacet::FlatTree => {
            run_reconcile_unit(unit, mirror, entry, appstate, config, now).await
        }
        RepoFacet::StructuredByHash => {
            run_byhash_unit(unit, mirror, entry, appstate, now, CacheLayout::DistsByHash).await
        }
        RepoFacet::FlatByHash => {
            run_byhash_unit(unit, mirror, entry, appstate, now, CacheLayout::FlatByHash).await
        }
        RepoFacet::StructuredMetadata => {
            run_metadata_unit(unit, mirror, now, CacheLayout::Dists, false).await
        }
        RepoFacet::FlatMetadata => {
            run_metadata_unit(unit, mirror, now, CacheLayout::Flat, true).await
        }
        RepoFacet::Partials => Ok(run_partials_unit(unit, mirror, now).await),
    }
}

/// Reap one `Partials` unit's `tmp/` directory (the classifier emits one for
/// the structured tree, one for the flat tree — see `model::classify_mirror`).
///
/// Delegates to [`partials::cleanup_tmp_dir`] for the actual sweep and logs
/// the same summary line `cleanup_stale_partials` used to emit (formerly
/// aggregated across every mirror in one pre-pass; now per-unit). The count is
/// deliberately NOT returned in `UnitStats` — partial-download
/// scratch files are not cached content, so they must not inflate
/// `CLEANUP_EVICTIONS`/`CLEANUP_BYTES_RECLAIMED` or the quota reconcile, exactly
/// matching the old pre-pass, which only ever logged its total.
async fn run_partials_unit(unit: &CleanupUnit, mirror: &Mirror, now: SystemTime) -> UnitStats {
    let removed = cleanup_tmp_dir(&unit.tree.root, now).await;

    if removed > 0 {
        info!(
            "Removed {removed} stale tmp entries for mirror {mirror} in `{}`",
            unit.tree.root.display()
        );
    }

    UnitStats::default()
}

/// Age out stale index metadata for a `StructuredMetadata` / `FlatMetadata`
/// unit: a direct [`sweep_aged_metadata`] over the unit's tree root. Structured
/// (`CacheLayout::Dists`, `skip_debs = false`) sweeps the pure `dists/` metadata
/// tree; flat (`CacheLayout::Flat`, `skip_debs = true`) sweeps the flat root,
/// leaving co-mingled `.deb` files to the flat-deb cleanup. The summary line is
/// emitted only when something was removed; the metadata units contribute nothing to `files_retained` (their
/// `scanned` equals `removed`, so the derived retained count is zero).
///
/// The always-fired debug marker documents the unit ordering: the metadata sweep runs
/// (and logs) before this mirror's by-hash units in the same cycle, so a stale
/// `Release` freed now unpins its digests this cycle.
async fn run_metadata_unit(
    unit: &CleanupUnit,
    mirror: &Mirror,
    now: SystemTime,
    layout: CacheLayout,
    skip_debs: bool,
) -> Result<UnitStats, ProxyCacheError> {
    let RetentionPolicy::AgeOnly { span } = unit.policy else {
        // The classifier only ever pairs a metadata facet with `AgeOnly`; a
        // mismatch means a mis-built unit, so do nothing rather than guess a span.
        return Ok(UnitStats::default());
    };

    debug!(
        "Sweeping aged index metadata for mirror {mirror} in `{}`",
        unit.tree.root.display()
    );

    let swept = sweep_aged_metadata(&unit.tree.root, span, now, mirror, layout, skip_debs).await;

    if swept.files_removed > 0 {
        info!(
            "Removed {} stale index metadata files for mirror {mirror} ({})",
            swept.files_removed,
            HumanFmt::Size(swept.bytes_removed),
        );
    }

    Ok(UnitStats {
        scanned: swept.files_removed,
        removed: swept.files_removed,
        bytes_removed: swept.bytes_removed,
        removed_unreferenced: 0,
    })
}

/// Counters from a single [`sweep_byhash_dir`] pass, mirroring the fields the
/// old `ByHashStats` carried so the summary + accounting stay identical.
#[derive(Default)]
struct ByHashOutcome {
    /// By-hash files kept: referenced digests (dropped from the candidate map
    /// before the sweep) plus candidates too young for their span.
    retained: u64,
    /// Total files removed: candidate removals plus removed anomalous entries
    /// (symlink / FIFO / ... in the by-hash dir).
    removed: u64,
    /// Subset of `removed` that were unreferenced but algorithm-covered.
    removed_unreferenced: u64,
    bytes_removed: u64,
}

/// Execute a `StructuredByHash` / `FlatByHash` unit: probe the by-hash tree,
/// build its `Release` reference set, and sweep the leftovers.
///
/// Invariant 5 (reference mode preconditions) is enforced entirely by
/// [`build_byhash_reference_set`] / [`active_origin_distributions`]: structured
/// trees gate on the complete active-origin distribution union (a DB error ⇒
/// `None` ⇒ age mode); flat trees pass an empty expected list. A `None`
/// reference set means age mode — every candidate stays `ByHashUncovered` and is
/// judged purely by the backstop. The per-file keep/remove decision is made via
/// candidate classes + span selection (see [`sweep_byhash_dir`]).
///
/// `byhash_dir_present` is probed up front so an absent tree (the common case
/// for a mirror without by-hash) skips the origins query and Release reads.
async fn run_byhash_unit(
    unit: &CleanupUnit,
    mirror: &Mirror,
    entry: &MirrorEntry,
    appstate: &AppState,
    now: SystemTime,
    layout: CacheLayout,
) -> Result<UnitStats, ProxyCacheError> {
    let byhash_path = &unit.tree.root;

    // Cheap absence check: skip the origins query + Release reads for a mirror
    // whose per-layout by-hash tree does not exist.
    if !byhash_dir_present(byhash_path).await {
        return Ok(UnitStats::default());
    }

    let Some(group) = unit.groups.first() else {
        return Ok(UnitStats::default());
    };
    let IndexSource::LocalReleaseDigests {
        release_dir,
        dist_gate,
    } = &group.source
    else {
        return Ok(UnitStats::default());
    };
    let RetentionPolicy::ByHash { grace, backstop } = unit.policy else {
        return Ok(UnitStats::default());
    };

    // Build the union reference set (`None` ⇒ age-based fallback for the whole
    // tree). Structured trees gate reference mode on the complete active-origin
    // distribution set; a DB error there forces age mode (never reconcile
    // against a possibly-incomplete origin set). Flat trees have a single root
    // Release and no per-dist union, so they pass an empty expected list.
    let reference = match dist_gate {
        DistGate::ActiveOriginDists => match active_origin_distributions(appstate, entry).await {
            Some(expected_dists) => {
                build_byhash_reference_set(release_dir, layout, &expected_dists).await
            }
            None => None,
        },
        DistGate::None => build_byhash_reference_set(release_dir, layout, &[]).await,
    };

    let outcome = sweep_byhash_dir(
        byhash_path,
        reference.as_ref(),
        grace,
        backstop,
        now,
        mirror,
        layout,
    )
    .await?;

    info!(
        "Removed {} files acquired by-hash for mirror {mirror} ({}; {} unreferenced, {} retained)",
        outcome.removed,
        HumanFmt::Size(outcome.bytes_removed),
        outcome.removed_unreferenced,
        outcome.retained,
    );

    // `scanned = retained + removed` so the derived `files_retained`
    // (`scanned - removed`) equals the kept count, exactly as the old by-hash
    // task reported it; anomaly removals cancel out of the retained figure.
    Ok(UnitStats {
        scanned: outcome.retained + outcome.removed,
        removed: outcome.removed,
        bytes_removed: outcome.bytes_removed,
        removed_unreferenced: outcome.removed_unreferenced,
    })
}

/// Walk one by-hash directory, classify each regular entry against `reference`,
/// and sweep the leftovers on a per-class span — the map-classify + sweep
/// equivalent of the old `cleanup_byhash_dir`.
///
/// Referenced digests are removed from the candidate map (kept forever);
/// unreferenced-but-covered candidates become `ByHashCovered` (swept past
/// `grace`, counted as `removed_unreferenced`); anything uncovered,
/// unclassifiable, or in age mode (`reference` is `None`) stays `ByHashUncovered`
/// (swept past `backstop`). Non-regular entries (symlink / FIFO / stray dir) are
/// removed / skipped inline via `handle_anomalous_entry(DirAction::Skip)` and a
/// removed one counts toward `removed`, matching the old walk. Removal, metadata
/// invalidation, future-timestamp and I/O-error handling all flow through
/// [`sweep_candidates`].
///
/// `NotFound` is treated as "nothing to do" (TOCTOU: the caller pre-probes with
/// `byhash_dir_present`, but the tree may vanish in between).
async fn sweep_byhash_dir(
    byhash_path: &Path,
    reference: Option<&ByHashReferenceSet>,
    grace: Duration,
    backstop: Duration,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> Result<ByHashOutcome, ProxyCacheError> {
    let mut candidates: HashMap<String, Candidate> = HashMap::new();
    let mut anomaly_removed = 0u64;

    let mut dir = match tokio::fs::read_dir(byhash_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(ByHashOutcome::default()),
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read directory `{}`:  {err}",
                byhash_path.display()
            );
            return Err(ProxyCacheError::Io(err));
        }
    };

    loop {
        let entry = match dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate directory `{}`:  {err}",
                    byhash_path.display()
                );
                return Err(ProxyCacheError::Io(err));
            }
        };
        let path = entry.path();

        // lstat semantics on tokio's `DirEntry`, so a planted symlink is seen as
        // itself (non-regular) rather than followed.
        let file_type = match entry.metadata().await {
            Ok(m) => m.file_type(),
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!("Error inspecting file `{}`:  {err}", path.display());
                continue;
            }
        };

        if !file_type.is_file() {
            // A symlink/FIFO/socket/device is removed (counted); a stray dir is
            // skipped — the DirAction::Skip anomaly routing the old walk used.
            if matches!(
                handle_anomalous_entry(&path, file_type, DirAction::Skip).await,
                AnomalyOutcome::Removed
            ) {
                anomaly_removed += 1;
            }
            continue;
        }

        // Every regular entry starts uncovered (age mode); the reference-set
        // pass below promotes covered digests and drops referenced ones. Key on
        // the file name (a bare hex digest); a non-UTF-8 name — never a real
        // by-hash file — falls back to the lossy path so it still ages out via
        // the backstop, exactly as the old walk treated an unclassifiable name.
        let key = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_owned(),
            None => path.to_string_lossy().into_owned(),
        };
        candidates.insert(
            key,
            Candidate {
                path,
                class: SpanClass::ByHashUncovered,
            },
        );
    }

    // Classify against the reference set (reference mode). A referenced digest
    // is dropped from the map — kept forever, regardless of age. An unreferenced
    // covered digest is promoted to `ByHashCovered` (grace span); an uncovered
    // algorithm or unclassifiable name stays `ByHashUncovered` (backstop).
    let mut referenced_kept = 0u64;
    if let Some(refset) = reference {
        candidates.retain(|_key, candidate| {
            let classified = candidate
                .path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| refset.classify(n));
            match classified {
                Some((_algo, true)) => {
                    referenced_kept += 1;
                    false
                }
                Some((algo, false)) => {
                    candidate.class = if refset.covers(algo) {
                        SpanClass::ByHashCovered
                    } else {
                        SpanClass::ByHashUncovered
                    };
                    true
                }
                None => {
                    candidate.class = SpanClass::ByHashUncovered;
                    true
                }
            }
        });
    }

    let survivors = candidates.len() as u64;
    let swept = sweep_candidates(
        &candidates,
        SpanTable {
            // No `Deb`-class candidates in a by-hash tree; the covered/uncovered
            // spans are the ones that fire.
            deb: backstop,
            byhash_covered: grace,
            byhash_uncovered: backstop,
        },
        now,
        mirror,
        layout,
    )
    .await;

    Ok(ByHashOutcome {
        // Referenced keeps + candidates the sweep left in place (too young / I/O
        // skipped); anomaly removals never count as retained.
        retained: referenced_kept + survivors.saturating_sub(swept.files_removed),
        removed: swept.files_removed + anomaly_removed,
        removed_unreferenced: swept.removed_unreferenced,
        bytes_removed: swept.bytes_removed,
    })
}

/// Generic candidate-reconcile engine tail, shared by every candidate facet:
/// scan the tree, resolve each ordered [`SourceGroup`] into a [`GroupResult`],
/// let [`decide_sweep`] pick the [`SweepAction`] from the unit's policy, and act
/// on it. The per-source resolvers (fetch / reduce / diagnostics) and the
/// per-facet completion summaries are the only facet-specific parts — the
/// *decision* is shared, so adding a facet is a new
/// resolver arm, not a second decision path.
async fn run_reconcile_unit(
    unit: &CleanupUnit,
    mirror: &Mirror,
    entry: &MirrorEntry,
    appstate: &AppState,
    config: &Config,
    now: SystemTime,
) -> Result<UnitStats, ProxyCacheError> {
    let mut cached_files = scan_candidates(
        &unit.tree.root,
        &entry.path,
        &ScanSpec {
            recurse: unit.tree.recurse,
            skip_subdirs: unit.tree.skip_subdirs,
            boundaries: unit.tree.boundaries.clone(),
        },
    )
    .await
    .inspect_err(|err| {
        error!(
            "Error listing files in `{}`:  {err}",
            unit.tree.root.display()
        );
    })?;

    trace!("Cached files ({}): {cached_files:?}", cached_files.len());

    let mut tally = Tally::default();
    tally.scanned(cached_files.len() as u64);

    let ctx = ReconcileCtx {
        unit,
        mirror,
        entry,
        appstate,
        config,
    };

    // Resolve every source group in order and collect the full ordered result
    // set. The tail's ONLY short-circuit is `Exhausted` (the candidate map
    // emptied — nothing left to sweep); every other outcome is
    // handed to `decide_sweep`, which needs *all* groups present (the flat
    // cascade's decision depends on the always-last co-located group appearing
    // even when an earlier root/hybrid group failed). Per-source bail (e.g.
    // stop fetching remaining origins on the first failure) lives inside each
    // resolver, which returns a single result — never a tail `break` that would
    // hide later groups from `decide_sweep`.
    let mut results: Vec<GroupResult> = Vec::with_capacity(unit.groups.len());
    // Set when an owning group (the hybrid archive-root reconcile) Completes:
    // its archive-root segment, for the strict-reconcile summary. Its presence
    // short-circuits the remaining root/colocated groups (parity with the old
    // `try_strict_flat_pool_cleanup` returning `Some(done)` on full success).
    let mut owning_root: Option<&str> = None;
    for group in &unit.groups {
        match resolve_group(&ctx, group, &mut cached_files, &mut tally).await? {
            GroupResolution::Exhausted => return Ok(tally.unit_stats()),
            GroupResolution::Skipped => {}
            GroupResolution::Ran(result) => {
                // An owning group that Completed owns the whole reconciliation:
                // stop resolving further groups and grace-sweep the leftovers.
                let owning_complete =
                    result.owning && matches!(result.outcome, GroupOutcome::Complete);
                results.push(result);
                if owning_complete {
                    owning_root = archive_root_segment(&group.source);
                    break;
                }
            }
        }
    }

    // Strict-hybrid early finish: the owning archive-root group reconciled the
    // flat-pool mirror against the structured `dists/` index of its archive
    // root. Grace-sweep the leftover unreferenced debs and emit the strict
    // summary, folding through the shared tally so deletions performed before
    // a mid-cascade failure stay accounted. The generic
    // `decide_sweep` for `[owning(Complete)]` also returns `Grace`, but the
    // early break preserves the old behavior of never probing the root/colocated
    // sources once strict succeeds, plus the strict-specific summary line.
    if let Some(archive_root) = owning_root {
        let swept = sweep_candidates(
            &cached_files,
            span_table_grace(&unit.policy),
            now,
            mirror,
            CacheLayout::Flat,
        )
        .await;
        info!(
            "Strict-reconciled flat-pool mirror {mirror} against archive root `{archive_root}`: removed {} unreferenced deb files ({})",
            swept.files_removed,
            HumanFmt::Size(swept.bytes_removed)
        );
        tally.fold(swept);
        return Ok(tally.unit_stats());
    }

    // Nothing to sweep (the tree scanned empty; a reduce that emptied the map
    // already short-circuited as `Exhausted`). Skip the no-op sweep + its
    // summary, matching the previous empty-cache early return.
    if cached_files.is_empty() {
        return Ok(tally.unit_stats());
    }

    // The shared decision core: policy + group results -> sweep action.
    match decide_sweep(&unit.policy, &results) {
        // At least one source reconciled (or none needed to): reap leftovers on
        // the short grace span.
        SweepAction::Grace => {
            let swept = sweep_candidates(
                &cached_files,
                span_table_grace(&unit.policy),
                now,
                mirror,
                reconcile_layout(unit.facet),
            )
            .await;
            log_reconcile_removed(unit.facet, mirror, &swept);
            tally.fold(swept);
        }
        // Conservative bail: no sweep this cycle. The resolver
        // already emitted the per-origin warn with the failing host/path/status.
        SweepAction::Bail => {}
        // Flat time-based fallback: every index source failed, so
        // the reference set is incomplete and leftovers age out on the long
        // `RETENTION_TIME` span instead of the short grace. Only the flat facet
        // (`ReferencedOrAge`) ever reaches here.
        SweepAction::AgeFallback {
            primary,
            root_failed,
        } => {
            // Diagnostic: the root fallback was unavailable because the
            // flat-repo root has no `mirrors_v2` row (root-segment groups carry
            // `root_seg`; the hybrid group does not, so it is not reported here).
            for result in &results {
                if result.root_seg.is_some()
                    && let GroupOutcome::NotApplicable(SkipReason::NoRow { seg }) = &result.outcome
                {
                    info!(
                        "Flat mirror {mirror}: no `mirrors_v2` row for flat-repo root `{seg}`; skipping root fallback"
                    );
                }
            }
            // Suffix only when the root fallback was attempted and failed with a
            // status *differing* from the co-located probe.
            let suffix = match &root_failed {
                Some((seg, root_status)) if *root_status != primary => {
                    format!(", flat-root `{seg}` {root_status}")
                }
                _ => String::new(),
            };
            let spans = span_table_fallback(&unit.policy);
            warn!(
                "Could not fetch flat Packages file for mirror {mirror} ({primary}{suffix}); falling back to {} time-based retention",
                HumanFmt::Time(spans.deb)
            );
            let swept = sweep_candidates(
                &cached_files,
                spans,
                now,
                mirror,
                reconcile_layout(unit.facet),
            )
            .await;
            info!(
                "Removed {} aged flat deb files for mirror {mirror} ({})",
                swept.files_removed,
                HumanFmt::Size(swept.bytes_removed)
            );
            tally.fold(swept);
        }
    }

    Ok(tally.unit_stats())
}

/// Dispatch one [`SourceGroup`] to its resolver: the structured-pool, hybrid
/// archive-root, and flat (root-segment / co-located) sources. The by-hash
/// `LocalReleaseDigests` source is resolved by [`run_byhash_unit`] and never
/// reaches this reconcile path.
async fn resolve_group(
    ctx: &ReconcileCtx<'_>,
    group: &SourceGroup,
    cached_files: &mut HashMap<String, Candidate>,
    tally: &mut Tally,
) -> Result<GroupResolution, ProxyCacheError> {
    match &group.source {
        IndexSource::OriginPackages {
            origin_rows_of: OriginOwner::SelfRow,
            keymap: _,
            cache_layout: _,
        } => resolve_origin_packages_self(ctx, cached_files, tally).await,
        IndexSource::OriginPackages {
            origin_rows_of: OriginOwner::ArchiveRoot { root },
            keymap,
            cache_layout,
        } => {
            resolve_origin_packages_archive_root(
                ctx,
                root,
                keymap,
                *cache_layout,
                cached_files,
                tally,
            )
            .await
        }
        IndexSource::FlatPackages {
            fetch: FlatFetch::Colocated,
        } => resolve_flat_colocated(ctx, cached_files, tally).await,
        IndexSource::FlatPackages {
            fetch: FlatFetch::RootSegment { seg, prefix },
        } => resolve_flat_root_segment(ctx, seg, prefix, cached_files, tally).await,
        // By-hash units resolve their local `Release` digest sets in
        // `run_byhash_unit`, never through the reconcile tail, so this arm is
        // unreachable in practice; skip defensively rather than fetch.
        IndexSource::LocalReleaseDigests {
            release_dir: _,
            dist_gate: _,
        } => Ok(GroupResolution::Skipped),
    }
}

/// Extract the archive-root segment of an owning hybrid group's source, for the
/// strict-reconcile summary. Only [`OriginOwner::ArchiveRoot`] carries one.
fn archive_root_segment(source: &IndexSource) -> Option<&str> {
    match source {
        IndexSource::OriginPackages {
            origin_rows_of: OriginOwner::ArchiveRoot { root },
            keymap: _,
            cache_layout: _,
        } => Some(root.as_str()),
        IndexSource::OriginPackages {
            origin_rows_of: OriginOwner::SelfRow,
            keymap: _,
            cache_layout: _,
        }
        | IndexSource::FlatPackages { fetch: _ }
        | IndexSource::LocalReleaseDigests {
            release_dir: _,
            dist_gate: _,
        } => None,
    }
}

/// Build the reduce-time [`KeyMapper`] for a [`KeymapSpec`]. Flat-repo `Relpath`
/// keying has no [`KeymapSpec`] form (the co-located flat resolver hard-codes
/// it); only the structured-pool `Basename` and hybrid/root `RelpathUnderPrefix`
/// specs reach here.
fn keymapper_for(spec: &KeymapSpec) -> KeyMapper<'_> {
    match spec {
        KeymapSpec::Basename => KeyMapper::Basename,
        KeymapSpec::RelpathUnderPrefix { prefix } => KeyMapper::RelpathUnderPrefix { prefix },
    }
}

/// Hybrid flat-pool source resolver (`OriginPackages { ArchiveRoot }`, issue
/// #162, e.g. Gitea/Forgejo `.../pool/<dist>/<comp>`): a faithful port of the
/// deleted `try_strict_flat_pool_cleanup`. The referencing `Packages` index
/// lives in the structured `dists/` tree of the flat repo's *archive root*, so
/// this reconciles the sub-path mirror's cached debs against the archive-root
/// row's active origins, stripping the in-mirror `prefix` from `Filename:`
/// values. Gated on an existing archive-root row so a fetch never mints a
/// cleanup-synthesised mirror row. This is the unit's `owning` group:
/// on full success (`GroupOutcome::Complete`) the tail short-circuits the
/// remaining root/colocated groups and grace-sweeps. Conservative on any fetch/
/// parse failure — the group resolves to `NotApplicable`/`FetchFailed`/
/// `ParseError` and the cascade continues. Metadata invalidation
/// keys by `owner_mirror = mirror` (the original sub-path mirror, NOT the
/// truncated archive-root fetch mirror); any checksum-mismatch
/// deletions performed before a mid-loop bail stay in the shared `tally`.
async fn resolve_origin_packages_archive_root(
    ctx: &ReconcileCtx<'_>,
    root: &str,
    keymap: &KeymapSpec,
    cache_layout: CacheLayout,
    cached_files: &mut HashMap<String, Candidate>,
    tally: &mut Tally,
) -> Result<GroupResolution, ProxyCacheError> {
    let &ReconcileCtx {
        unit: _,
        mirror,
        entry: _,
        appstate,
        config,
    } = ctx;

    // No candidates to reconcile: skip the DB gate + fetch entirely (a fetch
    // against an empty map would also trip `reduce_file_list`'s non-empty
    // debug-assert). Mirrors the structured resolver's empty-cache guard; the
    // unit's post-group empty check then returns without a sweep.
    if cached_files.is_empty() {
        return Ok(GroupResolution::Skipped);
    }

    match appstate
        .database
        .mirror_exists(mirror.host(), mirror.port(), root)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Ok(ran_owning(GroupOutcome::NotApplicable(SkipReason::NoRow {
                seg: root.to_owned(),
            })));
        }
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!("Error checking archive-root `{root}` mirror row:  {err}");
            return Ok(ran_owning(GroupOutcome::NotApplicable(SkipReason::DbError)));
        }
    }

    let origins = match appstate
        .database
        .get_origins_by_mirror(mirror.host(), mirror.port(), root)
        .await
    {
        Ok(o) => o,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!("Error looking up archive-root origins for `{root}`:  {err}");
            return Ok(ran_owning(GroupOutcome::NotApplicable(SkipReason::DbError)));
        }
    };

    let now: Duration = Clock::now_since_epoch().into();
    let active_origins: Vec<_> = origins
        .into_iter()
        .filter(|origin| {
            Duration::from_secs(
                u64::try_from(origin.last_seen)
                    .expect("Database should never store negative timestamp"),
            ) + RETENTION_TIME
                > now
        })
        .collect();

    if active_origins.is_empty() {
        return Ok(ran_owning(GroupOutcome::NotApplicable(
            SkipReason::NoActiveOrigins,
        )));
    }

    let archive_mirror = Mirror::new(
        mirror.host().clone(),
        mirror.port(),
        root.to_owned(),
        MirrorKind::Structured,
    );

    for origin in &active_origins {
        let plan = FetchPlan {
            mirror: archive_mirror.clone(),
            // The debs live under the original flat sub-path `mirror`, not the
            // archive root, so metadata invalidation must key by `mirror`.
            owner_mirror: mirror.clone(),
            base_uri: origin.uri(),
            layout: PackagesLayout::Dists,
            cache_layout,
            debname: DebnameKind::OriginScoped {
                distribution: origin.distribution.clone(),
                component: origin.component.clone(),
                architecture: origin.architecture.clone(),
            },
            keymap: keymapper_for(keymap),
        };
        match reduce_against(&plan, cached_files, tally, appstate, config).await {
            Ok(ReduceOutcome::Reduced) => {}
            Ok(ReduceOutcome::Exhausted) => return Ok(GroupResolution::Exhausted),
            Ok(ReduceOutcome::FetchFailed(status)) => {
                debug!(
                    "strict flat-pool cleanup: could not fetch archive-root Packages for `{root}` ({status}); continuing with fallback index sources for mirror {mirror}"
                );
                return Ok(ran_owning(GroupOutcome::FetchFailed(status)));
            }
            Err(err) => {
                error!("Failed to reduce archive-root Packages for `{root}`:  {err}");
                return Ok(ran_owning(GroupOutcome::ParseError));
            }
        }
    }

    Ok(ran_owning(GroupOutcome::Complete))
}

/// Flat root-segment source resolver (`FlatPackages { RootSegment }`): a flat
/// sub-path mirror (e.g. `apt/amd64`) whose `Packages` index lives at its
/// registered flat-repo root (`apt/`). Reconciles against that root index,
/// stripping the in-mirror `prefix` from `Filename:` values (via
/// [`flat_root_fetch_plan`], which also keys `owner_mirror` on the original
/// sub-path mirror). Gated on an existing root row (`NoRow`/
/// `DbError` → `NotApplicable`, both carrying `root_seg = Some(seg)` so
/// [`decide_sweep`] can build the fallback warn suffix). Never `owning`: a
/// complete root reference set still lets the always-last co-located group run
/// unless the reduce `Exhausted`s the map (the short-circuit above — this is
/// how the co-located probe is skipped when the root already references every
/// subdir deb).
async fn resolve_flat_root_segment(
    ctx: &ReconcileCtx<'_>,
    seg: &str,
    prefix: &str,
    cached_files: &mut HashMap<String, Candidate>,
    tally: &mut Tally,
) -> Result<GroupResolution, ProxyCacheError> {
    let &ReconcileCtx {
        unit: _,
        mirror,
        entry: _,
        appstate,
        config,
    } = ctx;

    // Skip the DB gate + fetch when there is nothing to reconcile (see the
    // hybrid resolver's guard for the debug-assert rationale).
    if cached_files.is_empty() {
        return Ok(GroupResolution::Skipped);
    }

    let root_seg = Some(seg.to_owned());

    match appstate
        .database
        .mirror_exists(mirror.host(), mirror.port(), seg)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Ok(GroupResolution::Ran(GroupResult {
                owning: false,
                root_seg,
                outcome: GroupOutcome::NotApplicable(SkipReason::NoRow {
                    seg: seg.to_owned(),
                }),
            }));
        }
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!("Error checking flat-repo root `{seg}` mirror row:  {err}");
            return Ok(GroupResolution::Ran(GroupResult {
                owning: false,
                root_seg,
                outcome: GroupOutcome::NotApplicable(SkipReason::DbError),
            }));
        }
    }

    let plan = flat_root_fetch_plan(mirror, seg, prefix);
    match reduce_against(&plan, cached_files, tally, appstate, config).await {
        Ok(ReduceOutcome::Reduced) => Ok(GroupResolution::Ran(GroupResult {
            owning: false,
            root_seg,
            outcome: GroupOutcome::Complete,
        })),
        Ok(ReduceOutcome::Exhausted) => {
            debug!(
                "Flat mirror {mirror}: fully reconciled against flat-repo root `{seg}`; skipped co-located probe"
            );
            Ok(GroupResolution::Exhausted)
        }
        Ok(ReduceOutcome::FetchFailed(status)) => Ok(GroupResolution::Ran(GroupResult {
            owning: false,
            root_seg,
            outcome: GroupOutcome::FetchFailed(status),
        })),
        Err(err) => {
            error!(
                "Error reducing flat-root Packages `{seg}` for mirror {mirror}:  {err}; falling back to time-based retention"
            );
            Ok(GroupResolution::Ran(GroupResult {
                owning: false,
                root_seg,
                outcome: GroupOutcome::ParseError,
            }))
        }
    }
}

/// Co-located flat source resolver (`FlatPackages { Colocated }`): the
/// always-last group, reconciling the mirror's own debs against its co-located
/// `<mirror.path>/Packages*` index (`keymap: Relpath`, `owner_mirror = mirror`).
/// Never `owning`. `decide_sweep` reads this (the last) group's outcome to pick
/// grace vs age fallback.
async fn resolve_flat_colocated(
    ctx: &ReconcileCtx<'_>,
    cached_files: &mut HashMap<String, Candidate>,
    tally: &mut Tally,
) -> Result<GroupResolution, ProxyCacheError> {
    let &ReconcileCtx {
        unit: _,
        mirror,
        entry: _,
        appstate,
        config,
    } = ctx;

    // Skip the co-located fetch when there is nothing to reconcile (see the
    // hybrid resolver's guard for the debug-assert rationale).
    if cached_files.is_empty() {
        return Ok(GroupResolution::Skipped);
    }

    let plan = FetchPlan {
        mirror: mirror.clone(),
        owner_mirror: mirror.clone(),
        base_uri: format!(
            "http://{}/{}/Packages",
            mirror.format_authority(),
            mirror.path()
        ),
        layout: PackagesLayout::Flat,
        cache_layout: CacheLayout::Flat,
        debname: DebnameKind::Flat,
        keymap: KeyMapper::Relpath,
    };
    match reduce_against(&plan, cached_files, tally, appstate, config).await {
        Ok(ReduceOutcome::Reduced) => Ok(GroupResolution::Ran(GroupResult {
            owning: false,
            root_seg: None,
            outcome: GroupOutcome::Complete,
        })),
        Ok(ReduceOutcome::Exhausted) => {
            debug!(
                "All cached flat deb files for mirror {mirror} are referenced by the Packages index"
            );
            Ok(GroupResolution::Exhausted)
        }
        Ok(ReduceOutcome::FetchFailed(status)) => Ok(GroupResolution::Ran(GroupResult {
            owning: false,
            root_seg: None,
            outcome: GroupOutcome::FetchFailed(status),
        })),
        Err(err) => {
            error!(
                "Error reducing co-located flat Packages for mirror {mirror}:  {err}; falling back to time-based retention"
            );
            Ok(GroupResolution::Ran(GroupResult {
                owning: false,
                root_seg: None,
                outcome: GroupOutcome::ParseError,
            }))
        }
    }
}

/// Build a `Ran(GroupResult)` for an `owning` group (the hybrid archive-root
/// reconcile) with no `root_seg` (that field is for flat root-segment groups).
fn ran_owning(outcome: GroupOutcome) -> GroupResolution {
    GroupResolution::Ran(GroupResult {
        owning: true,
        root_seg: None,
        outcome,
    })
}

/// Structured-pool source resolver (`OriginPackages { SelfRow }`): a faithful
/// port of the previous `cleanup_mirror_deb_files` reconcile body. Looks up the
/// mirror's own origins, filters to the active ones, logs the enumeration + the
/// no-origin / stale diagnostics, then reduces the candidate map against each
/// active origin's `dists/.../Packages*`. Returns a [`GroupResult`] the tail's
/// `decide_sweep` turns into a grace sweep or a conservative bail; on a fetch
/// miss it emits the exact invariant-1 warn *here* (where the origin host/path
/// and status are in hand) before handing back `FetchFailed`.
async fn resolve_origin_packages_self(
    ctx: &ReconcileCtx<'_>,
    cached_files: &mut HashMap<String, Candidate>,
    tally: &mut Tally,
) -> Result<GroupResolution, ProxyCacheError> {
    let &ReconcileCtx {
        unit,
        mirror,
        entry,
        appstate,
        config,
    } = ctx;

    // The grace window is used only for the diagnostics below; the sweep
    // span is re-derived from the policy in the tail.
    let grace = span_table_grace(&unit.policy).deb;

    let origins = appstate
        .database
        .get_origins_by_mirror(&entry.host, entry.port(), &entry.path)
        .await
        .inspect_err(|err| {
            error!("Error looking up origins:  {err}");
        })?;

    trace!("Origins ({}): {origins:?}", origins.len());

    let now: Duration = Clock::now_since_epoch().into();

    trace!("Now: {now:?}");

    let origins_count = origins.len();
    // Most-recent last_seen across all origin rows (in epoch seconds).
    // Used purely for the diagnostic log below when every row is stale.
    let most_recent_origin: i64 = origins.iter().map(|o| o.last_seen).max().unwrap_or(0);

    let active_origins = origins
        .into_iter()
        .filter(|origin| {
            Duration::from_secs(
                u64::try_from(origin.last_seen)
                    .expect("Database should never store negative timestamp"),
            ) + RETENTION_TIME
                > now
        })
        .collect::<Vec<_>>();

    info!(
        "Found {} active origins and {} cached deb files for mirror {}",
        active_origins.len(),
        cached_files.len(),
        entry.cache_path().display(),
    );

    // Diagnostic: cached debs exist but cleanup will fetch no Packages
    // index (no active origins).  Surface enough context to disambiguate
    // "no recent .deb traffic" (origins present but stale) from "origins
    // never recorded" (origins_count == 0).  Cheap: one extra info line
    // per cleanup cycle, only when the smelly state actually fires.
    if !cached_files.is_empty() && active_origins.is_empty() {
        if origins_count == 0 {
            info!(
                "Mirror {}: no origin records - cached debs cannot be reconciled against any Packages index; aging out via the {} grace window",
                entry.cache_path().display(),
                HumanFmt::Time(grace),
            );
        } else {
            let now_secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
            let age_secs = u64::try_from(now_secs.saturating_sub(most_recent_origin)).unwrap_or(0);
            let most_recent_age = Duration::from_secs(age_secs);
            info!(
                "Mirror {}: all {origins_count} origin records stale (most recent seen {} ago, retention window {}); cached debs will age out via the {} grace window",
                entry.cache_path().display(),
                HumanFmt::Time(most_recent_age),
                HumanFmt::Time(RETENTION_TIME),
                HumanFmt::Time(grace),
            );
        }
    }

    // No candidates, or no active origin index to reduce against: the group
    // does not run. `decide_sweep` on the resulting empty result set returns
    // `Grace`, matching the previous grace sweep (empty active origins swept
    // the leftovers). Returning early also avoids fetching a `Packages` index
    // when there are no debs to reconcile (which would otherwise stall on an
    // absent upstream).
    if cached_files.is_empty() || active_origins.is_empty() {
        return Ok(GroupResolution::Skipped);
    }

    // One fetch-buffer-reduce plan per active origin. `keymap: Basename`
    // because the structured pool flattens `Filename:` relpaths to basename;
    // `layout: Dists` is where the referencing `Packages` index lives.
    let structured_plans: Vec<FetchPlan<'_>> = active_origins
        .iter()
        .map(|origin| FetchPlan {
            mirror: mirror.clone(),
            owner_mirror: mirror.clone(),
            base_uri: origin.uri(),
            layout: PackagesLayout::Dists,
            cache_layout: CacheLayout::StructuredPool,
            debname: DebnameKind::OriginScoped {
                distribution: origin.distribution.clone(),
                component: origin.component.clone(),
                architecture: origin.architecture.clone(),
            },
            keymap: KeyMapper::Basename,
        })
        .collect();

    for (origin, plan) in active_origins.iter().zip(&structured_plans) {
        match reduce_against(plan, cached_files, tally, appstate, config).await {
            Ok(ReduceOutcome::Reduced) => {}
            Ok(ReduceOutcome::Exhausted) => {
                debug!(
                    "All cached deb files for mirror {mirror} are referenced by the Packages index"
                );
                return Ok(GroupResolution::Exhausted);
            }
            // A missing Packages file leaves us unable to complete the
            // reference set; deleting now risks wiping files referenced only by
            // this origin (typical when a distribution goes EOL upstream). Warn
            // here (host/path/status in hand) and hand the tail a `FetchFailed`
            // so `decide_sweep` returns `Bail` — no sweep this cycle.
            Ok(ReduceOutcome::FetchFailed(status)) => {
                warn!(
                    "Could not fetch package file for host {} path {} ({status}); skipping cleanup for mirror {mirror}",
                    origin.host, origin.mirror_path
                );
                return Ok(GroupResolution::Ran(GroupResult {
                    owning: false,
                    root_seg: None,
                    outcome: GroupOutcome::FetchFailed(status),
                }));
            }
            // A reduce parse error (malformed/decompression-bomb index, local
            // read failure) leaves the reference set incomplete just like a
            // fetch miss -- hand the tail a `ParseError` so it bails.
            Err(err) => {
                error!(
                    "Error reducing Packages index for mirror {mirror}:  {err}; skipping cleanup"
                );
                return Ok(GroupResolution::Ran(GroupResult {
                    owning: false,
                    root_seg: None,
                    outcome: GroupOutcome::ParseError,
                }));
            }
        }
    }

    // Every active origin's index reduced; leftovers are genuinely
    // unreferenced. `decide_sweep(ReferencedOrBail, [Complete])` returns
    // `Grace`, so the tail reaps them on the short grace span.
    Ok(GroupResolution::Ran(GroupResult {
        owning: false,
        root_seg: None,
        outcome: GroupOutcome::Complete,
    }))
}

/// Per-class sweep spans for the [`SweepAction::Grace`] action: leftovers reaped
/// past the policy's short grace span (by-hash uncovered past its backstop).
fn span_table_grace(policy: &RetentionPolicy) -> SpanTable {
    match policy {
        RetentionPolicy::ReferencedOrBail { grace }
        | RetentionPolicy::ReferencedOrAge { grace, fallback: _ } => SpanTable {
            deb: *grace,
            byhash_covered: *grace,
            byhash_uncovered: *grace,
        },
        RetentionPolicy::ByHash { grace, backstop } => SpanTable {
            deb: *grace,
            byhash_covered: *grace,
            byhash_uncovered: *backstop,
        },
        RetentionPolicy::AgeOnly { span } => SpanTable {
            deb: *span,
            byhash_covered: *span,
            byhash_uncovered: *span,
        },
    }
}

/// Per-class sweep spans for the [`SweepAction::AgeFallback`] action (flat
/// time-based retention). Only [`RetentionPolicy::ReferencedOrAge`] ever yields
/// that action; the other arms are a defensive identity so this stays a total
/// function (`StructuredPool` never reaches it).
fn span_table_fallback(policy: &RetentionPolicy) -> SpanTable {
    match policy {
        RetentionPolicy::ReferencedOrAge { grace: _, fallback } => SpanTable {
            deb: *fallback,
            byhash_covered: *fallback,
            byhash_uncovered: *fallback,
        },
        RetentionPolicy::ReferencedOrBail { grace } => SpanTable {
            deb: *grace,
            byhash_covered: *grace,
            byhash_uncovered: *grace,
        },
        RetentionPolicy::ByHash { grace, backstop } => SpanTable {
            deb: *grace,
            byhash_covered: *grace,
            byhash_uncovered: *backstop,
        },
        RetentionPolicy::AgeOnly { span } => SpanTable {
            deb: *span,
            byhash_covered: *span,
            byhash_uncovered: *span,
        },
    }
}

/// The [`CacheLayout`] the reconcile sweep keys `cache_metadata` invalidation
/// on, by facet.
fn reconcile_layout(facet: RepoFacet) -> CacheLayout {
    match facet {
        RepoFacet::StructuredPool => CacheLayout::StructuredPool,
        RepoFacet::StructuredByHash => CacheLayout::DistsByHash,
        RepoFacet::FlatByHash => CacheLayout::FlatByHash,
        // By-hash, metadata and partials units never route through the
        // reconcile sweep (`run_reconcile_unit` handles only StructuredPool
        // and FlatTree); defined layouts keep this match total.
        RepoFacet::StructuredMetadata => CacheLayout::Dists,
        RepoFacet::FlatTree | RepoFacet::FlatMetadata | RepoFacet::Partials => CacheLayout::Flat,
    }
}

/// Per-facet reconcile-sweep completion summary for the `Grace` action —
/// only the structured-pool and flat facets reach it (the by-hash units emit
/// their own summary in `run_byhash_unit`). The flat `AgeFallback` path emits
/// its own "aged flat deb files" line rather than routing through here.
fn log_reconcile_removed(facet: RepoFacet, mirror: &Mirror, swept: &SweepResult) {
    match facet {
        RepoFacet::StructuredPool => info!(
            "Removed {} unreferenced deb files for mirror {mirror} ({})",
            swept.files_removed,
            HumanFmt::Size(swept.bytes_removed)
        ),
        RepoFacet::FlatTree => info!(
            "Removed {} unreferenced flat deb files for mirror {mirror} ({})",
            swept.files_removed,
            HumanFmt::Size(swept.bytes_removed)
        ),
        RepoFacet::StructuredByHash
        | RepoFacet::FlatByHash
        | RepoFacet::StructuredMetadata
        | RepoFacet::FlatMetadata
        | RepoFacet::Partials => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientHost;

    #[test]
    fn flat_root_fetch_plan_keys_metadata_by_owner_mirror() {
        // Regression: the flat-root fallback fetches the *root* index, but the
        // debs it reconciles live under the original sub-path mirror. Metadata
        // invalidation must therefore key by `owner_mirror` (the sub-path
        // mirror), never the truncated root fetch `mirror` -- `Mirror` equality
        // includes path + kind, so a root-keyed invalidation could never match
        // the stored entry and would leak it.
        let owner = Mirror::new(
            ClientHost::new("deb.example.com".to_owned()).expect("valid host"),
            None,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        let plan = flat_root_fetch_plan(&owner, "apt", "amd64/");
        assert_eq!(plan.owner_mirror, owner);
        assert_eq!(plan.owner_mirror.path(), "apt/amd64");
        // The fetch mirror is the truncated flat-repo root, distinct from owner.
        assert_ne!(plan.mirror, owner);
        assert_eq!(plan.mirror.path(), "apt");
    }

    #[test]
    fn debname_kind_derives_cache_and_memfd_names() {
        let o = DebnameKind::OriginScoped {
            distribution: "bookworm".to_owned(),
            component: "main".to_owned(),
            architecture: "amd64".to_owned(),
        };
        assert_eq!(
            o.cache_name(PackageFormat::Xz),
            "bookworm_main_amd64_Packages.xz"
        );
        assert_eq!(
            o.memfd_name(PackageFormat::Xz),
            "bookworm_main_amd64_packages.xz"
        );
        assert_eq!(
            DebnameKind::Flat.cache_name(PackageFormat::Gz),
            "Packages.gz"
        );
        assert_eq!(
            DebnameKind::Flat.memfd_name(PackageFormat::Gz),
            "flat_packages.gz"
        );
    }

    #[test]
    fn archive_root_segment_only_for_owning_hybrid_source() {
        // Only the hybrid `ArchiveRoot` source carries the archive-root segment
        // the strict-reconcile summary needs; every other source (structured
        // `SelfRow`, flat, by-hash) yields `None`, so the tail never mistakes a
        // non-owning group for the strict early-finish.
        let hybrid = IndexSource::OriginPackages {
            origin_rows_of: OriginOwner::ArchiveRoot {
                root: "api/packages/85/debian".to_owned(),
            },
            keymap: KeymapSpec::RelpathUnderPrefix {
                prefix: "pool/php-zts/main/".to_owned(),
            },
            cache_layout: CacheLayout::Flat,
        };
        assert_eq!(
            archive_root_segment(&hybrid),
            Some("api/packages/85/debian")
        );

        let self_row = IndexSource::OriginPackages {
            origin_rows_of: OriginOwner::SelfRow,
            keymap: KeymapSpec::Basename,
            cache_layout: CacheLayout::StructuredPool,
        };
        assert_eq!(archive_root_segment(&self_row), None);

        let colocated = IndexSource::FlatPackages {
            fetch: FlatFetch::Colocated,
        };
        assert_eq!(archive_root_segment(&colocated), None);
    }

    #[test]
    fn keymapper_for_strips_hybrid_prefix_and_excludes_siblings() {
        // The hybrid/root sources key on the in-mirror relpath with the archive
        // prefix stripped; an entry outside that subtree belongs to a sibling
        // mirror and must not match (invariant-8 owner keying depends on this).
        let spec = KeymapSpec::RelpathUnderPrefix {
            prefix: "pool/php-zts/main/".to_owned(),
        };
        let km = keymapper_for(&spec);
        assert_eq!(
            km.map("pool/php-zts/main/php-zts-cli_8.5.7-1_amd64.deb")
                .as_deref(),
            Some("php-zts-cli_8.5.7-1_amd64.deb")
        );
        assert_eq!(km.map("pool/other-pkg/main/x_1.0_amd64.deb"), None);
    }

    // --- by-hash sweep (ported from the deleted `byhash::cleanup_byhash_dir`
    //     walk tests). These exercise the deletion behaviour at the sweep level
    //     with an injected `now` (birthtime is not backdatable on Linux) and an
    //     explicitly-built reference set; the DB-driven reference-set assembly
    //     (`active_origin_distributions` / `build_byhash_reference_set`) is
    //     covered by `refs.rs`'s unit tests, so isolating the sweep here keeps
    //     these tests DB-free while still gating the keep/remove verdicts.

    use hashbrown::HashSet;
    use std::num::NonZero;

    use crate::deb_mirror::MirrorKind;
    use crate::index_parser::hex_encode;

    const DAY: u64 = 24 * 60 * 60;

    fn byhash_test_mirror() -> Mirror {
        Mirror::new(
            ClientHost::new("deb.example.org".to_owned()).expect("valid host"),
            None::<NonZero<u16>>,
            "debian".to_owned(),
            MirrorKind::Structured,
        )
    }

    /// `cache_metadata::store()` (reached via `invalidate_metadata_for` on
    /// deletion) panics unless initialised. Idempotent across the test binary.
    fn ensure_metadata_store() {
        if crate::cache_metadata::init().is_err() {
            // Already installed by an earlier test in this process.
        }
    }

    #[tokio::test]
    async fn cleanup_reference_mode_removes_unreferenced_after_grace() {
        ensure_metadata_store();
        let dir = tempfile::tempdir().expect("tempdir");
        let referenced = [0x01u8; 32];
        let unref_a = [0x02u8; 32];
        let unref_b = [0x03u8; 32];
        for d in [&referenced, &unref_a, &unref_b] {
            std::fs::write(dir.path().join(hex_encode(d)), b"index-bytes").expect("write");
        }
        let mut set = ByHashReferenceSet {
            sha256: HashSet::new(),
            sha512: HashSet::new(),
        };
        set.sha256.insert(referenced);

        let now = SystemTime::now() + Duration::from_secs(10 * DAY);
        let outcome = sweep_byhash_dir(
            dir.path(),
            Some(&set),
            Duration::from_secs(3 * DAY),
            Duration::from_secs(90 * DAY),
            now,
            &byhash_test_mirror(),
            CacheLayout::DistsByHash,
        )
        .await
        .expect("sweep ok");

        assert_eq!(outcome.retained, 1);
        assert_eq!(outcome.removed, 2);
        assert_eq!(outcome.removed_unreferenced, 2);
        assert!(dir.path().join(hex_encode(&referenced)).exists());
        assert!(!dir.path().join(hex_encode(&unref_a)).exists());
    }

    #[tokio::test]
    async fn cleanup_reference_mode_grace_keeps_recent() {
        ensure_metadata_store();
        let dir = tempfile::tempdir().expect("tempdir");
        let unref = [0x07u8; 32];
        std::fs::write(dir.path().join(hex_encode(&unref)), b"x").expect("write");
        // Empty set "covers" nothing -> classify yields (Sha256, false) with
        // covers(Sha256) false, so the file would fall to the backstop. To
        // exercise the grace path the algo must be covered, so seed an
        // unrelated referenced digest.
        let mut set = ByHashReferenceSet {
            sha256: HashSet::new(),
            sha512: HashSet::new(),
        };
        set.sha256.insert([0x09u8; 32]);

        let now = SystemTime::now() + Duration::from_secs(DAY);
        let outcome = sweep_byhash_dir(
            dir.path(),
            Some(&set),
            Duration::from_secs(3 * DAY),
            Duration::from_secs(90 * DAY),
            now,
            &byhash_test_mirror(),
            CacheLayout::DistsByHash,
        )
        .await
        .expect("sweep ok");

        assert_eq!(outcome.retained, 1);
        assert_eq!(outcome.removed, 0);
        assert!(dir.path().join(hex_encode(&unref)).exists());
    }

    #[tokio::test]
    async fn cleanup_fallback_age_mode() {
        ensure_metadata_store();
        let dir = tempfile::tempdir().expect("tempdir");
        for d in [[0x21u8; 32], [0x22u8; 32]] {
            std::fs::write(dir.path().join(hex_encode(&d)), b"x").expect("write");
        }
        let grace = Duration::from_secs(3 * DAY);
        let backstop = Duration::from_secs(90 * DAY);

        // Past the backstop with no reference set -> aged out, not "unreferenced".
        let now = SystemTime::now() + Duration::from_secs(91 * DAY);
        let outcome = sweep_byhash_dir(
            dir.path(),
            None,
            grace,
            backstop,
            now,
            &byhash_test_mirror(),
            CacheLayout::DistsByHash,
        )
        .await
        .expect("sweep ok");
        assert_eq!(outcome.removed, 2);
        assert_eq!(outcome.removed_unreferenced, 0);

        // Recreate and verify young files are kept in fallback mode.
        for d in [[0x21u8; 32], [0x22u8; 32]] {
            std::fs::write(dir.path().join(hex_encode(&d)), b"x").expect("write");
        }
        let now = SystemTime::now() + Duration::from_secs(DAY);
        let outcome = sweep_byhash_dir(
            dir.path(),
            None,
            grace,
            backstop,
            now,
            &byhash_test_mirror(),
            CacheLayout::DistsByHash,
        )
        .await
        .expect("sweep ok");
        assert_eq!(outcome.removed, 0);
        assert_eq!(outcome.retained, 2);
    }
}
